mod common;

use std::path::Path;

use crypax::fs::pack::{PACK_FORMAT_VERSION, PACK_MAGIC};
use crypax::fs::pack_stream::PackStream;
use crypax::fs::restore_stream::RestoreStream;
use crypax::fs::scan::scan_source;

use common::{TempWorkspace, hash_tree, write_file};

const CREATED_AT: i64 = 1_700_000_000;
const ROOT_KIND_DIR: u8 = 1;

/// 一棵覆盖 restore_stream 所有代码路径的源树：
/// - 小文件（happy path）
/// - 较大文件（小段下跨多段）
/// - 空文件（data_len == 0，走 open_target 特判）
/// - 空目录（Directory entry，无数据）
/// - 嵌套文件（先建 sub 目录，再写里面的文件）
fn build_tree(root: &Path) {
    write_file(&root.join("a.txt"), b"hello from a");
    write_file(&root.join("b.dat"), &[0xAB; 200]);
    write_file(&root.join("empty.txt"), b"");
    std::fs::create_dir_all(root.join("empty_dir")).unwrap();
    write_file(&root.join("sub").join("c.txt"), b"nested c");
}

/// PackStream 逐段 drain → 逐段喂给 RestoreStream，然后断言还原树与源一致。
/// segment_size 越小，preamble / entry header / path / data 越被逼着跨多次 feed。
fn roundtrip_at(segment_size: usize) {
    let ws = TempWorkspace::new("restore-stream");
    let src = ws.path.join("src");
    build_tree(&src);
    let out = ws.path.join("out");
    std::fs::create_dir_all(&out).unwrap();

    let tree = scan_source(&src).expect("scan");
    let mut pack = PackStream::new(&tree, segment_size, CREATED_AT, ROOT_KIND_DIR).expect("pack");
    let mut restore = RestoreStream::new(out.clone(), tree.entries.len() as u32);
    while let Some(seg) = pack.next_segment().expect("next_segment") {
        restore.feed(seg).expect("feed");
    }

    // 所有文件的相对路径 + 字节内容必须一致
    assert_eq!(
        hash_tree(&src),
        hash_tree(&out),
        "restored tree differs from source at segment_size={segment_size}"
    );
    // hash_tree 只看文件，目录结构单独确认
    assert!(
        out.join("empty_dir").is_dir(),
        "empty dir not restored (seg={segment_size})"
    );
    assert!(
        out.join("sub").is_dir(),
        "nested dir not restored (seg={segment_size})"
    );
}

#[test]
fn roundtrip_tiny_segments_force_every_boundary_to_straddle() {
    // segment_size 远小于 preamble(26) / entry header / 路径 / 数据，
    // 强制每个字段都跨多次 feed —— 专门压今天修过的跨段 bug（尤其 Path/Data）。
    for &size in &[1usize, 7, 13] {
        roundtrip_at(size);
    }
}

#[test]
fn roundtrip_large_segments_process_many_states_per_feed() {
    // 另一端：整条流塞进 1~2 个 feed，feed 的 loop 一次跑完所有状态。
    for &size in &[64usize, 1024, 1024 * 1024] {
        roundtrip_at(size);
    }
}

#[test]
fn empty_file_produces_zero_byte_file_without_underflow() {
    // 专覆盖 open_target 的 data_len == 0 分支：不进 Data、remaining 不下溢。
    let ws = TempWorkspace::new("restore-empty-file");
    let src = ws.path.join("src");
    write_file(&src.join("empty.txt"), b"");
    let out = ws.path.join("out");
    std::fs::create_dir_all(&out).unwrap();

    let tree = scan_source(&src).expect("scan");
    let mut pack = PackStream::new(&tree, 8, CREATED_AT, ROOT_KIND_DIR).expect("pack");
    let mut restore = RestoreStream::new(out.clone(), tree.entries.len() as u32);
    while let Some(seg) = pack.next_segment().expect("next_segment") {
        restore.feed(seg).expect("feed");
    }

    let restored = out.join("empty.txt");
    assert!(restored.is_file(), "empty file not created");
    assert_eq!(
        std::fs::metadata(&restored).unwrap().len(),
        0,
        "empty file restored with non-zero size"
    );
}

#[test]
fn large_file_data_streams_across_many_segments() {
    // 大文件数据跨数百段：验证 Data 批量写 + remaining 跨 feed 保留。
    let ws = TempWorkspace::new("restore-large-file");
    let src = ws.path.join("src");
    let big: Vec<u8> = (0..10_000).map(|i| (i % 251) as u8).collect();
    write_file(&src.join("big.bin"), &big);
    let out = ws.path.join("out");
    std::fs::create_dir_all(&out).unwrap();

    let tree = scan_source(&src).expect("scan");
    // segment_size=64 → big.bin 的 10000 字节跨 ~156 段
    let mut pack = PackStream::new(&tree, 64, CREATED_AT, ROOT_KIND_DIR).expect("pack");
    let mut restore = RestoreStream::new(out.clone(), tree.entries.len() as u32);
    while let Some(seg) = pack.next_segment().expect("next_segment") {
        restore.feed(seg).expect("feed");
    }

    assert_eq!(
        std::fs::read(out.join("big.bin")).unwrap(),
        big,
        "byte-exact mismatch"
    );
}

#[test]
fn rejects_unsafe_path_in_archive() {
    // 手搓带穿越路径的 pack 流：restore 必须拒绝，且拒绝前不得写出文件（防写穿 out_dir）。
    let ws = TempWorkspace::new("restore-traversal");
    let out = ws.path.join("out");
    std::fs::create_dir_all(&out).unwrap();

    for evil in &["../evil.txt", "/etc/passwd", "a/../../b"] {
        let bytes = single_entry_pack(evil);
        let mut restore = RestoreStream::new(out.clone(), 1);
        let err = restore
            .feed(&bytes)
            .err()
            .unwrap_or_else(|| panic!("expected rejection for path {evil:?}, but feed succeeded"));
        assert!(
            format!("{err}").contains("unsafe path"),
            "path {evil:?}: wrong error: {err}"
        );
    }
    // ".." 那条若没被拒绝，会写到 out 的上一级；确认它没逃出去。
    assert!(
        !ws.path.join("evil.txt").exists(),
        "traversal escaped out_dir!"
    );
}

/// 手搓一条 pack 字节流：preamble + 一个 File entry（data_len=0），
/// path 由调用者指定。用于向 restore 喂入 scan 永远不会产生的恶意路径。
fn single_entry_pack(path: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    // preamble: magic(11) + version(2) + entry_count(4) + created_at(8) + root_kind(1)
    bytes.extend_from_slice(PACK_MAGIC);
    bytes.extend_from_slice(&PACK_FORMAT_VERSION.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes()); // entry_count
    bytes.extend_from_slice(&CREATED_AT.to_le_bytes());
    bytes.push(ROOT_KIND_DIR);
    // entry framing: kind(1) + perms(1) + path_len(8) + path + size(8) + data_len(8)
    bytes.push(1); // kind = File
    bytes.push(0); // permissions
    bytes.extend_from_slice(&(path.len() as u64).to_le_bytes());
    bytes.extend_from_slice(path.as_bytes());
    bytes.extend_from_slice(&0u64.to_le_bytes()); // size
    bytes.extend_from_slice(&0u64.to_le_bytes()); // data_len
    bytes
}
