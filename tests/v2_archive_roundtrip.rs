mod common;

use std::fs::{File, OpenOptions};
use std::path::Path;

use crypax::archive::reader_v2::ArchiveReaderV2;
use crypax::archive::writer_v2::ArchiveWriterV2;
use crypax::crypto::keys::{KdfParams, KeySalt, derive_archive_key};
use crypax::fs::pack_stream::PackStream;
use crypax::fs::restore_stream::RestoreStream;
use crypax::fs::scan::scan_source;

use common::{TempWorkspace, hash_tree, write_file};

const CREATED_AT: i64 = 1_700_000_000;
const ROOT_KIND_DIR: u8 = 1;
const PASSWORD: &str = "correct horse battery staple";

fn test_kdf_params() -> KdfParams {
    KdfParams {
        memory_cost_kib: 8,
        time_cost: 1,
        parallelism: 1,
    }
}

fn build_tree(root: &Path) {
    write_file(&root.join("a.txt"), b"hello from a");
    write_file(&root.join("b.dat"), &[0xAB; 200]);
    write_file(&root.join("empty.txt"), b"");
    std::fs::create_dir_all(root.join("empty_dir")).unwrap();
    write_file(&root.join("sub").join("c.txt"), b"nested c");
}

fn roundtrip_via_archive(src: &Path, out: &Path, archive_path: &Path, segment_size: usize) {
    let tree = scan_source(src).expect("scan");

    let salt = KeySalt::from_bytes([7u8; 16]);
    let key = derive_archive_key(PASSWORD, &salt, &test_kdf_params()).expect("derive key");

    // Write: pack → encrypt → archive file
    {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(archive_path)
            .expect("create archive");
        let mut writer =
            ArchiveWriterV2::new(file, *salt.as_bytes(), *key.as_bytes()).expect("writer new");
        let mut pack =
            PackStream::new(&tree, segment_size, CREATED_AT, ROOT_KIND_DIR).expect("pack");
        while let Some(seg) = pack.next_segment().expect("next_segment") {
            writer.write_segment(seg).expect("write_segment");
        }
        writer.finalize().expect("finalize");
    }

    // Read: archive file → decrypt → restore
    let file = File::open(archive_path).expect("open archive");
    let mut reader = ArchiveReaderV2::open(file).expect("reader open");
    let mut restore = RestoreStream::new(out.to_path_buf(), tree.entries.len() as u32);
    while let Some(plaintext) = reader.next_segment(&key).expect("next_segment") {
        restore.feed(&plaintext).expect("feed");
    }
}

#[test]
fn roundtrip_mixed_tree_various_segment_sizes() {
    for &seg_size in &[64usize, 1024, 1024 * 1024] {
        let ws = TempWorkspace::new("v2-roundtrip");
        let src = ws.path.join("src");
        build_tree(&src);
        let out = ws.path.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let archive = ws.path.join("archive.cryx");

        roundtrip_via_archive(&src, &out, &archive, seg_size);

        assert_eq!(
            hash_tree(&src),
            hash_tree(&out),
            "content mismatch at segment_size={seg_size}"
        );
        assert!(out.join("empty_dir").is_dir(), "empty dir missing");
        assert!(out.join("sub").is_dir(), "nested dir missing");
    }
}

#[test]
fn roundtrip_large_file_across_many_segments() {
    let ws = TempWorkspace::new("v2-large-file");
    let src = ws.path.join("src");
    let big: Vec<u8> = (0..500_000).map(|i| (i % 251) as u8).collect();
    write_file(&src.join("big.bin"), &big);
    let out = ws.path.join("out");
    std::fs::create_dir_all(&out).unwrap();
    let archive = ws.path.join("archive.cryx");

    roundtrip_via_archive(&src, &out, &archive, 64 * 1024);

    assert_eq!(
        std::fs::read(out.join("big.bin")).unwrap(),
        big,
        "byte-exact mismatch on large file"
    );
}

#[test]
fn wrong_password_fails_to_decrypt() {
    let ws = TempWorkspace::new("v2-wrong-pw");
    let src = ws.path.join("src");
    write_file(&src.join("secret.txt"), b"top secret");
    let archive = ws.path.join("archive.cryx");

    let tree = scan_source(&src).expect("scan");
    let salt = KeySalt::from_bytes([7u8; 16]);
    let key = derive_archive_key(PASSWORD, &salt, &test_kdf_params()).expect("derive key");

    {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&archive)
            .expect("create archive");
        let mut writer =
            ArchiveWriterV2::new(file, *salt.as_bytes(), *key.as_bytes()).expect("writer new");
        let mut pack = PackStream::new(&tree, 1024, CREATED_AT, ROOT_KIND_DIR).expect("pack");
        while let Some(seg) = pack.next_segment().expect("next_segment") {
            writer.write_segment(seg).expect("write_segment");
        }
        writer.finalize().expect("finalize");
    }

    let wrong_key =
        derive_archive_key("wrong password", &salt, &test_kdf_params()).expect("derive key");
    let file = File::open(&archive).expect("open archive");
    let mut reader = ArchiveReaderV2::open(file).expect("reader open");
    let err = reader.next_segment(&wrong_key).unwrap_err();
    assert!(
        format!("{err}").contains("authentication failed"),
        "expected auth error, got: {err}"
    );
}
