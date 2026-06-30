mod common;

use std::{fs, path::Path};

use crypax::fs::pack::{PACK_FORMAT_VERSION, PACK_MAGIC};
use crypax::fs::pack_stream::PackStream;
use crypax::fs::scan::scan_source;

use common::{TempWorkspace, write_file};

/// Build a tree that exercises every PackStream code path:
/// - a small file
/// - a larger file (spans multiple 64-byte segments)
/// - an empty directory (Directory entry, no data)
/// - a nested file (Directory entry "sub" + a file inside it)
fn build_tree(root: &Path) {
    write_file(&root.join("a.txt"), b"hello from a");
    write_file(&root.join("b.dat"), &[0xAB; 200]);
    fs::create_dir_all(root.join("empty_dir")).unwrap();
    write_file(&root.join("sub").join("c.txt"), b"nested c");
}

/// Concatenate every segment PackStream emits.
fn drain_all(pack: &mut PackStream) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(seg) = pack.next_segment().expect("next_segment") {
        out.extend_from_slice(seg);
    }
    out
}

/// Invariant: no segment may exceed segment_size.
#[test]
fn segments_never_exceed_segment_size() {
    let ws = TempWorkspace::new("pack-stream-cap");
    let src = ws.path.join("src");
    build_tree(&src);
    let tree = scan_source(&src).expect("scan");

    let segment_size = 64;
    let mut pack = PackStream::new(&tree, segment_size, 1_700_000_000, 1).expect("new");
    while let Some(seg) = pack.next_segment().expect("next_segment") {
        assert!(
            seg.len() <= segment_size,
            "segment {} bytes exceeds segment_size {segment_size}",
            seg.len()
        );
    }
}

/// The pack-stream preamble encodes archive-level metadata (created_at / root_kind)
/// alongside magic / version / entry count. These live in the encrypted stream
/// (not the plaintext header) to avoid leaking metadata. Full content round-trip
/// is covered later by the restore_stream tests.
#[test]
fn preamble_encodes_archive_metadata() {
    let ws = TempWorkspace::new("pack-stream-preamble");
    let src = ws.path.join("src");
    build_tree(&src);
    let tree = scan_source(&src).expect("scan");

    let created_at: i64 = 1_700_000_000;
    let root_kind: u8 = 1; // source root is a directory
    let mut pack = PackStream::new(&tree, 1024 * 1024, created_at, root_kind).expect("new");
    let bytes = drain_all(&mut pack);

    // preamble = magic(11) + version(u16) + count(u32) + created_at(i64) + root_kind(u8) = 26B
    let mut pos = 0;
    assert_eq!(&bytes[pos..pos + 11], PACK_MAGIC);
    pos += 11;
    let version = u16::from_le_bytes(bytes[pos..pos + 2].try_into().unwrap());
    assert_eq!(version, PACK_FORMAT_VERSION);
    pos += 2;
    let count = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap());
    assert_eq!(count as usize, tree.entries.len());
    pos += 4;
    let parsed_created_at = i64::from_le_bytes(bytes[pos..pos + 8].try_into().unwrap());
    assert_eq!(parsed_created_at, created_at);
    pos += 8;
    assert_eq!(bytes[pos], root_kind);
}
