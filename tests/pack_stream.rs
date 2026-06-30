mod common;

use std::fs;
use std::path::Path;

use crypax::fs::pack::pack_source;
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

/// Tiny segments force the segment boundary to land inside framing bytes and
/// mid-file-data — exactly where a streaming packer is most likely to break.
/// The concatenated output must be byte-identical to v1 pack_source.
#[test]
fn pack_stream_matches_pack_source_tiny_segments() {
    let ws = TempWorkspace::new("pack-stream-tiny");
    let src = ws.path.join("src");
    build_tree(&src);
    let tree = scan_source(&src).expect("scan");

    let expected = pack_source(&tree).expect("pack").bytes;
    let mut pack = PackStream::new(&tree, 64).expect("new");
    let got = drain_all(&mut pack);

    assert_eq!(got, expected, "streamed pack differs from v1 pack_source");
}

/// With a segment larger than the whole stream, everything fits in one segment.
/// Same oracle, confirms segment_size is pure chunking (total bytes unchanged).
#[test]
fn pack_stream_matches_pack_source_single_segment() {
    let ws = TempWorkspace::new("pack-stream-single");
    let src = ws.path.join("src");
    build_tree(&src);
    let tree = scan_source(&src).expect("scan");

    let expected = pack_source(&tree).expect("pack").bytes;
    let mut pack = PackStream::new(&tree, 1024 * 1024).expect("new");
    let got = drain_all(&mut pack);

    assert_eq!(
        got, expected,
        "single-segment pack differs from v1 pack_source"
    );
}

/// Invariant: no segment may exceed segment_size.
#[test]
fn segments_never_exceed_segment_size() {
    let ws = TempWorkspace::new("pack-stream-cap");
    let src = ws.path.join("src");
    build_tree(&src);
    let tree = scan_source(&src).expect("scan");

    let segment_size = 64;
    let mut pack = PackStream::new(&tree, segment_size).expect("new");
    while let Some(seg) = pack.next_segment().expect("next_segment") {
        assert!(
            seg.len() <= segment_size,
            "segment {} bytes exceeds segment_size {segment_size}",
            seg.len()
        );
    }
}
