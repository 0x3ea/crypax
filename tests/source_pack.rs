use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use crypax::fs::{
    pack::{PackedSource, pack_source},
    scan::scan_source,
};

#[test]
fn packs_single_file_source() {
    let temp = TempDir::new("pack-single-file");
    let source = temp.path().join("note.txt");
    fs::write(&source, b"hello").expect("write source file");

    let packed = pack_path(&source);
    let records = parse_packed_source(&packed);

    assert_eq!(records.len(), 1);
    assert_eq!(records[0].kind, 1);
    assert_eq!(records[0].path, "note.txt");
    assert_eq!(records[0].declared_size, 5);
    assert_eq!(records[0].payload, b"hello");
}

#[test]
fn packs_directory_source_in_stable_relative_order() {
    let temp = TempDir::new("pack-directory");
    fs::write(temp.path().join("b.txt"), b"b").expect("write b.txt");
    fs::write(temp.path().join("a.txt"), b"aa").expect("write a.txt");
    fs::create_dir(temp.path().join("nested")).expect("create nested dir");
    fs::write(temp.path().join("nested").join("z.txt"), b"zzz").expect("write nested file");

    let packed = pack_path(temp.path());
    let records = parse_packed_source(&packed);
    let paths: Vec<&str> = records.iter().map(|record| record.path.as_str()).collect();

    assert_eq!(paths, vec!["a.txt", "b.txt", "nested", "nested/z.txt"]);
    assert_eq!(records[0].kind, 1);
    assert_eq!(records[0].declared_size, 2);
    assert_eq!(records[0].payload, b"aa");
    assert_eq!(records[2].kind, 2);
    assert_eq!(records[2].declared_size, 0);
    assert!(records[2].payload.is_empty());
}

#[test]
fn packs_ascii_special_characters_in_relative_paths() {
    let temp = TempDir::new("pack-special-name");
    let name = "space name [v1] #1.txt";
    fs::write(temp.path().join(name), b"special").expect("write special file");

    let packed = pack_path(temp.path());
    let records = parse_packed_source(&packed);

    assert_eq!(records.len(), 1);
    assert_eq!(records[0].kind, 1);
    assert_eq!(records[0].path, name);
    assert_eq!(records[0].payload, b"special");
}

#[test]
fn packed_bytes_do_not_include_absolute_source_path() {
    let temp = TempDir::new("pack-no-absolute-path");
    fs::create_dir(temp.path().join("docs")).expect("create docs dir");
    fs::write(temp.path().join("docs").join("readme.txt"), b"readme").expect("write readme");

    let packed = pack_path(temp.path());
    let packed_text = String::from_utf8_lossy(&packed.bytes);
    let absolute_root = temp.path().to_string_lossy();
    let absolute_file = temp.path().join("docs").join("readme.txt");

    assert!(!packed_text.contains(absolute_root.as_ref()));
    assert!(!packed_text.contains(absolute_file.to_string_lossy().as_ref()));
}

#[test]
fn rejects_file_size_change_after_scan() {
    let temp = TempDir::new("pack-size-change");
    let source = temp.path().join("note.txt");
    fs::write(&source, b"short").expect("write initial source");

    let tree = scan_source(&source).expect("scan source");
    fs::write(&source, b"longer content").expect("rewrite source with different size");

    let err = match pack_source(&tree) {
        Ok(_) => panic!("size change should fail packing"),
        Err(err) => err,
    };

    assert_eq!(err.to_string(), "invalid input: append file record");
}

fn pack_path(source: &Path) -> PackedSource {
    let tree = scan_source(source).expect("scan source");
    pack_source(&tree).expect("pack source")
}

fn parse_packed_source(packed: &PackedSource) -> Vec<PackedRecord> {
    let bytes = packed.bytes.as_slice();
    let mut cursor = Cursor::new(bytes);

    assert_eq!(cursor.read_exact(11), b"CRYPAXPACK\0");
    assert_eq!(cursor.read_u16(), 1);
    let entry_count = cursor.read_u32();

    let mut records = Vec::new();
    for _ in 0..entry_count {
        let kind = cursor.read_u8();
        let path = String::from_utf8(cursor.read_bytes()).expect("record path should be utf-8");
        let declared_size = cursor.read_u64();
        let payload = cursor.read_bytes();

        records.push(PackedRecord {
            kind,
            path,
            declared_size,
            payload,
        });
    }

    assert_eq!(cursor.remaining(), 0);
    records
}

struct PackedRecord {
    kind: u8,
    path: String,
    declared_size: u64,
    payload: Vec<u8>,
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.offset
    }

    fn read_u8(&mut self) -> u8 {
        self.read_exact(1)[0]
    }

    fn read_u16(&mut self) -> u16 {
        u16::from_le_bytes(self.read_array())
    }

    fn read_u32(&mut self) -> u32 {
        u32::from_le_bytes(self.read_array())
    }

    fn read_u64(&mut self) -> u64 {
        u64::from_le_bytes(self.read_array())
    }

    fn read_bytes(&mut self) -> Vec<u8> {
        let len = self.read_u64();
        let len: usize = len.try_into().expect("record length should fit usize");
        self.read_exact(len).to_vec()
    }

    fn read_array<const N: usize>(&mut self) -> [u8; N] {
        self.read_exact(N)
            .try_into()
            .expect("read length should match array size")
    }

    fn read_exact(&mut self, len: usize) -> &'a [u8] {
        let end = self
            .offset
            .checked_add(len)
            .expect("cursor offset overflow");
        assert!(end <= self.bytes.len(), "packed bytes ended early");
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        value
    }
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(name: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after unix epoch")
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("crypax-{name}-{}-{unique}", std::process::id()));
        fs::create_dir(&path).expect("create temp dir");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
