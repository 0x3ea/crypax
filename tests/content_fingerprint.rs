use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use crypax::fs::{pack::compute_content_fingerprint, scan::scan_source};

#[test]
fn computes_fingerprint_for_single_file_source() {
    let temp = TempDir::new("single-file-fingerprint");
    let source = temp.path().join("note.txt");
    fs::write(&source, b"same bytes").expect("write source file");

    let tree = scan_source(&source).expect("scan source file");
    let fingerprint = compute_content_fingerprint(&tree).expect("compute fingerprint");

    assert_eq!(fingerprint.len(), 64);
    assert!(fingerprint.chars().all(|ch| ch.is_ascii_hexdigit()));
}

#[test]
fn same_content_in_different_absolute_paths_has_same_fingerprint() {
    let left = TempDir::new("same-left");
    let right = TempDir::new("same-right");
    write_same_tree(left.path());
    write_same_tree(right.path());

    let left_fingerprint = fingerprint_for(left.path());
    let right_fingerprint = fingerprint_for(right.path());

    assert_eq!(left_fingerprint, right_fingerprint);
}

#[test]
fn file_content_changes_fingerprint() {
    let first = TempDir::new("content-first");
    let second = TempDir::new("content-second");
    fs::write(first.path().join("note.txt"), b"first").expect("write first file");
    fs::write(second.path().join("note.txt"), b"second").expect("write second file");

    assert_ne!(
        fingerprint_for(first.path()),
        fingerprint_for(second.path())
    );
}

#[test]
fn file_name_changes_fingerprint() {
    let first = TempDir::new("name-first");
    let second = TempDir::new("name-second");
    fs::write(first.path().join("a.txt"), b"same bytes").expect("write a.txt");
    fs::write(second.path().join("b.txt"), b"same bytes").expect("write b.txt");

    assert_ne!(
        fingerprint_for(first.path()),
        fingerprint_for(second.path())
    );
}

#[test]
fn directory_structure_changes_fingerprint() {
    let flat = TempDir::new("structure-flat");
    let nested = TempDir::new("structure-nested");
    fs::write(flat.path().join("note.txt"), b"same bytes").expect("write flat file");
    fs::create_dir(nested.path().join("docs")).expect("create nested dir");
    fs::write(nested.path().join("docs").join("note.txt"), b"same bytes")
        .expect("write nested file");

    assert_ne!(fingerprint_for(flat.path()), fingerprint_for(nested.path()));
}

#[test]
fn rewriting_same_contents_keeps_fingerprint_unchanged() {
    let temp = TempDir::new("same-content-rewrite");
    let source = temp.path().join("note.txt");
    fs::write(&source, b"stable").expect("write source file");
    let before = fingerprint_for(temp.path());

    fs::write(&source, b"stable").expect("rewrite source file");
    let after = fingerprint_for(temp.path());

    assert_eq!(before, after);
}

fn write_same_tree(root: &Path) {
    fs::create_dir(root.join("docs")).expect("create docs dir");
    fs::write(root.join("docs").join("readme.txt"), b"readme").expect("write readme");
    fs::write(root.join("notes.txt"), b"notes").expect("write notes");
}

fn fingerprint_for(source: &Path) -> String {
    let tree = scan_source(source).expect("scan source");
    compute_content_fingerprint(&tree).expect("compute content fingerprint")
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
