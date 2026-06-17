use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use crypax::fs::scan::{EntryKind, SourceEntry, scan_source};

#[test]
fn scans_single_file_with_relative_path_and_size() {
    let temp = TempDir::new("single-file");
    let source = temp.path().join("note.txt");
    fs::write(&source, b"hello crypax").expect("write source file");

    let tree = scan_source(&source).expect("scan source file");

    assert_eq!(tree.root, source);
    assert_eq!(tree.entries.len(), 1);

    let entry = &tree.entries[0];
    assert_eq!(entry.relative_path, "note.txt");
    assert!(matches!(entry.kind, EntryKind::File));
    assert_eq!(entry.size, 12);
    assert!(!Path::new(&entry.relative_path).is_absolute());
}

#[test]
fn scans_directory_with_sorted_relative_entries() {
    let temp = TempDir::new("directory");
    fs::write(temp.path().join("b.txt"), b"b").expect("write b.txt");
    fs::write(temp.path().join("a.txt"), b"aa").expect("write a.txt");
    fs::create_dir(temp.path().join("nested")).expect("create nested dir");
    fs::write(temp.path().join("nested").join("z.txt"), b"zzz").expect("write nested file");

    let tree = scan_source(temp.path()).expect("scan directory");
    let paths: Vec<&str> = tree
        .entries
        .iter()
        .map(|entry| entry.relative_path.as_str())
        .collect();

    assert_eq!(paths, vec!["a.txt", "b.txt", "nested", "nested/z.txt"]);
    for entry in &tree.entries {
        assert!(!Path::new(&entry.relative_path).is_absolute());
        assert!(
            !entry
                .relative_path
                .contains(temp.path().to_string_lossy().as_ref())
        );
    }

    let entries = entries_by_path(&tree.entries);
    assert!(matches!(entries["a.txt"].kind, EntryKind::File));
    assert_eq!(entries["a.txt"].size, 2);
    assert!(matches!(entries["nested"].kind, EntryKind::Directory));
    assert_eq!(entries["nested"].size, 0);
    assert!(matches!(entries["nested/z.txt"].kind, EntryKind::File));
    assert_eq!(entries["nested/z.txt"].size, 3);
}

#[test]
fn preserves_ascii_special_characters_in_relative_paths() {
    let temp = TempDir::new("special-names");
    let name = "space name [v1] #1.txt";
    fs::write(temp.path().join(name), b"special").expect("write special file");

    let tree = scan_source(temp.path()).expect("scan special file name");

    assert_eq!(tree.entries.len(), 1);
    assert_eq!(tree.entries[0].relative_path, name);
    assert!(matches!(tree.entries[0].kind, EntryKind::File));
}

#[test]
fn missing_source_returns_error() {
    let temp = TempDir::new("missing");
    let missing = temp.path().join("does-not-exist");

    assert!(scan_source(&missing).is_err());
}

fn entries_by_path(entries: &[SourceEntry]) -> BTreeMap<&str, &SourceEntry> {
    entries
        .iter()
        .map(|entry| (entry.relative_path.as_str(), entry))
        .collect()
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
