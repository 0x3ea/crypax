use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use crypax::fs::pack::compute_content_fingerprint;
use crypax::fs::scan::scan_source;
use crypax::index::db::IndexDb;
use crypax::index::models::NewIndexRecord;

#[test]
fn duplicate_fingerprint_is_rejected_by_index() {
    let temp = TempDir::new("index-dedup");

    let source_file = temp.path().join("data.bin");
    fs::write(&source_file, b"unique content for dedup test").expect("write source");

    let tree = scan_source(&source_file).expect("scan");
    let fingerprint = compute_content_fingerprint(&tree).expect("fingerprint");

    let db_path = temp.path().join("test-index.db");
    let index = IndexDb::open(&db_path).expect("open index");

    // First insert succeeds
    index
        .insert_record(NewIndexRecord {
            archive_id: "archive-001".to_string(),
            fingerprint: fingerprint.clone(),
            archive_path: temp.path().join("archive-001"),
            metadata: Default::default(),
        })
        .expect("first insert should succeed");

    // Same fingerprint found
    let found = index
        .find_by_fingerprint(&fingerprint)
        .expect("find by fingerprint");
    assert!(found.is_some(), "record should exist after insert");

    let record = found.unwrap();
    assert_eq!(record.archive_id, "archive-001");
    assert_eq!(record.fingerprint, fingerprint);

    // Duplicate insert fails due to UNIQUE constraint
    let dup_result = index.insert_record(NewIndexRecord {
        archive_id: "archive-002".to_string(),
        fingerprint: fingerprint.clone(),
        archive_path: temp.path().join("archive-002"),
        metadata: Default::default(),
    });
    assert!(
        dup_result.is_err(),
        "duplicate fingerprint insert should fail"
    );
}

#[test]
fn different_content_produces_different_fingerprints() {
    let temp = TempDir::new("index-diff-fp");

    let file_a = temp.path().join("a.txt");
    let file_b = temp.path().join("b.txt");
    fs::write(&file_a, b"content alpha").expect("write a");
    fs::write(&file_b, b"content beta").expect("write b");

    let tree_a = scan_source(&file_a).expect("scan a");
    let tree_b = scan_source(&file_b).expect("scan b");
    let fp_a = compute_content_fingerprint(&tree_a).expect("fp a");
    let fp_b = compute_content_fingerprint(&tree_b).expect("fp b");

    assert_ne!(
        fp_a, fp_b,
        "different content should produce different fingerprints"
    );
}

#[test]
fn nonexistent_fingerprint_returns_none() {
    let temp = TempDir::new("index-miss");
    let db_path = temp.path().join("test-index.db");
    let index = IndexDb::open(&db_path).expect("open index");

    let result = index
        .find_by_fingerprint("nonexistent-fingerprint-abc123")
        .expect("query should not error");
    assert!(result.is_none(), "missing fingerprint should return None");
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
