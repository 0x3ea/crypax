use std::path::PathBuf;
use tempfile::TempDir;

use crypax::index::db::IndexDb;
use crypax::index::models::{NewIndexRecord, UserMetadata};

fn open_test_db(dir: &TempDir) -> IndexDb {
    let db_path = dir.path().join("index.db");
    IndexDb::open(&db_path).unwrap()
}

fn sample_record(id: &str, fp: &str) -> NewIndexRecord {
    NewIndexRecord {
        archive_id: id.to_string(),
        fingerprint: fp.to_string(),
        archive_path: PathBuf::from("/tmp/archive_out"),
        metadata: UserMetadata::default(),
    }
}

#[test]
fn list_empty_database() {
    let dir = TempDir::new().unwrap();
    let db = open_test_db(&dir);
    let records = db.list_records().unwrap();
    assert!(records.is_empty());
}

#[test]
fn list_returns_inserted_records() {
    let dir = TempDir::new().unwrap();
    let db = open_test_db(&dir);

    db.insert_record(sample_record("aaaa-1111", "fp_aaa"))
        .unwrap();
    db.insert_record(sample_record("bbbb-2222", "fp_bbb"))
        .unwrap();

    let records = db.list_records().unwrap();
    assert_eq!(records.len(), 2);
}

#[test]
fn forget_by_archive_id() {
    let dir = TempDir::new().unwrap();
    let db = open_test_db(&dir);

    db.insert_record(sample_record("aaaa-1111", "fp_aaa"))
        .unwrap();
    let deleted = db.delete_by_target("aaaa-1111").unwrap();
    assert!(deleted);

    let records = db.list_records().unwrap();
    assert!(records.is_empty());
}

#[test]
fn forget_by_fingerprint() {
    let dir = TempDir::new().unwrap();
    let db = open_test_db(&dir);

    db.insert_record(sample_record("aaaa-1111", "fp_aaa"))
        .unwrap();
    let deleted = db.delete_by_target("fp_aaa").unwrap();
    assert!(deleted);

    let records = db.list_records().unwrap();
    assert!(records.is_empty());
}

#[test]
fn forget_nonexistent_returns_false() {
    let dir = TempDir::new().unwrap();
    let db = open_test_db(&dir);

    let deleted = db.delete_by_target("no-such-id").unwrap();
    assert!(!deleted);
}

#[test]
fn forget_allows_reinsertion_of_same_fingerprint() {
    let dir = TempDir::new().unwrap();
    let db = open_test_db(&dir);

    db.insert_record(sample_record("aaaa-1111", "fp_aaa"))
        .unwrap();
    db.delete_by_target("aaaa-1111").unwrap();

    // Same fingerprint can be inserted again after forget
    db.insert_record(sample_record("cccc-3333", "fp_aaa"))
        .unwrap();
    let record = db.find_by_fingerprint("fp_aaa").unwrap();
    assert!(record.is_some());
    assert_eq!(record.unwrap().archive_id, "cccc-3333");
}

#[test]
fn find_by_target_matches_archive_id() {
    let dir = TempDir::new().unwrap();
    let db = open_test_db(&dir);

    db.insert_record(sample_record("aaaa-1111", "fp_aaa"))
        .unwrap();
    let record = db.find_by_target("aaaa-1111").unwrap();
    assert!(record.is_some());
    assert_eq!(record.unwrap().fingerprint, "fp_aaa");
}

#[test]
fn find_by_target_matches_fingerprint() {
    let dir = TempDir::new().unwrap();
    let db = open_test_db(&dir);

    db.insert_record(sample_record("aaaa-1111", "fp_aaa"))
        .unwrap();
    let record = db.find_by_target("fp_aaa").unwrap();
    assert!(record.is_some());
    assert_eq!(record.unwrap().archive_id, "aaaa-1111");
}

#[test]
fn find_by_target_returns_none_for_unknown() {
    let dir = TempDir::new().unwrap();
    let db = open_test_db(&dir);

    let record = db.find_by_target("no-such").unwrap();
    assert!(record.is_none());
}
