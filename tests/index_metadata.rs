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
fn update_metadata_sets_title() {
    let dir = TempDir::new().unwrap();
    let db = open_test_db(&dir);
    db.insert_record(sample_record("aaaa-1111", "fp_aaa"))
        .unwrap();

    let mut record = db.find_by_target("aaaa-1111").unwrap().unwrap();
    record.metadata.title = Some("My Archive".to_string());
    db.update_metadata("aaaa-1111", &record.metadata).unwrap();

    let updated = db.find_by_target("aaaa-1111").unwrap().unwrap();
    assert_eq!(updated.metadata.title.as_deref(), Some("My Archive"));
}

#[test]
fn update_metadata_sets_note() {
    let dir = TempDir::new().unwrap();
    let db = open_test_db(&dir);
    db.insert_record(sample_record("aaaa-1111", "fp_aaa"))
        .unwrap();

    let mut record = db.find_by_target("aaaa-1111").unwrap().unwrap();
    record.metadata.note = Some("important backup".to_string());
    db.update_metadata("aaaa-1111", &record.metadata).unwrap();

    let updated = db.find_by_target("aaaa-1111").unwrap().unwrap();
    assert_eq!(updated.metadata.note.as_deref(), Some("important backup"));
}

#[test]
fn update_metadata_appends_tags() {
    let dir = TempDir::new().unwrap();
    let db = open_test_db(&dir);
    db.insert_record(sample_record("aaaa-1111", "fp_aaa"))
        .unwrap();

    let mut record = db.find_by_target("aaaa-1111").unwrap().unwrap();
    record.metadata.tags.push("photos".to_string());
    record.metadata.tags.push("2024".to_string());
    db.update_metadata("aaaa-1111", &record.metadata).unwrap();

    let updated = db.find_by_target("aaaa-1111").unwrap().unwrap();
    assert_eq!(updated.metadata.tags, vec!["photos", "2024"]);
}

#[test]
fn update_metadata_sets_custom_json() {
    let dir = TempDir::new().unwrap();
    let db = open_test_db(&dir);
    db.insert_record(sample_record("aaaa-1111", "fp_aaa"))
        .unwrap();

    let mut record = db.find_by_target("aaaa-1111").unwrap().unwrap();
    let value: serde_json::Value = serde_json::from_str(r#"{"key": "val"}"#).unwrap();
    record.metadata.custom = Some(value);
    db.update_metadata("aaaa-1111", &record.metadata).unwrap();

    let updated = db.find_by_target("aaaa-1111").unwrap().unwrap();
    assert_eq!(updated.metadata.custom.unwrap()["key"], "val");
}

#[test]
fn update_metadata_sets_thumbnail_path() {
    let dir = TempDir::new().unwrap();
    let db = open_test_db(&dir);
    db.insert_record(sample_record("aaaa-1111", "fp_aaa"))
        .unwrap();

    let mut record = db.find_by_target("aaaa-1111").unwrap().unwrap();
    record.metadata.thumbnail = Some("thumbnails/aaaa-1111.jpg".to_string());
    db.update_metadata("aaaa-1111", &record.metadata).unwrap();

    let updated = db.find_by_target("aaaa-1111").unwrap().unwrap();
    assert_eq!(
        updated.metadata.thumbnail.as_deref(),
        Some("thumbnails/aaaa-1111.jpg")
    );
}

#[test]
fn update_metadata_nonexistent_target_fails() {
    let dir = TempDir::new().unwrap();
    let db = open_test_db(&dir);

    let metadata = UserMetadata {
        title: Some("ghost".to_string()),
        ..Default::default()
    };
    let result = db.update_metadata("no-such-id", &metadata);
    assert!(result.is_err());
}

#[test]
fn update_metadata_via_fingerprint() {
    let dir = TempDir::new().unwrap();
    let db = open_test_db(&dir);
    db.insert_record(sample_record("aaaa-1111", "fp_aaa"))
        .unwrap();

    let mut record = db.find_by_target("fp_aaa").unwrap().unwrap();
    record.metadata.title = Some("via fp".to_string());
    db.update_metadata("fp_aaa", &record.metadata).unwrap();

    let updated = db.find_by_target("aaaa-1111").unwrap().unwrap();
    assert_eq!(updated.metadata.title.as_deref(), Some("via fp"));
}
