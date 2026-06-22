mod common;

use std::fs;

use common::{
    TempWorkspace, corrupt_one_archive_file, decrypt_archive, encrypt_to_archive,
    remove_n_archive_files, write_file,
};

#[test]
fn wrong_password_returns_error() {
    let ws = TempWorkspace::new("err-wrong-pw");
    let source = ws.path.join("secret.txt");
    write_file(&source, b"confidential data");

    let archive_dir = ws.path.join("archive");
    let restore_dir = ws.path.join("restored");
    fs::create_dir(&restore_dir).unwrap();

    encrypt_to_archive(&source, &archive_dir, "correct-password");
    let result = decrypt_archive(&archive_dir, &restore_dir, "wrong-password");

    assert!(result.is_err());
    let err_msg = format!("{:#}", result.unwrap_err());
    assert!(
        err_msg.contains("authentication failed"),
        "expected authentication error, got: {}",
        err_msg
    );
}

#[test]
fn wrong_password_leaves_no_residual_files() {
    let ws = TempWorkspace::new("err-no-residual");
    let source = ws.path.join("data.bin");
    write_file(&source, b"important bytes");

    let archive_dir = ws.path.join("archive");
    let restore_dir = ws.path.join("restored");
    fs::create_dir(&restore_dir).unwrap();

    encrypt_to_archive(&source, &archive_dir, "real-pw");
    let _ = decrypt_archive(&archive_dir, &restore_dir, "bad-pw");

    let entries: Vec<_> = fs::read_dir(&restore_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();
    assert!(
        entries.is_empty(),
        "no files should remain after failed decrypt"
    );
}

// PLACEHOLDER_MORE

#[test]
fn corrupt_manifest_returns_error() {
    let ws = TempWorkspace::new("err-corrupt-manifest");
    let source = ws.path.join("file.txt");
    write_file(&source, b"data");

    let archive_dir = ws.path.join("archive");
    encrypt_to_archive(&source, &archive_dir, "pw");

    let header_path = archive_dir.join("crypax.archive");
    let mut header_bytes = fs::read(&header_path).unwrap();
    let len = header_bytes.len();
    if len > 20 {
        header_bytes[len - 10] ^= 0xFF;
        header_bytes[len - 5] ^= 0xFF;
    }
    fs::write(&header_path, &header_bytes).unwrap();

    let restore_dir = ws.path.join("restored");
    fs::create_dir(&restore_dir).unwrap();
    let result = decrypt_archive(&archive_dir, &restore_dir, "pw");
    assert!(result.is_err());
}

#[test]
fn corrupt_chunk_detected_on_decrypt() {
    let ws = TempWorkspace::new("err-corrupt-chunk");
    let source = ws.path.join("file.txt");
    write_file(&source, b"some content to encrypt");

    let archive_dir = ws.path.join("archive");
    encrypt_to_archive(&source, &archive_dir, "pw");
    corrupt_one_archive_file(&archive_dir);

    let restore_dir = ws.path.join("restored");
    fs::create_dir(&restore_dir).unwrap();
    let result = decrypt_archive(&archive_dir, &restore_dir, "pw");
    assert!(result.is_err());
    let err_msg = format!("{:#}", result.unwrap_err());
    assert!(
        err_msg.contains("authentication failed"),
        "expected authentication error on corrupt chunk, got: {}",
        err_msg
    );
}

#[test]
fn missing_chunk_file_returns_error() {
    let ws = TempWorkspace::new("err-missing-chunk");
    let source = ws.path.join("file.txt");
    write_file(&source, b"hello world data");

    let archive_dir = ws.path.join("archive");
    encrypt_to_archive(&source, &archive_dir, "pw");
    remove_n_archive_files(&archive_dir, 1);

    let restore_dir = ws.path.join("restored");
    fs::create_dir(&restore_dir).unwrap();
    let result = decrypt_archive(&archive_dir, &restore_dir, "pw");
    assert!(result.is_err());
}

#[test]
fn missing_header_file_returns_error() {
    let ws = TempWorkspace::new("err-missing-header");
    let source = ws.path.join("file.txt");
    write_file(&source, b"data");

    let archive_dir = ws.path.join("archive");
    encrypt_to_archive(&source, &archive_dir, "pw");
    fs::remove_file(archive_dir.join("crypax.archive")).unwrap();

    let restore_dir = ws.path.join("restored");
    fs::create_dir(&restore_dir).unwrap();
    let result = decrypt_archive(&archive_dir, &restore_dir, "pw");
    assert!(result.is_err());
}

#[test]
fn unknown_version_in_header_returns_error() {
    let ws = TempWorkspace::new("err-unknown-version");
    let source = ws.path.join("file.txt");
    write_file(&source, b"data");

    let archive_dir = ws.path.join("archive");
    encrypt_to_archive(&source, &archive_dir, "pw");

    let header_path = archive_dir.join("crypax.archive");
    let mut header_bytes = fs::read(&header_path).unwrap();
    // Version field is at offset 7 (after 7-byte magic "CRYPAX\0"), 2 bytes LE
    header_bytes[7] = 99;
    header_bytes[8] = 0;
    fs::write(&header_path, &header_bytes).unwrap();
    for bak in ["crypax.archive.bak.1", "crypax.archive.bak.2"] {
        let p = archive_dir.join(bak);
        if p.exists() {
            fs::write(&p, &header_bytes).unwrap();
        }
    }

    let restore_dir = ws.path.join("restored");
    fs::create_dir(&restore_dir).unwrap();
    let result = decrypt_archive(&archive_dir, &restore_dir, "pw");
    assert!(result.is_err());
    let err_msg = format!("{:#}", result.unwrap_err());
    assert!(
        err_msg.contains("unsupported")
            || err_msg.contains("version")
            || err_msg.contains("no archive found"),
        "expected version or unrecoverable error, got: {}",
        err_msg
    );
}

#[test]
fn duplicate_content_is_rejected_by_index() {
    use crypax::fs::pack::compute_content_fingerprint;
    use crypax::fs::scan::scan_source;
    use crypax::index::db::IndexDb;
    use crypax::index::models::NewIndexRecord;

    let ws = TempWorkspace::new("err-dedup");
    let source = ws.path.join("file.txt");
    write_file(&source, b"unique content for dedup");

    let tree = scan_source(&source).unwrap();
    let fingerprint = compute_content_fingerprint(&tree).unwrap();

    let db_path = ws.path.join("index.db");
    let db = IndexDb::open(&db_path).unwrap();

    db.insert_record(NewIndexRecord {
        archive_id: "archive-001".to_string(),
        fingerprint: fingerprint.clone(),
        archive_path: ws.path.join("archive-001"),
        metadata: Default::default(),
    })
    .unwrap();

    let dup = db.insert_record(NewIndexRecord {
        archive_id: "archive-002".to_string(),
        fingerprint: fingerprint.clone(),
        archive_path: ws.path.join("archive-002"),
        metadata: Default::default(),
    });
    assert!(dup.is_err(), "duplicate fingerprint should be rejected");
}

#[test]
fn forget_allows_re_encrypt_same_content() {
    use crypax::fs::pack::compute_content_fingerprint;
    use crypax::fs::scan::scan_source;
    use crypax::index::db::IndexDb;
    use crypax::index::models::NewIndexRecord;

    let ws = TempWorkspace::new("err-forget-reencrypt");
    let source = ws.path.join("file.txt");
    write_file(&source, b"content to forget and redo");

    let tree = scan_source(&source).unwrap();
    let fingerprint = compute_content_fingerprint(&tree).unwrap();

    let db_path = ws.path.join("index.db");
    let db = IndexDb::open(&db_path).unwrap();

    db.insert_record(NewIndexRecord {
        archive_id: "archive-001".to_string(),
        fingerprint: fingerprint.clone(),
        archive_path: ws.path.join("archive-001"),
        metadata: Default::default(),
    })
    .unwrap();

    db.delete_by_target("archive-001").unwrap();

    db.insert_record(NewIndexRecord {
        archive_id: "archive-003".to_string(),
        fingerprint: fingerprint.clone(),
        archive_path: ws.path.join("archive-003"),
        metadata: Default::default(),
    })
    .expect("re-insert after forget should succeed");
}

#[test]
fn archive_decryptable_without_index() {
    let ws = TempWorkspace::new("err-no-index");
    let source = ws.path.join("file.txt");
    write_file(&source, b"data that outlives its index");

    let archive_dir = ws.path.join("archive");
    encrypt_to_archive(&source, &archive_dir, "pw");

    let restore_dir = ws.path.join("restored");
    fs::create_dir(&restore_dir).unwrap();
    decrypt_archive(&archive_dir, &restore_dir, "pw").unwrap();

    assert_eq!(
        fs::read(restore_dir.join("file.txt")).unwrap(),
        b"data that outlives its index"
    );
}
