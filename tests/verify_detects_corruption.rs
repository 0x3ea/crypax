use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use crypax::archive::format::{self, ARCHIVE_FORMAT_VERSION};
use crypax::archive::layout::random_archive_file_name;
use crypax::archive::manifest::{
    ErasureParams, ManifestChunkEntry, ManifestFileEntry, PlainManifest, RootKind,
    encode_plain_manifest,
};
use crypax::chunks::erasure::{encode_recovery_shards, plan_erasure};
use crypax::chunks::split::{plan_chunks, split_into_data_shards};
use crypax::crypto::aead::{EncryptedBlob, decrypt_segment, encrypt_blob, encrypt_segment};
use crypax::crypto::keys::{default_kdf_params, derive_archive_key, generate_salt};
use crypax::fs::pack::pack_source;
use crypax::fs::scan::{EntryKind, scan_source};

// --- helpers ---

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(name: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("crypax-{name}-{}-{unique}", std::process::id()));
        fs::create_dir_all(&path).expect("create temp dir");
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

struct ArchiveFixture {
    archive_dir: PathBuf,
    _password: String,
    manifest: PlainManifest,
    key: crypax::crypto::keys::ArchiveKey,
}

fn create_test_archive(temp: &TempDir, password: &str) -> ArchiveFixture {
    let src_dir = temp.path().join("source");
    fs::create_dir_all(&src_dir).expect("mkdir source");
    fs::write(src_dir.join("a.txt"), b"file a content").expect("write a");
    fs::write(src_dir.join("b.txt"), b"file b content here").expect("write b");

    let archive_dir = temp.path().join("archive");

    let tree = scan_source(&src_dir).expect("scan");
    let packed = pack_source(&tree).expect("pack");

    let salt = generate_salt();
    let kdf_params = default_kdf_params();
    let key = derive_archive_key(password, &salt, &kdf_params).expect("derive key");

    let plan = plan_chunks(packed.bytes.len() as u64);
    let data_shards = split_into_data_shards(&packed.bytes, &plan);

    let erasure_plan = plan_erasure(data_shards.len(), 20);
    let recovery_shards = encode_recovery_shards(&data_shards, &erasure_plan).expect("erasure");

    let archive_id = uuid::Uuid::new_v4();
    let archive_id_bytes = archive_id.as_bytes();
    let archive_id_str = archive_id.to_string();

    let mut encrypted_shards = Vec::new();
    for (i, shard) in data_shards.iter().enumerate() {
        let blob = encrypt_segment(
            &key,
            &shard.data,
            i as u64,
            archive_id_bytes,
            ARCHIVE_FORMAT_VERSION,
        )
        .expect("encrypt data shard");
        encrypted_shards.push(blob);
    }
    let offset = data_shards.len();
    for (i, shard) in recovery_shards.iter().enumerate() {
        let blob = encrypt_segment(
            &key,
            &shard.data,
            (offset + i) as u64,
            archive_id_bytes,
            ARCHIVE_FORMAT_VERSION,
        )
        .expect("encrypt recovery shard");
        encrypted_shards.push(blob);
    }

    let chunk_file_names: Vec<String> = encrypted_shards
        .iter()
        .map(|_| random_archive_file_name())
        .collect();

    let root_kind = RootKind::Directory;

    let manifest = PlainManifest {
        format_version: ARCHIVE_FORMAT_VERSION,
        archive_id: archive_id_str,
        created_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64,
        root_kind,
        files: tree
            .entries
            .iter()
            .filter(|e| e.kind == EntryKind::File)
            .map(|e| ManifestFileEntry {
                path: e.relative_path.to_string(),
                size: e.size,
                modified_at: None,
                chunks: vec![],
            })
            .collect(),
        chunks: encrypted_shards
            .iter()
            .enumerate()
            .map(|(i, blob)| ManifestChunkEntry {
                id: format!("{}", i),
                file_name: chunk_file_names[i].clone(),
                size: (blob.nonce.len() + blob.ciphertext.len()) as u64,
                plaintext_offset: (i * plan.shard_size) as u64,
                plaintext_size: plan.shard_size as u64,
            })
            .collect(),
        erasure: ErasureParams {
            data_shards: plan.data_shards as u16,
            parity_shards: erasure_plan.parity_shards as u16,
            redundancy_percent: 20,
        },
        total_packed_size: packed.bytes.len() as u64,
    };

    let manifest_bytes = encode_plain_manifest(&manifest).expect("encode manifest");
    let encrypted_manifest = encrypt_blob(&key, &manifest_bytes, b"").expect("encrypt manifest");

    fs::create_dir_all(&archive_dir).expect("create archive dir");

    let mut manifest_blob = Vec::new();
    manifest_blob.extend_from_slice(&encrypted_manifest.nonce);
    manifest_blob.extend_from_slice(&encrypted_manifest.ciphertext);

    let header = format::ArchiveHeader {
        version: ARCHIVE_FORMAT_VERSION,
        salt: salt.as_bytes().to_vec(),
        encrypted_manifest: manifest_blob,
    };
    format::write_header(&archive_dir.join("crypax.archive"), &header).expect("write header");

    for (blob, file_name) in encrypted_shards.iter().zip(chunk_file_names.iter()) {
        let chunk_path = archive_dir.join(file_name);
        let mut chunk_bytes = Vec::with_capacity(blob.nonce.len() + blob.ciphertext.len());
        chunk_bytes.extend_from_slice(&blob.nonce);
        chunk_bytes.extend_from_slice(&blob.ciphertext);
        fs::write(&chunk_path, &chunk_bytes).expect("write chunk");
    }

    ArchiveFixture {
        archive_dir,
        _password: password.to_string(),
        manifest,
        key,
    }
}

/// Replicate verify logic for testing (since verify::run requires interactive password)
fn verify_archive(fixture: &ArchiveFixture) -> Vec<ShardIssue> {
    let archive_id_uuid: uuid::Uuid = fixture.manifest.archive_id.parse().expect("parse uuid");
    let archive_id = archive_id_uuid.as_bytes();

    let mut issues = Vec::new();
    for (i, chunk_entry) in fixture.manifest.chunks.iter().enumerate() {
        let chunk_path = fixture.archive_dir.join(&chunk_entry.file_name);

        if !chunk_path.exists() {
            issues.push(ShardIssue::Missing(i));
            continue;
        }

        let raw = fs::read(&chunk_path).expect("read chunk");
        if raw.len() as u64 != chunk_entry.size {
            issues.push(ShardIssue::Corrupt(i));
            continue;
        }

        let nonce: [u8; 24] = match raw[..24].try_into() {
            Ok(n) => n,
            Err(_) => {
                issues.push(ShardIssue::Corrupt(i));
                continue;
            }
        };
        let blob = EncryptedBlob {
            nonce,
            ciphertext: raw[24..].to_vec(),
        };

        if decrypt_segment(
            &fixture.key,
            &blob,
            i as u64,
            archive_id,
            fixture.manifest.format_version,
        )
        .is_err()
        {
            issues.push(ShardIssue::Corrupt(i));
        }
    }
    issues
}

#[derive(Debug, PartialEq)]
enum ShardIssue {
    Missing(usize),
    Corrupt(usize),
}

// --- tests ---

#[test]
fn healthy_archive_reports_no_issues() {
    let temp = TempDir::new("verify-healthy");
    let fixture = create_test_archive(&temp, "password123");

    let issues = verify_archive(&fixture);
    assert!(issues.is_empty(), "healthy archive should have no issues");
}

#[test]
fn detects_missing_shard() {
    let temp = TempDir::new("verify-missing");
    let fixture = create_test_archive(&temp, "password123");

    // Delete the first chunk file
    let first_chunk = &fixture.manifest.chunks[0].file_name;
    fs::remove_file(fixture.archive_dir.join(first_chunk)).expect("delete chunk");

    let issues = verify_archive(&fixture);
    assert!(issues.contains(&ShardIssue::Missing(0)));
}

#[test]
fn detects_corrupt_shard_bit_flip() {
    let temp = TempDir::new("verify-corrupt");
    let fixture = create_test_archive(&temp, "password123");

    // Flip a bit in the first chunk file
    let first_chunk = &fixture.manifest.chunks[0].file_name;
    let chunk_path = fixture.archive_dir.join(first_chunk);
    let mut data = fs::read(&chunk_path).expect("read chunk");
    data[30] ^= 0x01;
    fs::write(&chunk_path, &data).expect("write corrupted chunk");

    let issues = verify_archive(&fixture);
    assert!(issues.contains(&ShardIssue::Corrupt(0)));
}

#[test]
fn reports_repairable_when_within_parity() {
    let temp = TempDir::new("verify-repairable");
    let fixture = create_test_archive(&temp, "password123");

    // Delete one shard
    let first_chunk = &fixture.manifest.chunks[0].file_name;
    fs::remove_file(fixture.archive_dir.join(first_chunk)).expect("delete chunk");

    let issues = verify_archive(&fixture);
    let parity = fixture.manifest.erasure.parity_shards as usize;
    assert!(
        issues.len() <= parity,
        "single shard loss should be repairable"
    );
}

#[test]
fn reports_unrepairable_when_exceeds_parity() {
    let temp = TempDir::new("verify-unrepairable");
    let fixture = create_test_archive(&temp, "password123");

    let parity = fixture.manifest.erasure.parity_shards as usize;

    // Delete more shards than parity can handle
    for chunk in fixture.manifest.chunks.iter().take(parity + 1) {
        let path = fixture.archive_dir.join(&chunk.file_name);
        if path.exists() {
            fs::remove_file(&path).expect("delete chunk");
        }
    }

    let issues = verify_archive(&fixture);
    assert!(issues.len() > parity, "should be unrepairable");
}
