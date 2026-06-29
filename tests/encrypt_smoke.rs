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
use crypax::crypto::aead::{encrypt_blob, encrypt_segment};
use crypax::crypto::keys::{default_kdf_params, derive_archive_key, generate_salt};
use crypax::fs::pack::{compute_content_fingerprint, pack_source};
use crypax::fs::scan::{EntryKind, scan_source};

#[test]
fn encrypts_single_file_to_archive_directory() {
    let temp = TempDir::new("encrypt-smoke");
    let source_file = temp.path().join("secret.txt");
    fs::write(&source_file, b"hello crypax").expect("write source");

    let output_dir = temp.path().join("archive-out");
    let password = "test-password-123";

    let tree = scan_source(&source_file).expect("scan");
    let fingerprint = compute_content_fingerprint(&tree).expect("fingerprint");
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

    let manifest = PlainManifest {
        format_version: ARCHIVE_FORMAT_VERSION,
        archive_id: archive_id_str.clone(),
        created_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64,
        root_kind: RootKind::File,
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

    // Write archive
    fs::create_dir_all(&output_dir).expect("create output dir");

    let mut manifest_blob = Vec::new();
    manifest_blob.extend_from_slice(&encrypted_manifest.nonce);
    manifest_blob.extend_from_slice(&encrypted_manifest.ciphertext);

    let header = format::ArchiveHeader {
        version: ARCHIVE_FORMAT_VERSION,
        salt: salt.as_bytes().to_vec(),
        encrypted_manifest: manifest_blob,
    };
    let header_path = output_dir.join("crypax.archive");
    format::write_header(&header_path, &header).expect("write header");

    for (blob, file_name) in encrypted_shards.iter().zip(chunk_file_names.iter()) {
        let chunk_path = output_dir.join(file_name);
        let mut chunk_bytes = Vec::with_capacity(blob.nonce.len() + blob.ciphertext.len());
        chunk_bytes.extend_from_slice(&blob.nonce);
        chunk_bytes.extend_from_slice(&blob.ciphertext);
        fs::write(&chunk_path, &chunk_bytes).expect("write chunk");
    }

    // Assertions
    assert!(output_dir.exists(), "archive directory should exist");
    assert!(header_path.exists(), "header file should exist");

    // No source file name or extension leaks into archive
    let entries: Vec<String> = fs::read_dir(&output_dir)
        .expect("read archive dir")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();

    for name in &entries {
        assert!(!name.contains("secret"), "source name should not leak");
        assert!(
            name == "crypax.archive" || name.ends_with(".bin"),
            "unexpected file: {}",
            name
        );
    }

    // Header is readable and valid
    let read_back = format::read_header_with_fallback(&output_dir).expect("read header back");
    assert_eq!(read_back.version, ARCHIVE_FORMAT_VERSION);
    assert_eq!(read_back.salt, salt.as_bytes().to_vec());

    // Correct number of chunk files (data + recovery)
    let chunk_count = entries.iter().filter(|n| n.ends_with(".bin")).count();
    assert_eq!(chunk_count, encrypted_shards.len());

    // Fingerprint is stable
    let tree2 = scan_source(&source_file).expect("rescan");
    let fingerprint2 = compute_content_fingerprint(&tree2).expect("fingerprint2");
    assert_eq!(fingerprint, fingerprint2);
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
