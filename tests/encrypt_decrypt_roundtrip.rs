use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use crypax::archive::format::{self, ARCHIVE_FORMAT_VERSION};
use crypax::archive::layout::random_archive_file_name;
use crypax::archive::manifest::{
    ErasureParams, ManifestChunkEntry, ManifestFileEntry, PlainManifest, RootKind,
    decode_plain_manifest, encode_plain_manifest,
};
use crypax::chunks::erasure::{encode_recovery_shards, plan_erasure};
use crypax::chunks::split::{DataShard, join_data_shards, plan_chunks, split_into_data_shards};
use crypax::crypto::aead::{
    EncryptedBlob, decrypt_blob, decrypt_segment, encrypt_blob, encrypt_segment,
};
use crypax::crypto::keys::{KeySalt, default_kdf_params, derive_archive_key, generate_salt};
use crypax::fs::pack::pack_source;
use crypax::fs::restore::restore_packed_source;
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

/// Encrypt a source path into archive_dir using the given password.
/// Returns the archive_dir path.
fn encrypt_to_archive(source: &Path, archive_dir: &Path, password: &str) {
    let tree = scan_source(source).expect("scan");
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

    let root_kind = if source.is_file() {
        RootKind::File
    } else {
        RootKind::Directory
    };

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

    // Write archive to disk
    fs::create_dir_all(archive_dir).expect("create archive dir");

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
}

/// Decrypt an archive into output_dir, replicating the decrypt command logic.
fn decrypt_archive(
    archive_dir: &Path,
    output_dir: &Path,
    password: &str,
) -> crypax::error::Result<()> {
    let header = format::read_header_with_fallback(archive_dir).expect("read header");

    let salt = KeySalt::try_from_vec(&header.salt)?;
    let params = default_kdf_params();
    let key = derive_archive_key(password, &salt, &params)?;

    // Decrypt manifest
    let raw = &header.encrypted_manifest;
    let nonce: [u8; 24] = raw[..24].try_into().unwrap();
    let ciphertext = raw[24..].to_vec();
    let manifest_blob = EncryptedBlob { nonce, ciphertext };
    let manifest_bytes = decrypt_blob(&key, &manifest_blob, b"")?;
    let manifest = decode_plain_manifest(&manifest_bytes)?;

    // Decrypt data shards
    let data_count = manifest.erasure.data_shards as usize;
    let archive_id_uuid: uuid::Uuid = manifest.archive_id.parse().expect("parse archive_id");
    let archive_id = archive_id_uuid.as_bytes();

    let mut shards = Vec::with_capacity(data_count);
    for (i, chunk_entry) in manifest.chunks[..data_count].iter().enumerate() {
        let chunk_path = archive_dir.join(&chunk_entry.file_name);
        let raw = fs::read(&chunk_path).expect("read chunk");
        let nonce: [u8; 24] = raw[..24].try_into().unwrap();
        let ciphertext = raw[24..].to_vec();
        let blob = EncryptedBlob { nonce, ciphertext };
        let plaintext =
            decrypt_segment(&key, &blob, i as u64, archive_id, manifest.format_version)?;
        shards.push(DataShard {
            index: i,
            data: plaintext,
        });
    }

    let packed_bytes = join_data_shards(&shards, manifest.total_packed_size)?;
    restore_packed_source(&packed_bytes, output_dir)
}

// --- tests ---

#[test]
fn roundtrip_single_file() {
    let temp = TempDir::new("rt-single");
    let source = temp.path().join("hello.txt");
    fs::write(&source, b"hello world").expect("write source");

    let archive_dir = temp.path().join("archive");
    let restore_dir = temp.path().join("restored");
    fs::create_dir(&restore_dir).expect("create restore dir");

    encrypt_to_archive(&source, &archive_dir, "password123");
    decrypt_archive(&archive_dir, &restore_dir, "password123").expect("decrypt");

    let restored = fs::read(restore_dir.join("hello.txt")).expect("read restored");
    assert_eq!(restored, b"hello world");
}

#[test]
fn roundtrip_directory_with_nested_files() {
    let temp = TempDir::new("rt-dir");
    let src_dir = temp.path().join("project");
    fs::create_dir_all(src_dir.join("sub")).expect("mkdir");
    fs::write(src_dir.join("a.txt"), b"file a content").expect("write a");
    fs::write(src_dir.join("sub/b.bin"), vec![0xDE, 0xAD, 0xBE, 0xEF]).expect("write b");

    let archive_dir = temp.path().join("archive");
    let restore_dir = temp.path().join("restored");
    fs::create_dir(&restore_dir).expect("create restore dir");

    encrypt_to_archive(&src_dir, &archive_dir, "s3cret!");
    decrypt_archive(&archive_dir, &restore_dir, "s3cret!").expect("decrypt");

    assert_eq!(
        fs::read(restore_dir.join("a.txt")).unwrap(),
        b"file a content"
    );
    assert_eq!(
        fs::read(restore_dir.join("sub/b.bin")).unwrap(),
        vec![0xDE, 0xAD, 0xBE, 0xEF]
    );
}

#[test]
fn wrong_password_fails_and_leaves_no_residual_files() {
    let temp = TempDir::new("rt-wrong-pw");
    let source = temp.path().join("secret.txt");
    fs::write(&source, b"top secret data").expect("write source");

    let archive_dir = temp.path().join("archive");
    let restore_dir = temp.path().join("restored");
    fs::create_dir(&restore_dir).expect("create restore dir");

    encrypt_to_archive(&source, &archive_dir, "correct-password");
    let result = decrypt_archive(&archive_dir, &restore_dir, "wrong-password");

    assert!(result.is_err(), "decrypt with wrong password should fail");

    // No files should have been written to restore_dir
    let entries: Vec<_> = fs::read_dir(&restore_dir)
        .expect("read restore dir")
        .filter_map(|e| e.ok())
        .collect();
    assert!(
        entries.is_empty(),
        "wrong password should leave no residual files"
    );
}
