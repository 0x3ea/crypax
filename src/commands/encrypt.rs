use crate::archive::format::{ARCHIVE_FORMAT_VERSION, ArchiveHeader, write_header};
use crate::archive::layout::random_archive_file_name;
use crate::archive::manifest::encode_plain_manifest;
use crate::archive::manifest::{
    ErasureParams, ManifestChunkEntry, ManifestFileEntry, PlainManifest, RootKind,
};
use crate::chunks::erasure::plan_erasure;
use crate::chunks::erasure::{ErasurePlan, encode_recovery_shards};
use crate::chunks::split::split_into_data_shards;
use crate::chunks::split::{ChunkPlan, plan_chunks};
use crate::crypto::aead::{EncryptedBlob, encrypt_blob, encrypt_chunk};
use crate::crypto::keys::derive_archive_key;
use crate::crypto::keys::generate_salt;
use crate::crypto::keys::{KeySalt, default_kdf_params};
use crate::error::Result;
use crate::fs::pack::compute_content_fingerprint;
use crate::fs::pack::pack_source;
use crate::fs::scan::{EntryKind, SourceTree, scan_source};
use crate::index::db::IndexDb;
use crate::index::models::NewIndexRecord;
use std::fs::{self};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

pub fn run(source: PathBuf, output_dir: PathBuf) -> Result<()> {
    // 1. read_password
    let password = read_password()?;

    // 2.scan
    let tree = scan_source(&source)?;

    // 3.fingerprint
    let fingerprint = compute_content_fingerprint(&tree)?;

    // 4. check_duplicate
    let index = IndexDb::open_default()?;
    ensure_not_duplicate(&index, &fingerprint)?;

    // 5.pack
    let packed = pack_source(&tree)?;

    // 6.derive key
    let salt = generate_salt();
    let kdf_params = default_kdf_params();
    let key = derive_archive_key(&password, &salt, &kdf_params)?;

    //7.split
    let plan = plan_chunks(packed.bytes.len() as u64);
    let data_shards = split_into_data_shards(&packed.bytes, &plan);

    // 8.erasure
    let erasure_plan = plan_erasure(data_shards.len(), 20);
    let recovery_shards = encode_recovery_shards(&data_shards, &erasure_plan)?;

    // 9.encrypt
    let uuid = Uuid::new_v4();
    let archive_id = uuid.as_bytes();
    let mut encrypted_shards = Vec::new();
    for (i, shard) in data_shards.iter().enumerate() {
        let blob = encrypt_chunk(
            &key,
            &shard.data,
            i as u64,
            archive_id,
            ARCHIVE_FORMAT_VERSION,
        )?;
        encrypted_shards.push(blob);
    }

    let offset = data_shards.len();
    for (i, shard) in recovery_shards.iter().enumerate() {
        let blob = encrypt_chunk(
            &key,
            &shard.data,
            (offset + i) as u64,
            archive_id,
            ARCHIVE_FORMAT_VERSION,
        )?;
        encrypted_shards.push(blob);
    }

    // 10.build_plain_manifest
    let archive_id_str = uuid.to_string();
    let manifest = build_plain_manifest(
        &archive_id_str,
        &source,
        &tree,
        &plan,
        &erasure_plan,
        &encrypted_shards,
        packed.bytes.len() as u64,
    );

    // 11.encode manifest
    let manifest_bytes = encode_plain_manifest(&manifest)?;
    let encrypted_manifest = encrypt_blob(&key, &manifest_bytes, b"")?;

    // 12.write archive
    let archive_subdir = output_dir.join(&archive_id_str[..8]);
    let chunk_file_names: Vec<String> = manifest
        .chunks
        .iter()
        .map(|c| c.file_name.clone())
        .collect();
    write_encrypted_archive(
        &archive_subdir,
        &salt,
        &encrypted_manifest,
        &encrypted_shards,
        &chunk_file_names,
    )?;

    println!("Archive created: {}", archive_subdir.display());

    index.insert_record(NewIndexRecord {
        archive_id: archive_id_str,
        fingerprint,
        archive_path: archive_subdir,
        metadata: Default::default(),
    })?;

    Ok(())
}

fn read_password() -> Result<String> {
    let password_a = rpassword::prompt_password("Enter Password: ")?;
    let password_b = rpassword::prompt_password("Confirm Password: ")?;
    if password_a != password_b {
        anyhow::bail!("passwords do not match");
    }
    Ok(password_a)
}

fn ensure_not_duplicate(index: &IndexDb, fingerprint: &str) -> Result<()> {
    if index.find_by_fingerprint(fingerprint)?.is_some() {
        anyhow::bail!(
            "duplicate content: this source has already been encrypted. Use `crypax forget` to remove the existing record first."
        );
    }
    Ok(())
}

fn build_plain_manifest(
    archive_id: &str,
    source: &Path,
    tree: &SourceTree,
    plan: &ChunkPlan,
    erasure_plan: &ErasurePlan,
    encrypted_shards: &[EncryptedBlob],
    total_packed_size: u64,
) -> PlainManifest {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let files = tree
        .entries
        .iter()
        .filter(|e| e.kind == EntryKind::File)
        .map(|e| ManifestFileEntry {
            path: e.relative_path.to_string(),
            size: e.size,
            modified_at: None,
            chunks: vec![],
        })
        .collect();

    let chunks = encrypted_shards
        .iter()
        .enumerate()
        .map(|(i, blob)| ManifestChunkEntry {
            id: format!("{}", i),
            file_name: random_archive_file_name(),
            size: (blob.nonce.len() + blob.ciphertext.len()) as u64,
            plaintext_offset: (i * plan.shard_size) as u64,
            plaintext_size: plan.shard_size as u64,
        })
        .collect();

    let root_kind = if source.is_file() {
        RootKind::File
    } else {
        RootKind::Directory
    };

    PlainManifest {
        format_version: ARCHIVE_FORMAT_VERSION,
        archive_id: archive_id.to_string(),
        created_at: now,
        root_kind,
        files,
        chunks,
        erasure: ErasureParams {
            data_shards: plan.data_shards as u16,
            parity_shards: erasure_plan.parity_shards as u16,
            redundancy_percent: 20,
        },
        total_packed_size,
    }
}

fn write_encrypted_archive(
    output_dir: &Path,
    salt: &KeySalt,
    encrypted_manifest: &EncryptedBlob,
    encrypted_shards: &[EncryptedBlob],
    chunk_file_names: &[String],
) -> Result<()> {
    if !output_dir.exists() {
        fs::create_dir_all(output_dir)?;
    }

    let mut manifest_blob = Vec::new();
    manifest_blob.extend_from_slice(&encrypted_manifest.nonce);
    manifest_blob.extend_from_slice(&encrypted_manifest.ciphertext);

    let header = ArchiveHeader {
        version: ARCHIVE_FORMAT_VERSION,
        salt: salt.as_bytes().to_vec(),
        encrypted_manifest: manifest_blob,
    };

    let archive_path = output_dir.join("crypax.archive");
    write_header(&archive_path, &header)?;

    for (blob, file_name) in encrypted_shards.iter().zip(chunk_file_names.iter()) {
        let chunk_path = output_dir.join(file_name);
        let mut chunk_bytes = Vec::with_capacity(blob.nonce.len() + blob.ciphertext.len());
        chunk_bytes.extend_from_slice(&blob.nonce);
        chunk_bytes.extend_from_slice(&blob.ciphertext);
        fs::write(&chunk_path, &chunk_bytes)?;
    }
    Ok(())
}
