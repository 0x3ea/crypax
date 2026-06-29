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
use crypax::chunks::split::{DataShard, join_data_shards, plan_chunks, split_into_data_shards};
use crypax::crypto::aead::{EncryptedBlob, decrypt_segment, encrypt_blob, encrypt_segment};
use crypax::crypto::keys::{default_kdf_params, derive_archive_key, generate_salt};
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

    let manifest = PlainManifest {
        format_version: ARCHIVE_FORMAT_VERSION,
        archive_id: archive_id_str,
        created_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64,
        root_kind: RootKind::Directory,
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

/// Repair damaged shards using reed-solomon, replicating the repair command logic.
fn repair_archive(fixture: &ArchiveFixture) -> anyhow::Result<()> {
    let archive_id_uuid: uuid::Uuid = fixture.manifest.archive_id.parse()?;
    let archive_id = archive_id_uuid.as_bytes();

    let mut shards: Vec<Option<Vec<u8>>> = Vec::new();
    for (i, chunk_entry) in fixture.manifest.chunks.iter().enumerate() {
        let chunk_path = fixture.archive_dir.join(&chunk_entry.file_name);
        let shard = (|| -> Option<Vec<u8>> {
            let raw = fs::read(&chunk_path).ok()?;
            let nonce: [u8; 24] = raw[..24].try_into().ok()?;
            let blob = EncryptedBlob {
                nonce,
                ciphertext: raw[24..].to_vec(),
            };
            decrypt_segment(
                &fixture.key,
                &blob,
                i as u64,
                archive_id,
                fixture.manifest.format_version,
            )
            .ok()
        })();
        shards.push(shard);
    }

    let damaged_indices: Vec<usize> = shards
        .iter()
        .enumerate()
        .filter(|(_, s)| s.is_none())
        .map(|(i, _)| i)
        .collect();

    let parity = fixture.manifest.erasure.parity_shards as usize;
    if damaged_indices.len() > parity {
        anyhow::bail!(
            "too many damaged shards ({}), max recoverable: {}",
            damaged_indices.len(),
            parity
        );
    }

    let data_count = fixture.manifest.erasure.data_shards as usize;
    let r = reed_solomon_erasure::ReedSolomon::<reed_solomon_erasure::galois_8::Field>::new(
        data_count, parity,
    )?;
    r.reconstruct(&mut shards)?;

    for &i in &damaged_indices {
        let plaintext = shards[i].as_ref().expect("reconstructed");
        let blob = encrypt_segment(
            &fixture.key,
            plaintext,
            i as u64,
            archive_id,
            fixture.manifest.format_version,
        )?;
        let chunk_path = fixture
            .archive_dir
            .join(&fixture.manifest.chunks[i].file_name);
        let tmp_path = chunk_path.with_extension("tmp");
        let mut bytes = Vec::with_capacity(blob.nonce.len() + blob.ciphertext.len());
        bytes.extend_from_slice(&blob.nonce);
        bytes.extend_from_slice(&blob.ciphertext);
        fs::write(&tmp_path, &bytes)?;
        fs::rename(&tmp_path, &chunk_path)?;
    }

    Ok(())
}

/// Decrypt an archive to verify content is recoverable after repair.
fn decrypt_archive(fixture: &ArchiveFixture, output_dir: &Path) -> anyhow::Result<()> {
    let archive_id_uuid: uuid::Uuid = fixture.manifest.archive_id.parse()?;
    let archive_id = archive_id_uuid.as_bytes();

    let data_count = fixture.manifest.erasure.data_shards as usize;
    let mut shards = Vec::with_capacity(data_count);

    for (i, chunk_entry) in fixture.manifest.chunks[..data_count].iter().enumerate() {
        let chunk_path = fixture.archive_dir.join(&chunk_entry.file_name);
        let raw = fs::read(&chunk_path)?;
        let nonce: [u8; 24] = raw[..24].try_into().unwrap();
        let blob = EncryptedBlob {
            nonce,
            ciphertext: raw[24..].to_vec(),
        };
        let plaintext = decrypt_segment(
            &fixture.key,
            &blob,
            i as u64,
            archive_id,
            fixture.manifest.format_version,
        )?;
        shards.push(DataShard {
            index: i,
            data: plaintext,
        });
    }

    let packed_bytes = join_data_shards(&shards, fixture.manifest.total_packed_size)?;
    restore_packed_source(&packed_bytes, output_dir)?;
    Ok(())
}

/// Check all shards are valid (verify logic).
fn all_shards_healthy(fixture: &ArchiveFixture) -> bool {
    let archive_id_uuid: uuid::Uuid = fixture.manifest.archive_id.parse().unwrap();
    let archive_id = archive_id_uuid.as_bytes();

    for (i, chunk_entry) in fixture.manifest.chunks.iter().enumerate() {
        let chunk_path = fixture.archive_dir.join(&chunk_entry.file_name);
        let raw = match fs::read(&chunk_path) {
            Ok(r) => r,
            Err(_) => return false,
        };
        let nonce: [u8; 24] = match raw[..24].try_into() {
            Ok(n) => n,
            Err(_) => return false,
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
            return false;
        }
    }
    true
}

// --- tests ---

#[test]
fn repair_recovers_missing_shard() {
    let temp = TempDir::new("repair-missing");
    let fixture = create_test_archive(&temp, "password123");

    // Delete one shard
    let target = &fixture.manifest.chunks[0].file_name;
    fs::remove_file(fixture.archive_dir.join(target)).expect("delete chunk");

    assert!(!all_shards_healthy(&fixture));

    repair_archive(&fixture).expect("repair should succeed");

    assert!(all_shards_healthy(&fixture));
}

#[test]
fn repair_recovers_corrupt_shard_and_decrypt_works() {
    let temp = TempDir::new("repair-corrupt");
    let fixture = create_test_archive(&temp, "password123");

    // Flip a bit in the first data shard
    let target = &fixture.manifest.chunks[0].file_name;
    let chunk_path = fixture.archive_dir.join(target);
    let mut data = fs::read(&chunk_path).expect("read");
    data[30] ^= 0x01;
    fs::write(&chunk_path, &data).expect("write corrupted");

    assert!(!all_shards_healthy(&fixture));

    repair_archive(&fixture).expect("repair should succeed");

    assert!(all_shards_healthy(&fixture));

    // Verify full decrypt works after repair
    let restore_dir = temp.path().join("restored");
    fs::create_dir(&restore_dir).expect("mkdir restore");
    decrypt_archive(&fixture, &restore_dir).expect("decrypt after repair");

    assert_eq!(
        fs::read(restore_dir.join("a.txt")).unwrap(),
        b"file a content"
    );
    assert_eq!(
        fs::read(restore_dir.join("b.txt")).unwrap(),
        b"file b content here"
    );
}

#[test]
fn repair_fails_when_too_many_shards_damaged() {
    let temp = TempDir::new("repair-too-many");
    let fixture = create_test_archive(&temp, "password123");

    let parity = fixture.manifest.erasure.parity_shards as usize;

    // Delete more shards than parity can handle
    for chunk in fixture.manifest.chunks.iter().take(parity + 1) {
        let path = fixture.archive_dir.join(&chunk.file_name);
        if path.exists() {
            fs::remove_file(&path).expect("delete chunk");
        }
    }

    let result = repair_archive(&fixture);
    assert!(
        result.is_err(),
        "repair should fail when damage exceeds parity"
    );
}
