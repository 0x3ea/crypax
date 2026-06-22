#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use crypax::archive::format::{self, ARCHIVE_FORMAT_VERSION};
use crypax::archive::layout::random_archive_file_name;
use crypax::archive::manifest::{
    ErasureParams, ManifestChunkEntry, ManifestFileEntry, PlainManifest, RootKind,
    decode_plain_manifest, encode_plain_manifest,
};
use crypax::chunks::erasure::{encode_recovery_shards, plan_erasure};
use crypax::chunks::split::{DataShard, join_data_shards, plan_chunks, split_into_data_shards};
use crypax::crypto::aead::{
    EncryptedBlob, decrypt_blob, decrypt_chunk, encrypt_blob, encrypt_chunk,
};
use crypax::crypto::keys::{KeySalt, default_kdf_params, derive_archive_key, generate_salt};
use crypax::fs::pack::pack_source;
use crypax::fs::restore::restore_packed_source;
use crypax::fs::scan::{EntryKind, scan_source};

pub struct TempWorkspace {
    pub path: PathBuf,
}

impl TempWorkspace {
    pub fn new(label: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "crypax-test-{label}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create temp workspace");
        Self { path }
    }
}

impl Drop for TempWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

// PLACEHOLDER_REMAINING

pub fn write_file(path: &Path, bytes: &[u8]) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create parent dirs");
    }
    fs::write(path, bytes).expect("write file");
}

pub fn hash_tree(path: &Path) -> String {
    use blake3::Hasher;
    let mut hasher = Hasher::new();
    let mut entries: Vec<PathBuf> = Vec::new();
    collect_files(path, &mut entries);
    entries.sort();
    for entry in &entries {
        let rel = entry.strip_prefix(path).unwrap();
        hasher.update(rel.to_string_lossy().as_bytes());
        hasher.update(&fs::read(entry).unwrap());
    }
    hasher.finalize().to_hex().to_string()
}

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
    if dir.is_file() {
        out.push(dir.to_path_buf());
        return;
    }
    for entry in fs::read_dir(dir).expect("read dir") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.is_dir() {
            collect_files(&path, out);
        } else {
            out.push(path);
        }
    }
}

pub struct CommandOutput {
    pub status: std::process::ExitStatus,
    pub stdout: String,
    pub stderr: String,
}

pub fn run_crypax(args: &[&str]) -> CommandOutput {
    run_crypax_with_stdin(args, "")
}

pub fn run_crypax_with_stdin(args: &[&str], stdin_data: &str) -> CommandOutput {
    let bin = env!("CARGO_BIN_EXE_crypax");
    let output = Command::new(bin)
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            if !stdin_data.is_empty()
                && let Some(ref mut stdin) = child.stdin
            {
                let _ = stdin.write_all(stdin_data.as_bytes());
            }
            drop(child.stdin.take());
            child.wait_with_output()
        })
        .expect("run crypax binary");
    CommandOutput {
        status: output.status,
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    }
}

// 解密 archive 的 manifest，供需要按 shard 角色（data/parity）定位文件的测试辅助使用。
// 直线 decrypt 路径只读取 data shard（manifest.chunks[..data_shards]），从不触碰 parity
// shard，因此"破坏某个 shard 后期望 decrypt 报错"的测试必须确定性地命中 data shard，
// 否则会受 fs::read_dir 顺序影响（不同平台/文件系统顺序不同）而偶发失败。
fn load_plain_manifest(archive_dir: &Path, password: &str) -> PlainManifest {
    let header = format::read_header(&archive_dir.join("crypax.archive")).expect("read header");
    let salt = KeySalt::try_from_vec(&header.salt).expect("parse salt");
    let params = default_kdf_params();
    let key = derive_archive_key(password, &salt, &params).expect("derive key");
    let raw = &header.encrypted_manifest;
    let nonce: [u8; 24] = raw[..24].try_into().unwrap();
    let ciphertext = raw[24..].to_vec();
    let blob = EncryptedBlob { nonce, ciphertext };
    let manifest_bytes = decrypt_blob(&key, &blob, b"").expect("decrypt manifest");
    decode_plain_manifest(&manifest_bytes).expect("decode manifest")
}

pub fn corrupt_one_archive_file(archive_dir: &Path) {
    // 确定性地破坏第一个 data shard（decrypt 实际会读取并校验的 shard）。
    // 不能按 fs::read_dir 顺序挑 .bin：那样可能命中 parity shard，而 parity shard 在
    // 直线 decrypt 中根本不被读取，破坏它不会触发认证失败，测试会非确定性失败。
    let manifest = load_plain_manifest(archive_dir, "pw");
    let target = manifest
        .chunks
        .first()
        .expect("manifest must have at least one chunk");
    let path = archive_dir.join(&target.file_name);
    let mut data = fs::read(&path).expect("read chunk");
    if let Some(byte) = data.last_mut() {
        *byte ^= 0xFF;
    }
    fs::write(&path, &data).expect("write corrupted chunk");
}

pub fn remove_n_archive_files(archive_dir: &Path, n: usize) {
    let manifest = load_plain_manifest(archive_dir, "pw");
    let data_count = manifest.erasure.data_shards as usize;
    let mut removed = 0;
    for chunk in &manifest.chunks[..data_count] {
        let path = archive_dir.join(&chunk.file_name);
        fs::remove_file(&path).expect("remove data shard file");
        removed += 1;
        if removed >= n {
            return;
        }
    }
}

pub fn assert_no_name_leaks(archive_dir: &Path, forbidden: &[&str]) {
    for entry in fs::read_dir(archive_dir).expect("read archive dir") {
        let entry = entry.expect("dir entry");
        let name = entry.file_name().to_string_lossy().to_string();
        for f in forbidden {
            assert!(
                !name.contains(f),
                "archive file name '{}' leaks forbidden pattern '{}'",
                name,
                f
            );
        }
        let path = entry.path();
        if path.is_file() && name != "crypax.archive" {
            let content = fs::read(&path).expect("read file for leak check");
            let content_str = String::from_utf8_lossy(&content);
            for f in forbidden {
                assert!(
                    !content_str.contains(f),
                    "file '{}' content leaks forbidden pattern '{}'",
                    name,
                    f
                );
            }
        }
    }
}

pub fn encrypt_to_archive(source: &Path, archive_dir: &Path, password: &str) {
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
        let blob = encrypt_chunk(
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
        let blob = encrypt_chunk(
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
        // PLACEHOLDER_MANIFEST_CONT
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

pub fn decrypt_archive(
    archive_dir: &Path,
    output_dir: &Path,
    password: &str,
) -> crypax::error::Result<()> {
    let header = format::read_header(&archive_dir.join("crypax.archive"))?;

    let salt = KeySalt::try_from_vec(&header.salt)?;
    let params = default_kdf_params();
    let key = derive_archive_key(password, &salt, &params)?;

    let raw = &header.encrypted_manifest;
    let nonce: [u8; 24] = raw[..24].try_into().unwrap();
    let ciphertext = raw[24..].to_vec();
    let manifest_blob = EncryptedBlob { nonce, ciphertext };
    let manifest_bytes = decrypt_blob(&key, &manifest_blob, b"")?;
    let manifest = decode_plain_manifest(&manifest_bytes)?;

    let data_count = manifest.erasure.data_shards as usize;
    let archive_id_uuid: uuid::Uuid = manifest.archive_id.parse().expect("parse archive_id");
    let archive_id = archive_id_uuid.as_bytes();

    let mut shards = Vec::with_capacity(data_count);
    for (i, chunk_entry) in manifest.chunks[..data_count].iter().enumerate() {
        let chunk_path = archive_dir.join(&chunk_entry.file_name);
        let raw = fs::read(&chunk_path)?;
        let nonce: [u8; 24] = raw[..24].try_into().unwrap();
        let ciphertext = raw[24..].to_vec();
        let blob = EncryptedBlob { nonce, ciphertext };
        let plaintext = decrypt_chunk(&key, &blob, i as u64, archive_id, manifest.format_version)?;
        shards.push(DataShard {
            index: i,
            data: plaintext,
        });
    }

    let packed_bytes = join_data_shards(&shards, manifest.total_packed_size)?;
    restore_packed_source(&packed_bytes, output_dir)
}
