use std::{
    fs,
    path::{Path, PathBuf},
};

use crate::error::Result;
use crate::{
    archive::{
        format::read_header,
        manifest::{PlainManifest, decrypt_manifest},
    },
    crypto::{
        aead::{EncryptedBlob, decrypt_chunk},
        keys::{ArchiveKey, unlock_archive_key},
    },
    error::corrupt_archive,
};
#[derive(Default)]
pub struct VerifyReport {
    pub findings: Vec<VerifyFinding>,
}
#[allow(dead_code)]
pub enum VerifyFinding {
    MissingShard { index: usize },
    CorruptShard { index: usize },
}

impl VerifyReport {
    pub fn is_healthy(&self) -> bool {
        self.findings.is_empty()
    }

    #[allow(dead_code)]
    pub fn can_repair(&self, parity_shards: usize) -> bool {
        self.findings.len() <= parity_shards
    }
}
pub fn run(archive_dir: PathBuf) -> Result<VerifyReport> {
    let password = rpassword::prompt_password("Enter password")?;

    let header_path = archive_dir.join("crypax.archive");
    let archive = read_header(&header_path)?;

    let archive_key = unlock_archive_key(&password, &archive)?;

    let manifest = decrypt_manifest(&archive_key, &archive.encrypted_manifest)?;

    verify_archive(&archive_key, &manifest, &archive_dir)
}

pub(crate) fn verify_archive(
    key: &ArchiveKey,
    manifest: &PlainManifest,
    archive_dir: &Path,
) -> Result<VerifyReport> {
    let archive_id_uuid: uuid::Uuid = manifest
        .archive_id
        .parse()
        .map_err(|_| corrupt_archive("invalid archive_id in manifest"))?;
    let archive_id = archive_id_uuid.as_bytes();

    let mut report = VerifyReport::default();
    for (i, chunk_entry) in manifest.chunks.iter().enumerate() {
        let chunk_path = archive_dir.join(&chunk_entry.file_name);

        if !chunk_path.exists() {
            report
                .findings
                .push(VerifyFinding::MissingShard { index: i });
            continue;
        }

        let raw = fs::read(&chunk_path)?;
        if raw.len() as u64 != chunk_entry.size {
            report
                .findings
                .push(VerifyFinding::CorruptShard { index: i });
            continue;
        }

        let nonce: [u8; 24] = match raw[..24].try_into() {
            Ok(n) => n,
            Err(_) => {
                report
                    .findings
                    .push(VerifyFinding::CorruptShard { index: i });
                continue;
            }
        };
        let blob = EncryptedBlob {
            nonce,
            ciphertext: raw[24..].to_vec(),
        };

        if decrypt_chunk(key, &blob, i as u64, archive_id, manifest.format_version).is_err() {
            report
                .findings
                .push(VerifyFinding::CorruptShard { index: i });
        }
    }
    Ok(report)
}
