use std::path::Path;

use crate::archive::format::read_header_with_fallback;
use crate::error::Result;
use crate::{
    archive::manifest::{PlainManifest, decrypt_manifest},
    chunks::split::{DataShard, join_data_shards},
    crypto::{
        aead::{EncryptedBlob, decrypt_segment},
        keys::{ArchiveKey, unlock_archive_key},
    },
    error::corrupt_archive,
    fs::restore::restore_packed_source,
};

pub fn run(archive_dir: &Path, output_dir: &Path) -> Result<()> {
    let password = rpassword::prompt_password("Enter password: ")?;

    let archive = read_header_with_fallback(archive_dir)?;

    let archive_key = unlock_archive_key(&password, &archive)?;

    let manifest = decrypt_manifest(&archive_key, &archive.encrypted_manifest)?;

    let packed_bytes = decrypt_data_shards(&archive_key, &manifest, archive_dir)?;

    restore_packed_source(&packed_bytes, output_dir)
}

fn decrypt_data_shards(
    key: &ArchiveKey,
    manifest: &PlainManifest,
    archive_dir: &Path,
) -> Result<Vec<u8>> {
    let data_count = manifest.erasure.data_shards as usize;

    let mut shards = Vec::with_capacity(data_count);

    let archive_id_uuid: uuid::Uuid = manifest
        .archive_id
        .parse()
        .map_err(|_| corrupt_archive("invalid archive_id in manifest"))?;
    let archive_id = archive_id_uuid.as_bytes();

    for (i, chunk_entry) in manifest.chunks[..data_count].iter().enumerate() {
        let chunk_path = archive_dir.join(&chunk_entry.file_name);
        let raw = std::fs::read(&chunk_path)?;

        let nonce = raw
            .get(..24)
            .ok_or_else(|| corrupt_archive("chunk file too short"))?;

        let nonce = nonce
            .try_into()
            .map_err(|_| corrupt_archive("invalid nonce length"))?;

        let ciphertext = raw[24..].to_vec();

        let blob = EncryptedBlob { nonce, ciphertext };
        let plaintext = decrypt_segment(key, &blob, i as u64, archive_id, manifest.format_version)?;
        shards.push(DataShard {
            index: i,
            data: plaintext,
        });
    }

    join_data_shards(&shards, manifest.total_packed_size)
}
