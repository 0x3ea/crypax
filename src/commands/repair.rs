use std::{
    fs,
    path::{Path, PathBuf},
};

use crate::{
    archive::{
        format::read_header_with_fallback,
        manifest::{PlainManifest, decrypt_manifest},
    },
    crypto::{
        aead::{EncryptedBlob, decrypt_chunk, encrypt_chunk},
        keys::{ArchiveKey, unlock_archive_key},
    },
    error::corrupt_archive,
};

use crate::{commands::verify, error::Result};
pub fn run(archive_dir: PathBuf) -> Result<()> {
    let password = rpassword::prompt_password("Enter password")?;

    let archive = read_header_with_fallback(&archive_dir)?;

    let archive_key = unlock_archive_key(&password, &archive)?;

    let manifest = decrypt_manifest(&archive_key, &archive.encrypted_manifest)?;

    let archive_id_uuid: uuid::Uuid = manifest
        .archive_id
        .parse()
        .map_err(|_| corrupt_archive("invalid archive_id in manifest"))?;
    let archive_id = archive_id_uuid.as_bytes();

    let mut to_restore: Vec<Option<Vec<u8>>> =
        collect_available_shards(&archive_key, &manifest, &archive_dir, archive_id)?;

    let damaged_count = to_restore.iter().filter(|s| s.is_none()).count();
    if damaged_count > manifest.erasure.parity_shards as usize {
        anyhow::bail!(
            "too many shards ({damaged_count}), cannot repair (max recoverable: {})",
            manifest.erasure.parity_shards
        );
    }
    let damaged_indices: Vec<usize> = to_restore
        .iter()
        .enumerate()
        .filter(|(_, s)| s.is_none())
        .map(|(i, _)| i)
        .collect();

    reconstruct_missing_or_corrupt(
        &mut to_restore,
        manifest.erasure.data_shards as usize,
        manifest.erasure.parity_shards as usize,
    )?;

    write_recovered_shards(
        &archive_key,
        &manifest,
        &archive_dir,
        archive_id,
        &to_restore,
        &damaged_indices,
    )?;

    reverify_after_repair(&archive_key, &manifest, &archive_dir)
}

fn collect_available_shards(
    key: &ArchiveKey,
    manifest: &PlainManifest,
    archive_dir: &Path,
    archive_id: &[u8],
) -> Result<Vec<Option<Vec<u8>>>> {
    let total = manifest.chunks.len();
    let mut shards = Vec::with_capacity(total);

    for (i, chunk_entry) in manifest.chunks.iter().enumerate() {
        let chunk_path = archive_dir.join(&chunk_entry.file_name);

        let shard = (|| -> Option<Vec<u8>> {
            let raw = fs::read(chunk_path).ok()?;
            let nonce = raw[..24].try_into().ok()?;
            let blob = EncryptedBlob {
                nonce,
                ciphertext: raw[24..].to_vec(),
            };
            decrypt_chunk(key, &blob, i as u64, archive_id, manifest.format_version).ok()
        })();

        shards.push(shard);
    }
    Ok(shards)
}

fn reconstruct_missing_or_corrupt(
    shards: &mut [Option<Vec<u8>>],
    data_shards: usize,
    parity_shards: usize,
) -> Result<()> {
    let r = reed_solomon_erasure::ReedSolomon::<reed_solomon_erasure::galois_8::Field>::new(
        data_shards,
        parity_shards,
    )
    .map_err(|e| anyhow::anyhow!("failed to create reed-solomon codec: {}", e))?;

    r.reconstruct(shards)
        .map_err(|e| anyhow::anyhow!("reconstruction failed: {}", e))?;

    Ok(())
}

fn write_recovered_shards(
    key: &ArchiveKey,
    manifest: &PlainManifest,
    archive_dir: &Path,
    archive_id: &[u8],
    shards: &[Option<Vec<u8>>],
    damaged_indices: &[usize],
) -> Result<()> {
    for &i in damaged_indices {
        let plaintext = shards[i].as_ref().expect("shard should be reconstructed");
        let chunk_entry = &manifest.chunks[i];

        let blob = encrypt_chunk(
            key,
            plaintext,
            i as u64,
            archive_id,
            manifest.format_version,
        )?;

        let chunk_path = archive_dir.join(&chunk_entry.file_name);
        let tmp_path = chunk_path.with_extension("tmp");

        let mut bytes = Vec::with_capacity(blob.nonce.len() + blob.ciphertext.len());
        bytes.extend_from_slice(&blob.nonce);
        bytes.extend_from_slice(&blob.ciphertext);

        fs::write(&tmp_path, &bytes)?;
        fs::rename(&tmp_path, &chunk_path)?;
    }
    Ok(())
}

fn reverify_after_repair(
    key: &ArchiveKey,
    manifest: &PlainManifest,
    archive_dir: &Path,
) -> Result<()> {
    let report = verify::verify_archive(key, manifest, archive_dir)?;
    if !report.is_healthy() {
        anyhow::bail!("archive still issues after repair");
    }
    Ok(())
}
