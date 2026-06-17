use crate::{
    crypto::keys::ArchiveKey,
    error::{Result, corrupt_archive},
};

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
pub const NONCE_LEN: usize = 24;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedBlob {
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

pub fn encrypt_blob(key: &ArchiveKey, plaintext: &[u8], aad: &[u8]) -> Result<EncryptedBlob> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes())
        .map_err(|_| corrupt_archive("invalid archive key length"))?;

    let mut nonce = [0u8; NONCE_LEN];
    rand::fill(&mut nonce);

    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| corrupt_archive("encryption failed"))?;

    Ok(EncryptedBlob { nonce, ciphertext })
}

pub fn decrypt_blob(key: &ArchiveKey, blob: &EncryptedBlob, aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes())
        .map_err(|_| corrupt_archive("invalid archive key length"))?;

    cipher
        .decrypt(
            XNonce::from_slice(&blob.nonce),
            Payload {
                msg: blob.ciphertext.as_ref(),
                aad,
            },
        )
        .map_err(|_| corrupt_archive("authentication failed"))
}

pub fn encrypt_chunk(
    key: &ArchiveKey,
    chunk_data: &[u8],
    chunk_index: u64,
    archive_id: &[u8],
    format_version: u16,
) -> Result<EncryptedBlob> {
    let aad = build_chunk_aad(archive_id, format_version, chunk_index);
    encrypt_blob(key, chunk_data, &aad)
}

pub fn decrypt_chunk(
    key: &ArchiveKey,
    blob: &EncryptedBlob,
    chunk_index: u64,
    archive_id: &[u8],
    format_version: u16,
) -> Result<Vec<u8>> {
    let aad = build_chunk_aad(archive_id, format_version, chunk_index);
    decrypt_blob(key, blob, &aad)
}

fn build_chunk_aad(archive_id: &[u8], format_version: u16, chunk_index: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(archive_id.len() + 2 + 8);
    aad.extend_from_slice(archive_id);
    aad.extend_from_slice(&format_version.to_le_bytes());
    aad.extend_from_slice(&chunk_index.to_le_bytes());
    aad
}
