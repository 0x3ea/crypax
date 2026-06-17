use crate::{
    archive::format::ArchiveHeader,
    error::{Result, invalid_input},
};
use argon2::{Argon2, Params};
use zeroize::Zeroize;
pub const ARCHIVE_KEY_LEN: usize = 32;
pub const KEY_SALT_LEN: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KdfParams {
    pub memory_cost_kib: u32,
    pub time_cost: u32,
    pub parallelism: u32,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySalt([u8; KEY_SALT_LEN]);

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct ArchiveKey([u8; ARCHIVE_KEY_LEN]);

impl KeySalt {
    pub fn from_bytes(bytes: [u8; KEY_SALT_LEN]) -> Self {
        Self(bytes)
    }

    pub fn try_from_vec(bytes: &[u8]) -> Result<Self> {
        let arr: [u8; KEY_SALT_LEN] = bytes.try_into().map_err(|_| {
            invalid_input(format!(
                "invalid salt length: expected {KEY_SALT_LEN}, got {}",
                bytes.len()
            ))
        })?;
        Ok(Self(arr))
    }

    pub fn as_bytes(&self) -> &[u8; KEY_SALT_LEN] {
        &self.0
    }
}

impl ArchiveKey {
    pub fn from_bytes(bytes: [u8; ARCHIVE_KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; ARCHIVE_KEY_LEN] {
        &self.0
    }
}

pub fn default_kdf_params() -> KdfParams {
    KdfParams {
        memory_cost_kib: 64 * 1024,
        time_cost: 3,
        parallelism: 1,
    }
}

pub fn generate_salt() -> KeySalt {
    let mut bytes: [u8; KEY_SALT_LEN] = [0_u8; KEY_SALT_LEN];
    rand::fill(&mut bytes);
    let salt: KeySalt = KeySalt(bytes);
    salt
}

pub fn derive_archive_key(
    password: &str,
    salt: &KeySalt,
    params: &KdfParams,
) -> Result<ArchiveKey> {
    let mut output = [0u8; ARCHIVE_KEY_LEN];
    let argon2_params = Params::new(
        params.memory_cost_kib,
        params.time_cost,
        params.parallelism,
        Some(ARCHIVE_KEY_LEN),
    )
    .map_err(|err| invalid_input(format!("invalid KDF params: {err:?}")))?;
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2_params,
    );
    argon2
        .hash_password_into(password.as_bytes(), salt.as_bytes(), &mut output)
        .map_err(|err| invalid_input(format!("key derivation failed: {err:?}")))?;

    Ok(ArchiveKey::from_bytes(output))
}

pub fn unlock_archive_key(password: &str, archive: &ArchiveHeader) -> Result<ArchiveKey> {
    let salt = KeySalt::try_from_vec(&archive.salt)?;
    let params = default_kdf_params();
    derive_archive_key(password, &salt, &params)
}
