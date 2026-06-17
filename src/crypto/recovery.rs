use argon2::{Argon2, Params};
use data_encoding::BASE32;
use zeroize::Zeroize;

use crate::{
    crypto::keys::{ARCHIVE_KEY_LEN, ArchiveKey, KeySalt, default_kdf_params},
    error::{Result, invalid_input},
};

pub const RECOVERY_SECRET_LEN: usize = 32;
const RECOVERY_PREFIX: &str = "crypax-r1-";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryCode {
    encoded: String,
}

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct RecoverySecret([u8; RECOVERY_SECRET_LEN]);

impl RecoverySecret {
    pub fn from_bytes(bytes: [u8; RECOVERY_SECRET_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; RECOVERY_SECRET_LEN] {
        &self.0
    }
}
impl RecoveryCode {
    fn new_unchecked(encoded: String) -> Self {
        Self { encoded }
    }

    pub fn as_str(&self) -> &str {
        &self.encoded
    }
}

pub fn generate_recovery_code() -> Result<(RecoveryCode, RecoverySecret)> {
    let mut rnd = [0_u8; 32];
    rand::fill(&mut rnd);

    let secret = RecoverySecret::from_bytes(rnd);
    let encoded = BASE32.encode(secret.as_bytes());
    let code = RecoveryCode::new_unchecked(format!("crypax-r1-{encoded}"));

    Ok((code, secret))
}

pub fn parse_recovery_code(input: &str) -> Result<RecoveryCode> {
    let normalized = input.trim();

    let payload = normalized
        .strip_prefix(RECOVERY_PREFIX)
        .ok_or_else(|| invalid_input("recovery code"))?;

    let decoded = BASE32
        .decode(payload.as_bytes())
        .map_err(|_| invalid_input("recovery decode"))?;

    let _: [u8; RECOVERY_SECRET_LEN] = decoded.try_into().map_err(|_| invalid_input("secret"))?;

    Ok(RecoveryCode::new_unchecked(normalized.to_string()))
}

pub fn derive_key_from_recovery(code: &RecoveryCode, salt: &KeySalt) -> Result<ArchiveKey> {
    let payload = code
        .as_str()
        .strip_prefix(RECOVERY_PREFIX)
        .ok_or_else(|| invalid_input("recovery code"))?;

    let secret = BASE32
        .decode(payload.as_bytes())
        .map_err(|_| invalid_input("recovery code"))?;

    let params = default_kdf_params();
    let argon2_params = Params::new(
        params.memory_cost_kib,
        params.time_cost,
        params.parallelism,
        Some(ARCHIVE_KEY_LEN),
    )
    .map_err(|e| invalid_input(format!("invalid KDF params: {e:?}")))?;

    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2_params,
    );

    let mut output = [0u8; ARCHIVE_KEY_LEN];
    argon2
        .hash_password_into(&secret, salt.as_bytes(), &mut output)
        .map_err(|e| invalid_input(format!("key derivation failed: {e:?}")))?;

    Ok(ArchiveKey::from_bytes(output))
}
