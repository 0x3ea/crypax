use crate::error::{Result, corrupt_archive};

pub struct ShardDigest {
    pub hash: String,
}

pub fn hash_shard(bytes: &[u8]) -> ShardDigest {
    let hash = blake3::hash(bytes);
    ShardDigest {
        hash: hash.to_hex().to_string(),
    }
}

pub fn verify_shard_digest(bytes: &[u8], expected: &ShardDigest) -> Result<()> {
    let actual = hash_shard(bytes);
    if actual.hash != expected.hash {
        return Err(corrupt_archive("shard digest mismatch"));
    }
    Ok(())
}
