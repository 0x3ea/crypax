use crate::{
    crypto::{
        aead::{EncryptedBlob, decrypt_blob},
        keys::ArchiveKey,
    },
    error::{Result, corrupt_archive},
};
use serde::{self, Deserialize, Serialize};

/// 加密后的manifest
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedManifest {
    pub nonce: Vec<u8>,
    /// 加密后的 manifest 内容
    pub ciphertext: Vec<u8>,
}
/// 未加密的 manifest
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlainManifest {
    /// manifest 格式版本
    pub format_version: u16,
    /// 这个归档的唯一 ID
    pub archive_id: String,
    /// 创建时间
    pub created_at: i64,
    pub root_kind: RootKind,
    /// 原始文件列表
    pub files: Vec<ManifestFileEntry>,
    /// 归档中的 chunk 列表
    pub chunks: Vec<ManifestChunkEntry>,
    /// 纠删码参数
    pub erasure: ErasureParams,
    /// pack 字节流的原始总长度（用于 join_data_shards 截断）
    pub total_packed_size: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RootKind {
    File,
    Directory,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestFileEntry {
    // 原始相对路径
    pub path: String,
    /// 原始文件大小(byte)
    pub size: u64,
    // 原始文件修改时间
    pub modified_at: Option<i64>,
    // 文件由哪些 chunk 组成
    pub chunks: Vec<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestChunkEntry {
    /// chunk 内部 ID
    pub id: String,
    /// chunk 名
    pub file_name: String,
    /// chunk 大小
    pub size: u64,
    /// 该 chunk 对应原始明文流中的起始位置
    pub plaintext_offset: u64,
    /// 该 chunk 解密后对应的明文长度
    pub plaintext_size: u64,
}
/// 记录 archive 实际使用的纠删码参数
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ErasureParams {
    //parity_shards ≈ ceil(data_shards * redundancy_percent / 100)
    /// 数据分片数量
    pub data_shards: u16,
    // 冗余修复分片数量
    pub parity_shards: u16,
    // 冗余比例
    pub redundancy_percent: u8,
}

pub fn decrypt_manifest(key: &ArchiveKey, raw: &[u8]) -> Result<PlainManifest> {
    let nonce = raw
        .get(..24)
        .ok_or_else(|| corrupt_archive("manifest too short"))?;
    let nonce = nonce
        .try_into()
        .map_err(|_| corrupt_archive("invalid nonce length"))?;

    let ciphertext = &raw[24..];
    let blob = EncryptedBlob {
        nonce,
        ciphertext: ciphertext.to_vec(),
    };
    let plaintext = decrypt_blob(key, &blob, b"")?;
    decode_plain_manifest(&plaintext)
}

pub fn encode_plain_manifest(manifest: &PlainManifest) -> Result<Vec<u8>> {
    serde_json::to_vec(manifest).map_err(crate::error::corrupt_archive)
}

pub fn decode_plain_manifest(bytes: &[u8]) -> Result<PlainManifest> {
    serde_json::from_slice(bytes).map_err(crate::error::corrupt_archive)
}
