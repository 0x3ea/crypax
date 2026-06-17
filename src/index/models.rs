use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UserMetadata {
    pub title: Option<String>,
    pub tags: Vec<String>,
    pub note: Option<String>,
    pub custom: Option<serde_json::Value>,
    pub thumbnail: Option<String>,
}
#[derive(Debug, Clone)]
pub struct IndexRecord {
    pub archive_id: String,
    pub fingerprint: String,
    pub archive_path: PathBuf,
    pub created_at: i64,
    pub updated_at: i64,
    pub metadata: UserMetadata,
}

pub struct NewIndexRecord {
    pub archive_id: String,
    pub fingerprint: String,
    pub archive_path: PathBuf,
    pub metadata: UserMetadata,
}
