use rusqlite::Connection;

use crate::{
    error::Result,
    index::models::{IndexRecord, NewIndexRecord, UserMetadata},
};
use std::{
    fs,
    path::{Path, PathBuf},
};
pub struct IndexDb {
    conn: rusqlite::Connection,
}

pub fn default_index_dir() -> Result<PathBuf> {
    let project_dirs = directories::ProjectDirs::from("com", "crypax", "crypax")
        .ok_or_else(|| anyhow::anyhow!("cannot determine system data directory"))?;
    Ok(project_dirs.data_dir().to_path_buf())
}

impl IndexDb {
    pub fn open(path: &Path) -> Result<IndexDb> {
        let conn = Connection::open(path)?;
        let db = IndexDb { conn };
        db.migrate()?;
        Ok(db)
    }

    pub fn open_default() -> Result<IndexDb> {
        let path = default_index_dir()?;
        let db_path = path.join("index.db");
        if !path.exists() {
            fs::create_dir_all(path)?;
        }
        Self::open(&db_path)
    }

    pub fn migrate(&self) -> Result<()> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS archives (
                archive_id    TEXT PRIMARY KEY,
                fingerprint   TEXT NOT NULL UNIQUE,
                archive_path  TEXT NOT NULL,
                metadata_json TEXT NOT NULL DEFAULT '{}',
                created_at    INTEGER NOT NULL,
                updated_at    INTEGER NOT NULL
            )",
        )?;
        Ok(())
    }

    pub fn find_by_fingerprint(&self, fp: &str) -> Result<Option<IndexRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT archive_id, fingerprint, archive_path, metadata_json,
    created_at, updated_at
             FROM archives WHERE fingerprint = ?1",
        )?;

        let result = stmt.query_row(rusqlite::params![fp], |row| {
            Ok(IndexRecord {
                archive_id: row.get(0)?,
                fingerprint: row.get(1)?,
                archive_path: PathBuf::from(row.get::<_, String>(2)?),
                created_at: row.get(4)?,
                updated_at: row.get(5)?,
                metadata: serde_json::from_str(&row.get::<_, String>(3)?).unwrap_or_default(),
            })
        });

        match result {
            Ok(record) => Ok(Some(record)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn insert_record(&self, record: NewIndexRecord) -> Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let metadata_json = serde_json::to_string(&record.metadata)?;
        self.conn.execute(
            "INSERT INTO archives (archive_id, fingerprint, archive_path,
    metadata_json, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                record.archive_id,
                record.fingerprint,
                record.archive_path.to_str().unwrap_or(""),
                metadata_json,
                now,
                now,
            ],
        )?;

        Ok(())
    }

    pub fn list_records(&self) -> Result<Vec<IndexRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT archive_id, fingerprint, archive_path, metadata_json,
                  created_at, updated_at
           FROM archives ORDER BY created_at DESC",
        )?;

        let mut records = Vec::new();
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            records.push(IndexRecord {
                archive_id: row.get(0)?,
                fingerprint: row.get(1)?,
                archive_path: PathBuf::from(row.get::<_, String>(2)?),
                created_at: row.get(4)?,
                updated_at: row.get(5)?,
                metadata: serde_json::from_str(&row.get::<_, String>(3)?).unwrap_or_default(),
            });
        }
        Ok(records)
    }

    pub fn delete_by_target(&self, target: &str) -> Result<bool> {
        let pattern = format!("{}%", target);
        let affected = self.conn.execute(
            "DELETE FROM archives WHERE archive_id LIKE ?1",
            rusqlite::params![pattern],
        )?;
        if affected > 0 {
            return Ok(true);
        }
        let affected = self.conn.execute(
            "DELETE FROM archives WHERE fingerprint LIKE ?1",
            rusqlite::params![pattern],
        )?;
        Ok(affected > 0)
    }

    pub fn find_by_target(&self, target: &str) -> Result<Option<IndexRecord>> {
        let pattern = format!("{}%", target);
        let mut stmt = self.conn.prepare(
            "SELECT archive_id, fingerprint, archive_path, metadata_json,
                    created_at, updated_at
             FROM archives WHERE archive_id LIKE ?1 OR fingerprint LIKE ?1",
        )?;

        let result = stmt.query_row(rusqlite::params![pattern], |row| {
            Ok(IndexRecord {
                archive_id: row.get(0)?,
                fingerprint: row.get(1)?,
                archive_path: PathBuf::from(row.get::<_, String>(2)?),
                created_at: row.get(4)?,
                updated_at: row.get(5)?,
                metadata: serde_json::from_str(&row.get::<_, String>(3)?).unwrap_or_default(),
            })
        });

        match result {
            Ok(record) => Ok(Some(record)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn update_metadata(&self, target: &str, metadata: &UserMetadata) -> Result<()> {
        let json = serde_json::to_string(metadata)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let pattern = format!("{}%", target);
        let affected = self.conn.execute(
            "UPDATE archives SET metadata_json = ?1, updated_at = ?2
             WHERE archive_id LIKE ?3 OR fingerprint LIKE ?3",
            rusqlite::params![json, now, pattern],
        )?;

        if affected == 0 {
            anyhow::bail!("no archive found matching '{}'", target);
        }
        Ok(())
    }
}
