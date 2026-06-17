use std::{
    fs,
    path::{Path, PathBuf},
};

use crate::{
    archive::format,
    error::{self, Result},
};
use anyhow::Ok;
use rand::{Rng, distr::Alphanumeric};
use std::string::String;

pub const ARCHIVE_HEADER_FILE_NAME: &str = "crypax.archive";

pub struct ArchiveLayout {
    pub archive_dir: PathBuf,
    pub header_path: PathBuf,
}

pub fn create_archive_dir(output_dir: &Path) -> Result<ArchiveLayout> {
    if output_dir.exists() && !output_dir.is_dir() {
        return Err(error::invalid_input("invalid path"));
    }
    if !output_dir.exists() {
        fs::create_dir(output_dir)?;
    }
    Ok(ArchiveLayout {
        archive_dir: output_dir.to_path_buf(),
        header_path: output_dir.join(ARCHIVE_HEADER_FILE_NAME),
    })
}

pub fn open_archive_dir(archive_dir: &Path) -> Result<ArchiveLayout> {
    if !archive_dir.exists() {
        return Err(error::invalid_input("archive directory does not exis"));
    }
    if !archive_dir.is_dir() {
        return Err(error::invalid_input("archive path is not a directory"));
    }

    let header_path = archive_dir.join(ARCHIVE_HEADER_FILE_NAME);

    if !header_path.exists() {
        return Err(error::corrupt_archive("missing archive header"));
    }

    format::read_header(&header_path)?;

    Ok(ArchiveLayout {
        archive_dir: archive_dir.to_path_buf(),
        header_path,
    })
}

pub fn random_archive_file_name() -> String {
    let id: String = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    format!("{id}.bin")
}
