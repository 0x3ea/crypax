use std::{
    fs::File,
    io::{BufReader, BufWriter, Read, Write},
    path::Path,
};

use crate::error::{self, Result};

pub const ARCHIVE_MAGIC: &[u8] = b"CRYPAX\0";
pub const ARCHIVE_FORMAT_VERSION: u16 = 1;

#[derive(Debug)]
pub struct ArchiveHeader {
    pub version: u16,
    pub salt: Vec<u8>,
    pub encrypted_manifest: Vec<u8>,
}

pub fn ensure_supported_version(version: u16) -> Result<()> {
    if version != 1 {
        return Err(error::unsupported_archive_version(version));
    }
    Ok(())
}

pub fn write_header(path: &Path, header: &ArchiveHeader) -> Result<()> {
    ensure_supported_version(header.version)?;

    let salt_len: u16 = header
        .salt
        .len()
        .try_into()
        .map_err(|_| error::invalid_input("archive salt is too large"))?;

    let manifest_len: u32 = header
        .encrypted_manifest
        .len()
        .try_into()
        .map_err(|_| error::invalid_input("encrypted manifest is too large"))?;

    let file = File::create(path)?;
    let mut writer = BufWriter::new(file);

    writer.write_all(ARCHIVE_MAGIC)?;
    writer.write_all(&header.version.to_le_bytes())?;
    writer.write_all(&salt_len.to_le_bytes())?;

    writer.write_all(&manifest_len.to_le_bytes())?;
    writer.write_all(&header.salt)?;
    writer.write_all(&header.encrypted_manifest)?;
    Ok(())
}

pub fn read_header_with_fallback(path: &Path) -> Result<ArchiveHeader> {
    let candidates = [
        "crypax.archive",
        "crypax.archive.bak.1",
        "crypax.archive.bak.2",
    ];

    for name in candidates {
        let archive_path = path.join(name);
        if let Ok(header) = read_header(&archive_path) {
            return Ok(header);
        }
    }

    Err(error::corrupt_archive("no archive found"))
}

fn read_header(path: &Path) -> Result<ArchiveHeader> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut magic = vec![0_u8; ARCHIVE_MAGIC.len()];
    reader.read_exact(&mut magic)?;

    if magic != ARCHIVE_MAGIC {
        return Err(error::corrupt_archive("invalid archive magic"));
    }

    let version = read_u16_le(&mut reader)?;
    ensure_supported_version(version)?;

    let salt_len = read_u16_le(&mut reader)? as usize;
    let manifest_len = read_u32_le(&mut reader)? as usize;

    let mut salt = vec![0_u8; salt_len];
    reader.read_exact(&mut salt)?;

    let mut encrypted_manifest = vec![0_u8; manifest_len];
    reader.read_exact(&mut encrypted_manifest)?;

    Ok(ArchiveHeader {
        version,
        salt,
        encrypted_manifest,
    })
}

fn read_u16_le(reader: &mut impl Read) -> Result<u16> {
    let mut bytes = [0_u8; 2];
    reader.read_exact(&mut bytes)?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_u32_le(reader: &mut impl Read) -> Result<u32> {
    let mut bytes = [0_u8; 4];
    reader.read_exact(&mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn rejects_unknown_archive_version() {
        let dir =
            std::env::temp_dir().join(format!("crypax-format-version-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let header_path = dir.join("crypax.archive");

        let mut file = fs::File::create(&header_path).unwrap();
        file.write_all(ARCHIVE_MAGIC).unwrap();
        file.write_all(&999u16.to_le_bytes()).unwrap();
        file.write_all(&0u16.to_le_bytes()).unwrap();
        file.write_all(&0u32.to_le_bytes()).unwrap();
        drop(file);

        let err = read_header(&header_path).unwrap_err();
        assert_eq!(err.to_string(), "unsupported archive format version: 999");

        let _ = fs::remove_dir_all(&dir);
    }
}
