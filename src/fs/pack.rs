use crate::error::{self, Result};
use crate::fs::scan::{EntryKind, SourceEntry, SourceTree};
pub struct PackedSource {
    pub bytes: Vec<u8>,
}

pub fn compute_content_fingerprint(tree: &SourceTree) -> Result<String> {
    let mut entries = tree.entries.iter().collect::<Vec<_>>();

    entries.sort_by_key(|entry| &entry.relative_path);

    let mut hasher = blake3::Hasher::new();
    for entry in entries {
        update_str(&mut hasher, "path");
        update_str(&mut hasher, &entry.relative_path);

        match entry.kind {
            EntryKind::File => {
                update_str(&mut hasher, "file");
                update_u64(&mut hasher, entry.size);

                let path = tree.base_dir.join(&entry.relative_path);
                let bytes = std::fs::read(path)?;
                let file_hash = blake3::hash(&bytes);

                update_bytes(&mut hasher, file_hash.as_bytes());
            }
            EntryKind::Directory => {
                update_str(&mut hasher, "directory");
                update_u64(&mut hasher, 0);
            }
        }
    }
    Ok(hasher.finalize().to_hex().to_string())
}

pub fn pack_source(tree: &SourceTree) -> Result<PackedSource> {
    let mut bytes = Vec::new();

    bytes.extend_from_slice(b"CRYPAXPACK\0");
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&(tree.entries.len() as u32).to_le_bytes());

    let mut entries = tree.entries.iter().collect::<Vec<_>>();
    entries.sort_by_key(|entry| &entry.relative_path);

    for entry in entries {
        append_entry(&mut bytes, tree, entry)?;
    }
    Ok(PackedSource { bytes })
}

fn update_bytes(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn update_str(hasher: &mut blake3::Hasher, value: &str) {
    update_bytes(hasher, value.as_bytes());
}

fn update_u64(hasher: &mut blake3::Hasher, value: u64) {
    hasher.update(&value.to_le_bytes());
}

fn append_entry(bytes: &mut Vec<u8>, tree: &SourceTree, entry: &SourceEntry) -> Result<()> {
    match entry.kind {
        EntryKind::File => append_file_record(bytes, tree, entry),
        EntryKind::Directory => append_directory_record(bytes, entry),
    }
}
/// TODO:校验大小->校验哈希
fn append_file_record(bytes: &mut Vec<u8>, tree: &SourceTree, entry: &SourceEntry) -> Result<()> {
    let file_path = tree.base_dir.join(&entry.relative_path);
    let file_bytes = std::fs::read(file_path)?;

    if file_bytes.len() as u64 != entry.size {
        return Err(error::invalid_input("append file record"));
    }
    write_u8(bytes, 1);
    write_str(bytes, &entry.relative_path)?;
    write_u64(bytes, entry.size);
    write_bytes(bytes, &file_bytes)?;

    Ok(())
}

fn append_directory_record(bytes: &mut Vec<u8>, entry: &SourceEntry) -> Result<()> {
    write_u8(bytes, 2);
    write_str(bytes, &entry.relative_path)?;
    write_u64(bytes, 0);
    write_bytes(bytes, b"")?;
    Ok(())
}

fn write_u8(bytes: &mut Vec<u8>, value: u8) {
    bytes.push(value);
}

fn write_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn write_bytes(bytes: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    let len: u64 = value
        .len()
        .try_into()
        .map_err(|_| crate::error::invalid_input("packed field is too large"))?;

    write_u64(bytes, len);
    bytes.extend_from_slice(value);
    Ok(())
}

fn write_str(bytes: &mut Vec<u8>, value: &str) -> Result<()> {
    write_bytes(bytes, value.as_bytes())
}
