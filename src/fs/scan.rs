use crate::error::{self, Result};
use std::{
    fs::Metadata,
    path::{self, Path, PathBuf},
};
use walkdir::WalkDir;

pub struct SourceTree {
    pub root: PathBuf,
    pub base_dir: PathBuf,
    pub entries: Vec<SourceEntry>,
}

pub struct SourceEntry {
    pub relative_path: String,
    pub kind: EntryKind,
    pub size: u64,
    pub permissions: BasicPermissions,
}

pub struct BasicPermissions {
    pub readonly: bool,
}
#[derive(PartialEq, Eq)]
pub enum EntryKind {
    File,
    Directory,
}
pub fn scan_source(source: &Path) -> Result<SourceTree> {
    let base_dir = if source.is_file() {
        source
            .parent()
            .ok_or_else(|| error::invalid_input("source file has no parent directory"))?
    } else {
        source
    };

    let mut source_tree = SourceTree {
        root: source.to_path_buf(),
        base_dir: base_dir.to_path_buf(),
        entries: Vec::new(),
    };
    let walker = WalkDir::new(source).into_iter();
    for entry in walker.into_iter() {
        let entry = entry?;

        let relative = entry
            .path()
            .strip_prefix(base_dir)
            .map_err(error::invalid_input)?;

        if relative.as_os_str().is_empty() {
            continue;
        }

        let metadata = entry.metadata()?;

        let source_entry = SourceEntry {
            relative_path: normalize_relative_path(relative)?,
            kind: if entry.file_type().is_file() {
                EntryKind::File
            } else if entry.file_type().is_dir() {
                EntryKind::Directory
            } else {
                return Err(error::invalid_input("unsupported source entry type"));
            },
            size: if entry.file_type().is_file() {
                metadata.len()
            } else {
                0
            },
            permissions: read_basic_permissions(&metadata),
        };

        source_tree.entries.push(source_entry);
    }

    source_tree
        .entries
        .sort_by(|left, right| left.relative_path.cmp(&right.relative_path));

    Ok(source_tree)
}

fn normalize_relative_path(path: &Path) -> Result<String> {
    let mut parts = Vec::new();

    for component in path.components() {
        match component {
            path::Component::Normal(value) => {
                let value = value
                    .to_str()
                    .ok_or_else(|| error::invalid_input("source path is not valid UTF-8"))?;
                parts.push(value.to_string());
            }
            _ => {
                return Err(error::invalid_input("invalid relative source path"));
            }
        }
    }

    if parts.is_empty() {
        return Err(error::invalid_input("empty relative source path"));
    }
    Ok(parts.join("/"))
}

fn read_basic_permissions(metadata: &Metadata) -> BasicPermissions {
    BasicPermissions {
        readonly: metadata.permissions().readonly(),
    }
}
