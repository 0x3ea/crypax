use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use crypax::archive::{
    format::{self, ARCHIVE_FORMAT_VERSION, ARCHIVE_MAGIC, ArchiveHeader},
    layout::{self, ARCHIVE_HEADER_FILE_NAME},
    manifest::{
        self, ErasureParams, ManifestChunkEntry, ManifestFileEntry, PlainManifest, RootKind,
    },
};

#[test]
fn writes_and_reads_archive_header() {
    let temp = TempDir::new("header-roundtrip");
    let header_path = temp.path().join(ARCHIVE_HEADER_FILE_NAME);
    let header = ArchiveHeader {
        version: ARCHIVE_FORMAT_VERSION,
        salt: vec![1, 2, 3, 4],
        encrypted_manifest: vec![5, 6, 7, 8, 9],
    };

    format::write_header(&header_path, &header).expect("write header");

    let decoded = format::read_header(&header_path).expect("read header");
    assert_eq!(decoded.version, header.version);
    assert_eq!(decoded.salt, header.salt);
    assert_eq!(decoded.encrypted_manifest, header.encrypted_manifest);
}

#[test]
fn rejects_unknown_archive_version() {
    let temp = TempDir::new("unknown-version");
    let header_path = temp.path().join(ARCHIVE_HEADER_FILE_NAME);
    write_raw_header(&header_path, 999, &[], &[]);

    let err = match format::read_header(&header_path) {
        Ok(_) => panic!("unsupported version should fail"),
        Err(err) => err,
    };

    assert_eq!(err.to_string(), "unsupported archive format version: 999");
}

#[test]
fn roundtrips_plain_manifest_json() {
    let manifest = PlainManifest {
        format_version: ARCHIVE_FORMAT_VERSION,
        archive_id: "archive-001".to_string(),
        created_at: 1_717_171_717,
        root_kind: RootKind::Directory,
        files: vec![ManifestFileEntry {
            path: "docs/readme.txt".to_string(),
            size: 42,
            modified_at: Some(1_717_171_700),
            chunks: vec!["chunk-001".to_string()],
        }],
        chunks: vec![ManifestChunkEntry {
            id: "chunk-001".to_string(),
            file_name: "random-name.bin".to_string(),
            size: 128,
            plaintext_offset: 0,
            plaintext_size: 42,
        }],
        erasure: ErasureParams {
            data_shards: 10,
            parity_shards: 2,
            redundancy_percent: 20,
        },
        total_packed_size: 42,
    };

    let encoded = manifest::encode_plain_manifest(&manifest).expect("encode manifest");
    let decoded = manifest::decode_plain_manifest(&encoded).expect("decode manifest");

    assert_eq!(decoded, manifest);
}

#[test]
fn creates_and_opens_archive_layout() {
    let temp = TempDir::new("layout");
    let archive_dir = temp.path().join("archive");

    let created = layout::create_archive_dir(&archive_dir).expect("create archive dir");
    assert_eq!(created.archive_dir, archive_dir);
    assert_eq!(
        created.header_path,
        created.archive_dir.join(ARCHIVE_HEADER_FILE_NAME)
    );

    let header = ArchiveHeader {
        version: ARCHIVE_FORMAT_VERSION,
        salt: Vec::new(),
        encrypted_manifest: Vec::new(),
    };
    format::write_header(&created.header_path, &header).expect("write archive header");

    let opened = layout::open_archive_dir(&archive_dir).expect("open archive dir");
    assert_eq!(opened.archive_dir, archive_dir);
    assert_eq!(opened.header_path, created.header_path);
}

#[test]
fn random_archive_file_name_uses_safe_opaque_bin_name() {
    let first = layout::random_archive_file_name();
    let second = layout::random_archive_file_name();

    assert_ne!(first, second);
    assert_random_bin_name(&first);
    assert_random_bin_name(&second);
    assert!(!first.contains("source"));
    assert!(!first.contains("txt"));
    assert!(!first.contains('/'));
    assert!(!first.contains('\\'));
}

fn assert_random_bin_name(name: &str) {
    let stem = name
        .strip_suffix(".bin")
        .expect("random name should end in .bin");
    assert_eq!(stem.len(), 32);
    assert!(stem.chars().all(|ch| ch.is_ascii_alphanumeric()));
}

fn write_raw_header(path: &Path, version: u16, salt: &[u8], encrypted_manifest: &[u8]) {
    let mut file = fs::File::create(path).expect("create raw header");
    let salt_len: u16 = salt.len().try_into().expect("salt length should fit u16");
    let manifest_len: u32 = encrypted_manifest
        .len()
        .try_into()
        .expect("manifest length should fit u32");

    file.write_all(ARCHIVE_MAGIC).expect("write magic");
    file.write_all(&version.to_le_bytes())
        .expect("write version");
    file.write_all(&salt_len.to_le_bytes())
        .expect("write salt length");
    file.write_all(&manifest_len.to_le_bytes())
        .expect("write manifest length");
    file.write_all(salt).expect("write salt");
    file.write_all(encrypted_manifest)
        .expect("write encrypted manifest");
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(name: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after unix epoch")
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("crypax-{name}-{}-{unique}", std::process::id()));
        fs::create_dir(&path).expect("create temp dir");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
