mod common;

use std::fs;

use common::{TempWorkspace, decrypt_archive, encrypt_to_archive, hash_tree, write_file};

#[test]
fn roundtrip_single_file_content_matches() {
    let ws = TempWorkspace::new("cli-single");
    let source = ws.path.join("hello.txt");
    write_file(&source, b"hello world");

    let archive_dir = ws.path.join("archive");
    let restore_dir = ws.path.join("restored");
    fs::create_dir(&restore_dir).unwrap();

    encrypt_to_archive(&source, &archive_dir, "test-pw");
    decrypt_archive(&archive_dir, &restore_dir, "test-pw").unwrap();

    assert_eq!(
        fs::read(restore_dir.join("hello.txt")).unwrap(),
        b"hello world"
    );
}

#[test]
fn roundtrip_empty_file() {
    let ws = TempWorkspace::new("cli-empty");
    let source = ws.path.join("empty.bin");
    write_file(&source, b"");

    let archive_dir = ws.path.join("archive");
    let restore_dir = ws.path.join("restored");
    fs::create_dir(&restore_dir).unwrap();

    encrypt_to_archive(&source, &archive_dir, "pw");
    decrypt_archive(&archive_dir, &restore_dir, "pw").unwrap();

    assert_eq!(fs::read(restore_dir.join("empty.bin")).unwrap(), b"");
}

#[test]
fn roundtrip_nested_directory_tree() {
    let ws = TempWorkspace::new("cli-nested");
    let src_dir = ws.path.join("project");
    write_file(&src_dir.join("README.md"), b"# Hello");
    write_file(&src_dir.join("src/main.rs"), b"fn main() {}");
    write_file(&src_dir.join("src/lib/util.rs"), b"pub fn x() {}");
    write_file(&src_dir.join("data/empty.dat"), b"");

    let archive_dir = ws.path.join("archive");
    let restore_dir = ws.path.join("restored");
    fs::create_dir(&restore_dir).unwrap();

    encrypt_to_archive(&src_dir, &archive_dir, "nested-pw");
    decrypt_archive(&archive_dir, &restore_dir, "nested-pw").unwrap();

    assert_eq!(hash_tree(&src_dir), hash_tree(&restore_dir));
}

// PLACEHOLDER_MORE_TESTS

#[test]
fn roundtrip_special_characters_in_filenames() {
    let ws = TempWorkspace::new("cli-special");
    let src_dir = ws.path.join("special");
    write_file(&src_dir.join("spaces in name.txt"), b"space");
    write_file(&src_dir.join("日本語.txt"), b"unicode");
    write_file(
        &src_dir.join("file-with-dashes_and_underscores.log"),
        b"mixed",
    );

    let archive_dir = ws.path.join("archive");
    let restore_dir = ws.path.join("restored");
    fs::create_dir(&restore_dir).unwrap();

    encrypt_to_archive(&src_dir, &archive_dir, "special-pw");
    decrypt_archive(&archive_dir, &restore_dir, "special-pw").unwrap();

    assert_eq!(hash_tree(&src_dir), hash_tree(&restore_dir));
}

#[test]
fn roundtrip_binary_content() {
    let ws = TempWorkspace::new("cli-binary");
    let source = ws.path.join("random.bin");
    let data: Vec<u8> = (0..=255).cycle().take(4096).collect();
    write_file(&source, &data);

    let archive_dir = ws.path.join("archive");
    let restore_dir = ws.path.join("restored");
    fs::create_dir(&restore_dir).unwrap();

    encrypt_to_archive(&source, &archive_dir, "bin-pw");
    decrypt_archive(&archive_dir, &restore_dir, "bin-pw").unwrap();

    assert_eq!(fs::read(restore_dir.join("random.bin")).unwrap(), data);
}

#[test]
fn roundtrip_large_file_multiple_shards() {
    let ws = TempWorkspace::new("cli-large");
    let source = ws.path.join("big.dat");
    let data = vec![0xABu8; 512 * 1024];
    write_file(&source, &data);

    let archive_dir = ws.path.join("archive");
    let restore_dir = ws.path.join("restored");
    fs::create_dir(&restore_dir).unwrap();

    encrypt_to_archive(&source, &archive_dir, "large-pw");
    decrypt_archive(&archive_dir, &restore_dir, "large-pw").unwrap();

    assert_eq!(fs::read(restore_dir.join("big.dat")).unwrap(), data);
}
