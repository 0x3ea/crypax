mod common;

use std::fs;

use common::{TempWorkspace, assert_no_name_leaks, encrypt_to_archive, write_file};

#[test]
fn archive_does_not_leak_original_file_names() {
    let ws = TempWorkspace::new("privacy-names");
    let src_dir = ws.path.join("documents");
    write_file(&src_dir.join("secret_report.pdf"), b"fake pdf content");
    write_file(&src_dir.join("passwords.txt"), b"hunter2");
    write_file(&src_dir.join("sub/vacation_photo.jpg"), b"jpeg data");

    let archive_dir = ws.path.join("archive");
    encrypt_to_archive(&src_dir, &archive_dir, "pw");

    assert_no_name_leaks(
        &archive_dir,
        &[
            "secret_report",
            "passwords",
            "vacation_photo",
            ".pdf",
            ".txt",
            ".jpg",
            "documents",
            "sub",
        ],
    );
}

#[test]
fn archive_does_not_leak_directory_structure() {
    let ws = TempWorkspace::new("privacy-dirs");
    let src_dir = ws.path.join("my_project");
    write_file(&src_dir.join("src/main.rs"), b"fn main() {}");
    write_file(&src_dir.join("config/database.yml"), b"host: localhost");
    write_file(&src_dir.join("docs/api/endpoints.md"), b"# API");

    let archive_dir = ws.path.join("archive");
    encrypt_to_archive(&src_dir, &archive_dir, "pw");

    assert_no_name_leaks(
        &archive_dir,
        &[
            "my_project",
            "src",
            "config",
            "docs",
            "api",
            "main.rs",
            "database",
            "endpoints",
            ".rs",
            ".yml",
            ".md",
        ],
    );
}

#[test]
fn archive_files_are_random_bin_names() {
    let ws = TempWorkspace::new("privacy-random");
    let source = ws.path.join("data.txt");
    write_file(&source, b"some content");

    let archive_dir = ws.path.join("archive");
    encrypt_to_archive(&source, &archive_dir, "pw");

    for entry in fs::read_dir(&archive_dir).unwrap() {
        let name = entry.unwrap().file_name().to_string_lossy().to_string();
        if name == "crypax.archive" {
            continue;
        }
        assert!(
            name.ends_with(".bin"),
            "chunk file '{}' should end with .bin",
            name
        );
        let stem = name.trim_end_matches(".bin");
        assert!(
            stem.len() >= 16,
            "chunk file name stem '{}' should be at least 16 chars (random)",
            stem
        );
        assert!(
            stem.chars().all(|c| c.is_ascii_alphanumeric()),
            "chunk file name stem '{}' should be alphanumeric",
            stem
        );
    }
}

#[test]
fn archive_content_does_not_contain_plaintext() {
    let ws = TempWorkspace::new("privacy-content");
    let src_dir = ws.path.join("secrets");
    let secret = "THIS_IS_A_VERY_UNIQUE_SECRET_STRING_12345";
    write_file(&src_dir.join("credentials.txt"), secret.as_bytes());

    let archive_dir = ws.path.join("archive");
    encrypt_to_archive(&src_dir, &archive_dir, "pw");

    for entry in fs::read_dir(&archive_dir).unwrap() {
        let entry = entry.unwrap();
        let content = fs::read(entry.path()).unwrap();
        let content_str = String::from_utf8_lossy(&content);
        assert!(
            !content_str.contains(secret),
            "archive file '{}' contains plaintext secret",
            entry.file_name().to_string_lossy()
        );
    }
}
