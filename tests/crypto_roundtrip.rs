use crypax::crypto::aead::{decrypt_blob, decrypt_segment, encrypt_blob, encrypt_segment};
use crypax::crypto::keys::{
    ARCHIVE_KEY_LEN, ArchiveKey, KEY_SALT_LEN, KdfParams, KeySalt, derive_archive_key,
    generate_salt,
};
use crypax::crypto::recovery::{
    derive_key_from_recovery, generate_recovery_code, parse_recovery_code,
};

#[test]
fn derives_same_archive_key_for_same_password_salt_and_params() {
    let params = test_kdf_params();
    let salt = KeySalt::from_bytes([7; KEY_SALT_LEN]);

    let first = derive_archive_key("correct horse battery staple", &salt, &params)
        .expect("derive first archive key");
    let second = derive_archive_key("correct horse battery staple", &salt, &params)
        .expect("derive second archive key");

    assert_eq!(first.as_bytes(), second.as_bytes());
}

#[test]
fn derives_different_archive_keys_for_different_salts() {
    let params = test_kdf_params();
    let first_salt = KeySalt::from_bytes([1; KEY_SALT_LEN]);
    let second_salt = KeySalt::from_bytes([2; KEY_SALT_LEN]);

    let first = derive_archive_key("same password", &first_salt, &params)
        .expect("derive first archive key");
    let second = derive_archive_key("same password", &second_salt, &params)
        .expect("derive second archive key");

    assert_ne!(first.as_bytes(), second.as_bytes());
}

#[test]
fn rejects_invalid_kdf_params_without_returning_a_key() {
    let salt = KeySalt::from_bytes([3; KEY_SALT_LEN]);
    let invalid_params = KdfParams {
        memory_cost_kib: 1,
        time_cost: 1,
        parallelism: 1,
    };

    let err = match derive_archive_key("password", &salt, &invalid_params) {
        Ok(_) => panic!("invalid KDF params should fail"),
        Err(err) => err,
    };

    assert!(err.to_string().contains("invalid KDF params"));
}

#[test]
fn generated_salts_have_expected_length_and_vary() {
    let first = generate_salt();
    let second = generate_salt();

    assert_eq!(first.as_bytes().len(), KEY_SALT_LEN);
    assert_eq!(second.as_bytes().len(), KEY_SALT_LEN);
    assert_ne!(first, second);
}

#[test]
fn archive_key_wraps_exact_key_length() {
    let key = ArchiveKey::from_bytes([9; ARCHIVE_KEY_LEN]);

    assert_eq!(key.as_bytes(), &[9; ARCHIVE_KEY_LEN]);
}

#[test]
fn encrypts_and_decrypts_blob_with_aad() {
    let key = test_archive_key();
    let plaintext = b"packed source bytes";
    let aad = b"archive-001:chunk-0001";

    let blob = encrypt_blob(&key, plaintext, aad).expect("encrypt blob");
    let decrypted = decrypt_blob(&key, &blob, aad).expect("decrypt blob");

    assert_eq!(decrypted, plaintext);
    assert_ne!(blob.ciphertext, plaintext);
}

#[test]
fn decrypt_rejects_modified_ciphertext() {
    let key = test_archive_key();
    let aad = b"archive-001:chunk-0001";
    let mut blob = encrypt_blob(&key, b"authenticated plaintext", aad).expect("encrypt blob");
    blob.ciphertext[0] ^= 0b0000_0001;

    let err = match decrypt_blob(&key, &blob, aad) {
        Ok(_) => panic!("modified ciphertext should fail authentication"),
        Err(err) => err,
    };

    assert_eq!(err.to_string(), "corrupt archive: authentication failed");
}

#[test]
fn decrypt_rejects_wrong_aad() {
    let key = test_archive_key();
    let blob = encrypt_blob(&key, b"authenticated plaintext", b"archive-001:chunk-0001")
        .expect("encrypt blob");

    let err = match decrypt_blob(&key, &blob, b"archive-001:chunk-0002") {
        Ok(_) => panic!("wrong AAD should fail authentication"),
        Err(err) => err,
    };

    assert_eq!(err.to_string(), "corrupt archive: authentication failed");
}

#[test]
fn encrypt_uses_fresh_nonce_for_each_blob() {
    let key = test_archive_key();
    let aad = b"archive-001:chunk-0001";

    let first = encrypt_blob(&key, b"same plaintext", aad).expect("encrypt first blob");
    let second = encrypt_blob(&key, b"same plaintext", aad).expect("encrypt second blob");

    assert_ne!(first.nonce, second.nonce);
    assert_ne!(first.ciphertext, second.ciphertext);
}

// --- encrypt_chunk / decrypt_chunk ---

#[test]
fn encrypts_and_decrypts_chunk_roundtrip() {
    let key = test_archive_key();
    let data = b"chunk payload data here";
    let archive_id = b"archive-001";

    let blob = encrypt_segment(&key, data, 0, archive_id, 1).expect("encrypt chunk");
    let decrypted = decrypt_segment(&key, &blob, 0, archive_id, 1).expect("decrypt chunk");

    assert_eq!(decrypted, data);
}

#[test]
fn decrypt_chunk_rejects_wrong_chunk_index() {
    let key = test_archive_key();
    let blob = encrypt_segment(&key, b"payload", 5, b"arc", 1).expect("encrypt chunk");

    let result = decrypt_segment(&key, &blob, 6, b"arc", 1);
    assert!(result.is_err());
}

#[test]
fn decrypt_chunk_rejects_wrong_archive_id() {
    let key = test_archive_key();
    let blob = encrypt_segment(&key, b"payload", 0, b"archive-A", 1).expect("encrypt chunk");

    let result = decrypt_segment(&key, &blob, 0, b"archive-B", 1);
    assert!(result.is_err());
}

#[test]
fn decrypt_chunk_rejects_wrong_format_version() {
    let key = test_archive_key();
    let blob = encrypt_segment(&key, b"payload", 0, b"arc", 1).expect("encrypt chunk");

    let result = decrypt_segment(&key, &blob, 0, b"arc", 2);
    assert!(result.is_err());
}

// --- recovery code ---

#[test]
fn generate_and_parse_recovery_code_roundtrip() {
    let (code, _secret) = generate_recovery_code().expect("generate recovery code");

    let parsed = parse_recovery_code(code.as_str()).expect("parse recovery code");
    assert_eq!(parsed, code);
}

#[test]
fn parse_recovery_code_trims_whitespace() {
    let (code, _) = generate_recovery_code().expect("generate");
    let padded = format!("  {}  \n", code.as_str());

    let parsed = parse_recovery_code(&padded).expect("parse padded");
    assert_eq!(parsed, code);
}

#[test]
fn parse_recovery_code_rejects_missing_prefix() {
    let result = parse_recovery_code("AABBCCDD");
    assert!(result.is_err());
}

#[test]
fn parse_recovery_code_rejects_invalid_base32() {
    let result = parse_recovery_code("crypax-r1-!!!invalid!!!");
    assert!(result.is_err());
}

#[test]
fn parse_recovery_code_rejects_wrong_length() {
    let result = parse_recovery_code("crypax-r1-MFRA");
    assert!(result.is_err());
}

#[test]
fn derive_key_from_recovery_produces_consistent_key() {
    let (code, _) = generate_recovery_code().expect("generate");
    let salt = KeySalt::from_bytes([11; KEY_SALT_LEN]);

    let key1 = derive_key_from_recovery(&code, &salt).expect("derive first");
    let key2 = derive_key_from_recovery(&code, &salt).expect("derive second");

    assert_eq!(key1.as_bytes(), key2.as_bytes());
}

#[test]
fn derive_key_from_recovery_differs_with_different_salt() {
    let (code, _) = generate_recovery_code().expect("generate");
    let salt1 = KeySalt::from_bytes([1; KEY_SALT_LEN]);
    let salt2 = KeySalt::from_bytes([2; KEY_SALT_LEN]);

    let key1 = derive_key_from_recovery(&code, &salt1).expect("derive first");
    let key2 = derive_key_from_recovery(&code, &salt2).expect("derive second");

    assert_ne!(key1.as_bytes(), key2.as_bytes());
}

fn test_kdf_params() -> KdfParams {
    KdfParams {
        memory_cost_kib: 8,
        time_cost: 1,
        parallelism: 1,
    }
}

fn test_archive_key() -> ArchiveKey {
    ArchiveKey::from_bytes([42; ARCHIVE_KEY_LEN])
}
