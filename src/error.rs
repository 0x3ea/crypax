pub type Result<T> = anyhow::Result<T>;

pub fn invalid_input(message: impl std::fmt::Display) -> anyhow::Error {
    anyhow::anyhow!("invalid input: {message}")
}

pub fn unsupported_archive_version(found: u16) -> anyhow::Error {
    anyhow::anyhow!("unsupported archive format version: {found}")
}

pub fn wrong_password_or_recovery_code() -> anyhow::Error {
    anyhow::anyhow!("wrong password or recovery code")
}

pub fn corrupt_archive(message: impl std::fmt::Display) -> anyhow::Error {
    anyhow::anyhow!("corrupt archive: {message}")
}

pub fn index_error(message: impl std::fmt::Display) -> anyhow::Error {
    anyhow::anyhow!("index error: {message}")
}

pub fn duplicate_content(fingerprint: impl std::fmt::Display) -> anyhow::Error {
    anyhow::anyhow!("content already encrypted: {fingerprint}")
}

pub fn not_implemented(feature: &'static str) -> anyhow::Error {
    anyhow::anyhow!("not implemented yet: {feature}")
}
