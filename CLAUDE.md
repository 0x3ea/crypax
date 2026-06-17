# Repository Guidelines

## 项目结构与模块组织

这是一个 Rust CLI 项目，包名为 `crypax`，将文件或文件夹加密为匿名归档分片。`src/lib.rs` 导出所有公共模块，`src/main.rs` 作为 thin binary 调用库。

- `src/main.rs`：程序入口，调用 `crypax::cli::parse()` 和 `crypax::commands::dispatch()`。
- `src/lib.rs`：库根，导出全部公共模块。
- `src/cli.rs`：基于 `clap` 的命令行参数定义与解析。
- `src/error.rs`：集中维护稳定的用户可见错误文案及 `Result<T>` 类型别名。
- `src/commands/`：每个 CLI 命令一个模块（`encrypt.rs`、`decrypt.rs`、`verify.rs`、`repair.rs`、`list.rs`、`forget.rs`、`meta.rs`），通过 `mod.rs` 分发。
- `src/archive/`：归档格式（`format.rs` header 二进制读写、`layout.rs` 目录与文件名、`manifest.rs` JSON manifest 及加解密）。
- `src/crypto/`：密钥派生（`keys.rs` Argon2id）、AEAD 加解密（`aead.rs` XChaCha20-Poly1305）、恢复码（`recovery.rs`，v1 未启用）。
- `src/fs/`：源文件扫描（`scan.rs`）、明文打包（`pack.rs`）、还原（`restore.rs`）。
- `src/chunks/`：数据分片（`split.rs`）、Reed-Solomon 纠删码（`erasure.rs`）、分片校验（`verify.rs`）。
- `src/index/`：本地 SQLite 索引（`db.rs`，支持前缀匹配查找/删除）和数据模型（`models.rs`）。
- `tests/`：111 个集成测试，`tests/common/mod.rs` 提供共享辅助函数。
- `docs/`：项目文档（`test.md` 测试覆盖分析、`workflow.md` 命令工作流程）。

## 构建、测试与开发命令

- `cargo check`：快速检查项目是否可编译。
- `cargo build`：构建 debug 版本二进制。
- `cargo run -- --help`：查看顶层 CLI 帮助。
- `cargo run -- encrypt <source> <output_dir>`：加密文件或目录，归档写入 `output_dir/<id>/`。
- `cargo test`：运行全部 111 个测试。
- `cargo clippy --all-targets -- -D warnings`：静态检查，必须零警告。
- `cargo fmt --check`：格式检查。

提交前必须通过 `cargo clippy --all-targets -- -D warnings` 和 `cargo fmt --check`。

## 编码风格与命名约定

使用 Rust 标准格式，缩进由 `cargo fmt` 处理。模块和文件名使用 `snake_case`，类型和枚举使用 `PascalCase`，函数和变量使用 `snake_case`。

保持命令模块轻量：参数定义放在 `src/cli.rs`，分发逻辑放在 `src/commands/mod.rs`，具体行为放在 `src/commands/<command>.rs`。

可失败函数优先返回 `crate::error::Result<T>`。面向用户的稳定错误文案应通过 `src/error.rs` 中的 helper 构造。

## 测试指南

使用 Rust 内置测试框架。集成测试位于 `tests/`，共享辅助函数位于 `tests/common/mod.rs`。测试命名应描述行为，例如 `roundtrip_single_file` 或 `wrong_password_returns_error`。

测试分类：
- `tests/archive_format.rs`：归档格式层单元测试。
- `tests/crypto_roundtrip.rs`：密钥派生和 AEAD 单元测试。
- `tests/chunk_split.rs`、`tests/erasure_params.rs`：分片和纠删码单元测试。
- `tests/source_scan.rs`、`tests/source_pack.rs`、`tests/content_fingerprint.rs`：文件系统层单元测试。
- `tests/cli_smoke.rs`：端到端 encrypt→decrypt roundtrip。
- `tests/error_cases.rs`：错误路径覆盖。
- `tests/privacy_leak_check.rs`：隐私泄漏检查。
- `tests/cross_platform_paths.rs`：跨平台路径处理。
- `tests/verify_detects_corruption.rs`、`tests/repair_recovers_damage.rs`：verify/repair 流程。
- `tests/index_*.rs`：索引和元数据操作。

新增测试时优先使用 `tests/common/mod.rs` 中的辅助函数（`TempWorkspace`、`encrypt_to_archive`、`decrypt_archive` 等）。

## 提交与 Pull Request 规范

提交和 Pull Request 必须严格遵守项目约定，使用明确的类型前缀，例如：

- `fix: correct decrypt argument names`
- `feat: add archive header parser`
- `docs: update test coverage`
- `test: add CLI parsing tests`

Pull Request 应包含变更摘要、已运行的验证命令，以及仍未完成的风险或缺口。只有在能帮助理解行为或失败时，才粘贴终端输出。
