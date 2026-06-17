# 测试覆盖分析

## 概览

- 测试总数：111
- 全部通过，0 失败
- 验证命令：`cargo test`、`cargo clippy --all-targets -- -D warnings`、`cargo fmt --check`

## 测试文件分布

| 测试文件 | 数量 | 覆盖范围 |
|---------|------|---------|
| `archive_format.rs` | 5 | header 读写往返、未知版本拒绝、manifest JSON 序列化、layout 创建、随机文件名 |
| `chunk_split.rs` | 9 | 分片拆分/合并往返、大小数据、空输入、乱序重组、非连续拒绝 |
| `cli_smoke.rs` | 6 | 端到端 roundtrip：单文件、空文件、嵌套目录、特殊字符、二进制、大文件多分片 |
| `content_fingerprint.rs` | 6 | 指纹稳定性、路径无关、内容/文件名/目录结构变化检测 |
| `cross_platform_paths.rs` | 4 | manifest 用 `/` 分隔符、路径穿越防护、嵌套路径往返、绝对路径拒绝 |
| `crypto_roundtrip.rs` | 20 | 密钥派生、AEAD 加解密、chunk AAD 绑定、recovery code 解析、nonce 唯一性 |
| `encrypt_decrypt_roundtrip.rs` | 3 | 完整 encrypt→decrypt 往返、嵌套目录、错误密码无残留 |
| `encrypt_smoke.rs` | 1 | 单文件加密端到端流程 |
| `erasure_params.rs` | 7 | 纠删码参数计算、编码重建往返、超量丢失失败、最大允许恢复 |
| `error_cases.rs` | 10 | 错误密码、无残留、损坏 manifest/chunk、缺失 chunk/header、未知版本、去重拒绝、forget 后重加密、无索引可解密 |
| `index_commands.rs` | 9 | list 空库/有记录、forget by id/fp/不存在/重新插入、find_by_target |
| `index_dedup.rs` | 3 | 指纹去重、不同内容不同指纹、不存在返回 None |
| `index_metadata.rs` | 7 | 元数据 title/note/tags/custom/thumbnail 更新、不存在报错、按 fingerprint 更新 |
| `privacy_leak_check.rs` | 4 | 文件名不泄漏、目录结构不泄漏、chunk 文件名随机、密文不含明文 |
| `repair_recovers_damage.rs` | 3 | 缺失 shard 修复、corrupt shard 修复后可解密、超冗余失败 |
| `source_pack.rs` | 5 | 单文件/目录打包、特殊字符、绝对路径不泄露、扫描后大小变化检测 |
| `source_scan.rs` | 4 | 单文件扫描、目录排序、特殊字符、缺失路径报错 |
| `verify_detects_corruption.rs` | 5 | 健康归档、缺失 shard、bit flip、可修复/不可修复判断 |

## 按模块覆盖

### archive（格式与布局）
- header 二进制格式读写往返
- 未知版本号拒绝并返回稳定错误
- manifest JSON 序列化/反序列化
- 归档目录创建和打开
- 随机文件名生成格式验证

### crypto（密钥与加密）
- Argon2id 密钥派生：同输入同输出、不同 salt 不同 key
- 无效 KDF 参数拒绝
- XChaCha20-Poly1305 AEAD 加解密往返
- 密文篡改检测（bit flip）
- 错误 AAD 拒绝
- 每次加密使用不同 nonce
- chunk 级加解密：AAD 绑定 archive_id + version + index
- recovery code 生成、解析、whitespace trim、错误格式拒绝

### chunks（分片与纠删码）
- 数据拆分与合并往返（小/大/空/单字节）
- 分片等长验证
- 乱序分片可重组
- 非连续 index 拒绝
- Reed-Solomon 编码与重建往返
- 超量丢失稳定失败
- 最大允许丢失恢复成功

### fs（扫描、打包、还原）
- 单文件和目录递归扫描
- 相对路径规范化（`/` 分隔符）
- 特殊字符文件名保留
- 缺失源路径报错
- 明文打包格式往返
- 绝对路径不泄露到打包数据
- 扫描后文件大小变化检测
- 还原时路径穿越防护（绝对路径、`..` 组件）

### index（本地索引）
- SQLite 打开/迁移
- 记录插入、查询、列表
- 指纹唯一约束（去重）
- 按 archive_id 或 fingerprint 前缀删除
- 按前缀查找
- 元数据更新（title/note/tags/custom/thumbnail）
- 不存在记录报错

### 集成（端到端）
- encrypt → decrypt 内容 hash 一致
- 空文件、嵌套目录、特殊字符、二进制、大文件 roundtrip
- 错误密码返回认证错误且无残留文件
- 损坏 manifest / chunk 返回错误
- 缺失文件返回错误
- 未知版本返回错误
- verify 检测健康/损坏/缺失
- repair 恢复损坏并可后续解密
- 归档不泄漏原始信息（文件名、目录结构、明文内容）

## 未覆盖 / 薄弱点

| 场景 | 原因 |
|------|------|
| CLI 二进制集成测试（通过 `cargo run` 跑完整命令） | 需要交互式密码输入，无法在普通测试中模拟 |
| 并发 / 多线程安全 | 当前设计为单线程顺序执行 |
| 超大文件（>可用内存） | v1 设计不支持流式处理，此为已知限制 |
| Windows / macOS 平台 | 仅在 Linux 验证，路径逻辑已用 `/` 统一但未实机测试 |
| 索引跨进程持久性 | 测试在单进程内完成，未模拟重启后读取 |
| recovery code 解密路径 | crypto 层有单元测试，但命令层已移除该功能（v1 不支持） |
| `meta thumbnail` 完整流程 | 有元数据字段测试，但未测真实图片文件拷贝 |
| 符号链接处理 | 扫描时未明确测试符号链接行为 |
| 磁盘空间不足时的行为 | 未测试写入失败的错误处理 |

## 测试辅助设施

共享 helpers 位于 `tests/common/mod.rs`：

- `TempWorkspace` — 自动清理的临时目录
- `write_file` — 自动创建父目录并写入
- `hash_tree` — BLAKE3 递归哈希整个目录树
- `run_crypax` / `run_crypax_with_stdin` — 执行编译好的二进制
- `encrypt_to_archive` — 库级别完整加密流程
- `decrypt_archive` — 库级别完整解密流程
- `corrupt_one_archive_file` — 翻转一个 .bin 文件的最后一字节
- `remove_n_archive_files` — 删除 n 个分片文件
- `assert_no_name_leaks` — 检查归档目录中无禁止模式泄漏
