# 命令工作流程文档

本文档描述每个 CLI 命令的执行流程及调用的核心函数。

---

## encrypt

**用途**：将文件或目录加密为匿名归档分片。

**命令**：`crypax encrypt <source> <output_dir>`

**入口**：`src/commands/encrypt.rs::run()`

| 步骤 | 描述 | 调用函数 | 所在模块 |
|------|------|---------|---------|
| 1 | 读取密码（交互输入两次确认） | `rpassword::prompt_password()` | 外部 crate |
| 2 | 递归扫描源文件/目录 | `fs::scan::scan_source()` | `src/fs/scan.rs` |
| 3 | 计算内容指纹 | `fs::pack::compute_content_fingerprint()` | `src/fs/pack.rs` |
| 4 | 打开索引并检查去重 | `IndexDb::open_default()` | `src/index/db.rs` |
|   |  | `IndexDb::find_by_fingerprint()` | `src/index/db.rs` |
| 5 | 将源文件打包为字节流 | `fs::pack::pack_source()` | `src/fs/pack.rs` |
| 6 | 生成盐并派生加密密钥 | `crypto::keys::generate_salt()` | `src/crypto/keys.rs` |
|   |  | `crypto::keys::derive_archive_key()` | `src/crypto/keys.rs` |
| 7 | 按大小拆分为数据分片 | `chunks::split::plan_chunks()` | `src/chunks/split.rs` |
|   |  | `chunks::split::split_into_data_shards()` | `src/chunks/split.rs` |
| 8 | 生成 Reed-Solomon 校验分片 | `chunks::erasure::plan_erasure()` | `src/chunks/erasure.rs` |
|   |  | `chunks::erasure::encode_recovery_shards()` | `src/chunks/erasure.rs` |
| 9 | 加密所有分片（data + parity） | `crypto::aead::encrypt_chunk()` | `src/crypto/aead.rs` |
| 10 | 构建明文 manifest | `build_plain_manifest()` | `src/commands/encrypt.rs` |
| 11 | 序列化并加密 manifest | `archive::manifest::encode_plain_manifest()` | `src/archive/manifest.rs` |
|    |  | `crypto::aead::encrypt_blob()` | `src/crypto/aead.rs` |
| 12 | 写出归档文件 | `write_encrypted_archive()` | `src/commands/encrypt.rs` |
|    | - 写 header 文件 | `archive::format::write_header()` | `src/archive/format.rs` |
|    | - 写各分片 .bin 文件 | `std::fs::write()` | 标准库 |
| 13 | 记录到本地索引 | `IndexDb::insert_record()` | `src/index/db.rs` |

**输出目录结构**：
```
output_dir/
  <archive_id前8位>/
    crypax.archive        # header（magic + version + salt + encrypted manifest）
    <random>.bin          # 加密后的数据分片
    <random>.bin          # 加密后的校验分片
    ...
```

---

## decrypt

**用途**：解密归档，还原为原始文件/目录。

**命令**：`crypax decrypt <archive_dir> <output_dir>`

**入口**：`src/commands/decrypt.rs::run()`

| 步骤 | 描述 | 调用函数 | 所在模块 |
|------|------|---------|---------|
| 1 | 读取密码 | `rpassword::prompt_password()` | 外部 crate |
| 2 | 读取 header 文件 | `archive::format::read_header()` | `src/archive/format.rs` |
| 3 | 从密码派生密钥 | `crypto::keys::unlock_archive_key()` | `src/crypto/keys.rs` |
| 4 | 解密 manifest | `archive::manifest::decrypt_manifest()` | `src/archive/manifest.rs` |
| 5 | 解密数据分片 | `decrypt_data_shards()` | `src/commands/decrypt.rs` |
|   | - 读取每个 chunk 文件 | `std::fs::read()` | 标准库 |
|   | - AEAD 解密 | `crypto::aead::decrypt_chunk()` | `src/crypto/aead.rs` |
| 6 | 合并分片为打包字节流 | `chunks::split::join_data_shards()` | `src/chunks/split.rs` |
| 7 | 还原为文件/目录 | `fs::restore::restore_packed_source()` | `src/fs/restore.rs` |

---

## verify

**用途**：检查归档完整性，报告缺失或损坏的分片。

**命令**：`crypax verify <archive_dir>`

**入口**：`src/commands/verify.rs::run()`

| 步骤 | 描述 | 调用函数 | 所在模块 |
|------|------|---------|---------|
| 1 | 读取密码 | `rpassword::prompt_password()` | 外部 crate |
| 2 | 读取 header | `archive::format::read_header()` | `src/archive/format.rs` |
| 3 | 派生密钥 | `crypto::keys::unlock_archive_key()` | `src/crypto/keys.rs` |
| 4 | 解密 manifest | `archive::manifest::decrypt_manifest()` | `src/archive/manifest.rs` |
| 5 | 逐片校验 | `verify_archive()` | `src/commands/verify.rs` |
|   | - 检查文件是否存在 | `Path::exists()` | 标准库 |
|   | - 检查文件大小 | `fs::read()` + 长度比较 | 标准库 |
|   | - 尝试 AEAD 解密 | `crypto::aead::decrypt_chunk()` | `src/crypto/aead.rs` |

**输出**：`VerifyReport`，含 `findings` 列表（`MissingShard` 或 `CorruptShard`）。

---

## repair

**用途**：利用 Reed-Solomon 冗余修复损坏或缺失的分片。

**命令**：`crypax repair <archive_dir>`

**入口**：`src/commands/repair.rs::run()`

| 步骤 | 描述 | 调用函数 | 所在模块 |
|------|------|---------|---------|
| 1 | 读取密码 | `rpassword::prompt_password()` | 外部 crate |
| 2 | 读取 header | `archive::format::read_header()` | `src/archive/format.rs` |
| 3 | 派生密钥 | `crypto::keys::unlock_archive_key()` | `src/crypto/keys.rs` |
| 4 | 解密 manifest | `archive::manifest::decrypt_manifest()` | `src/archive/manifest.rs` |
| 5 | 收集可用分片（解密成功为 Some，失败为 None） | `collect_available_shards()` | `src/commands/repair.rs` |
|   |  | `crypto::aead::decrypt_chunk()` | `src/crypto/aead.rs` |
| 6 | 检查损坏数量是否可修复 | 比较 `damaged_count` 与 `parity_shards` | — |
| 7 | Reed-Solomon 重建 | `reconstruct_missing_or_corrupt()` | `src/commands/repair.rs` |
|   |  | `ReedSolomon::reconstruct()` | 外部 crate |
| 8 | 重新加密并写回修复的分片 | `write_recovered_shards()` | `src/commands/repair.rs` |
|   |  | `crypto::aead::encrypt_chunk()` | `src/crypto/aead.rs` |
|   | - 写临时文件后原子 rename | `fs::write()` + `fs::rename()` | 标准库 |
| 9 | 修复后重新校验 | `reverify_after_repair()` | `src/commands/repair.rs` |
|   |  | `verify::verify_archive()` | `src/commands/verify.rs` |

---

## list

**用途**：列出本地索引中所有已知归档。

**命令**：`crypax list`

**入口**：`src/commands/list.rs::run()`

| 步骤 | 描述 | 调用函数 | 所在模块 |
|------|------|---------|---------|
| 1 | 打开默认索引 | `IndexDb::open_default()` | `src/index/db.rs` |
| 2 | 查询所有记录 | `IndexDb::list_records()` | `src/index/db.rs` |
| 3 | 格式化输出 | `format_record()` | `src/commands/list.rs` |

**输出格式**：`<id前8位> <fingerprint前12位> <path> <date> <title>`

---

## forget

**用途**：从本地索引中移除归档记录（不删除归档文件）。

**命令**：`crypax forget <target>`

**入口**：`src/commands/forget.rs::run()`

| 步骤 | 描述 | 调用函数 | 所在模块 |
|------|------|---------|---------|
| 1 | 打开默认索引 | `IndexDb::open_default()` | `src/index/db.rs` |
| 2 | 按前缀删除记录 | `IndexDb::delete_by_target()` | `src/index/db.rs` |

`target` 支持 archive_id 或 fingerprint 的前缀匹配。

---

## meta show

**用途**：显示归档的全部元数据。

**命令**：`crypax meta show <target>`

**入口**：`src/commands/meta.rs::run_show()`

| 步骤 | 描述 | 调用函数 | 所在模块 |
|------|------|---------|---------|
| 1 | 打开索引 | `IndexDb::open_default()` | `src/index/db.rs` |
| 2 | 按前缀查找记录 | `IndexDb::find_by_target()` | `src/index/db.rs` |
| 3 | 打印全部字段 | `println!()` | — |

---

## meta set

**用途**：更新归档元数据（title、note、tags、custom JSON）。

**命令**：`crypax meta set <target> [--title T] [--note N] [--tag T] [--custom JSON]`

**入口**：`src/commands/meta.rs::run_set()`

| 步骤 | 描述 | 调用函数 | 所在模块 |
|------|------|---------|---------|
| 1 | 打开索引 | `IndexDb::open_default()` | `src/index/db.rs` |
| 2 | 查找记录 | `IndexDb::find_by_target()` | `src/index/db.rs` |
| 3 | 合并元数据字段 | 直接修改 `record.metadata` | — |
| 4 | 写回索引 | `IndexDb::update_metadata()` | `src/index/db.rs` |

---

## meta thumbnail

**用途**：将图片关联为归档缩略图。

**命令**：`crypax meta thumbnail <target> <image_path>`

**入口**：`src/commands/meta.rs::run_thumbnail()`

| 步骤 | 描述 | 调用函数 | 所在模块 |
|------|------|---------|---------|
| 1 | 检查图片文件存在 | `Path::exists()` | 标准库 |
| 2 | 打开索引并查找记录 | `IndexDb::open_default()` | `src/index/db.rs` |
|   |  | `IndexDb::find_by_target()` | `src/index/db.rs` |
| 3 | 拷贝图片到 thumbnails/ | `fs::copy()` | 标准库 |
| 4 | 更新元数据中的 thumbnail 路径 | `IndexDb::update_metadata()` | `src/index/db.rs` |
