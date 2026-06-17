# crypax

将文件或文件夹加密为匿名归档分片，支持密码保护、Reed-Solomon 纠删冗余和本地元数据索引。

## 安装

```bash
cargo build --release
# 二进制位于 target/release/crypax
```

## 命令

```
crypax encrypt <source> <output_dir>   # 加密文件或目录
crypax decrypt <archive_dir> <output_dir>  # 解密归档
crypax verify <archive_dir>            # 检查归档完整性
crypax repair <archive_dir>            # 修复损坏的分片（冗余范围内）
crypax list                            # 列出所有已索引的归档
crypax forget <target>                 # 从索引中移除归档记录
crypax meta show <target>              # 显示归档元数据
crypax meta set <target> [--title T] [--note N] [--tag T]  # 更新元数据
crypax meta thumbnail <target> <image> # 关联缩略图
```

## 工作原理

1. 扫描源文件，打包为单一字节流，计算内容指纹。
2. 通过 Argon2id 从密码派生加密密钥。
3. 将打包数据拆分为数据分片，并生成 Reed-Solomon 校验分片（默认 20% 冗余）。
4. 每个分片使用 XChaCha20-Poly1305 加密（每片绑定独立 AAD）。
5. 归档写出为一个头文件（`crypax.archive`）加若干随机命名的 `.bin` 分片文件，放在 `<id>/` 子目录中。

## 隐私保证

- 归档分片文件使用随机字母数字命名，不泄露原始文件名、扩展名或目录结构。
- 分片内容完全加密，明文不会出现在归档目录中。
- 文件清单（文件列表、分片映射）加密存储在头文件内部。

## 本地索引

归档元数据存储在平台数据目录下的本地 SQLite 数据库中：

| 平台 | 路径 |
|------|------|
| Linux | `~/.local/share/crypax/` |
| macOS | `~/Library/Application Support/com.crypax.crypax/` |
| Windows | `C:\Users\<用户>\AppData\Roaming\crypax\crypax\data\` |

索引通过内容指纹防止重复加密。删除索引不影响已有归档——只要有正确的密码，归档仍可独立解密。

## 限制（v0.1）

- 不支持流式处理：打包阶段会将整个源文件加载到内存。
- 尚不支持恢复码——丢失密码则归档不可恢复。
- 不支持部分文件还原——必须解密整个归档。
- 不内置云同步或远程存储集成。

## 开发

```bash
cargo check          # 快速编译检查
cargo test           # 运行全部 111 个测试
cargo clippy --all-targets -- -D warnings  # 静态检查
cargo fmt --check    # 格式检查
```

项目文档位于 `docs/` 目录：

- `docs/workflow.md` — 每个命令的执行流程及调用的函数链路
- `docs/test.md` — 测试覆盖分析（按模块、按文件、未覆盖点）
