# Coding Runtime 对齐说明

## 当前状态

本分支按 `Khaos_Coding_Agent_Codex_Alignment_Spec.md` 完成 Phase 0～Phase 8 的首轮骨架实现。所有阶段均使用独立原子提交，未修改主工作树。

已具备：

- Task Worktree 与 ChangeSet 内容哈希绑定；
- Host ExecutionBackend 与 Docker 安全参数；
- Python/JavaScript/TypeScript/Go/Rust Legacy Registry；
- SQLite 增量代码索引与基础查询；
- 可选 stdio LSP 生命周期 client；
- 项目探测与 VerificationPipeline；
- Verify-Fix 无进展检测、只读 Reviewer、风险分类。

## 配置

Coding runtime 的安全默认值是：

- 主工作树只读；
- Task Worktree 是默认 writable root；
- ExecutionBackend 网络策略为 `none`；
- 环境变量使用 allowlist；
- Docker 根文件系统只读、无额外 capabilities、限制 PID；
- LSP Server 不自动安装或下载。

可选能力缺失时必须降级：没有 Tree-sitter/LSP 时使用 Legacy Adapter；无法安全执行时返回结构化拒绝。

## 故障排查

1. Worktree 创建失败：检查主工作树是否干净，以及任务目录是否可写。
2. 验证没有计划：项目缺少受信任 Manifest，请显式提供验证命令。
3. LSP 不可用：检查 Server 可执行文件和 Worktree cwd；索引查询仍可使用 Legacy 结果。
4. 执行超时：查看 `timed-out` 诊断，确认进程组已终止后再重试。
5. ChangeSet 审批失效：Diff 内容变化后必须重新生成 ChangeSet 并审批。

## 已知限制

- 非 Python 语言当前为 Legacy/正则级解析，尚未达到完整语义精度。
- LSP 查询 enrichment、完整引用/调用边和 FTS5 尚未完成。
- VerificationPipeline 尚未提供完整 flaky/baseline 报告。
- Windows 安全后端策略尚未建立实机矩阵。

## 离线验证

```bash
python3.11 -m pytest python/tests/ -q --ignore=python/tests/tui
GOCACHE=/tmp/khaos-go-cache go test ./...
cargo test --manifest-path rust/khaos-core/Cargo.toml
```

当前已验证：Python `854 passed, 4 skipped`，Go 测试通过，Rust 测试 `23 passed`。
