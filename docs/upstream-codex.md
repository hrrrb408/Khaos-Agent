# OpenAI Codex 固定上游基线与复用台账

> 状态：首次架构对标基线（只读审查，不引入上游代码）
> 审查日期：2026-07-15（Asia/Shanghai）

## 1. 可复现基线

| 对象 | 仓库 | 分支/来源 | 固定 commit | commit 时间 | 审查方式 |
| --- | --- | --- | --- | --- | --- |
| OpenAI Codex | `https://github.com/openai/codex` | 远端 `HEAD` | `3f74f00295dcb1346340686bb09c5bfd4f0237c4` | 2026-07-15 02:43:31 UTC | `git ls-remote` 固定后以 depth-1 clone 审查 |
| Khaos-Agent | `https://github.com/hrrrb408/Khaos-Agent` | `feature/m4-agent-planning` | `17f90ba0e63f7a43b7b062c9ae3e9b810b1f051d` | 2026-07-15 01:05:26 +08:00 | 从本地仓库复制为干净快照审查 |

Codex 当前远端 `HEAD` 在审查时解析为 `3f74f00295dcb1346340686bb09c5bfd4f0237c4`。所有 Codex 文件、符号和测试结论均绑定该 SHA。后续同步必须先提出新的基线升级记录，不得把浮动 `main` 当作构建依赖或事实来源。

Khaos commit SHA 固定为 `17f90ba0e63f7a43b7b062c9ae3e9b810b1f051d`。

Khaos 当前工作区在固定提交之上存在未提交的 Phase 0 变更及 `.zcode/`。这些内容不属于上述 Khaos SHA，不用于判定固定基线已经修复；它们只能作为后续实施候选，在单独审查、测试和原子提交后进入新基线。

## 2. 被审查目录

### Codex

- `codex-rs/core`：线程、会话、turn、Agent loop、工具、审批、压缩。
- `codex-rs/protocol`、`app-server-protocol`：sandbox/permission 与 App Server schema。
- `codex-rs/sandboxing`、`linux-sandbox`、`windows-sandbox-rs`：macOS/Linux/Windows 强制边界。
- `codex-rs/exec-server`、`shell-command`、`apply-patch`：进程、命令策略、patch。
- `codex-rs/app-server`、`app-server-transport`：JSON-RPC、传输、认证、背压。
- `codex-rs/thread-store`、`rollout`、`state`、`agent-graph-store`：持久化、重放与图状态。
- `codex-rs/mcp`、`rmcp-client`、`core/src/session/mcp.rs`：MCP 生命周期与 elicitation。
- `codex-rs/tui`、`cli`、`config`：客户端与配置。
- `.github/workflows`、各 crate 的 `tests`/snapshot：CI 和平台验证。
- 根 `LICENSE`、`NOTICE`、`third_party`、`Cargo.lock`、`pnpm-lock.yaml`、`codex-rs/deny.toml`：许可与依赖治理。

### Khaos

- `python/khaos/agent`、`coding`、`tools`、`security`、`permissions`。
- `python/khaos/coding/execution`、`workspace`、`planning`、`verification`。
- `python/khaos/grpc_server.py`、`go/cmd/gateway`、`go/internal/api|platform|ws`。
- `python/khaos/tui`、`config.py`、`scheduler`、`subagents`、`audit`、`db`。
- `python/tests`、`go/**/*_test.go`、`rust`、`.github/workflows`。
- `docs/adr`、runtime gap/closure 文档和四份主设计文档。

未审查云端闭源服务内部实现、未在仓库中的部署编排、真实多租户生产环境和未提供的密钥管理系统；这些列入审计盲区。

## 3. 许可边界

### 3.1 Codex 上游

- 根 `LICENSE`：Apache License 2.0，版权声明为 `Copyright 2025 OpenAI`。
- 根 `NOTICE`：OpenAI Codex 版权通知；同时声明部分代码源自 Ratatui（MIT），保留 Florian Dehau 与 Ratatui Developers 的版权信息。
- `third_party/wezterm/LICENSE`：独立第三方许可文件。
- Rust workspace 声明 `Apache-2.0`；`codex-rs/deny.toml` 对 Apache、MIT、BSD、ISC、MPL-2.0、OpenSSL、Unicode、Zlib 等许可证设有显式 allowlist，并维护安全公告例外。
- 固定依赖快照由 `codex-rs/Cargo.lock`、`pnpm-lock.yaml` 和根 `package.json` 的固定 package-manager 版本描述。许可证结论应以每次真正复制代码时的依赖清单扫描为准，不能只依赖本报告摘要。

### 3.2 Khaos 与组合分发

Khaos 为 MIT。Apache-2.0 代码可以进入 MIT 项目，但被复制部分仍受 Apache-2.0 的通知、归属、变更说明和专利条款约束；不能把组合分发描述为“全部仅受 MIT 约束”。Apache-2.0 不授予 OpenAI 商标使用权。

若发生直接复制，必须同时执行：

1. 在分发物中保留 Apache-2.0 许可证文本；
2. 保留源文件中的版权、专利、商标和归属声明；
3. 对修改过的上游文件作显著变更说明；
4. 将上游 `NOTICE` 中适用内容合并到 Khaos `NOTICE`；
5. 在 `THIRD_PARTY_NOTICES` 和本文件的复用台账中记录固定 SHA、符号和目标文件；
6. 对引入的新依赖运行许可证与安全公告扫描。

本次交付没有复制 Codex 源码，因此暂不新增根 `NOTICE`/`THIRD_PARTY_NOTICES`，避免制造“已引入第三方代码”的错误信号。首次直接复制提交必须把这些文件与代码放在同一原子提交中。

## 4. 复用策略

默认顺序为：设计级 `ADAPT` > 小型、边界清晰的直接复用 > 大模块复制。不同语言之间优先重写契约和测试，而不是逐行翻译 Rust。

| 候选 | 上游文件与行号/稳定符号 | 上游 commit | 许可 | Khaos 目标 | 直接复制 | 改写 | 修改说明 | 对应测试 | 同步策略 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| turn 终态与事件顺序 | `core/src/tasks/regular.rs::RegularTask`；`core/src/session/turn.rs::run_turn`；turn event enums | `3f74f002…` | Apache-2.0，设计引用 | Agent Loop / RPC events | 否 | 是 | 加入 Task/Workspace/Verification projection 和 durable terminal invariant | 终态唯一、取消、审批等待、重放 | 基线升级时做语义 diff |
| 请求级权限 profile | `protocol/src/permissions.rs::{FileSystemSandboxPolicy,NetworkSandboxPolicy}`；`protocol/src/protocol.rs::SandboxPolicy` | `3f74f002…` | Apache-2.0，设计引用 | `coding/execution/models.py` | 否 | 是 | 转为 Khaos versioned profile，加入 Task/Workspace principal scope | 每种 profile 的拒绝矩阵与平台 E2E | schema 版本化，不自动跟随 |
| sandbox backend 编排 | `sandboxing/src/manager.rs::{SandboxManager,select_initial,transform}` | `3f74f002…` | Apache-2.0，设计引用 | backend selector/service | 否 | 是 | 按 Python/平台重写，受限模式删除 Host fallback | unavailable/probe failure/no host fallback | 每季度或安全公告触发复核 |
| 审批执行编排 | `core/src/tools/approvals.rs::ApprovalAction`；`core/src/tools/sandboxing.rs::ExecApprovalRequirement` | `3f74f002…` | Apache-2.0，设计引用 | ApprovalBroker/ApprovalRuntime | 否 | 是 | 增强 principal、Task、ChangeSet、args digest、nonce 和 proof binding | replay/cross-principal/task/workspace/expiry | 以 Khaos invariant 为主 |
| App Server schema | `app-server-protocol/src/protocol/v1.rs::InitializeParams`；`protocol/v2/{thread,turn}.rs` | `3f74f002…` | Apache-2.0，设计引用 | 新 Khaos RPC schema | 否 | 是 | 保留 Khaos 方法域，采用 init/version/typed event/backpressure 形态 | schema golden、版本协商、大小限制 | 显式版本，不追逐字段 |
| 有界输出截断 | `utils/output-truncation/src/lib.rs` 的 token/byte 头尾截断符号 | `3f74f002…` | Apache-2.0 | ExecutionResult 输出策略 | 当前否；后续可评估 | 是 | 统一 stdout/stderr 公平预算、UTF-8 和 artifact 引用 | UTF-8、头尾、bytes/token 上限 | 若复制则保留文件标头、NOTICE、符号和 SHA |
| 进程树终止 | `exec-server/src/connection.rs` 的 terminate/kill helper | `3f74f002…` | Apache-2.0，设计引用 | managed/foreground process | 否 | 是 | 分平台实现 TERM→grace→KILL 和 execution registry | child/grandchild、timeout、cancel、crash | 跟随 OS 行为测试 |
| rollout 重建 | `core/src/session/rollout_reconstruction.rs`；`thread-store/src/local/live_writer.rs::resume_thread` | `3f74f002…` | Apache-2.0，设计引用 | Khaos durable event ledger | 否 | 是 | 加入 Task/Approval/Verification 事件和跨 store migration | crash/restart/partial tail/replay | 格式迁移必须前后兼容 |
| compaction 窗口 | `core/src/compact.rs`；`core/src/context_manager/history.rs` | `3f74f002…` | Apache-2.0，设计引用 | compressor/context | 否 | 是 | structured Task/Plan/Approval facts 不进入自由摘要 | 工具配对、审批/计划事实不丢失 | 以 invariant tests 固定 |
| patch 解析/应用 | `apply-patch` crate 的 parser/apply symbols，行号待 Batch E 候选冻结 | `3f74f002…` | Apache-2.0 | ChangeSet apply 层 | 否 | 暂缓 | 先完成 SafeWorkspaceFS，再判断小型 parser 是否值得复用 | symlink/hardlink/rename race/atomicity | Batch E 决策前补精确符号/行号 |

目前“是否直接复制”全部为否。任何后续直接复制项必须先把本表补充到文件、行号或稳定符号粒度，并在目标文件头标注来源、固定 SHA、许可证和修改说明。

## 5. 固定链接规则

源代码引用使用如下永久格式：

`https://github.com/openai/codex/blob/3f74f00295dcb1346340686bb09c5bfd4f0237c4/<path>#Lx-Ly`

Khaos 引用使用：

`https://github.com/hrrrb408/Khaos-Agent/blob/17f90ba0e63f7a43b7b062c9ae3e9b810b1f051d/<path>#Lx-Ly`

行号只作为该 SHA 的定位辅助；跨基线同步以符号、行为测试和安全不变量为准。
