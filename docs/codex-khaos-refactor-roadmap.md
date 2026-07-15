# Khaos 统一安全重构路线（Batch A–H）

> 前置报告：`docs/codex-khaos-architecture-gap-analysis.md`
> 上游台账：`docs/upstream-codex.md`
> 原则：逐边界实施、设计优先、fail closed、不保留静默 fallback、不降低 Verification 证明

## 1. 全局不变量

1. 一个 turn 只有一个 durable terminal state；事件 sequence 单调且可重放。
2. 所有副作用必须经过唯一 Tool Dispatcher 和不可变 PermissionProfile。
3. 受限 profile 只有在 OS backend 证明可用时执行；否则返回 infrastructure unavailable。
4. approval 是 one-shot capability，不是布尔值；必须绑定主体、上下文、参数和有效期。
5. Task、Workspace、ChangeSet、Verification 的身份不可由客户端任意声明或互换。
6. Trusted Verification 的 canonical input 和结果账本不得由被测进程写入。
7. 所有写入有 durable audit；安全终态在对外可见前落盘。
8. API 兼容通过显式 adapter/migration 提供；旧权威实现必须删除，不能静默并行。

实施顺序建议：A 的事件契约与 B 的 profile schema 先形成共同基础；随后 C、D、E；F 依赖 B/C/E；G、H 在协议稳定后完成。每个 batch 都先落 ADR/schema/tests，再实现，再删除旧路径。

## 2. Batch A：Agent Loop 与事件模型

实施进度（2026-07-15）：A1-A5 已完成兼容式切换。每个 turn 获得 server-issued
TurnId/AttemptId 和 SQLite 单调 sequence；tool call/result 与 approval wait 由
`TurnCoordinator` 校验，terminal event 与 turn status 同事务提交。重复/迟到/乱序事件
拒绝，进程重启把遗留 running turn 写为 interrupted，不伪造 completed。旧 `Message`
stream 作为 adapter 保留，done/error metadata 携带 turn/attempt/sequence。

| 项 | 内容 |
| --- | --- |
| 范围 | `agent/core.py`、model streaming、ToolScheduler、TaskManager 状态投影、Gateway/TUI event adapter |
| 不变量 | `TurnStarted` 后恰有一个 Completed/Interrupted/Failed；tool call/result 成对；terminal 前 durable flush；迟到事件被拒绝 |
| 威胁模型 | cancel 与 tool result 竞态、审批等待悬挂、重试产生双终态、断线后事件重复/乱序、模型空响应 |
| 设计 | 引入 `TurnId/AttemptId/EventSeq`、typed `TurnEvent`、单写者 `TurnCoordinator`、层级 cancellation token；TaskStatus 作为投影而非第二个 turn 权威 |
| 代码修改 | 新建 `agent/events.py`, `agent/turn.py`; 将 loop 拆为 sampling/tool/terminal；Gateway 与 TUI 只消费事件；保留旧 Message adapter 一个迁移周期 |
| 迁移 | 旧消息记录转换为 legacy event；新 session 写 v2；启动时将无终态 in-flight turn 标为 interrupted，不伪造 completed |
| 负向测试 | 双 terminal、result-before-call、cancel-during-approval、late approval、late tool result、sequence gap/replay、crash before/after terminal flush |
| 回归测试 | provider streaming、并行工具、verify-fix、Task 创建、SSE/TUI 渲染、Office 模式 |
| 回滚方案 | schema 双读；feature flag 仅切换 reader，不能回退旧写者；若失败停止新 turn 并保留事件账本 |
| 文档 | ADR turn state machine、event schema、错误分类、序列图 |
| 原子提交 | A1 schema+golden tests；A2 coordinator；A3 tool/cancel；A4 adapters；A5 migration；A6 删除旧终态写路径 |

## 3. Batch B：Execution 与 Sandbox

实施进度（2026-07-15）：B1–B7 已完成首轮收敛。B1 `PermissionProfile`、B2
`ProcessSupervisor`、B3 Linux、B4 macOS、B5 Docker、B6 Windows/unsupported 与 B7
Host fallback 删除已验证。profile 已覆盖 filesystem、network、workspace roots、
unreadable host-secret roots、environment allowlist、resources 和稳定 digest；显式
profile 无法被旧字段 `replace()` 降权。macOS 真实 sandbox gate 已验证工作区写、
工作区外拒写、网络拒绝和 secret-root 拒读。所有 foreground、managed stdio 和
Docker foreground process 现由共享 supervisor 负责 process-group TERM→grace→KILL、
取消、shutdown 与公平有界 stdout/stderr；完整输出 artifact 旁路已删除。Linux bwrap
现使用 probe/execute 同构拓扑、新 `/proc`、network/PID/IPC/UTS 隔离、new-session、
die-with-parent 和相对 cwd 映射；异常 probe fail closed，并由 Linux CI 真实 gate 强制。
macOS capability 使用真实 Seatbelt probe，本机真实 gate 已通过。Docker 使用 digest、
pull-never、owner-nonce cleanup、mount delimiter rejection 与共享 supervisor；真实 Docker
destructive E2E 仅在干净 CI runner gate。Windows 在实现 OS 强制 backend 前显式拒绝。

| 项 | 内容 |
| --- | --- |
| 范围 | ExecutionRequest/Service、backend selector、Host/Docker/macOS/Linux/Windows、terminal/test/LSP |
| 不变量 | restricted profile 无 Host fallback；cwd/roots/profile 每请求绑定；network none 由 OS 证明；所有进程可取消和清理 |
| 威胁模型 | probe 伪阳性、backend 消失、宿主文件/secret/网络访问、fork 后逃逸、输出 DoS、容器 socket/代理泄漏 |
| 设计 | versioned `PermissionProfile`（FS entries + network + resources + env）；`BackendPlan` 在执行前验证；统一 `ProcessSupervisor`；full access 必须显式 approval capability |
| 代码修改 | 删除 AgentLoop 默认 Host；selector 对 read-only 也 fail closed；平台 profile 只读挂载+protected metadata；最小 env；流式 bounded stdout/stderr；Windows backend 明确 unsupported 前拒绝 |
| 迁移 | `access_mode/network_policy/writable_roots` 转换为 v1 profile；无法无损转换的配置启动失败并给出迁移提示 |
| 负向测试 | backend unavailable、probe failure、invalid config、outside cwd、network/DNS/UDS、HOME/SSH/cloud/Docker secret、fork/grandchild、timeout/cancel/crash |
| 回归测试 | test_run、terminal、LSP、Docker、macOS/Linux E2E、artifact 截断 |
| 回滚方案 | 保留旧字段 parser，不保留旧 executor；安全 backend 故障时停用执行，不转 Host |
| 文档 | threat model、各平台保证/限制、运维 probe、profile schema |
| 原子提交 | B1 profile；B2 supervisor/output；B3 Linux；B4 macOS；B5 Docker；B6 Windows/unsupported；B7 删除 Host fallback |

## 4. Batch C：Approval 与 Principal

实施进度（2026-07-15）：C1 普通 tool approval 已完成 principal/session/task/turn/call/
arguments/workspace/profile/expiry/nonce binding 与 one-shot consume；Gateway confirm 和
task approve/reject principal 来自认证 context，客户端自报 principal 无效。既有 Plan
Approval signed durable receipt 保留。C2 destructive operation/ChangeSet durable ledger
已完成，使用事务化 one-shot consume，并覆盖 restart 与跨连接竞争。C3 多租户 principal
provider 与 ordinary approval durable invalidation audit 尚未关闭。

| 项 | 内容 |
| --- | --- |
| 范围 | PermissionEngine、ApprovalBroker、plan/operation approval、Gateway/TUI 回调、Scheduler/SubAgent delegated approval |
| 不变量 | capability 绑定 `principal+session+task+turn+call+args_digest+workspace+profile_delta+expiry+nonce`；一次消费；拒绝和取消不可复活 |
| 威胁模型 | ID 猜测、跨 session/task/workspace replay、参数替换、批准后扩大权限、时钟回拨、双消费、同进程伪造 writer |
| 设计 | server-issued challenge；canonical serialization + digest；signed durable decision receipt；monotonic deadline + wall expiry；consume 使用事务/CAS；principal 来自 authenticated transport |
| 代码修改 | 收敛 broker 的 tool/operation/plan key space；ApprovalSnapshot 成为不可变输入；所有 tool handler 接收已消费 capability，不接收 `approved=True` |
| 迁移 | 未完成的旧 approval 启动后全部失效并重新询问；旧 remember rule 迁移为受限 policy rule，不能生成已批准 receipt |
| 负向测试 | cross-principal/session/task/workspace、args mutation、expired、nonce replay、double consume、restart、clock skew、cancel race |
| 回归测试 | ask/approve/reject/session rule、ChangeSet、plan execution、TUI dialog、Gateway approval API |
| 回滚方案 | 新消费表 append-only；出现错误冻结 approval，不回用旧 broker decision cache |
| 文档 | principal model、capability schema、canonicalization、key rotation/boot policy |
| 原子提交 | C1 principal types；C2 challenge/receipt；C3 CAS consume；C4 tool integration；C5 scheduler/subagent；C6 删除布尔审批旁路 |

## 5. Batch D：App Server / RPC

实施进度（2026-07-15）：D1 Gateway HTTP boundary 已完成 protocol version header、
1 MiB 普通请求/2 MiB webhook 上限、strict single-value JSON、authenticated session/task
ownership、SSE `Last-Event-ID` sequence replay cursor，以及 client disconnect 到上游 context
的取消传播。认证态下未知 ownership 在进程重启后 fail closed；durable ownership source、
全客户端统一 schema generation 与跨进程 backpressure telemetry 仍待后续 D2。

| 项 | 内容 |
| --- | --- |
| 范围 | Go Gateway、Python server/client、SSE/WS、TUI/IDE/渠道 adapter、Task/Approval/Audit API |
| 不变量 | initialize 后才能请求；principal 与 connection/session ownership 绑定；取消向下传播；队列有界；所有响应可关联 request id |
| 威胁模型 | 裸 TCP 注入、session hijack、大 frame/深 JSON、慢客户端、重放、断线造成孤儿 turn、错误泄露 secret |
| 设计 | Khaos RPC v1 typed envelope；本机 UDS/pipe 默认，0600；远程 TLS+bearer/mTLS；capability negotiation；per-connection bounded queue；event cursor/replay |
| 代码修改 | schema 定义并生成 Python/Go types；统一 error enum；max bytes/depth/items；connection registry；cancel/interrupt；REST/SSE/WS 变薄 adapter |
| 迁移 | 旧 REST 保持路径，内部转换为 RPC v1；旧 Python TCP 默认关闭，可显式临时兼容且只 bind loopback、发弃用告警 |
| 负向测试 | pre-init、bad version/auth、wrong owner、oversize、slow consumer、duplicate idempotency key、disconnect/reconnect/replay、cancel propagation |
| 回归测试 | Chat、Task、Approval、Audit、Channel、SubAgent、TUI/SSE/WS |
| 回滚方案 | Gateway adapter 可回滚，server authority 不回滚；协议不兼容时拒绝并保持任务可恢复 |
| 文档 | schema、版本政策、auth/ownership、错误、背压和 replay |
| 原子提交 | D1 schema/golden；D2 UDS auth；D3 processor；D4 event replay；D5 adapters；D6 禁用旧 TCP |

## 6. Batch E：Filesystem

实施进度（2026-07-15）：E1-E5 已完成。复用既有 planned mutation 的固定 root dirfd/
逐段 `O_NOFOLLOW`/inode revalidation/fsync/atomic exchange 原语，新增通用
`SafeWorkspaceFS`。Coding read/write/patch/multi-edit/copy/move/search/symbol 工具均绑定
active TaskWorkspace，拒绝 traversal、protected metadata、symlink、hardlink 与目标覆盖；
用户配置写入改为 0600 同目录临时文件 + fsync + dirfd rename。平台真实 rename-race 与
磁盘故障注入继续由 CI security gate 覆盖。

| 项 | 内容 |
| --- | --- |
| 范围 | file tools、workspace boundary/apply/recovery、config writes、patch/ChangeSet、Rust bridge |
| 不变量 | 所有 agent 路径相对 workspace handle；no-follow/beneath；protected metadata 默认只读；ChangeSet 原子或可证明回滚 |
| 威胁模型 | traversal、symlink/hardlink、rename race、mount swap、TOCTOU、跨设备 rename、`.git`/agent config 篡改、host secret read |
| 设计 | `SafeWorkspaceFS`；Linux openat2，macOS/Windows 逐段 handle walk；目标目录同设备 temp+fsync+rename；inode/device/link-count 验证；base digest CAS |
| 代码修改 | file tools 不再直接 `Path.read/write`；统一 read/write/patch/copy/move；config writer atomic；ChangeSet 应用消费安全 handle；移除重复 PathGuard 写边界 |
| 迁移 | 绝对路径 API 转 workspace-relative；adapter 对合法旧调用转换，对 workspace 外请求拒绝；恢复记录增加 inode/digest/version |
| 负向测试 | symlink leaf/parent、hardlink、rename loop/exchange、replace-after-check、cross-device、protected metadata、partial write、disk full、crash |
| 回归测试 | read/write/multi-edit/patch/copy/move、git worktree、ChangeSet apply/rollback、config wizard |
| 回滚方案 | 先写 journal 再变更；失败进入 recovery-required，不回落普通 pathlib；提供只读导出工具 |
| 文档 | filesystem guarantees、平台差异、atomic protocol、recovery runbook |
| 原子提交 | E1 API+race harness；E2 read；E3 atomic write；E4 patch/ChangeSet；E5 config；E6 删除直接写旁路 |

## 7. Batch F：Verification

实施进度（2026-07-15）：F1-F4 已完成并保留 Khaos 差异化证明。Verification writer
的 proof/success ledger 已位于独立 spawn 子进程；主状态 writer 仍在受信任 Runtime，
但通过 boot-lifetime SQLite EXCLUSIVE lock 阻断预打开 writer FD 竞态。canonical read
handle 只提供固定 query，DB/WAL/SHM（或 SHM 持续缺失）和 schema identity 被 pin，
旧 boot success 必须重新验证。Authority proof/success ledger
现改为跨启动保留的 boot-scoped SQLite ledger；每个 accepted/rejected/boot event 进入
SHA-256 previous-hash chain，启动先验证全链，旧 boot proof 仍不可用于当前 boot。

| 项 | 内容 |
| --- | --- |
| 范围 | Trusted Verification、runner/sandbox、authority/storage/store、Approval Snapshot、CleanupProof、Recovery |
| 不变量 | 被测代码不能写 trusted input/result；verification 只读已批准 ChangeSet 快照；proof 绑定 boot/task/workspace/commit/profile；旧证明不降级 |
| 威胁模型 | 同进程 authority 冒用、SQLite 连接写、trigger 绕过、canonical read 被替换、cross-boot replay、cleanup 假证明、结果日志截断欺骗 |
| 设计 | 最小权限独立 verification service；只读 mount/handle；独立 append-only signed ledger；approval snapshot digest；runner attestation；cleanup 由 supervisor 观测 |
| 代码修改 | 把 authority 私钥/写端移出 Agent 进程；trusted store 单写者；canonical handles 来自 Batch E；验证 profile 来自 Batch B；恢复基于 Batch A event ledger |
| 迁移 | 旧 proofs 保留为 legacy/untrusted-for-apply，不删除；新 apply gate 只接受 v2 proof；提供审计导出 |
| 负向测试 | forged writer、SQLite direct write、cross-boot/session/task/workspace、canonical swap、runner crash、ledger tail corruption、cleanup failure、replay |
| 回归测试 | approved plan execution、verification catalog、sandbox tests、rollback、recovery、CleanupProof |
| 回滚方案 | verification service 不可用则禁止 apply/complete；不使用 legacy proof 兜底 |
| 文档 | authority threat model、proof schema、key lifecycle、recovery/incident response |
| 原子提交 | F1 v2 proof；F2 service boundary；F3 trusted read；F4 ledger；F5 recovery；F6 gate cutover |

## 8. Batch G：Context 与 Compaction

实施进度（2026-07-15）：G1-G4 已完成。上下文分为 immutable rules、durable facts、
conversation summary 与 ephemeral observation；system/Task/approval/workspace 事实每轮从
权威状态重建，仓库内容以不受信任 user observation 注入。Compactor 不把结构化事实、
tool call 或 tool result 发送给摘要模型；每次压缩将输入 window digest、结果 digest、替换
数量和 token 计数写入有序 turn ledger，事件不持久化可能含 secret 的正文。legacy summary
仍可读取，但不能成为 Task/Approval/Verification 的权威来源。

| 项 | 内容 |
| --- | --- |
| 范围 | compressor、history builder、project context、Task/Plan/Approval/Verification 注入、resume |
| 不变量 | system/project rules、未决 tool pair、Task goal/plan/invariants、approval/ChangeSet/proof refs 不由模型自由摘要；窗口可重建 |
| 威胁模型 | prompt injection 经摘要持久化、审批事实丢失、工具结果错配、跨 task context 污染、超长 item DoS |
| 设计 | context 分层：immutable rules、durable structured facts、conversation window、ephemeral observations；window id + replacement history；每 item/token 上限 |
| 代码修改 | compactor 仅摘要 conversation；结构化 facts 重新注入；记录 compaction event/window；resume 重建；敏感 tool output 引用 artifact 而非全量复制 |
| 迁移 | legacy summary 标记来源；首次 v2 compaction 建立新 window baseline；不能证明配对的 tool items 隔离并告警 |
| 负向测试 | tool pair split、approval omitted、cross-task facts、malicious summary、double compaction、crash/replay、oversize item |
| 回归测试 | 长会话、project context、skills/memory、model switch、verify-fix、Task resume |
| 回滚方案 | 可禁用自动 compact 并停止新 turn；不回到覆盖式不可重建摘要 |
| 文档 | context layers、保留/丢弃规则、token accounting、重建算法 |
| 原子提交 | G1 fact schema；G2 window events；G3 compactor；G4 reconstruction；G5 migration |

## 9. Batch H：TUI 与用户体验

实施进度（2026-07-15）：H1、H2、H4、H6 已完成安全收敛。Permission view model
只消费 server-issued binding 字段，展示 principal/task/workspace、permission level、arguments/
profile/binding digest 和 expiry；过期或重复 pending callback fail closed，所有动态文案进行
markup escape。TUI 不再调用 host `subprocess git diff`，只渲染受控工具结果已经携带的
diff/patch artifact。既有 slash command、Office/Coding 双模式和 typed turn metadata 保留。
H3 的跨进程恢复状态展示与 H5 的全尺寸 Textual snapshot matrix 继续受可选 Textual CI
环境门禁约束，不得成为恢复 host 旁路的理由。

| 项 | 内容 |
| --- | --- |
| 范围 | Textual TUI、Gateway clients、permission dialog、task/recovery/sandbox status、diff preview |
| 不变量 | UI 不直接执行副作用；显示的 profile/arguments/diff 与 approval digest 一致；断线重连不重复批准或重复提交 |
| 威胁模型 | UI 参数截断误导、隐藏权限增量、clickjacking 式确认、host git diff 旁路、过期 approval 点击 |
| 设计 | event-native view model；approval 显示 principal/task/workspace/command/files/profile delta/expiry；所有动作调用 RPC；replay cursor 恢复 |
| 代码修改 | 删除 TUI 直接 `subprocess git diff`，改由受限 read service；状态栏展示 backend/profile；明确 interrupted/recovery-required；snapshot tests |
| 迁移 | 保留斜杠命令和双模式；旧 Message renderer 通过 adapter 逐步退役；不复制 Codex 品牌/文案/布局 |
| 负向测试 | stale approval、digest mismatch、disconnect during approval、slow stream、malformed event、wrong owner、oversized diff |
| 回归测试 | Office/Coding、Task 列表、diff、permission、cancel/resume、setup wizard、终端尺寸/Unicode |
| 回滚方案 | UI 可回旧 renderer 但仍只读新 RPC；不得恢复 UI 直调 host |
| 文档 | UX state chart、权限文案、无障碍、错误恢复 |
| 原子提交 | H1 view model；H2 approval UX；H3 task/recovery；H4 diff；H5 snapshots；H6 删除 host UI 旁路 |

## 10. 测试矩阵与门禁

每个被采用设计至少覆盖下列维度，并在测试名/marker 中标注类别：

| 类别 | 必测维度 | 运行位置 | 合并门禁 |
| --- | --- | --- | --- |
| Codex 行为复现 | turn event ordering、tool call/result、approval wait、cancel、resume、compaction、backpressure | host-local mock + protocol golden | 每个 PR |
| Khaos 特有不变量 | Task/ChangeSet/Approval Snapshot/Trusted Verification/CleanupProof/Recovery/Scheduler/Multi-Agent | domain integration + crash harness | 每个 PR |
| 平台相关 | process tree、dir handles、mount/ACL/network、atomic rename/fsync | Linux/macOS/Windows matrix | 对应平台必过 |
| 真实 Sandbox | read-only、workspace-write、network denial、secret isolation、backend unavailable | 非 mock runner/VM/container | security label PR 必过，定时全量 |
| Mock | provider error、time、rare crash、RPC reorder | 快速测试 | 不能单独关闭安全项 |

每个边界的共同负向集：正常、拒绝、升级、取消、timeout、crash、restart、replay、跨 session/task/workspace、symlink、hardlink、rename race、network denial、host secret、backend unavailable、invalid config。报告必须分别列出 host-local、CI gate、real sandbox 与 mock 结果。

## 11. 预计删除或合并的重复模块

| 当前重叠 | 处理 | 目标权威 |
| --- | --- | --- |
| `security.Sandbox` tool allowlist vs Execution permission | 合并；allowlist 降为风险提示，不作强边界 | `PermissionProfile` + OS backend |
| `PathGuard`、file tool 自检、workspace boundary | 合并路径解析和写入；保留 policy reporting adapter | `SafeWorkspaceFS` |
| Host/platform/Docker 各自进程管理和截断 | 合并 supervisor/output；backend 只负责隔离转换 | `ProcessSupervisor` |
| PermissionEngine、broker tool approval、operation/plan approval | 合并 challenge/consume，保留 domain-specific summary | `ApprovalCapabilityService` |
| Message stop_reason、TaskStatus、WorkspaceState 的 turn 终态 | 终态由 event ledger 唯一提交，其他为 projection | `TurnCoordinator` |
| Go REST/WS event、Python JSON-lines event | schema 统一；客户端 adapter 保留 | Khaos RPC v1 |
| verification 多 store/write hooks | 收敛单写者和 append-only ledger | Verification service |
| compressor summary 与 task metadata 拼接 | 分层，structured facts 独立 | ContextAssembler |

不会删除 TaskManager、ApprovalBroker 的领域语义、ChangeSet、Trusted Verification、Approval Snapshot、CleanupProof、Verification Recovery、Scheduler、多 Agent 或 durable audit；被替换的是重复执行权威和不安全 transport/adapter。

## 12. 交付和基线升级规则

- 每个 batch 从 `feature/m4-agent-planning` 的已接受新基线创建独立 `codex/<batch>-...` 分支；不修改历史。
- 先提交测试/ADR/schema，再提交实现，再提交迁移和旧路径删除；每个提交只做一件事。
- 合并前更新 `docs/upstream-codex.md` 的复用台账；若 Codex SHA 升级，单独提交 baseline diff，不夹带业务修改。
- 安全测试失败不能通过删除/skip 测试解决；平台不可用应明确标为 infrastructure unavailable，并由要求真实平台的 gate 拒绝合并。
- 回滚只能回滚 adapter/启用开关，不能恢复已判定不安全的 Host fallback、裸 RPC、普通路径写或 legacy verification proof。
