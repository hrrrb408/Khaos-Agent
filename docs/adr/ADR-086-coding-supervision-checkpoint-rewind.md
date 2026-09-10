# ADR-086: Coding supervision, cooperative control, checkpoints, and rewind

状态：active（M8.6 Coding UX / Supervision / Checkpoint / Rewind）

## Context

Coding 任务需要在长时间运行、等待审批、并行子代理和进程重启期间保持可
观察、可控、可恢复。UI、CLI 或 Gateway 不能各自维护一份 task state，也不
能把模型输出、工具 stdout、diff 或 completion proposal 当作权威事实。

M8.2 已经拥有 generation-bound `EditTransaction`，M8.3 已经拥有
authoritative verification ledger，M8.5 已经拥有 Child Worktree、MergePlan、
cleanup/publication barrier，`CompletionGate` 仍是唯一完成权威。本 ADR 只把
这些 owner 的 typed facts 汇总为可重启的 supervision projection，并提供
安全的 pause/resume/cancel、checkpoint 和 rewind 入口；不复制 Git、workspace、
edit、verification、approval、merge 或 completion authority。

## Decision

### Canonical supervision plane

`TaskSupervisionService` 与 `TaskSupervisionRepository` 是用户可见 Coding
监督状态的唯一 writer。每个 `(principal_id, project_id, task_id)` 拥有单调
递增 event sequence、append-only event history 和有界 `TaskSupervisionState`
projection。event 与 projection 都带 canonical digest；事件 payload 只允许
有界的 ID、digest、枚举、计数、相对路径和状态字段，拒绝 source/content/
diff/patch/stdout/stderr/output/transcript 等披露字段。

Projection 的 `SupervisionStatus` 覆盖计划、调查、编辑、验证、修复、审批、
子代理、合并、暂停、阻塞、就绪、完成、失败、取消和 quarantine。展示层只
消费这个 projection 或 canonical event replay；它不能改变状态，也不能从
worktree 另算第二份 diff。读到序列缺口、owner drift 或 digest 不一致时，
repository 直接 fail closed。

### Control semantics

`TaskControlService` 是 task-scoped cooperative control owner。pause/resume/
cancel 命令绑定 owner、expected revision 和 idempotency command ID，返回
`APPLIED`、`NOOP`、`REJECTED_STALE`、`BLOCKED`、`REQUIRES_APPROVAL` 或
`FAILED`。pause 先持久化 `PAUSING`，运行时只在 safe point settle 为
`PAUSED`；运行中的 critical effect 由既有 effect owner drain。pause 不允许
新的 model/tool/child admission。resume 只能从持久化 `PAUSED` 重新校验
context/generation 后继续。cancel 先进入 `CANCELLING`，等待既有 cleanup/
lease/child owners 的 terminal proof，再落为 `CANCELLED`；cancel 不执行
rewind，也不篡改 repository truth。重启后的 runtime registration 重新绑定
同一 owner 并恢复持久化 control state。

### Checkpoints

`CheckpointService` 是 checkpoint capture/rewind 的 application owner，物理
文件读取仍通过 `WorkspaceManager.workspace_storage_scope` 和
`SafeWorkspaceFS`，并受 entry、file、byte、depth 与时间/生命周期边界约束。
`TaskCheckpoint` 不可变且 digest-bound，绑定 task/workspace/principal/project、
repository generation、HEAD/tree、task/plan revision、verification evidence、
kind/label 和 bounded snapshot。自动 checkpoint 只在稳定已知状态创建：

- pre-edit；
- post-verification；
- pre-parallel-merge；
- post-merge。

用户 checkpoint 使用同一个 owner 和同一持久化表，不产生旁路 snapshot。
重复请求通过 deterministic identity/idempotency 复用既有 checkpoint；超出
任务配额时 fail closed。

### Rewind

rewind 是一次新的受控 mutation，不是 Git reset。`RewindPlan` 绑定当前
generation/HEAD/tree 和 snapshot digest、目标 checkpoint digest、user drift、
preserved paths、conflicts 以及新的 M8.2 `EditTransaction` digest。执行前
必须没有活动 runtime、child、merge、approval 或 quarantine barrier，并重新
读取当前 workspace。任何 source drift、checkpoint tamper、owner/project
drift 或 stale plan 都是 `REJECTED_STALE`/`BLOCKED`，不会写入文件。

可执行 rewind 只能经 `EditTransactionService` 产生 generation `N -> N+1`，
并在 effect 后重新运行 M8.3 verification；旧 verification evidence 不会被
rebind 成新 generation 的证明。用户新增/未归属文件默认保留；目标会覆盖的
未归属路径、已知文件的 user drift、活动资源和不确定清理都会阻塞或 quarantine。
rewind result 通过 CAS 持久化，竞争者读取 durable winner；任务重启后只
恢复已持久化 plan/result，不推断未完成 mutation 成功。

### Presentation adapters

Python RPC `TaskService` 是 owner-scoped application adapter。Go Gateway 通过
可选 `TaskControlClient` 暴露 typed supervision、event replay、checkpoint 和
rewind routes，同时保留旧 `TaskClient` 契约兼容性。CLI 提供只读 status/events
和显式 control/checkpoint/rewind 命令；TUI slash commands 调用同一
`TaskService`/typed owners，rewind 在 TUI 中仅显示 plan preview，不直接执行。
所有 adapter 都要求 authenticated principal/project binding；缺少 active
workspace owner 时控制面返回 `BLOCKED`。

## Authority ownership

| Boundary | Owner | M8.6 responsibility |
| --- | --- | --- |
| Supervision events/projection | `TaskSupervisionRepository` | append-only history, bounded projection, digest/replay |
| Pause/resume/cancel | `TaskControlService` | revision/idempotency and safe-point coordination |
| Task lifecycle/completion | existing `TaskManager` + `CompletionGate` | physical task state and sole completion authority |
| Workspace/files | `WorkspaceManager` + `SafeWorkspaceFS` | owner binding, storage fence, generation |
| File mutation | `EditTransactionService` | all rewind effects and generation CAS |
| Verification | existing M8.3 coordinator/ledger | fresh post-edit and post-merge evidence |
| Child/merge lifecycle | existing M8.5 coordinators | child/merge barriers and publication truth |
| Checkpoint/rewind orchestration | `CheckpointService` | digest-bound plans and calls into existing owners |
| Presentation | Python RPC, Go Gateway, CLI, TUI | adapters only; no state authority |

## Security and failure rules

The supervision plane is observability/control state, not a permission grant. It
cannot widen EffectiveSecurityPolicy, ApprovalBroker, Sandbox, WorkspaceStorage,
Network, Credential, Trusted Git, M8.2 or M8.3 fences. Model prose is always an
untrusted observation; only typed verification/merge/completion owners can produce
positive proof. A partial event history, tampered checkpoint/projection, stale
revision, uncertain cleanup, active child/merge, or post-publication uncertainty
must remain visible as blocked/unverified/quarantined truth rather than becoming a
false green state.

## Persistence

Migration `0030_coding_supervision_checkpoint_rewind.sql` adds the owner-scoped
`task_supervision_events`, `task_supervision_states`, `task_control_state`,
`task_checkpoints`, and `rewind_records` tables. Events and checkpoints have
immutable SQLite triggers. Mutable control/projection rows use compare-and-set
revision updates. All task control, checkpoint creation and rewind attempts are
audited with bounded metadata only.

## Non-goals

This ADR does not add a new model loop, recursive delegation, a second completion
gate, a second verification authority, Git reset/clean, raw transcript storage,
automatic conflict resolution, or a global lock. It does not reopen M7 or replace
the M8.1–M8.5 authority chain.

## Evidence

Implementation lives under `python/khaos/supervision/` and
`python/khaos/coding/checkpoints/`, with runtime wiring in the existing AgentLoop,
TaskService, MergeCoordinator, CLI, TUI and optional Go Gateway adapters. Focused
regressions live in
`python/tests/coding/test_m8_6_supervision_checkpoint_rewind.py`; the final
closure state depends on local validation plus required exact-SHA CI on the pushed
commit. Until those checks are terminal and successful, M8.6 remains
`NOT_CLOSED`.
