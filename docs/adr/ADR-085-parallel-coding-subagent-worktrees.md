# ADR-085: Parallel coding subagents use isolated child Worktrees

状态：active（M8.5）

## Context

并行 Coding 子代理可以降低等待时间，但不能把 Parent 的 canonical
workspace 变成多个模型共享的可变目录。Child 的成功结果也只能证明 Child
快照，不能直接成为 Parent 的完成证据。M8.5 需要在现有 WorkspaceManager、
EditTransaction、Trusted Git、M8.3 Verification 和 CompletionGate 之上增加
编排层，而不是复制这些 authority。

## Decision

Parent 只在稳定、干净且 generation/HEAD 匹配时创建 Child。每个 assignment
得到独立的 Git Task Worktree、独立 principal（`subagent:<parent>:<assignment>`）
和有界的 context/budget。Child 的 mutating edit 必须通过现有
EditTransaction/WorkspaceStorageAuthority；Child 结果必须包含 base、final
commit、实际 ChangeSet artifact、digest、changed paths 和验证状态。

MergeCoordinator 不运行模型，也不接受模型 prose 作为合并依据。它按固定
assignment priority/id 建立 digest-bound MergePlan，在自己拥有的 Integration
Worktree 中只应用已验证 artifact，先执行 M8.3 integration verification，再以
Parent HEAD/generation CAS 发布，并在 Parent 上重新执行 M8.3 verification。
发布之后才触发既有 Repo Intelligence refresh；是否完成仍由既有
CompletionGate 决定。

## Authority ownership

| Boundary | Owner | M8.5 responsibility |
| --- | --- | --- |
| Assignment/context/budget | `SubagentCoordinator` + typed contracts | bounded immutable input and scheduling only |
| Child Worktree/Git | `WorkspaceManager` + `TrustedGitRunner` | worktree lifecycle, Git plumbing, artifact ownership |
| Child mutation | `EditTransactionService` | generation-bound typed edits and rollback |
| Integration/Parent merge | `MergeCoordinator` | deterministic artifact application and CAS publication |
| Verification | `AutonomousVerificationCoordinator` (M8.3) | integration and resulting Parent observations |
| Repository facts | existing `RepoIntelligenceService` | refresh after a published Parent generation |
| Completion | existing `CompletionGate` | sole completion authority |
| Durable state | `ParallelSubagentRepository` | immutable digests, monotonic state, append-only events |

## Fail-closed conditions

Stale Parent, dirty Parent, base mismatch, dependency failure, path/symbol overlap,
artifact ownership mismatch, Child HEAD drift, verification failure, cancellation,
restart ambiguity, merge conflict, or cleanup uncertainty never publishes Parent.
Integration and Child cleanup are attempted under shielded existing lifecycle
paths; cleanup uncertainty remains `QUARANTINED` rather than being reported as
closed. Restart reconciliation marks unfinished records `UNKNOWN`; it never
infers success from an interrupted process.

## Non-goals

This ADR does not add recursive delegation, a mesh/DAG engine, a second AgentLoop,
AI merge resolution, hooks/MCP/browser coding, remote/distributed Worktrees, or a
parallel CompletionGate. The first version exposes an explicit trusted
`ChildWorker` adapter seam; production tool/verification authorities remain the
existing composed services.

## Implementation and evidence

The contracts, coordinator, scheduler, child lifecycle, merge coordinator,
durable repository and recovery projection live under
`python/khaos/subagents/`. Migration v29 owns the durable M8.5 tables. The
workspace manager records artifact-to-changed-file metadata so merge admission
can prove that a result did not hide an out-of-scope file in a valid-looking
artifact. Regression coverage is in
`python/tests/subagents/test_m8_5_parallel_worktrees.py`, with runtime wiring and
M8.3 merge-verification coverage in the existing runtime/coding test modules.
