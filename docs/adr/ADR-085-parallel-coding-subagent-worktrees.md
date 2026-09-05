# ADR-085: Parallel coding subagents use isolated child Worktrees

状态：active（M8.5 Merge Authority Closure Remediation）

## Context

并行 Coding 子代理可以降低等待时间，但不能把 Parent 的 canonical
workspace 变成多个模型共享的可变目录。Child 的成功结果只能证明 Child
快照，不能直接成为 Parent 的完成证据。M8.5 在现有 WorkspaceManager、
EditTransaction、Trusted Git、M8.3 Verification 和 CompletionGate 之上增加
编排层，不复制这些 authority。

## Decision

Parent 只在稳定、干净且 generation/HEAD 匹配时创建 Child。每个 assignment
得到独立的 Git Task Worktree、独立 principal（`subagent:<parent>:<assignment>`）
和有界的 context/budget。Child 的 mutating edit 必须通过现有
EditTransaction/WorkspaceStorageAuthority；Child result 必须包含 base、final
commit、实际 ChangeSet artifact、digest、changed paths 和验证状态。

MergeCoordinator 不运行模型，也不接受模型 prose、summary 或布尔值作为生产
合并 authority。它从已验证的 `SubagentAssignment` + `SubagentResult` 构造
不可变 `MergeCandidateBinding`，并按 assignment priority/id 建立
artifact-bound `MergePlan`。Plan digest 覆盖 Parent task/workspace/principal/
project、generation/HEAD、每个 assignment digest、result digest、Child
workspace/final commit、change digest、artifact SHA-256/length/path、changed
paths、verification evidence，以及候选顺序和冲突分析。执行 merge 时重新构造
binding 并与 Plan 做逐字段的精确比较；任何 drift 都是 `REJECTED_STALE`，不会
静默重建 Plan。

强制发布链为：

```text
Child result/artifact binding
  -> immutable MergePlan
  -> Integration Worktree
  -> M8.3 authoritative integration verification
  -> exact verified integration tree
  -> manager-owned VerifiedIntegrationArtifact
  -> Child + Integration resource barrier
  -> Parent generation/HEAD CAS publication from the frozen artifact
  -> exact Git tree PublicationAttestation
  -> current Parent-generation observation
  -> existing CompletionGate
```

Integration correctness verification 必须在 Parent publication 前完成。验证成功
后，WorkspaceManager 将 ChangeSet artifact 复制、重新校验并登记为独立的
`VerifiedIntegrationArtifact`；发布不再读取可变 Integration Worktree。只有
Child cleanup、Integration cleanup 都得到现有生命周期 owner 的明确 terminal
证明，并且 Parent 仍满足 CAS snapshot 时，才允许进入 publication barrier。

Parent publication 后的 M8.3 调用是 Option A consistency audit：它不能首次决定
代码是否正确，也不能把旧 evidence 直接 rebind 成 Parent evidence。Parent
current-generation 证据由 `PublicationAttestation` 新建，且必须证明
`integration commit^{tree} == parent commit^{tree}`，绑定双方 workspace、commit、
generation、task/project trust domain、source verification evidence、Plan 和
changed paths。Parent audit、attestation 或后续 Repo Intelligence refresh 失败
时，已发生的 Git effect 必须如实保留为 `PUBLISHED_UNVERIFIED` 或
`PUBLISHED_QUARANTINED`；只有完整链路成功才是 `PUBLISHED`。CompletionGate 仍是
唯一 completion authority，M8.5 结果不会绕过或替代它。

## Authority ownership

| Boundary | Owner | M8.5 responsibility |
| --- | --- | --- |
| Assignment/context/budget | `SubagentCoordinator` + typed contracts | bounded immutable input and scheduling only |
| Child Worktree/Git | `WorkspaceManager` + `TrustedGitRunner` | worktree lifecycle, Git plumbing, artifact ownership |
| Child mutation | `EditTransactionService` | generation-bound typed edits and rollback |
| Candidate binding / merge plan | `MergeCoordinator` + typed contracts | exact result/artifact identity and deterministic ordering |
| Integration artifact | `WorkspaceManager` | independent immutable copy, digest/length recheck, lifecycle ownership |
| Resource barrier / publication | `MergeCoordinator` | orchestration invariant; no new permission authority |
| Verification | `AutonomousVerificationCoordinator` (M8.3) | authoritative integration proof and Parent consistency observation |
| Publication integrity | `PublicationAttestation` | exact current Parent tree identity and generation evidence |
| Repository facts | existing `RepoIntelligenceService` | refresh only after publication integrity is established |
| Completion | existing `CompletionGate` | sole completion authority |
| Durable state | `ParallelSubagentRepository` | immutable JSON digests, monotonic state, append-only events |

## Fail-closed and truthful effect conditions

Stale Parent, dirty Parent, base mismatch, dependency failure, path/symbol overlap,
artifact ownership mismatch, candidate/result/artifact drift, Child HEAD drift,
integration verification failure/timeout/infrastructure error, CAS failure,
cancellation before publication, restart ambiguity, merge conflict, or cleanup
uncertainty cannot produce a plain `PUBLISHED` result. Integration verification
failure leaves Parent HEAD, generation, and files unchanged. A Child or Integration
cleanup failure before publication leaves Parent unchanged and produces
`QUARANTINED`; retained resources remain owned for retry/recovery. A failure or
cancellation after the Parent ref effect is observed never becomes plain
`CANCELLED`, `FAILED`, or unpublished `QUARANTINED`: it is recorded as
`PUBLISHED_UNVERIFIED` or `PUBLISHED_QUARANTINED` according to the remaining
integrity/resource evidence.

The shielded lifecycle path drains cleanup to terminal observation before returning.
Restart reconciliation never infers success from an interrupted operation: active
records become `UNKNOWN`, while already quarantined records remain quarantined and
require recovery. The durable v29 JSON/event projection carries Plan, candidate
binding, verified artifact, barrier, publication, attestation, and cleanup digests;
no v30 schema migration is required for this remediation.

## Non-goals

This ADR does not add recursive delegation, a mesh/DAG engine, a second AgentLoop,
AI merge resolution, hooks/MCP/browser coding, remote/distributed Worktrees, a
parallel CompletionGate, or M8.6 UX/checkpoint/rewind/supervision UI. The first
version exposes an explicit trusted `ChildWorker` adapter seam; production
tool/verification authorities remain the existing composed services.

## Implementation and evidence

The contracts, coordinator, scheduler, child lifecycle, merge coordinator, durable
repository and recovery projection live under `python/khaos/subagents/`. The
WorkspaceManager owns the independent verified publication artifact. Regression
coverage is in `python/tests/subagents/test_m8_5_parallel_worktrees.py`, with
runtime wiring and M8.3 merge-verification coverage in the existing runtime/coding
test modules. The remediation evidence and CI boundary are recorded in
`docs/m8.5-merge-authority-remediation-closure-report.md`.
