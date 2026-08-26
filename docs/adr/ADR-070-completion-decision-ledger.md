# ADR-070: CompletionDecision Durable Ledger

- 状态：已定（M7.1.4）
- 日期：2026-08-26
- 范围：Agent control-plane completion evidence contract

## Context

`GoalSpec` declares what a coding task is asking for. `AgentCognitiveState` records the
current engineering phase, while `TaskStatus` remains the externally visible task lifecycle.
The later Completion Gate needs a durable, restart-safe record of each evaluation without
letting a model claim or a ledger row silently become task authority.

## Decision

### 1. Decision is an immutable evaluation record

`CompletionDecision` is one immutable snapshot. It is not a `TaskStatus` transition, an
evaluator, or a Completion Gate. An `outcome=COMPLETE` row is passive evidence in M7.1.4 and
does not project `TaskStatus.COMPLETED`. `PROPOSE_COMPLETION` and END_TURN interception are
deferred to later batches.

### 2. Separate declaration, assessment, and authority

`GoalSpec` remains the immutable declaration. `RequirementAssessment` and
`CriterionAssessment` contain only an ID, snapshot status, and typed evidence references;
they do not copy `required`, description, or source. Required semantics remain owned by the
bound GoalSpec and will be interpreted by M7.1.5.

`CompletionEvidenceRef` is a bounded reference (`kind`, `ref_id`, optional digest). A
`VERIFICATION_RUN` kind does not imply trusted or authoritative verification. Authority comes
only from the actual evidence owner and future evaluator/verification composition. No
`trusted`, `authoritative`, or `verified` caller flag is part of this contract.

### 3. Closed outcome and issue vocabulary

The only outcomes are `COMPLETE`, `REPLAN`, `BLOCKED`, and `FAILED`. `continuation_possible`
is derived from the outcome (`REPLAN` and `BLOCKED` are continuable; the other two are not).
There is no free `recoverable` boolean and no `CompletionDecision.is_complete()` proof method.
Issues are typed by `CompletionIssueCode`; their bounded human-readable summary is explanatory
only and cannot grant authority.

### 4. Input binding

Every decision binds `task_id`, `goal_spec_id`, `goal_spec_digest`, cognitive state,
`control_state_version`, `task_status_at_evaluation`, and optional `workspace_id`. This is a
snapshot fence for future stale-decision handling. M7.1.4 does not invent workspace generation
or base-SHA concepts. The task-level workspace snapshot is read from the owner-scoped
`coding_tasks.state_json.metadata.workspace_id` projection, which is currently the only stable
task/workspace binding persisted by the task path. The repository strictly decodes that
projection and rejects a decision whose `workspace_id` does not match it before append; missing
on both sides is the valid unbound case. This projection is used only for decision-input
identity consistency, not as a Workspace authority. A future gate must stale-check the current
task projection again after append.

### 5. Deterministic digest

`decision_digest` reuses `khaos.security.protocol_boundary.canonical_digest`. It covers the
semantic input snapshot, outcome, assessment snapshots, evidence references, and issues. It
excludes `decision_id`, `principal_id`, `project_id`, `decision_sequence`, and `created_at`
because storage identity/order is not decision meaning. Identity-keyed assessment collections
and all evidence collections use stable canonical ordering. Canonical JSON is a closed schema
and all semantic nested values are frozen dataclasses, Enums, or tuples in memory.

### 6. v18 append-only persistence

Migration v18 adds:

```sql
agent_completion_decisions(
    decision_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    decision_sequence INTEGER NOT NULL,
    schema_version INTEGER NOT NULL,
    decision_digest TEXT NOT NULL,
    canonical_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(task_id, decision_sequence)
)
```

The database has `BEFORE UPDATE` and `BEFORE DELETE` abort triggers. The repository has no
update/delete API. Repeating a `decision_id` is an explicit conflict even when the semantic
digest is identical; there is no silent overwrite or `INSERT OR REPLACE`. Sequence allocation
and append occur under the shared `BEGIN IMMEDIATE` transaction owner; callers cannot supply a
sequence number. Reads require principal/project scope, and foreign rows are indistinguishable
from missing rows.

### 7. No historical backfill

v18 creates zero decisions for pre-existing `COMPLETED`, `FAILED`, `BLOCKED`, or other tasks.
Legacy status, test results, END_TURN text, and historical assistant claims are not converted
into completion evidence.

### 8. Security boundary

The decision contract grants no tool capability, approval, workspace access, sandbox authority,
delegation authority, Memory visibility, or Trusted Verification status. Goal and decision

Workspace binding validation is likewise non-authoritative: it neither grants workspace access
nor changes Sandbox, Approval, Tool, execution-lease, or Trusted Verification authority. It only
prevents a completion snapshot from claiming a different durable task workspace. Completion
Gate remains responsible for repeating this binding check when it later considers projecting a
decision into task lifecycle state. The invariant remains: the Agent may describe desired work,
but the Security Runtime decides what work is allowed.

### 9. M7.1.3 debt carried forward

This batch does not add a dedicated event for every cognitive CAS transition. Future stale
controller handling must use `CognitiveTransitionResult`/an authoritative current snapshot,
not `TaskManager.load()` as a refresh primitive. A pre-existing `UNINITIALIZED` task must be
explicitly bootstrapped before a cognitive-state-dependent controller uses it.

## Consequences

The ledger is restart-readable and auditable while completion authority remains deliberately
unimplemented. The later CompletionEvaluator/Gate must validate evidence ownership and re-check
the task/GoalSpec/cognitive snapshot before any lifecycle projection.

## Deferred

- CompletionEvaluator and GoalAssessment
- Completion Gate and PROPOSE_COMPLETION flow
- TaskStatus projection
- Planning, Recovery/Replan, and Trusted Verification integration
