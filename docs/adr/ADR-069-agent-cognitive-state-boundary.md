# ADR-069: Agent Cognitive State Boundary and CAS Persistence

- Status: accepted
- Date: 2026-08-26
- Scope: M7.1.3 Agent Cognitive State & CAS Transition Foundation

## Context

Khaos has three different kinds of state that must not be collapsed into one
field:

1. `TurnPhase` describes the low-level orchestration phase of one runtime
   turn.
2. `TaskStatus` describes the durable lifecycle of a coding task, including
   `BLOCKED`, `COMPLETED`, `FAILED`, and `CANCELLED`.
3. `AgentCognitiveState` describes the engineering phase used by future
   planning, verification, recovery, and completion controllers.

`CompletionDecision` remains a later completion-gate contract.  A cognitive
phase is not evidence that a task is complete and is not a replacement for
task lifecycle status.

## Decision

### Closed cognitive vocabulary and transition graph

`AgentCognitiveState` contains only:

`UNINITIALIZED`, `UNDERSTANDING`, `EXPLORING`, `PLANNING`, `IMPLEMENTING`,
`VERIFYING`, `DIAGNOSING`, `RECOVERING`, `REPLANNING`, `REVIEWING`, and
`COMPLETION_CHECK`.

`BLOCKED`, `COMPLETED`, `FAILED`, and `CANCELLED` remain exclusively owned by
`TaskStatus`; they are not cognitive states.  `UNINITIALIZED` is a
bootstrap/migration state and is never inferred from task history.

The immutable `LEGAL_COGNITIVE_TRANSITIONS` table in
`python/khaos/agent/control/state.py` is the only transition graph.  An
explicit self-transition returns `UNCHANGED` and does not increment a
version.  No caller may widen the graph with an arbitrary target-state check.

### Separate pure machine and SQL owner

`AgentCognitiveStateMachine` owns transition legality only.  The
`AgentControlStateRepository` owns the SQL read/CAS operation only.  The
TaskManager is the application seam that invokes the pure machine first and
then the repository.  The repository does not define a second transition
graph.

The canonical SQL CAS predicate is owner-bound and fail-closed:

```sql
UPDATE coding_tasks
SET cognitive_state = ?,
    control_state_version = control_state_version + 1
WHERE id = ?
  AND principal_id = ?
  AND project_id = ?
  AND cognitive_state = ?
  AND control_state_version = ?
  AND status NOT IN ('completed', 'failed', 'cancelled')
```

CAS results are typed as `UPDATED`, `UNCHANGED`, `NOT_FOUND`,
`STALE_VERSION`, `STALE_STATE`, `ILLEGAL_TRANSITION`, or `TERMINAL_TASK`.
Foreign owner rows are intentionally indistinguishable from `NOT_FOUND`.
`OWNER_MISMATCH` remains part of the result vocabulary for future APIs that
can preserve the same fail-closed disclosure policy.

### Independent SQL columns

Migration v17 adds:

```sql
cognitive_state TEXT NOT NULL DEFAULT 'uninitialized'
control_state_version INTEGER NOT NULL DEFAULT 0
```

The columns are the canonical current control state.  `control_state_version`
is a CAS fence for this control-state domain only; it does not claim to fence
all mutable `coding_tasks` fields such as files, test history, metadata, or
TaskStatus.  The ordinary TaskManager persistence path does not update either
column.  A JSON value, when present for compatibility, is only a read
projection overwritten by the physical SQL columns on load.

The generic `state_version` name is deliberately deferred.  Existing task
file, test, metadata, and lifecycle writes do not share this CAS owner, so
calling the column `state_version` would falsely imply a row-wide write fence.
Future work may introduce a broader CAS domain only with an explicit owner
and migration contract.

### Creation and restart semantics

New task creation continues to use the existing GoalSpec transaction and
creates the SQL defaults `UNINITIALIZED/0`.  The AgentLoop's explicit coding
task start boundary performs `UNINITIALIZED → UNDERSTANDING` through the
dedicated owner.  Tool names do not infer cognitive state.

On restart, existing TaskManager behavior remains unchanged: active
`TaskStatus` values become `BLOCKED`.  The persisted cognitive state and CAS
version are preserved.  A legacy task is restored as `UNINITIALIZED/0`; no
`TaskStatus` or test history is used to infer a cognitive completion/failure
state.

### Security boundary

Cognitive state is descriptive control-plane state, not authority.  It cannot
grant tools, bypass approval, alter workspace access, become sandbox or
delegation authority, change memory visibility, or recover a terminal task.
Security Runtime and the existing Approval/Workspace/Sandbox boundaries remain
the authority for allowed effects.

## Consequences

- Concurrent managers sharing an owner can race safely: exactly one matching
  expected state/version wins the SQL CAS.
- A stale manager must refresh before making another decision and cannot
  overwrite the database's cognitive state with its old projection.
- The control-state version can evolve independently of TaskManager's legacy
  JSON persistence, avoiding a false claim that one counter protects the
  whole task row.
- The full planning, verification, recovery, completion-gate, and cognitive
  controller integrations remain deliberately deferred to later batches.
