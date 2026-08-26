# ADR-073: Completion Gate and Atomic Task Completion Projection

- 状态：已定（M7.1.7）
- 日期：2026-08-27
- 范围：Coding task lifecycle projection from the M7 completion control plane

## Context

`StopReason.END_TURN` is a turn-level model signal. `PROPOSE_COMPLETION` records
that the model asked for an evaluation; `CompletionEvaluator` produces a
deterministic semantic `CompletionDecision`; neither is lifecycle authority.
M7.1.7 needs one explicit boundary that can project a successful decision onto
`TaskStatus.COMPLETED` without allowing assistant prose, assessments, or an
in-memory decision object to do so.

## Decision

### 1. The Gate is the only successful control-plane projection owner

The successful coding path is:

```text
END_TURN
  -> PROPOSE_COMPLETION
  -> CompletionEvaluator
  -> append-only CompletionDecision
  -> CompletionGate
  -> fresh atomic checks
  -> TaskStatus.COMPLETED
```

`CompletionDecision.COMPLETE` is necessary but not sufficient. `REPLAN`,
`BLOCKED`, and `FAILED` remain passive decision outcomes in this batch and are
never projected by the Gate. The Gate does not automatically project those
outcomes to `TaskStatus`.

The successful branch in `AgentLoop._finalize_task()` was removed. Existing
MAX_TURNS, MAX_BUDGET, cancellation, internal-error, and known failing
Verify-Fix paths retain their independent failure/cancellation semantics.

### 2. Decision reload and authority are separate

The Gate reloads the immutable decision through the owner-scoped
`CompletionDecisionRepository`. It never treats a caller-held decision object
as authoritative. It then loads the canonical owner-scoped GoalSpec and asks a
typed `CompletionGateAuthorityPolicy` for a `CompletionAuthorityResult` bound
to:

```text
task_id + goal_spec_id + goal_spec_digest + decision_id + decision_digest
```

`CompletionAuthorityResult` contains no caller-set `trusted`, `verified`, or
`authoritative` flag. A decision, SATISFIED assessment, evidence kind, or fact
provider cannot mint authority. The production default is
`FailClosedCompletionAuthorityPolicy`, which returns
`AUTHORITY_INSUFFICIENT` until a designated trusted-evidence composition is
available. Tests may compose a synthetic, explicitly bound policy directly;
`ProductionRuntimeConfig` does not expose arbitrary policy injection.

The SQL repository's projection entry point additionally requires an internal
Gate-owner fence. Constructing an `AUTHORIZED` result and calling the lower
level repository directly is not a lifecycle capability; only the composed
Gate can cross that boundary.

### 3. Fresh checks and projection share one transaction

`CompletionGateRepository.project_completion()` owns the lifecycle SQL. Inside
the shared `Database.transaction()` (`BEGIN IMMEDIATE`) it reloads and
validates:

- decision identity, owner/project, canonical JSON, digest, and sequence;
- the task's owner/project and physical `cognitive_state`,
  `control_state_version`, and `status` columns;
- the canonical GoalSpec identity/digest and owner binding;
- the durable `state_json.metadata.workspace_id` projection;
- the decision's complete input snapshot against all current values.

Only the explicit active `running` task status is currently eligible. Terminal
tasks are never resurrected; a blocked task is not silently converted to
completed. The final `UPDATE` repeats owner, task status, cognitive state, and
control-version predicates and requires exactly one affected row. The task's
`state_json.status` and `updated_at` compatibility projection are updated in
the same transaction so physical and projection reads cannot disagree after a
successful commit.

An append-time match is not a permanent lease. A later Gate call repeats all
checks, including workspace binding. A race that changes the cognitive version,
state, task status, GoalSpec, or workspace before the projection returns
`STALE`; a second call after a successful projection returns
`ALREADY_TERMINAL` and cannot perform a second transition.

### 4. Turn lifecycle remains separate

After a recorded proposal the AgentLoop evaluates the Gate and appends a
bounded `completion.gated` event to the existing TurnCoordinator ledger. The
normal event order is:

```text
turn.started
completion.proposed
completion.evaluated
completion.gated
turn.completed
```

`turn.completed` is valid while the coding task remains `RUNNING` for
`NOT_COMPLETE`, `STALE`, or `AUTHORITY_INSUFFICIENT`. No event contains model
chain-of-thought or raw tool/test logs.

### 5. Cognitive state is observed, not fabricated

The Gate binds the decision's existing cognitive snapshot. It does not invent
`COMPLETION_CHECK` or manufacture an `UNDERSTANDING` -> `IMPLEMENTING` ->
`VERIFYING` -> `REVIEWING` transition path. Cognitive-state transition legality
and CAS remain owned by M7.1.3.

## Security consequences

The Gate grants no tool capability, Approval capability, workspace access,
Sandbox authority, execution lease, delegation authority, Memory visibility,
or Trusted Verification status. Its only new authority is the narrowly
bounded, owner/project/task-bound successful lifecycle write after all fresh
checks pass. Workspace binding is used only as a completion snapshot integrity
fact, not as an access grant.

## Consequences and deferred work

- Production coding END_TURN has zero direct successful `COMPLETED` writes.
- Completion outcomes other than COMPLETE remain passive.
- Trusted Verification composition is not implemented in M7.1.7.
- Planning integration, Recovery/Replan execution, and state-aware tool or
  memory routing remain later work.
- Future Gate revisions must preserve the final stale check even after trusted
  verification is integrated.
