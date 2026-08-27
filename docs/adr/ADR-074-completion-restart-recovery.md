# ADR-074: Durable Completion/Replan Restart Recovery

- 状态：已定（M7.1.8）
- 日期：2026-08-27
- 范围：Coding task completion-control continuation after process restart

## Context

M7.1.4 introduced an append-only `CompletionDecision` ledger and M7.1.7
introduced the Completion Gate.  Those records describe what happened during
an evaluation attempt; they are not restart capabilities.  A process may
restart after a `REPLAN`, an authority denial, a stale Gate attempt, or before
the Gate can run.  The next runtime must recover that control-plane knowledge
without replaying an old decision, authority result, model claim, or
conversation cache.

## Decision

### 1. History and continuation are separate

`CompletionDecision` remains immutable evaluation history.  The existing
`completion.gated` event in the durable `agent_turns` /
`agent_turn_events` ledger remains bounded Gate history.  M7.1.8 adds the
read-only `CompletionRecoveryResolver`, which deterministically interprets a
current durable task snapshot, the latest decision, and the exact decision-
bound Gate event as a `CompletionContinuationState`.

The continuation vocabulary is separate from both `TaskStatus` and
`AgentCognitiveState`:

```text
NO_DECISION
REPLAN_REQUIRED
REEVALUATION_REQUIRED
AUTHORITY_REQUIRED
EXTERNAL_BLOCKED
FAILURE_REVIEW_REQUIRED
TERMINAL_COMPLETED
TERMINAL_FAILED
TERMINAL_CANCELLED
INTEGRITY_ERROR
```

No continuation value invokes a model, planner, evaluator, Gate, recovery
strategy, or lifecycle transition.  M7.1.8 reconstructs state only; later
batches own continuation execution.

### 2. Durable reads are owner-scoped and fail closed

`CompletionRecoveryService` loads the canonical GoalSpec through the existing
owner-scoped repository and reads the current task snapshot through the
existing `CompletionDecisionRepository.read_current_task_snapshot()` seam.
Physical SQL status, cognitive state, and control-state version remain
authoritative; the durable task `metadata.workspace_id` projection is only a
snapshot binding fact.  No in-memory `TaskManager` cache, assistant prose,
Memory, or model confidence participates in recovery.

The latest CompletionDecision is selected by durable `decision_sequence`, not
`created_at`.  If the latest active-task decision is malformed, recovery
returns `INTEGRITY_ERROR` and never falls back to an older permissive decision.
Terminal physical `TaskStatus` has lifecycle precedence over historical
decisions, so a terminal task cannot be resurrected by a `REPLAN` or
`COMPLETE` record.

### 3. Gate history reuses the existing event ledger

M7.1.8 does not add a v19 table.  `Database.list_completion_gate_history()`
joins `agent_turns` and `agent_turn_events` with task, principal, and project
predicates and returns a bounded typed transport record.  The recovery module
strictly validates the event type, JSON object shape, required binding keys,
Gate status, and task identity.  An event is relevant only when its
`task_id`, `decision_id`, and `decision_digest` exactly match the current
decision.  Malformed or mismatched events are not authority; a COMPLETE
decision without a usable matching Gate event becomes
`REEVALUATION_REQUIRED`.

The previously returned `CompletionAuthorityResult` is never persisted or
replayed as a bearer token.  A successful Gate event is history only; a future
Gate attempt must reacquire current authority and repeat current stale checks.

### 4. Deterministic continuation interpretation

For a non-terminal task, the resolver maps the latest durable decision as
follows:

```text
REPLAN  -> REPLAN_REQUIRED
BLOCKED -> EXTERNAL_BLOCKED
FAILED  -> FAILURE_REVIEW_REQUIRED
```

For `COMPLETE`, the current task snapshot must exactly match the decision's
GoalSpec, cognitive state/version, TaskStatus, and workspace binding.  A
mismatch, missing matching Gate event, stale Gate, or any non-successful Gate
result produces `REEVALUATION_REQUIRED`.  A matching
`AUTHORITY_INSUFFICIENT` Gate history produces `AUTHORITY_REQUIRED`.  No
result is treated as a replayable completion capability.

### 5. Restart and old COMPLETE decisions

The existing `TaskManager.load()` restart safety rule is unchanged: an active
task is durably changed to `BLOCKED`.  An old COMPLETE decision captured while
the task was `RUNNING` is therefore stale after restart and resolves to
`REEVALUATION_REQUIRED`; recovery does not call the Gate again.  A successful
Gate projection that already made the physical task `COMPLETED` resolves to
`TERMINAL_COMPLETED`.  `REPLAN_REQUIRED` is never encoded by abusing
`TaskStatus.BLOCKED`.

### 6. Explicit cache reconciliation is not restart loading

`TaskManager.refresh_projection(task_id)` is a read-only, owner-scoped cache
reconciliation API.  It decodes the current durable row and canonical
GoalSpec, including the bounded workspace projection, replaces only the
in-memory projection, and fails closed on malformed durable projections.  It
never persists a status, applies active-to-BLOCKED restart semantics, or turns
a stale cache into a write authority.  It is distinct from `load()`, whose
purpose includes interruption marking.

### 7. Bounded context projection and idempotency

When composed into `AgentLoop`, recovery is exposed only as a bounded typed
fact containing task identity, latest decision identity/digest/sequence,
continuation state, outcome, and Gate status.  Raw ledger payloads, evidence
bodies, logs, and private reasoning are excluded.  Repeating recovery against
unchanged durable records performs no writes, appends no decisions, and
starts no Gate attempt; the same inputs produce the same continuation state.

## Security consequences

Recovery grants no Tool capability, Approval capability, Workspace access,
Sandbox authority, execution lease, delegation authority, Memory visibility,
Trusted Verification status, or Completion authority.  It is knowledge of
durable control state, not permission.  Owner and project predicates remain
part of every production read, and malformed history fails closed.

## Consequences and deferred work

- Existing M7.1.1--M7.1.7 lifecycle, Gate, and terminal-monotonicity rules are
  unchanged.
- No new database migration is required; the existing turn-event ledger is
  the Gate-history source.
- M7.1.8 does not execute replanning, recovery strategies, model calls,
  authority reacquisition, or automatic blocker/failure projections.
- Planning integration, Recovery/Replan execution, Trusted Verification, and
  M7.1.9 remain future work.
