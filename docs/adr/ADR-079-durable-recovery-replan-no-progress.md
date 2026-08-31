# ADR-079: Durable Recovery, Replanning, and No-Progress Control Plane

**Status:** Accepted — M7.5

## Context

M7.1–M7.4 established separate durable contracts for the user goal,
cognitive phase, completion decisions, completion projection, context, plans,
and trusted verification.  A failed verification or a repeated failure still
needs a bounded control-plane response.  Asking the model to retry is not a
durable recovery policy: it loses budget state on restart, cannot provide a
cross-runtime race fence, and can turn an unchanged failure into an infinite
loop.

The M4 `RecoveryDirectory` remains a filesystem rollback/restore mechanism.
It is not this agent-level recovery control plane.

## Decision

### Separate observation, decision, and effect

The M7.5 path is deliberately layered:

```text
failure observation
    -> RecoveryInput
    -> RecoveryEvaluator
    -> immutable RecoveryDecision ledger record
    -> RecoveryGate / RecoveryControlCoordinator
    -> cognitive recovery projection
    -> existing PlanningControlCoordinator (only for an explicit REPLAN)
```

`RecoveryEvaluator` is pure and deterministic.  It consumes a typed,
owner-bound snapshot and returns one of the closed actions `NO_ACTION`,
`RECOVER_CURRENT_PLAN`, `REPLAN`, or `BLOCK`.  It does not read the database,
call a model, run a tool, invoke Completion Gate, or grant a capability.

`RecoveryDecision` is immutable history, not an action capability.  It cannot
complete a task, approve an operation, execute a tool, grant a lease, or
change workspace/sandbox authority.  `RecoveryGate` is narrower than
`CompletionGate`: it may publish a recovery cognitive projection, but it may
never write `TaskStatus.COMPLETED` or any other lifecycle terminal state.

`CompletionGate` remains the sole owner of a successful active-task to
`COMPLETED` projection.  `RecoveryGate` and `PlanningControlCoordinator`
cannot replace it.

### Bounded failure identity and negative-signal asymmetry

`NormalizedFailureSignature` contains only bounded typed identities, counts,
digests, and plan identity.  Raw error strings, stack traces, stdout, and
stderr are not stored in a `RecoveryDecision`, its digest, or its event
payload.  Overflow is represented by an explicit count and aggregate digest;
it is never silently discarded.

Untrusted failure observations are allowed to narrow behavior: a failing or
stalled signal may cause diagnosis, recovery, replanning, or blocking.  They
cannot widen behavior into verification success, completion, approval, or
tool authority.  `VerifyFixLoop` remains a low-level compatibility strategy;
its typed no-progress signal is an input to M7.5, not a recovery authority.

The trusted production policy is immutable and bounded.  Recovery attempts,
identical-failure threshold, replan budget, per-turn recovery cycles, and
history reads are all capped by the policy.  Model prose, repository text,
TaskManager compatibility counters, and caller flags cannot raise those
limits.

### Durable ledger and strict history head

Migration v22 adds the owner/project/task-scoped,
append-only `agent_recovery_decisions` ledger.  Its sequence is allocated by
the database writer transaction and is protected by a unique constraint.
The canonical decision and duplicated indexed columns are cross-checked on
every read.  Update and delete triggers make the history immutable.  Existing
M7.1–M7.4 tasks are not backfilled with fabricated recovery decisions.

All production reads are owner and project scoped.  The newest
`recovery_sequence` is the only history head.  A malformed newest record is
an integrity failure; readers and gates never fall back to an older
permissive record.

### Atomic recovery projection

`RecoveryGateRepository` performs the history-head check, task/GoalSpec/plan/
verification/completion binding checks, and cognitive-state CAS in one shared
SQLite writer transaction.  A `RECOVER_CURRENT_PLAN` decision moves a legal
phase to `RECOVERING` and preserves the exact published plan identity.

`REPLAN` first retires the current published plan identity and moves the task
to `REPLANNING` while recording
`last_applied_recovery_decision_id`.  The old `PlanRevision` and any old
verification assessment remain immutable history.  Clearing the projection
does not delete or rewrite either record.  A later plan must be produced by
the existing `PlanningControlCoordinator` from fresh context and published
through its existing plan-publication fence.  A newer recovery history head
invalidates an older decision before it can mutate cognitive state.

The `RECOVERING -> RECOVERING` case is an acknowledgement of an already
active recovery projection.  It records the applied decision marker without
incrementing `control_state_version`; this preserves the M7.1.3
self-transition invariant.

`latest_plan_revision_id` is planning history.  It is never substituted for
`published_plan_revision_id`, which is the current implementation identity.

### Completion and verification boundaries

Completion history is consumed only through the passive
`CompletionRecoveryService`.  A completion `REPLAN`, external blocker, or
failure-review state becomes a typed negative recovery signal; it cannot
become a successful lifecycle transition.  Trusted Verification assessments
are also read-only evidence.  Retiring a published plan makes an assessment
bound to the old plan non-current; no old assessment is replayed as a new
authority.

Recovery never uses a passing low-level test observation as completion
authority.  It also never calls the legacy
`khaos.coding.verification.pipeline`, which remains production-forbidden.

### TaskStatus and approval semantics

Recovery actions never write `TaskStatus`.  In particular, recovery `BLOCK`
is not silently projected to `TaskStatus.BLOCKED`.  Existing `BLOCKED`
semantics continue to represent approval/interruption behavior, and no
recovery result creates a pending approval or makes a blocked task
approvable.

### Restart and autonomous continuation

`RecoveryControlCoordinator.recover()` is a read-only interpretation of
durable history.  It strictly reloads the physical task snapshot, canonical
GoalSpec, plan/verification/completion bindings, and recovery history.  It
does not append a decision, apply a gate, invoke a planner, call a model, run
a verification, replay an approval, or execute a tool.  Repeated reads over
unchanged durable state are idempotent.

Terminal `TaskStatus` has precedence over recovery history.  An old decision
or gate result cannot resurrect a completed, failed, or cancelled task.  A
restart that changes an active task to the existing approval/interruption
`BLOCKED` state makes a decision captured against the previous running
snapshot stale; it requires fresh evaluation rather than replaying old
authority.

When explicitly composed into `AgentLoop`, recovery may be evaluated only at
bounded control boundaries: a negative completion decision or a typed
no-progress observation.  A successful replan may prepare the next plan, but
M7.5 does not add a general tool router or unbounded autonomous execution
loop.  Recovery facts exposed to the loop are bounded IDs, digests, status,
and reason codes; raw diagnostics and private reasoning are excluded.

Observability events (`recovery.evaluated`, `recovery.applied`,
`recovery.replan.started`, `recovery.replan.completed`,
`recovery.no_progress`, and `recovery.blocked`) are bounded and
non-authoritative.  Event presence never grants a capability.

## Consequences

- Repeated failures consume durable, policy-bounded recovery history instead
  of blindly consuming model turns or legacy fix attempts.
- A replan has an auditable retirement fence: the old published plan cannot
  remain the current implementation identity while a new plan is selected.
- Recovery and planning are safe to race across runtimes because the history
  head, task snapshot, and cognitive CAS are checked by the database writer.
- Recovery can stop with `BLOCK` when it cannot demonstrate progress, but
  this control result does not broaden the historical meaning of
  `TaskStatus.BLOCKED`.
- Restart reconstructs knowledge, not permission.  Any future execution or
  authority must be obtained again through its existing owner and policy
  boundary.

## Non-goals

M7.5 does not implement the M7.6 Tool Router or step enforcement, M7.7
state-aware memory retrieval, M7.8 Sub-Agent v2, M7.9 metrics, a new LLM
planner, automatic approval, Trusted Verification redesign, the legacy
verification pipeline, or a second completion authority.
