# ADR-064: Scheduler execution and recovery owners

## Status

Accepted — 2026-08-22

## Context

`CronEngine` had accumulated lifecycle control, executor admission, tick
selection, durable terminal writes, journal replay, lease recovery and task
loading in one module. That made a change to one state transition difficult to
review: the same file appeared to own both live execution and crash recovery.
The scheduler already has a repository port and a pure due selector, so the
remaining split must preserve the existing state machine and durable CAS
semantics rather than introduce another facade or a second SQL path.

## Decision

`CronEngine` remains the public lifecycle facade and composition root. It owns:

- construction of shared state and `ScheduledTaskRepository`;
- `start()`/`stop()` and the explicit lifecycle state machine;
- task creation and user control operations (`create`, `pause`, `resume`,
  `remove`, `get`, and principal/lifecycle checks);
- the execution epoch bump used by control operations.

`python/khaos/scheduler/execution.py` is the sole execution owner. Its
`SchedulerExecution` mixin owns executor arity adaptation, in-flight
cancellation, due-task publication, execution leases, terminal state
publication, per-task locks, and execution persistence. It may call recovery
ports exposed by the composed engine, but it does not own lifecycle startup or
database schema/SQL.

`python/khaos/scheduler/recovery.py` is the sole recovery owner. Its
`SchedulerRecovery` mixin owns `PendingPersistence`, pending-marker
reconciliation, scheduler-operation journal replay, snapshot-drift
quarantine, startup/task loading, and expired-lease recovery. It consumes the
same repository and execution methods supplied by the composed engine; it does
not start a tick loop or create a second executor registry.

Multiple inheritance is used only as an explicit composition mechanism:
`CronEngine(SchedulerRecovery, SchedulerExecution)`. The mixins contain no
independent `__init__` and all state remains allocated by `CronEngine`, so
existing callers retain the same object and private-method behavior while the
implementation has one physical owner per responsibility.

## Invariants and boundaries

1. The scheduler state machine and fail-closed shutdown/degraded/quarantine
   behavior are unchanged.
2. `ScheduledTaskRepository` remains the only scheduler SQL/persistence port;
   execution and recovery owners must not open connections or duplicate SQL.
3. Execution and recovery owners share the engine's task maps, epoch fences,
   persistence markers and per-task locks. A moved method must not be replaced
   by a wrapper that leaves a second implementation in `engine.py`.
4. The cancellation budget is owned by `execution.py`; recovery reads it at
   call time so bounded lease revocation and tests use the same budget without
   an import cycle.
5. `PendingPersistence` and `_task_from_row` are owned by `recovery.py`; the
   old engine-module exports are removed after caller migration.

## Verification and removal record

- `python/tests/scheduler/test_scheduler_owner_boundaries.py` asserts the
  module owner of lifecycle, execution and recovery methods and rejects the
  removed engine exports.
- The existing cron acceptance suites continue to exercise the full state
  machine, CAS, journal, lease, cancellation and drift behavior after the
  move; only patch/import module paths were migrated to their named owners.
- Generated reachability and security inventories must be regenerated after
  this ADR is landed so both owner modules are fingerprinted as production
  code.
