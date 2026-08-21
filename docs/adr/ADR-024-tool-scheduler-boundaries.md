# ADR-024: Tool scheduler value and budget boundaries

**Status:** Accepted

## Context

`python/khaos/tools/scheduler.py` is the only scheduler authority, but it had
also become the owner of every value object emitted by the scheduler and of
the shared hard-budget algorithm. That made a 3,600-line orchestration module
the import target for handlers, event adapters, and tests. Moving a type or
changing a budget rule therefore looked like a scheduler behavior change even
when the execution flow was untouched.

## Decision

- `python/khaos/tools/scheduler_models.py` owns `ToolResult`,
  `ToolExecutionOutcome`, `EffectOutcome`, `PermissionRequest`,
  `SchedulerEvent`, and the effect/delivery constants.
- `python/khaos/tools/budget.py` owns `ToolBudget`,
  `ToolBudgetReservation`, the hard output-budget exception, and bounded
  output measurement.
- `python/khaos/tools/admission.py` owns call normalization, raw phase capture,
  registry resolution, and schema validation. It returns an explicit accepted
  or rejected value and never performs an effect.
- `python/khaos/tools/scheduler.py` remains the sole orchestration authority.
  It imports these types and re-exports them temporarily for compatibility;
  it must not define a second copy.
- The extracted modules do not perform permission checks, persistence,
  process execution, or network access. They are value/concurrency boundaries
  and are safe to test without constructing a runtime.

## Invariants

1. A budget reservation is atomic across serial and parallel dispatch.
2. Every reservation is either committed with bounded output accounting or
   released before the caller returns.
3. A `ToolResult` separates effect state from delivery state; projection or
   audit degradation must not be represented as an ordinary retryable failure.
4. Legacy imports from `khaos.tools.scheduler` resolve to the exact canonical
   classes and constants, so there is one writer and one protocol definition.

## Migration

New code imports admission types from `khaos.tools.admission`, value objects
from `khaos.tools.scheduler_models`, and budget types from
`khaos.tools.budget`. The compatibility exports remain until all first-party
callers have migrated; their removal requires a repository-wide import audit
and a release-note entry.
