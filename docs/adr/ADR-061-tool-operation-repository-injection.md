# ADR-061: Inject the durable tool-operation owner

## Status

Accepted

## Context

`ToolOperationRepository` became the sole SQL owner for durable idempotency,
but `ToolOperationStore` still discovered that owner through `Database`
compatibility methods.  That left a silent in-memory fallback when a runtime
was assembled without a database and allowed maintenance code to call the
same SQL through a second-looking facade.

## Decision

- `Database.tool_operation_repository` is the read-only injection boundary for
  durable operation persistence.
- `ToolOperationStore` receives a `ToolOperationRepository` explicitly and
  fails closed before claiming an operation when the repository is absent.
- `MaintenanceService` consumes the repository directly for bounded pruning.
- The `Database.claim_tool_operation`, `complete_tool_operation`,
  `update_tool_operation_effect_id`, `mark_tool_operation_unknown`, and
  `prune_tool_operations` compatibility methods are deleted.
- Runtime composition passes the repository to `ToolScheduler` and
  `MaintenanceService`; tests use the same repository port rather than
  monkeypatching `Database` method names.

## Consequences

There is one durable operation writer and one terminal protocol.  A runtime
cannot accidentally report durable idempotency while operating only on a
process-local map.  Callers that need operation state must depend on the
repository port, making the SQL boundary visible in type signatures and
contract tests.

