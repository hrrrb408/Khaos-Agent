# ADR-060: Give scheduler and tool-operation SQL one repository owner

## Status

Accepted — 2026-08-22

## Context

`Database` is the shared connection and transaction facade, but it had also
accumulated the SQL for scheduled tasks, durable execution leases, the
scheduler operation journal, and the durable `tool_operations` idempotency
ledger.  That made the scheduler and tool runtime depend on a large, mixed
domain implementation and encouraged new SQL to be added beside unrelated
session, memory, and audit code.

## Decision

- `db/repositories/scheduler.py` is the sole SQL owner for
  `scheduled_tasks` and `scheduler_operation_journal`.  It owns owner-scoped
  reads, lease claims, lifecycle CAS transitions, recovery, and journal
  replay markers.
- `db/repositories/tool_operations.py` is the sole SQL owner for
  `tool_operations`.  It owns scope conflict detection, claim/terminal CAS,
  effect identity, orphan quarantine, and bounded tombstone pruning.
- `Database` keeps the released method names as thin compatibility facades
  during caller migration.  Those facades contain no SQL and no second state
  machine.
- `scheduler/repository.py` remains a project-scoped application adapter and
  `tools/operation_store.py` remains the in-process waiter/result owner; they
  must not open SQLite connections or reimplement repository invariants.

## Consequences

Repository contract tests can exercise scope and negative CAS behavior without
constructing an engine or scheduler.  Future scheduler and tool-operation
changes have one obvious writer and one transaction port.  Removing the
compatibility methods later is a caller migration task, not a storage rewrite.
