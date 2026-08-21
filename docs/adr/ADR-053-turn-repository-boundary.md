# ADR-053: Turn persistence repository boundary

## Status

Accepted — 2026-08-22

## Context

`TurnCoordinator` is the durable agent-turn state machine. It previously
accepted a `Database` object and called three unrelated database methods
directly. That made the state machine depend on the entire database facade,
made a fake turn store difficult to provide in tests, and encouraged new turn
behaviour to grow inside `database.py`.

## Decision

`TurnCoordinator` depends on the `TurnRepository` protocol only. The protocol
contains the three operations required for a turn lifecycle: recovery,
creation, and compare-and-set event append. `DatabaseTurnRepository` is the
composition adapter for the current shared SQLite database. It is the only
agent-layer component that knows the database method names.

The repository object, rather than the database object, is also the key for
the once-per-owner recovery task. This keeps recovery lifecycle scoped to the
same persistence owner while allowing tests and a future non-SQLite owner to
implement the protocol without importing `Database`.

`AgentLoop` still receives the database for session/message persistence and
constructs one turn adapter by default; callers may inject a repository when
assembling an alternative runtime. This is a composition default, not a
second turn writer.

## Invariants

- The repository owns durable turn writes; `TurnCoordinator` owns only the
  in-memory pairing and terminal state machine.
- Recovery is shared and awaited once per repository object.
- Terminal event and turn status remain one database transaction, enforced by
  the existing database implementation.
- The old database object must not be passed into `TurnCoordinator` or used by
  its event/terminal methods.

## Consequences

The first adapter is intentionally thin so the migration is behaviour
preserving. A later database extraction can move the SQL implementation behind
the same protocol without changing the agent state machine or its tests. New
turn operations must be added to this protocol and its owner tests, not called
ad hoc from `agent/events.py`.
