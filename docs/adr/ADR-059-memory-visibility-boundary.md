# ADR-059: Make memory visibility an explicit value object

## Status

Accepted — 2026-08-22

## Context

The memory schema has three namespaces: principal-private (`private`),
session-private (`session`) and project-shared (`shared`).  The first memory
boundary extracted SQL and principal/project ownership, but repository list
and FTS queries still received only a principal and project.  That made a
generic `list_all()` or `search()` include session rows for the same principal.
The same ambiguity affected row-id `touch` and `delete_by_id`: a caller that
already knew another session's row id could attempt a mutation without naming
the session it intended to operate in.

## Decision

`memory/ownership.py` owns the immutable `MemoryVisibility` value object:

* `MemoryVisibility.durable()` means principal-private and project-shared rows
  with `session_id=''`; it is the default read/mutation view.
* `MemoryVisibility.for_session(session_id)` means exactly one session-private
  partition and rejects an empty session id.
* `for_namespace()` validates that only the session namespace carries a
  session id, preventing malformed combinations before SQL is reached.

`MemoryStore` passes the same visibility object to the repository for
`list_by_scope`, `list_all`, FTS `search`, `touch`, `delete_by_id`, and decay.
`MemorySqlRepository` builds one ownership/namespace/session predicate for all
of those operations.  `MemoryManager.inject()` explicitly requests the durable
view; session-private memory is never mixed into a generic prompt by default.

## Consequences

* Session-private memories are not visible through durable list/search or
  generic prompt injection.
* A session-specific feature must name the session in its type-level call
  boundary, making cross-session mistakes straightforward to test.
* The repository remains the SQL owner; visibility policy is represented once
  in the domain and applied consistently to reads and row-id mutations.
* Existing callers retain the durable default.  No schema migration is
  required because the namespace and session columns already exist.

## Verification

The memory boundary suite verifies:

* malformed durable/session visibility values fail closed;
* durable list/search exclude session-private rows;
* explicit session views return only the requested session;
* session `touch` and `delete_by_id` cannot cross into another session; and
* `MemoryManager.inject()` excludes session-private rows.
