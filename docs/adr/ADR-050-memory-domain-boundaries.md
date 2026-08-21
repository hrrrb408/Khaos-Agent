# ADR-050: Give durable memory one domain boundary

## Status

Accepted — 2026-08-22

## Context

`python/khaos/memory/store.py` historically owned several unrelated concerns:
SQLite calls, principal/project namespace mapping, FTS search, access-frequency
mutation, TTL cleanup, conflict resolution, and regex-based proactive
extraction.  That made a small policy change require reasoning about database
transactions and made it easy for RPC callers to bypass the store (notably
for delete-by-id and unscoped access-frequency updates).

The memory contract also has security properties: private memories must be
principal-scoped, shared memories must remain project-scoped, and every runtime
write must carry the project identity.  These properties should be visible in
types and ports rather than repeated as keyword arguments in every method.

## Decision

The memory subsystem is split into the following owners:

| Owner | Responsibility |
| --- | --- |
| `memory/models.py` | `Memory`, `MemoryScope`, `MemoryConfidence`, and row conversion |
| `memory/ownership.py` | immutable principal/project binding and private/session/shared namespace rules |
| `memory/repository.py` | `MemoryRepository` port and the only SQLite adapter used by the domain |
| `memory/conflict.py` | pure confidence/timestamp conflict policy |
| `memory/decay.py` | pure TTL expiration selection |
| `memory/extraction.py` | bounded candidate extraction from user messages |
| `memory/retrieval.py` | deterministic L0/L1/L2 classification and ranking |
| `memory/store.py` | domain facade: validation, repository orchestration, and audit events |
| `memory/manager.py` | injection formatting, token budget, cross-mode intent, and extraction orchestration |

`MemoryStore(db, ...)` remains a one-release compatibility constructor.  It
immediately wraps the database in `SqliteMemoryRepository`; the store never
calls database methods directly.  New callers may inject a repository port.
All id-based deletes and touches use the bound principal and project.  The
RPC service routes deletion through the same store boundary as local callers.

## Consequences

* Policy modules can be unit-tested without a database or runtime.
* Ownership and namespace rules have one implementation and negative tests.
* The repository port can be replaced by a different durable backend without
  changing domain code.
* The compatibility constructor must be removed after production callers and
  tests inject the port; its removal is tracked in the maintainer architecture
  handbook.
* Context-bound audit sinks remain a follow-up for RPC principals.  The runtime
  factory already injects its principal-bound `AuditLogger`; the optional sink
  keeps older test construction side-effect free.

## Verification

The boundary suite covers:

* no direct SQLite calls in `MemoryStore`;
* equal-confidence/equal-timestamp conflicts remain unresolved;
* touch cannot mutate another principal/project's row;
* mutation audit events are emitted when an audit sink is supplied;
* unknown namespaces and session identities fail closed.

