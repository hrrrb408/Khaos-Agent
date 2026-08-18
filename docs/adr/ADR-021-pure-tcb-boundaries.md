# ADR-021: Pure TCB Boundaries for Protocol and Lifecycle State

**Status:** Accepted for M6 implementation

## Context

The RPC server, authority daemon, and execution owners necessarily contain
I/O, locks, and orchestration. Keeping their security meaning in implicit
Python object state makes it difficult to test canonical bytes, state
transitions, exact effects, and terminal cleanup independently.

## Decision

`python/khaos/security/protocol_boundary.py` owns the pure parts of the
security contract: canonical JSON/digesting, closed schema validation,
protocol negotiation, exact effect bindings, legal authority receipt
transitions, and resource-owner lifecycle transitions. It has no sockets,
subprocesses, database handles, or mutable service owners.

The authority daemon routes receipt state assignments through
`require_receipt_transition`; RPC and receipt protocol code uses the shared
canonical serializer. Resource owners must satisfy the `CLOSED` postcondition
through an external terminal proof and an empty ownership registry.

## Consequences

- Property-based tests can exercise security semantics without starting an
  Agent or authority service.
- A new state transition or wire field must be added to a small pure contract
  and its tests, rather than being introduced through an ad-hoc assignment.
- Pure tests do not become native-kernel or independent-governance evidence;
  those remain separate CI/evidence classes.
