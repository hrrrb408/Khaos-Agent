# ADR-055: Immutable routing table owner

## Status

Accepted — 2026-08-22

## Context

`ModelRouter` stored function rules in a mutable dictionary. The dictionary
was read while asynchronous calls were resolving models and could be mutated
from another setup path. `RoutingRule.fallback_models` was also a mutable list,
so a caller could change a fallback chain after registration.

## Decision

`RoutingTable` is an immutable value containing a mapping of function keys to
immutable `RoutingRule` values. Fallback chains are normalized to tuples.
`ModelRouter.set_rule` creates a new table and swaps one reference atomically;
resolution reads one table snapshot and never mutates it. The old `_rules`
attribute remains only as a read-only mapping-proxy compatibility view.

The table validates non-empty function/primary model values and rejects a key
that disagrees with `RoutingRule.function`. Provider availability and fallback
selection remain the responsibility of `ModelRouter`; the table contains no
I/O or provider state.

## Invariants

- A resolve operation sees either the old complete table or the new complete
  table, never a partially updated dictionary.
- A registered fallback chain cannot change through an aliased input list.
- Routing state has one writer (`ModelRouter.set_rule`) and one value owner
  (`RoutingTable`).
- Provider errors remain `ModelUnavailableError`; table validation errors are
  configuration errors and are not silently ignored.

## Consequences

Routing tests can exercise table replacement without network clients or
providers. A future durable/config-backed routing owner can publish a new
`RoutingTable` without changing the asynchronous model-call state machine.
