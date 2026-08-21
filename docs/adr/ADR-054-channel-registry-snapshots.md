# ADR-054: Channel registry writer and reader snapshots

## Status

Accepted — 2026-08-22

## Context

`ChannelRegistry` held mutable configuration and health records in a plain
dictionary. `get()` and `list_all()` returned those records directly, so a
tool, webhook handler, or UI caller could change `config.enabled`, secrets, or
health counters without validation. Concurrent health checks and delivery
updates also had no shared lock.

## Decision

`ChannelRegistry` is the single writer for channel configuration and health
state. All state changes use one re-entrant lock so synchronous delivery
callbacks and the asynchronous health task share the same serialization
boundary.

Reader methods return `RegisteredChannelSnapshot` values. Their nested config
and health values are frozen, and `extra` is a mapping proxy copied at the
boundary. Callers cannot mutate registry state through a read result.

Configuration changes use `register`, `replace_config`, `enable`, or
`disable`; every path validates generic webhook secrets and enabled-secret
uniqueness. The mutable `RegisteredChannel` record remains private to the
registry owner.

## Invariants

- A read observes one coherent point-in-time channel/config/health tuple.
- A caller cannot change a secret, enabled flag, or health counter by mutating
  a returned value.
- A disabled channel remains `DISABLED` after a successful delivery update.
- Health transitions and configuration transitions cannot interleave halfway.
- Webhook code consumes snapshots and never obtains a mutable registry record.

## Consequences

The public read shape remains attribute-compatible (`id`, `config`, `health`,
`is_enabled`, and `is_healthy`) while gaining immutability. Code that needs to
change configuration must call an explicit registry method, which makes the
writer visible in reviews and tests.
