# ADR-056: Pure permission evaluator and durable engine boundary

## Status

Accepted — 2026-08-22

## Context

`PermissionEngine.check` combined four responsibilities: authorization epoch
refresh, persistent rule materialization, decision precedence, and terminal
command/read-only matching. That made the security strategy hard to test
without SQLite and made it easy for a future database change to alter the
decision state machine accidentally.

## Decision

`PermissionEvaluator` is the pure decision owner. It receives one tuple rule
snapshot, the default mode, the effective `commands_require_approval` set,
and the execute-tool set. It performs policy-required approval first, typed or
enforcement-rule matching second, the interactive read-only convenience only
after explicit rules, and finally the configured default.

`PermissionEngine` remains the durable owner. It binds principal/project/
policy, loads and validates rows, tracks authorization epochs, persists grants
and revocations, and passes a tuple snapshot to the evaluator for each check.
Audit writes remain on the engine's bound audit logger.

The shared value types (`ApprovalMode`, `PermissionRule`, and
`PermissionDecision`) live in `permissions/models.py`; transport and command
normalization helpers used by the pure evaluator live beside it in
`permissions/evaluator.py`. Existing imports from `permissions.engine` remain
compatibility re-exports.

## Invariants

- The evaluator never accepts or stores a database, audit logger, or mutable
  authorization epoch.
- A rule list is captured as a tuple before evaluation, so a concurrent reload
  cannot change one decision halfway through.
- `commands_require_approval` precedes remembered auto-approve rules and the
  read-only terminal shortcut.
- Explicit deny/ask rules precede the interactive convenience shortcut.
- Durable epoch/policy drift remains a fail-closed `DENY` in the engine before
  the evaluator is invoked.

## Consequences

Decision precedence now has direct unit tests with no database fixture. The
engine's storage and lifecycle tests continue to cover epoch reload, owner
scoping, grant/revoke, and audit attribution. Future policy features should be
added to the evaluator as pure state transitions, not to the database path.
