# Pyright Type-Check Rollout Plan

> Status reference: 2026-08-04.

Review P2-6 found that Khaos had **no static type-check gate at all** —
`Makefile` lint literally printed "P0-A lint tooling not configured yet", and
`pyright` existed only under the optional `lsp` extra (used by the runtime
coding-intelligence integration, not as a CI gate). For a codebase with heavy
dynamic injection, `Any`, optional authority objects, and cross-service
payloads, this meant `None`-authority bugs, wrong context types, handler
injection-argument omission, and service-method payload drift could all slip
through undetected.

This document tracks the rollout of a Pyright gate to fix that.

## Current state

- `pyproject.toml` declares a `[tool.pyright]` config with **strict** mode for
  the three security-critical packages (`runtime/`, `security/`,
  `permissions/`) and **basic** mode for the rest of `python/khaos`.
- `.github/workflows/type-check.yml` runs `uv run pyright` on every PR and
  push. It is currently a **reporting gate** (`continue-on-error: true`): it
  surfaces errors but does not block the PR, because a large existing
  codebase produces errors on first strict enablement.

## Promotion plan

The gate is promoted to a **required merge authority** incrementally, one
module at a time, as each module reaches zero Pyright errors:

1. **Phase 1 — baseline visibility.** *(current)* The workflow runs and
   reports the error count per module. No PR is blocked. Track the error
   count trend per module in the PR comments.
2. **Phase 2 — per-module promotion.** When a strict module (e.g.
   `runtime/`) reaches zero errors, add a focused job that runs `pyright` on
   just that module with `continue-on-error: false`, and make THAT job a
   required status check. New errors in that module now block the PR.
3. **Phase 3 — full promotion.** Once all three strict modules
   (`runtime/`, `security/`, `permissions/`) are at zero errors, remove the
   workflow-level `continue-on-error: true` and make the whole `Type Check`
   job a required merge authority. Expand the strict set to the next tier
   (`coding/execution/`, `tools/registry.py`, `tools/scheduler.py`,
   `grpc_server.py`).

## Modules in the strict set

These are the security-critical paths where type safety matters most (the
review's explicit list):

| Module | Mode | Required-check? |
|---|---|---|
| `python/khaos/runtime/` | strict | no (reporting) — Phase 2 target |
| `python/khaos/security/` | strict | no (reporting) — Phase 2 target |
| `python/khaos/permissions/` | strict | no (reporting) — Phase 2 target |
| `python/khaos/coding/execution/` | basic | no — Phase 3 strict candidate |
| `python/khaos/tools/registry.py` | basic | no — Phase 3 strict candidate |
| `python/khaos/tools/scheduler.py` | basic | no — Phase 3 strict candidate |
| `python/khaos/grpc_server.py` | basic | no — Phase 3 strict candidate |
| everything else under `python/khaos` | basic | no |

## Why reporting, not required, on day one

A required gate that always fails on a large existing codebase is worse than
no gate: it trains contributors to ignore red checks, and it blocks every PR
for pre-existing debt. The honest path is to start with visibility, fix the
strict modules one at a time, and promote each to required as it goes green.
This matches how the review framed it ("can be rolled out per-module rather
than all-strict at once").

---

*Last updated: 2026-08-04. Maintainers: 瑞邦 + Hermes Agent.*
