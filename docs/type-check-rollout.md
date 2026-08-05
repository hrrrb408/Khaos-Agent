# Pyright Type-Check Rollout Plan

> Status reference: 2026-08-04.

Review P2-6 found that Khaos had **no static type-check gate at all** —
`Makefile` lint literally printed "P0-A lint tooling not configured yet", and
`pyright` existed only under the optional `lsp` extra (runtime LSP
integration, not a CI gate). For a codebase with heavy dynamic injection,
`Any`, optional authority objects, and cross-service payloads, None-authority
bugs and payload drift could slip through undetected.

This document tracks the rollout of a Pyright gate to fix that.

## Current state

- `pyproject.toml` declares a `[tool.pyright]` config with **strict** mode for
  the three security-critical packages (`runtime/`, `security/`,
  `permissions/`) and **basic** mode for the rest of `python/khaos`.
- `make lint` now runs `uv run pyright` locally so contributors get type
  feedback during development (it requires the `lsp` extra: `uv sync --extra
  lsp`).
- There is **no CI workflow gate yet** — see "Why no CI gate yet" below.

## Why no CI gate yet

The repository enforces a hard security invariant: **no `continue-on-error`
in any workflow** (`python/tests/security/test_ci_security_policy.py::
test_security_workflows_have_read_only_token_and_no_soft_failures`). A soft
gate is forbidden — every CI job must be a real, blocking check.

A Pyright CI gate therefore has to be a required (hard) gate from day one.
But a large existing codebase produces errors on first enablement: even
**basic** mode across `python/khaos` reports ~623 errors today (mostly
unresolved optional imports — `textual`, `tree-sitter`, `playwright` — plus
genuine type issues in legacy code), and the strict security-critical modules
report more. A hard gate that always red-bars every PR is worse than no gate:
it trains contributors to ignore the check.

So the honest path is: ship the config and local tooling now, do the
error-burn-down work, then add a hard CI gate that is green from the first
PR it runs on.

## Promotion plan

The gate lands in three phases. Each phase is a discrete work item tracked
in the governance remediation roadmap.

1. **Phase 1 — config + local tooling.** *(done)* `[tool.pyright]` config in
   `pyproject.toml`; `make lint` runs pyright. No CI gate. Contributors opt
   in locally.
2. **Phase 2 — error burn-down.** Fix the ~623 basic-mode errors. The bulk
   are optional-import false-positives — address them by declaring
   `reportMissingImports = "none"` for files behind optional extras
   (`tui/`, `browser_tools.py`, `coding/intelligence/`) and fixing the
   genuine type errors in the rest. Drive the basic-mode error count to zero
   across `python/khaos`.
3. **Phase 3 — hard CI gate.** Add `.github/workflows/type-check.yml` running
   `uv run pyright` as a **required** job (no `continue-on-error`) wired into
   the Security Closure Gate aggregate. Because Phase 2 reached zero errors,
   the gate is green from day one. Then tighten the security-critical modules
   to strict one at a time (`runtime/`, then `security/`, then
   `permissions/`), fixing each module's strict errors before promoting it.

## Modules targeted for strict

The review's explicit list of security-critical paths where type safety
matters most:

| Module | Current mode | Target mode | Pre-burn-down errors |
|---|---|---|---|
| `python/khaos/runtime/` | strict (config) | strict (gate) | pending audit |
| `python/khaos/security/` | strict (config) | strict (gate) | pending audit |
| `python/khaos/permissions/` | strict (config) | strict (gate) | pending audit |
| `python/khaos/coding/execution/` | basic | strict (Phase 3+) | — |
| `python/khaos/tools/registry.py` | basic | strict (Phase 3+) | — |
| `python/khaos/tools/scheduler.py` | basic | strict (Phase 3+) | — |
| `python/khaos/grpc_server.py` | basic | strict (Phase 3+) | — |

---

*Last updated: 2026-08-04. Maintainers: 瑞邦 + Hermes Agent.*
