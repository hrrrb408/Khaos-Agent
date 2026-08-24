# Pyright Type-Check Rollout Plan

> Status reference: 2026-08-25.

Review P2-6 found that Khaos had no static type-check gate at all. The current
repository now has a hard reusable `Type Check` workflow wired into the
Security Closure Gate. For a codebase with heavy dynamic injection, optional
authority objects, and cross-service payloads, the checked files are kept
explicit so a type-check failure is a blocking security result.

This document tracks the rollout of a Pyright gate to fix that.

## Current state

- `pyproject.toml` declares a `[tool.pyright]` config with **strict** mode for
  the three security-critical packages (`runtime/`, `security/`,
  `permissions/`) and **basic** mode for the rest of `python/khaos`.
- `make lint` runs `uv run pyright` locally so contributors get type
  feedback during development (it requires the `lsp` extra: `uv sync --extra
  lsp`).
- `.github/workflows/type-check.yml` is a hard CI workflow gate with no
  `continue-on-error`; Security Closure calls it as a required dependency.
- The gate includes the admission/phase/execution coordinator boundary, the
  authority transport and local closure evaluator, in addition to the
  already-covered runtime, execution, registry, scheduler, and approval
  modules.

## Gate semantics

The repository enforces a hard security invariant: **no `continue-on-error`
in any workflow** (`python/tests/security/test_ci_security_policy.py::
test_security_workflows_have_read_only_token_and_no_soft_failures`). A soft
gate is forbidden — every CI job must be a real, blocking check.

The gate is intentionally blocking. A missing optional dependency, a pyright
error, or a workflow failure remains a failed check; it is never represented as
green by a skip or soft-fail. Local workstation results are diagnostic until
the exact commit's GitHub gate run is verified by the release evidence
verifier.

## Promotion plan

The gate lands in three phases. Each phase is a discrete work item tracked
in the governance remediation roadmap.

1. **Phase 1 — config + local tooling.** *(done)* `[tool.pyright]` config in
   `pyproject.toml`; `make lint` runs pyright.
2. **Phase 2 — error burn-down.** Fix the ~623 basic-mode errors. The bulk
   are optional-import false-positives — address them by declaring
   `reportMissingImports = "none"` for files behind optional extras
   (`tui/`, `browser_tools.py`, `coding/intelligence/`) and fixing the
   genuine type errors in the rest. Drive the basic-mode error count to zero
   across `python/khaos`.
3. **Phase 3 — hard CI gate.** *(done for the current clean file set)* The
   reusable workflow runs `uv run pyright` as a required job with no
   `continue-on-error`, wired into the Security Closure Gate aggregate. The
   remaining repository-wide basic-mode rollout is separate and cannot weaken
   this security-critical gate.

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

*Last updated: 2026-08-25. Maintainers: 瑞邦 + Hermes Agent.*
