# Community Local Closure Worklog

This worklog is an evidence record for the closure run that started from the
refreshed protected baseline. It is not itself a closure decision and must not
be edited to manufacture a status.

## Baseline freeze

- Source branch: `main`
- Baseline branch state: clean
- Baseline SHA: `3909fabefab282558afa0dea782a936fc104597a`
- `origin/main` after `git fetch origin`: `3909fabefab282558afa0dea782a936fc104597a`
- Working branch created from that SHA: `codex/community-local-closure`
- Python: `3.13.4`
- Go: `go1.26.4 darwin/arm64`
- Rust: `rustc 1.97.1`, `cargo 1.97.1`
- OS: `macOS 26.6.1 (25G76)`

Baseline source digests:

| Artifact | SHA-256 |
| --- | --- |
| `docs/security_facts.yaml` | `78a4e69c7addf7edfb53cb4bd8d7959431a4ace2619a1380b332e06542326a67` |
| `docs/generated/production-reachability.md` | `e03bc4ad1ecfe688384d59f04d7e1d5009a428f0f3820b8899625f9a5ad0d44c` |
| `docs/m6-security-closure-report.md` | `ac4d3e19b0e2caaf576ece5448813fee06e20d19cf1a20a9798699eb60691758` |
| `docs/memory-v2-production-closure-report.md` | `893b64b0e61b363aa0736e992fb1f108eed4e9cb6c5ef9386401b16a7f210b99` |
| `docs/required-status-checks.md` | `89bfa8374d497f079f7bd568722e1c4fc6c80f610e4c01571f21648e5dfc0062` |
| `docs/type-check-rollout.md` | `7ed9da181068f826b9671cad275ca3b8203d123684ba9c16c9194966eb3c6594` |

Baseline generators and governance:

- `python3 scripts/generate_security_inventory.py --check`: PASS
- `python3 scripts/generate_production_reachability.py --check`: PASS
- `python3 scripts/validate_m6_governance.py`: PASS
- `git diff --check`: PASS
- Forbidden production imports reported by the reachability generator: `0`
- Unresolved production imports reported by the reachability generator: `0`

## Baseline focused tests

- Local trust, authority transport/protocol, and CI policy: `86 passed`, `1 skipped`,
  `1 failed`.
- Production reachability/composition: `12 passed`, `1 skipped`.
- Existing closure/evidence/release tests: `42 passed`.
- Existing orchestration/authorization/coordinator/finalizer tests: `18 passed`.

The one local-trust failure was reproduced only inside the managed sandbox:
the real POSIX UDS server received `EPERM` while creating its temporary socket.
It is recorded as an infrastructure limitation pending an approved-host rerun;
it is not converted into a skip, xfail, or soft pass.

## Scope rule

Subsequent entries must identify the exact commit, test command, result count,
and whether a failure is a regression, an existing defect, or infrastructure
limitation. A closure status may only be emitted by the evidence-bound verifier
after exact-commit and GitHub provenance checks succeed.

## Implementation and validation evidence

The implementation was kept in three atomic commits after the baseline
freeze:

- `109ef26` — profile-aware Community Local evidence schema, live GitHub
  provenance capability, exact Security Evidence/attestation verification,
  producer workflow, closure report consumer, and documentation/type-check
  contract.
- `87953c9` — production runtime composition rejection for HostBackend,
  testing sandbox, mock authority, and testing runtime objects, with static
  reachability and runtime negative tests.
- `2ffcf1f` — immutable admitted tool-call snapshots carried through
  scheduler authority preparation and execution, with argument-drift and raw
  production-call regressions.

Validation after the implementation commits:

- `PYTHONPATH=python uv run --extra test pytest -q -rs`: `4782 passed, 29
  skipped, 1 warning`; no failures. The skips are existing real Linux
  kernel/bwrap, Windows, Docker nightly, stale Rust extension, and unavailable
  authorityd conditions; no security test was removed or converted to a
  skip/xfail.
- Focused host-authority/adversarial matrix: `242 passed, 1 skipped`; the one
  skip is `no deployed authorityd: production runtime cannot be built`.
- Strict security Pyright project: `0 errors, 0 warnings, 0 informations`.
- `go test ./...`: pass; `go test -race ./...`: pass.
- `cargo test --locked`: pass; `cargo clippy --locked --all-targets -- -D
  warnings`: pass.
- Security inventory, production reachability, governance, and `git diff
  --check`: pass; production reachability reports zero forbidden and zero
  unresolved edges.

The managed sandbox initially produced an EPERM while creating a real POSIX
authorityd UDS. The same test boundary was rerun with approved host access;
the remaining authorityd skip is a separate unavailable-deployment condition.
It was not treated as a code pass.

## Current closure state

The local evaluator and report are intentionally `NOT_CLOSED` because this
branch has no producer-owned exact successful `push` runs on protected
`main`, no verified GitHub artifact provenance, and no exact release-gate
capability. The machine blocker is
`CLOSURE_PENDING_EXACT_SHA_CI_EVIDENCE`. Community Local explicitly reports
Apple Developer Program, Apple Team ID, Signed XPC, and notarization as
`NOT_APPLICABLE`; macOS Signed Distribution is
`OPTIONAL_PROFILE_NOT_ENABLED`; hostile same-UID isolation and independent
second-maintainer review are `NOT_CLAIMED` and non-blocking.
