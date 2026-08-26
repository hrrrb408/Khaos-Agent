# Required Status Checks — Branch Protection Reference

> GitHub rulesets are repository-side authority. The required configuration
> below is continuously audited by `.github/workflows/ruleset-audit.yml` and
> `scripts/audit-github-ruleset.sh`; drift produces a failed workflow and a
> JSON evidence artifact. `RULESET_AUDIT_TOKEN` must have read access to
> repository rulesets because the default Actions token cannot always inspect
> organization-managed rules.

The machine-facing profile, gate, proof, residual, platform, and type-check
facts live in `docs/security_facts.yaml`. This document is the operator-facing
projection of those facts; it does not create a release pass or closure
capability by itself.

## How to apply

1. Open the repo → **Settings** → **Branches**.
2. Edit (or create) the rule for `main`.
3. Under "Require status checks to pass before merging", tick **Require
   branches to be up to date before merging**.
4. Search for and add each check name below.

## Required check names

The merge-authority checks for `main` are exactly two aggregate gates
(round-11 review Critical-1 fix — the real GitHub ruleset now requires these,
not the 20 individual detail checks):

| Check name | Proves |
|---|---|
| `Security Closure Gate` | every reusable security workflow + the explicit schema/authz/process/event-loop adversarial job + the Pyright type check succeeded; mandatory evidence artifact was validated and uploaded |
| `Product Integrity Gate` | the full product test suite (Python 3.11/3.12/3.13, Go, Rust) succeeded independently of the security subset |

Both are required for merge. Neither substitutes for the other: Security Closure proves
the security boundary holds; Product Integrity proves the product as a whole is
not regressed. The detailed checks below are diagnostic dependencies of the
aggregates — they remain visible but are no longer direct merge authorities.

Release provenance has one additional Community Local exact-commit gate: the
`Community Local Security Closure` workflow must have a completed successful
`push` run for the same protected `main` commit with the
`local-security-evidence-${commit}` artifact live and digest-bound. A green
aggregate without that producer artifact cannot close Community Local.
`Native Authority Production E2E` remains a separate platform workflow;
macOS Signed Distribution is optional and reports
`OPTIONAL_PROFILE_NOT_ENABLED` when it is not enabled.

The aggregate job also downloads per-test evidence emitted only after the
owning job succeeds. Every fragment binds `commit`, Actions `run_id`, `job`,
test name, exact `blocked` result, production environment and a canonical
SHA-256 digest. The assembler rejects missing, duplicate, cross-commit or
digest-mismatched fragments; it never synthesizes a passing test result.

These are the `name:` fields of the jobs (the names shown in the GitHub
PR checks UI), grouped by workflow.

### `Batch 5 Required Jobs` (`.github/workflows/batch5-required-jobs.yml`)

| Check name | Proves |
|---|---|
| `DB Transaction Adversarial` | transaction owner / stale-recovery / static gate |
| `Shared DB Project Isolation` | principal + project_id isolation on shared DB |
| `Browser Netns Attack E2E` | browser egress guard + netns attack tests (+ round-6 nft authority) |
| `Go Race Test` | Go gateway under the race detector |
| `Rust Clippy` | Rust core compiles clean under `-D warnings` |
| `Full Python Security Suite` | full `python/tests/security/` directory |
| `Migration Fixture Matrix` | versioned migrations + immutable chain + lifecycle concurrency + chat stream + owner closure |

### `Platform Sandbox Security E2E` (`.github/workflows/platform-sandbox-security.yml`)

| Check name | Proves |
|---|---|
| `linux-bwrap-security` | real bubblewrap + cgroup v2 + ext4 io isolation |
| `browser-kernel-isolation` | **real** nft parser + netns/veth/cgroup creation + egress isolation + teardown (Batch 6.6) |
| `fullstack-browser-kernel` | **real** Chromium + BrowserManager + production sandbox + nft + proxy + cgroup PID, full-stack E2E (Batch 7.5) |
| `macos-sandbox-security` | real `sandbox-exec` on macOS |
| `windows-fail-closed-security` | Windows native helper probe and execution pass; missing evidence still fails closed |

### `Browser Security E2E` (`.github/workflows/browser-e2e.yml`)

| Check name | Proves |
|---|---|
| `playwright-security` | real Playwright Chromium route guard / context lifecycle |

### `Security Contract Matrix` (`.github/workflows/security-contract-matrix.yml`)

| Check name | Proves |
|---|---|
| `contract (ubuntu-24.04)` | cross-platform security contract on Linux |
| `contract (windows-2025)` | same on Windows |
| `contract (macos-14)` | same on macOS |

### `Docker Security E2E` (`.github/workflows/docker-security.yml`)

| Check name | Proves |
|---|---|
| `docker-isolation` | real Docker daemon sandbox isolation |
| `compose-deployment` | clean-checkout Compose startup, loopback-only development HTTP, and TLS/API-key/Host-allowlisted production HTTPS health checks |

### `Supply Chain Audit` (`.github/workflows/supply-chain-audit.yml`)

| Check name | Proves |
|---|---|
| `pip-audit (Python)` | Python dependency vulnerabilities |
| `cargo audit (Rust)` | Rust dependency vulnerabilities |
| `govulncheck (Go)` | Go dependency vulnerabilities |

### `Product Integrity Gate` (`.github/workflows/product-integrity-gate.yml`)

P1-3: the whole-repository product test suite, independent of the security
subset. Security Closure proves the boundary holds; Product Integrity proves
the product as a whole is not regressed. Both are required merge authorities.

| Check name | Proves |
|---|---|
| `Python Product Suite` | full `python/tests/` across the Python 3.11/3.12/3.13 × Ubuntu 24.04 and macOS 14 matrix (infrastructure-only suites remain owned by their dedicated security workflows) |
| `Python Product Suite (Windows 3.11)` | full applicable `python/tests/` on Windows with the native sandbox helper required; explicitly marked `posix_host` tests are excluded as a documented POSIX applicability boundary, while Windows native-or-fail-closed coverage remains required |
| `Go Product Suite` | full `go test -race ./...` |
| `Rust Product Suite` | `cargo test --locked --all-targets` + `cargo clippy --all-targets -- -D warnings` |
| `Product Integrity Gate` | aggregate — Linux/macOS/Windows Python plus Go and Rust suites green (exact success required; cancelled/skipped blocks) |

## Verification

After applying, open a PR against `main`. The PR view should show every
check above as **Required** (a small "Required" badge next to the name).
A PR with any of these failing or pending must be unmergeable until the
check passes.

The scheduled ruleset audit additionally requires active `main` coverage,
deletion and non-fast-forward blocking, resolved review threads, strict status
checks, and the complete required-check set. This repository currently has one
maintainer, so mandatory independent approval and last-pusher approval are
disabled to avoid an impossible self-lock. Run the audit locally with:

```bash
GITHUB_REPOSITORY=OWNER/REPO bash scripts/audit-github-ruleset.sh
```
