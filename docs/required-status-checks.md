# Required Status Checks — Branch Protection Reference

> Batch 6.6 (round-6 §22): GitHub branch protection is a **repository
> setting**, not a file in the repo, so it cannot be enforced from code.
> This document lists the exact check names that an admin MUST configure
> as "required" in **Settings → Branches → Branch protection rules** for
> `main`.  Without this step the CI jobs exist but a PR could be merged
> with a failing/missing check.

## How to apply

1. Open the repo → **Settings** → **Branches**.
2. Edit (or create) the rule for `main`.
3. Under "Require status checks to pass before merging", tick **Require
   branches to be up to date before merging**.
4. Search for and add each check name below.

## Required check names

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
| `macos-sandbox-security` | real `sandbox-exec` on macOS |
| `windows-fail-closed-security` | Windows refuses execution (no backend) |

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

### `Supply Chain Audit` (`.github/workflows/supply-chain-audit.yml`)

| Check name | Proves |
|---|---|
| `pip-audit` | Python dependency vulnerabilities |
| `cargo-audit` | Rust dependency vulnerabilities |
| `govulncheck` | Go dependency vulnerabilities |

## Verification

After applying, open a PR against `main`. The PR view should show every
check above as **Required** (a small "Required" badge next to the name).
A PR with any of these failing or pending must be unmergeable until the
check passes.
