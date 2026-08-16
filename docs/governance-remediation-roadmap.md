# Governance Remediation Roadmap

> Status reference: 2026-08-16 `main` branch and the current remediation branch.
>
> This roadmap tracks the review findings that **cannot be fixed by code
> alone** — they require organizational, infrastructure, or third-party
> decisions. The companion code-level fixes (RuntimeConfig sealing, tool
> descriptor unification, lifecycle close-failure semantics, Product Integrity
> Gate, Skill trust tiers, Pyright gate) are tracked as separate commits.
>
> Each item records: **current state**, **risk**, **proposed resolution**, and
> **prerequisite** (the condition that must hold before the item can close).

---

## Current review delta

The latest code review's locally code-fixable findings are now represented in
the implementation and security ledger: TrustedGit worktree effects are
strictly below the private authority root, file-based Git apply effects bind
patch length and SHA-256 before spawn, narrow aborts preserve the planned
event/reason, credential use has a broker-owned short-lived lease path, and
the first AgentLoop/ToolScheduler phase components are physically extracted.
These are not independent deployment or governance evidence until the
protected exact-SHA checks pass.

Two review boundaries remain deliberately open and fail closed: macOS/Windows
production authority transport still requires the native launchd/XPC or
Named Pipe/Service SID adapters, and the repository still has no independent
human approving maintainer. The Windows sandbox backend described below is a
sandbox primitive, not proof that the independent authority transport is
complete.

---

## G1 — Single-maintainer independent review (P1, governance)

**Current state.** `docs/required-status-checks.md:99-101` documents that the
repository has one maintainer, so mandatory independent approval and
last-pusher approval are disabled "to avoid an impossible self-lock".
`scripts/audit-github-ruleset.sh:28-33` *enforces* this permissive shape: the
scheduled audit requires `required_approving_review_count == 0`,
`require_code_owner_review == false`, `require_last_push_approval == false`,
and prints "active single-maintainer ruleset". `.github/CODEOWNERS` exists but
is advisory only (its own header warns it is not a substitute for branch
protection or a second reviewer).

**Risk.** The Security Closure Gate can prove that tests ran, but it cannot
prove that a security-critical change received an independent human review.
For a project claiming Codex-class local execution safety, this is the largest
organizational gap: every "tamper-evident local audit / fail-closed /
workspace-bound" claim is only as trustworthy as the review behind the commit.

**Proposed resolution.** Once a second reliable maintainer is onboarded:
1. Add security-sensitive CODEOWNERS entries (already present, advisory) and
   flip `require_code_owner_review` to `true`.
2. Set `required_approving_review_count >= 1` with last-pusher approval enabled.
3. Require resolved conversations and forbid admin override of the ruleset.
4. Require double approval on release tags.
5. Update `scripts/audit-github-ruleset.sh` to assert the stricter invariants
   (replacing the single-maintainer assertions) and update
   `scripts/github-main-ruleset.json`.

Security-sensitive CODEOWNERS paths (already enumerated in `.github/CODEOWNERS`):
`python/khaos/{security,permissions,audit,db}/`, `grpc_server.py`,
`go/internal/{auth,platform}/`, `rust/khaos-core/src/bin/`,
`.github/workflows/`, `scripts/audit-*`, `Dockerfile`, compose files.

**Prerequisite.** A second maintainer with security review capacity. Until
then the current permissive ruleset is the documented, audited compromise.

---

## G2 — Tamper-evident vs tamper-proof audit (P1, governance)

**Current state.** Audit integrity is layered: SQLite append-only triggers +
`prev_hash` chain checked against a local independent chain-head anchor in
`~/.khaos/audit/`. `docs/platform-security-guarantees.md` already states this
"detects local rollback/history edits but is not a remote WORM service and
does not defend against an actor who can rewrite both trusted stores." The
security inventory (`scripts/generate_security_inventory.py`) records: no
remote WORM sink, no independent human approval, local malicious admin still
inside the trust boundary.

**Risk.** The current audit is **tamper-evident** (rollback detectable
locally), not **tamper-proof** (an attacker controlling the host can rewrite
both the DB and the anchor). Outward-facing claims must distinguish the two;
calling the current design "non-repudiable" or "tamper-proof" would be
inaccurate.

**Proposed resolution.**
1. Keep the wording discipline already enforced in
   `docs/platform-security-guarantees.md` — describe the mechanism as
   "tamper-evident local audit", never "tamper-proof independent audit".
2. Optional hardening (out of scope for local single-user deployment): an
   append-only / WORM remote sink (e.g. object storage with object-lock, or a
   separate audit host) receiving hash-chain heads out-of-band. This closes
   the "rewrite both trusted stores" gap for multi-stakeholder deployments.

**Prerequisite.** A deployment model with more than one stakeholder. For
single-user local use the current tamper-evident design is the correct
trade-off.

---

## G3 — Windows sandbox (P1, feature/platform)

**Current state.** This head implements a native Windows execution backend.
`WindowsSandboxBackend` admits execution only after the Rust helper proves a
restricted primary token, Job Object limits with one native runtime process
(the outer helper owns the wait/cleanup transaction),
transactional workspace ACL, an OS-issued no-network AppContainer for native
commands and the trusted Python interpreter, and WFP-backed Firewall policy.
Trusted Python stages a copy of the resolved base executable and receives
temporary RX access only to that disposable runtime tree, so the venv
redirector cannot escape the child policy or force ACL mutation on an active
host runtime. The hosted
`windows-fail-closed-security` and `contract (windows-2025)` jobs build the
helper and set `KHAOS_REQUIRE_WINDOWS_NATIVE=1`; the merge claim remains
pending until those jobs pass on this head. Windows private-desktop parity and
browser-specific Linux netns parity are not claimed.

**Risk.** A failed native probe must continue to produce no execution
capability; the remaining risk is platform-specific CI/runtime compatibility,
not a silent Host bypass. The helper deliberately limits each execution to a
one native runtime process because Windows Firewall program rules cannot safely
authorize unknown descendants during a discovery race; the outer helper is
outside the Job and does not execute the model command.

**Resolution in this head.** Use the native helper as the only Windows Coding
backend: restricted token, child-process policy, inherited-handle allowlist,
per-execution no-network AppContainer for native `network=none` commands and
trusted Python, disposable staged base-executable launch for trusted Python, the
restricted-token/WFP path with exact runtime-file ACLs for brokered execution,
Job Object kill-on-close/resource limits and active
process limit one, transactional ACL grant/restore, exact native executable
resolution, and WFP-backed Firewall rules. Brokered egress accepts only the
loopback NetworkBroker endpoint. Any missing primitive, cleanup proof, or
unsupported command fails closed.

**Prerequisite.** A passing current-head Windows runner is required before
release; private-desktop support remains outside this closure.

This sandbox closure does not close the separate production AuthorityBroker
transport item: without the native authority service/identity adapter,
production authority-backed execution remains fail-closed on Windows.

---

## G4 — Independent penetration testing (P2, governance)

**Current state.** Security validation is entirely self-administered: CI
adversarial tests (schema fuzz, authorization drift, process lifecycle,
event-loop starvation, real-kernel browser/netns/nft, Docker isolation) plus
local hash-chain audit. No external / third-party penetration test has been
run.

**Risk.** Self-authored adversarial tests validate the threat models the
authors thought of. They cannot substitute for an independent red-team review
of the trust model itself.

**Proposed resolution.** Commission an independent penetration test focused on
the local execution boundary (bwrap/Seatbelt escape, FD-inidentity races,
RPC peer-credential spoofing, approval-replay across principal/project/policy
drift, managed-process lifecycle, browser teardown). Publish a summary report
and track findings to closure.

**Prerequisite.** Budget / partnership for an external assessment.

---

## G5 — Release provenance: signing, SBOM, attestation (P2, supply chain)

**Current state.** Supply-chain engineering is strong on the *dependency*
side: `uv.lock`, `go.sum`, `Cargo.lock`, hash-pinned requirements, SHA-pinned
Actions, pip-audit / cargo-audit / govulncheck, Dependabot, and a provenance
job that sha256sums the lockfiles (`supply-chain-audit.yml:36-62`). The
`Release Provenance` workflow now builds commit-bound source/native subjects,
generates an SPDX SBOM plus a checksum manifest, and stores signed GitHub
artifact-attestation bundles as release assets. A signed Git/GPG release tag
and an independent release approver remain governance controls outside the
workflow.

**Risk.** A consumer of a Khaos binary can now verify the workflow attestation,
SBOM, and digest manifest, but the repository still cannot enforce signed tag
creation or independent release approval while it has one maintainer.

**Proposed resolution.**
1. Keep `.github/workflows/release-provenance.yml` as the release path;
   it produces Sigstore-backed SLSA provenance and SBOM attestations.
2. Keep the generated SPDX document and checksum/manifest assets attached to
   the GitHub Release, not only in an expiring Actions artifact.
3. Require signed release tags and independent release approval once the G1
   maintainer prerequisite is satisfied.

**Prerequisite.** A release owner must publish releases from the workflow and
the repository must move from the current single-maintainer exception to
independent tag/release approval when the second maintainer exists.

---

## G6 — KHAOS_DEV_MODE as ambient authority (P2, hardening — partially code-fixable)

**Current state.** A single ambient env var `KHAOS_DEV_MODE` lowers many
security guarantees at once (catalogued in the review): RPC v2 requirement,
protocol metadata, project/policy claims, audit anchor, platform probes,
browser authority, native-launcher TCB validation. Production systemd and
Compose explicitly set it to `0`/unset, but a single env var controlling
multiple independent guarantees is an accident surface. The test suite sets
it to `1` globally (`python/tests/conftest.py:28`).

**Proposed resolution (split between code and governance).**
- *Code side (tracked separately):* prefer an explicit `--profile
  {production,test}` CLI flag over an ambient env switch; production packaged
  binaries (systemd/container) should be able to disable the dev profile
  entirely. Development mode must enforce loopback-only, temporary DB, visible
  UI warning, no real credentials, no remote Gateway, no production state root,
  and audit-marked-as-development.
- *Governance side:* document that `KHAOS_DEV_MODE=1` must never be set in a
  production systemd unit, container env, or operator runbook, and add a
  startup warning when it is set outside a TTY/CI environment.

**Prerequisite.** None for the documentation; the `--profile` refactor is a
code change that can be scheduled independently.

---

## G7 — Cross-language authority concentration (P3, architecture — multi-step)

**Current state.** Security authority is split across Python (policy
compilation, capability registry, permission engine, execution service,
audit), Go (Gateway auth, Host allowlist, API-key digest), and Rust (token
counting, exec launcher, netns helper). The same security semantics are
re-stated in multiple layers (see the Tool Security Descriptor unification
work). `grpc_server.py` (3623 lines) is a god-module combining lockfile, RPC
protocol, HMAC, peer credentials, lifecycle, all services, and the CLI entry.

**Proposed resolution.** Long-term architectural convergence toward fewer,
better-separated authority boundaries:
1. Unify tool security descriptors into one source of truth (code work, W2).
2. Generate Go/Python RPC schemas from a single IDL and verify a schema digest
   across the handshake (code work, part of W2).
3. Split `grpc_server.py` into `rpc/{protocol,schema,authenticator,peer_identity,transport,dispatcher}`,
   `services/{agent,task,session,memory,audit,channel,subagent}`,
   `lifecycle/{instance_lock,server_owner,shutdown,recovery}` — one authority
   and one state machine per module. This is high-risk pure refactoring and
   must be done in small atomic steps with the full test suite green at every
   step (the Product Integrity Gate from the code work is its precondition).

**Prerequisite.** Product Integrity Gate (W3) green, so the refactor has a
whole-repository regression net.

---

## Cross-reference: what code can and cannot fix

| Review item | Code-fixable? | Where tracked |
|---|---|---|
| P1-1 Runtime injection sealing | Yes | W1 (code) |
| P1-2 Tool descriptor duplication + Go `/api/tools` | Yes | W2 (code) |
| P1-3 Full test suite gate | Yes | W3 (code) |
| P1-4 same-UID threat model statement | Yes (doc) | done — `docs/platform-security-guarantees.md` |
| P1-4 single-maintainer / independent approval | No | G1 (this doc) |
| P2-1 aclose false-success | Yes | W4 (code) |
| P2-2 ManagedProcess lifecycle | Yes | W5 (code) |
| P2-3 `KHAOS_DEV_MODE` ambient authority | Partial | G6 (this doc) + code refactor |
| P2-4 god-module size / authority concentration | Partial | G7 (this doc) + W10 refactor |
| P2-5 Skill trust tiers | Yes | W7 (code) |
| P2-6 Pyright/mypy gate | Yes | W6 (code) |
| Tamper-evident vs tamper-proof audit | No | G2 (this doc) |
| Windows sandbox | No (feature) | G3 (this doc) |
| Independent penetration test | No | G4 (this doc) |
| Release signing / SBOM / provenance | No (infra) | G5 (this doc) |

---

*Last updated: 2026-08-04. Maintainers: 瑞邦 + Hermes Agent.*
