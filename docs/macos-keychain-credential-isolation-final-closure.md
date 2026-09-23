# Khaos macOS Keychain Environment & Credential Isolation Final Closure Report

Date: 2026-09-12

## Branch and repository identity

- Branch: `codex/m8-coding-evaluation`
- Exact HEAD: `3c1095ff69b1a5d800d96eb61e8b88a47fceca14`
- Working-tree identity: `c641f4d18a05706e9aa26cbe01e662977f855eb1ed664a67932c781741547b47` (digest includes status, tracked diff, and hashes of non-protected untracked files; it excludes this report itself and the protected local report so it is not self-referential).
- Protected local report: `docs/local-security-closure-report.md` remained untracked, unchanged, and unstaged. Its pre-existing metadata remained 851 bytes with SHA-256 `85dbfe1ee17475154a0f48a6d308750b252aec75f3b67dd4f2e47f06b25597a1`.
- No commit, push, rebase, merge, PR update, or cleanup was performed.

## Scope and credential boundary

- Real provider calls this run: **0**.
- Real credentials read this run: **NO**.
- Real Coding, browser Coding, full corpus, and M9: **NOT RUN**.
- Historical incident: a previous provider run exposed real credential material. Those credentials remain treated as compromised. No value, prefix, header, or replacement was read or repeated in this gate. `REAL CREDENTIAL ROTATION: OPERATOR ACTION REQUIRED`.

This gate used only in-memory, randomly generated synthetic material for tests. No secret was placed in an argv vector, prompt, JSONL record, repository configuration, environment dump, fixture, or durable diagnostic.

Provider metadata for this gate:

- Provider: **NONE / NOT USED**
- Model: **NONE / NOT USED**
- Reasoning configuration: **NOT APPLICABLE**
- Provider adapter/request count: **0**
- Usage accounting: **NOT APPLICABLE**; no provider request was made

## macOS backend audit

The production macOS implementation is `MacOSKeychainCredentialStore` in
`python/khaos/security/credentials.py`. It loads `Security.framework` with
`ctypes`, uses the native generic-password APIs, passes a null keychain handle
so the system default/login Keychain is selected, and calls
`SecKeychainSetUserInteractionAllowed(False)` before any credential operation.
It does not invoke the `security` CLI and does not use a plaintext file or
environment fallback.

The Coding task environment intentionally creates a synthetic `HOME` and a
small allowlisted environment. That is task isolation, not a replacement for
the trusted host Keychain. The child task cannot receive a Keychain secret or
redirect the trusted backend by changing `HOME`.

## Original failure and diagnosis

The bounded native diagnostic observed:

```text
platform=darwin
uid=501
interaction_policy_status=0
put_native_status=-25308
category=INTERACTION_REQUIRED
interaction_allowed=false
```

`-25308` is macOS `errSecInteractionNotAllowed`. The current default/login
Keychain requires user interaction for this write in the present session,
while Khaos has explicitly disabled interaction. The framework loaded and the
interaction-policy call itself succeeded. This is therefore not a synthetic
`HOME` routing defect and not a provider failure.

Classification: **OS_POLICY_BLOCKED / ENVIRONMENT_BLOCKED** for this host
session. Khaos did not enable dialogs, retry with interaction enabled, modify
the system Keychain, or fall back to plaintext.

The original code had a general observability defect: native `OSStatus` was
collapsed into a generic unavailable error. That defect was fixed without
changing the fail-closed policy.

## Fix applied

- Added bounded `CredentialStoreDiagnostic` metadata with typed native status,
  operation, backend, safe category, and interaction policy state.
- Added safe metadata on `CredentialStoreError`; native text and secret values
  are not included.
- Added `SecretValue.matches()` for in-memory comparison without exposing the
  value.
- Kept `UnavailableCredentialStore` as the explicit fail-closed path.
- Wired one canonical `SecretRedactor` through provider errors, AgentLoop
  messages, tool finalization, audit, memory, supervision/checkpoints,
  subagent progress, MCP/hooks/skills extension events, browser/app
  diagnostics, and benchmark JSONL.
- Unknown or cyclic output objects are replaced with a bounded redaction
  marker; redaction traversal errors fail closed.

## Synthetic Keychain sequence

The opt-in integration test generated one unique synthetic Keychain identity
and one random secret in memory only. The intended sequence is:

```text
put -> exists -> get -> in-memory compare -> replace -> get
-> in-memory compare -> delete -> missing -> get raises CredentialNotFound
```

The in-memory authoritative-store sequence passed deterministically. A direct
native status probe was used once to identify the OSStatus before the typed
diagnostic was added. After the fix, the production-shaped native integration
sequence was attempted once, stopped at `put`, and entered cleanup in
`finally`; it returned the same safe `-25308 / INTERACTION_REQUIRED` result.
No second native retry was made.

Native integration result: **ENVIRONMENT_BLOCKED**, not a source regression.

## Authority and sandbox gates

- Credential Authority: **PASS for synthetic store and broker contracts**;
  **ENVIRONMENT_BLOCKED for the host native Keychain write**.
- Plaintext fallback: **ABSENT / FAIL-CLOSED**.
- Sandbox/task environment isolation: **PASS** in deterministic tests; a child
  receives no credential material and cannot select the trusted Keychain.
- Trusted backend audit: **PASS** for native API selection and interaction-off
  policy; **not closed** for an interactive Keychain environment.
- Architecture bypass: **NONE OBSERVED**.

## Output Firewall Matrix

| Surface | Synthetic result | Boundary |
|---|---|---|
| Terminal stdout/stderr | PASS | canary absent after capture |
| Tool results/finalizer | PASS | result, error, arguments, warnings sanitized |
| Provider error diagnostics | PASS | typed metadata only; no response body |
| Audit DB and file sink | PASS | sanitized action/target/result/detail |
| Agent messages, state DB, FTS | PASS | content, tool calls, metadata sanitized |
| Memory and failure-memory paths | PASS | event payload and durable audit sanitized |
| Supervision, checkpoint, subagent progress | PASS | bounded event payload sanitized |
| MCP/hooks/skills extension events | PASS | event payload sanitized |
| Browser/app diagnostics | PASS (synthetic) | middleware boundary exercised; no real app run |
| Benchmark JSONL | PASS | sanitized payload and recomputed digest |
| Direct real MCP/browser/provider surfaces | N/A | no real external run was authorized |

## Synthetic canary and safe diagnostics

- Synthetic output-firewall canary: **PASS** (`1 passed` in
  `python/tests/security/test_credential_output_firewall.py`).
- Final scan of generated artifacts/log surfaces: **PASS**; no raw synthetic
  canary was present in captured durable or user-visible output.
- Safe native diagnostics: **PASS**; only bounded status/category metadata was
  retained. Raw native text, headers, and credential material were not
  retained.

## Regression and static verification

The final isolated test runs used a temporary synthetic `HOME` with config
loading disabled, so the existing host configuration was not read:

- credential/output/audit/evaluation closure group: **41 passed, 1 skipped**;
- supervision/memory/extension closure group: **51 passed**;
- tool scheduler and gRPC regression group: **86 passed**;
- compileall: **PASS**;
- targeted Ruff 0.16.2: **PASS**;
- targeted Pyright 1.1.411 for credentials, benchmark, and supervision:
  **0 errors**;
- `git diff --check`: **PASS** after the final edits.

An earlier non-isolated test invocation was blocked by an existing host
configuration containing plaintext provider material. The configuration was
not read, changed, or printed; the isolated reruns above are the valid source
regression evidence.

## Final gate verdict

- Provider Integration: **NOT RUN / BLOCKED BY CREDENTIAL AUTHORITY**
- Real Agent Harness: **UNMEASURED** in this gate
- Real Coding Capability: **UNMEASURED**
- Real Browser Capability: **UNMEASURED**
- Full Corpus Readiness: **NOT READY**
- Production Readiness: **NOT READY**
- M9: **NOT STARTED**
- Repository state: **NOT READY** until the operator completes credential
  rotation and a separately authorized native Keychain/provider gate runs in
  an environment where the no-dialog policy is satisfied.

The prior M8 capability reports remain conservative: the current evidence may
record secure credential isolation and an early diagnostic signal, but it does
not convert real-provider or real-browser capability from `UNMEASURED`.

## macOS Credential Provisioning & Non-Interactive Runtime Final Gate

This follow-up gate implemented and deterministically tested the explicit
operator/runtime split. It did not read the host Khaos configuration, invoke a
real provider, service a macOS authorization sheet, or start Coding/browser
evaluation.

### Required final report

Branch: `codex/m8-coding-evaluation`
Current base commit: `3c1095ff69b1a5d800d96eb61e8b88a47fceca14`
Working tree state: dirty pre-existing worktree preserved; no staged paths; no
commit, push, rebase, merge, cleanup, or PR mutation. Working-tree digest is
`c641f4d18a05706e9aa26cbe01e662977f855eb1ed664a67932c781741547b47`; it
excludes this report and the protected local report.

Provider: `NONE / NOT USED`
Model: `NONE / NOT USED`
Reasoning configuration: `NOT APPLICABLE`
Real provider calls: `0`
Real credentials read: `0`

Credential Authority: `PASS` for the synthetic/in-memory authority and typed
Broker boundary; native host provisioning remains environment-blocked.
Secret Leakage Check: `PASS` for generated output, diagnostics, tests, and
the bounded scan; no secret value is recorded in this report.
Provider Smoke: `NOT RUN` — intentionally stopped before any external
provider.
Usage Accounting: `NOT APPLICABLE` — no provider request.
Provider Failure Mapping: `PASS` for the tested typed Keychain categories;
real provider mapping remains `NOT RUN`.

### Backend and DPK decision

The production backend remains the legacy Security.framework generic-password
API (`SecKeychain*`) using the default Keychain. The safe backend audit now
records:

```text
backend: macos-keychain
api: legacy-SecKeychain
data_protection_keychain: NO
accessibility: UNSPECIFIED_LEGACY
access_control / ACL: NONE
userPresence: NO
synchronizable: NO
access_group: NONE
runtime authentication UI: FAIL / forbidden
provisioning authentication UI: ALLOW only inside explicit serialized scope
```

DPK decision: `PACKAGING_PREREQUISITE_BLOCKS_SWITCH`. The current development
Python runtime has no stable signed application identity/entitlement proof for
an access-group migration, and the existing native session cannot complete a
non-destructive synthetic item proof without UI. No DPK, `Always`, sync, ACL,
or user-presence workaround was introduced.

The preserved native status is `-25308`, macOS
`errSecInteractionNotAllowed`, observed on the Keychain write while Khaos had
interaction disabled. The evidence supports
`OS_POLICY_BLOCKED / ENVIRONMENT_BLOCKED`; it does not prove that the backend
or a provider is defective. Runtime never retries with interaction enabled and
never deletes/recreates on this error.

### Provisioning and runtime gates

| Gate | Result | Evidence |
|---|---|---|
| `khaos credentials set <provider>` | PASS (implementation) | hidden `getpass` input, no secret argv, no echo, explicit provisioning Broker path |
| `khaos credentials replace <provider>` | PASS (alias) | same hidden operator path; replacement rollback preserves the old value |
| `khaos credentials status [provider]` | PASS | status uses runtime mode and cannot prompt |
| `khaos credentials delete <provider>` | PASS (operator-only path) | no runtime auto-delete operation |
| Agent/tools can invoke provisioning | NO | no provisioning tool is registered; registry regression passes |
| Provisioning UI policy | PASS (code/test) | explicit scope may allow UI, serialized by process-global lock, restores `False` |
| Runtime UI policy | PASS (code/test) | every runtime store call explicitly sets interaction `False` |
| Atomic/cancel behavior | PASS (deterministic) | typed `-128` cancellation and old/new credential rollback tests |

Synthetic macOS sequence: `MANUAL_PROVISIONING_CONFIRMATION_REQUIRED /
ENVIRONMENT_BLOCKED`. The native item sequence was not re-run in this gate
because the previously observed session cannot service UI and no GUI
automation is permitted. The in-memory authoritative sequence
`PUT -> EXISTS -> GET #1/#2/#3 -> REPLACE -> GET -> DELETE -> MISSING` passed;
the mocked native interaction scope passed. Native runtime GET #1/#2/#3 are
therefore `MANUAL_CONFIRMATION_REQUIRED`, while the deterministic runtime
mode wiring is `PASS`.

### Authority / isolation / leak matrix

| Surface | Result | Boundary |
|---|---|---|
| Operator provisioning | PASS | explicit CLI/config/TUI path only; wrapped `SecretValue` |
| AgentLoop/provider transport | PASS | runtime handle and runtime store access only |
| Runtime popup prevention | PASS | no-dialog policy and typed interaction failure |
| Auto-delete on runtime failure | PASS | no runtime delete capability |
| Plaintext config/env fallback | PASS | `credential_ref` only; fail closed |
| Model/tool provisioning access | PASS | absent from builtin tool catalog |
| Provider discovery | PASS (synthetic transport) | provisioning mode is explicit and limited to `provider.discovery` |
| Workspace/sandbox/output firewall | PASS (existing + targeted) | no secret material in task surfaces or durable diagnostics |

### Task and benchmark status

Task 1–5 real-agent sanity: `NOT RUN`; the gate intentionally stopped before
real-provider execution.
Success / Partial / Failure / Timeout / Provider Error / Environment Blocked /
Security Failure: `0 / 0 / 0 / 0 / 0 / 1 / 0` for this gate.
False Completion Attempts: `0`
Human Interventions: `0`
Real Browser — real model: `NO`; real browser runtime: `NO`; real app runtime:
`NO`; result: `NOT RUN`.

JSONL Validation: `PASS` for existing deterministic schema contracts;
no real-provider task record was created.
Hidden Oracle Isolation: `PASS` for existing deterministic contracts;
real-agent corpus: `NOT RUN`.

Harness Defects: `BLOCKER 0; HIGH 0; MEDIUM 0; LOW 0; INFO 1` (the remaining
native Keychain confirmation is an environment gate, not a Harness defect).
Harness Fixes Applied: explicit `CredentialAccessMode`, serialized native
interaction scope, typed provisioning cancellation, safe backend/DPK audit,
operator-only credential commands, provisioning discovery route, and atomic
credential replacement rollback.
Model Limitations Observed: `NONE — real model not run`.
Provider Limitations Observed: `NONE — real provider not run`; native
`-25308` is classified as host OS policy/session blocking.
Benchmark Defects: `NONE OBSERVED`.
Environment Defects: current Keychain session cannot service the required
interactive provisioning UI; previous credential exposure still requires
operator rotation.

### Regression and architecture gates

The final isolated targeted run used a temporary synthetic `HOME` with
`KHAOS_NO_CONFIG=1`: `104 passed, 1 skipped, 1 warning`. Ruff passed on all
changed source/tests; targeted compileall passed; `git diff --check` passed.
A full-tree compileall scan reaches the intentional invalid-syntax fixture
`python/tests/fixtures/intelligence/syntax_error.py`, so it is not counted as
a repository-wide compile pass. Pyright was run through the available host
installation on the credential module;
broader pre-existing CLI/TUI typing diagnostics are not treated as evidence
against this credential gate.

```text
Credential Provisioning Gate: PASS (deterministic) / MANUAL_CONFIRMATION_REQUIRED (native UI)
Non-Interactive Runtime Credential Gate: PASS (policy + deterministic store) / ENVIRONMENT_BLOCKED (native item)
Production Credential Store Gate: ENVIRONMENT_BLOCKED
Secretless Config Gate: PASS
Sandbox Isolation Gate: PASS
Output Firewall Gate: PASS
Credential Isolation Gate: PARTIAL (synthetic PASS; native host confirmation pending)
Real Provider Benchmarking: BLOCKED / NOT RUN
GLM-5.3 vs GLM-5.3-Flash A/B: NOT RUN
Full Corpus Readiness: NOT READY
Current M8 Capability Status: UNMEASURED / EARLY SIGNAL ONLY
Production Readiness: NOT READY
```

`docs/local-security-closure-report.md`: `UNCHANGED / UNTRACKED / UNSTAGED`;
its pre/post metadata and SHA-256 were preserved.
REAL CREDENTIAL ROTATION: `OPERATOR ACTION REQUIRED`.
Repository state: `NOT READY` — no commit was made; operator credential
rotation and a separately authorized native Keychain confirmation remain
required before production/provider evaluation.

## Local-first CredentialSession gate (2026-09-12)

The local-first decision supersedes the earlier packaging-dependent DPK
direction for ordinary Khaos usage. `CredentialBroker` remains the canonical
credential authority and now owns a small `CredentialSession` facade. A
session starts `LOCKED`; an explicit human CLI/TUI action unlocks one
provider, reads the persistent Keychain value once with provisioning
interaction semantics, and retains only a wrapped `SecretValue` in the
trusted Broker process. Runtime provider authorization uses that in-memory
lease and does not query Keychain again. Lock, replacement, deletion,
shutdown, and process restart invalidate the lease; no lease metadata or
secret is persisted.

The line chat supports `khaos chat --unlock <provider>` and the running TUI/
REPL supports `/credentials unlock <provider|all>`, `/credentials lock
<provider|all>`, and `/credentials status`. These are human-facing paths;
the Agent tool registry exposes none of them. A locked runtime reports the
typed `CREDENTIAL_SESSION_LOCKED` boundary rather than silently triggering a
Keychain prompt.

The deterministic synthetic session gate passed: locked request fails closed,
explicit unlock loads once, three fake provider requests succeed with zero
runtime Store calls, status remains safe, lock fails closed, replacement and
deletion invalidate the lease, and a new Broker starts locked. Native Keychain
round-trip evidence was not fabricated or rerun in this change. The existing
legacy `SecKeychain*` backend remains the local persistent store; Data
Protection Keychain, stable signed identity, provisioning profiles, and Apple
Developer infrastructure are `OPTIONAL_FUTURE_HARDENING`, not local-first
release prerequisites.

This checkpoint still made zero real Provider requests and read zero real
credentials. Historical exposed credentials remain compromised and require
operator rotation before any future real-provider run.

## Manual native synthetic acceptance (2026-09-12)

The bounded manual acceptance used one fresh synthetic account,
`khaos-synthetic-keychain-8548b1665b3f00c2`, in the real macOS login
Keychain. The item was absent before the run and was removed in `finally`; the
final synthetic-leftover count was `0`. No real Provider call or real
credential read occurred.

The native sequence passed: SET, safe STATUS (`PRESENT` while the session
remained `LOCKED`), pre-unlock failure with `CREDENTIAL_SESSION_LOCKED`,
explicit UNLOCK with one persistent-store read, three fake Provider requests,
LOCK, explicit re-UNLOCK, REPLACE with stale-lease invalidation, explicit
replacement UNLOCK, shutdown/restart with a fresh `LOCKED` session, and DELETE
with `CREDENTIAL_MISSING`. Runtime persistent-store reads and runtime Keychain
UI were `0` after each unlock; the fake transport verified authorization only
in memory. Agent-visible and task-environment secret matches were `0`.

The post-fix targeted security/runtime regression passed `157 tests` with one
existing skip. Ruff, targeted compileall, and `git diff --check` passed. The
full Python suite was intentionally stopped after `229 passed` with no failure
output because its projected runtime was not practical; it is recorded as
`INCOMPLETE`, not as a full-suite pass.

The resulting gates are: Persistent Credential Store `PASS`, Credential
Session `PASS`, Runtime Credential `PASS`, Sandbox Credential Isolation
`PASS`, Output Firewall `PASS`, and Local-First Credential Closure `PASS` for
the synthetic/native local path. Git publication remains `UNCOMMITTED`.

The prior `-25308 / errSecInteractionNotAllowed` observation remains in the
historical record. It did not occur during this explicit provisioning/unlock
sequence. The backend remains Security.framework legacy `SecKeychain*`;
Data Protection Keychain and Apple signing/distribution infrastructure remain
`OPTIONAL_FUTURE_HARDENING`. Real credential rotation is still
`OPERATOR ACTION REQUIRED`, and real-provider benchmarking remains blocked.
