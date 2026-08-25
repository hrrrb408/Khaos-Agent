# ADR-066: Community Local and Signed Distribution Security Profiles

## Status

Accepted — 2026-08-24

## Context

PR #216 completed Memory V2's canonical event ledger, Broker, provider,
verification, maintenance, runtime integration, and closure contracts. The
remaining ambiguity was deployment evidence: the optional macOS launchd/XPC
path requires Apple signing material, while an open-source local install must
still have a real production security boundary without an Apple membership.

Treating missing Apple material as a Memory failure makes the closure claim
incorrect. Treating an unsigned local process as trusted without a separate
authority, protected state root, peer identity, policy binding, approval,
verification, and audit would also be incorrect.

## Decision

Khaos has two explicit deployment profiles. Memory Core is unchanged by this
ADR.

| Profile | Default / enablement | Required root | Evidence result |
| --- | --- | --- | --- |
| `community` — Community Local Profile | Default on macOS/POSIX personal installs | local user/runtime identity, owner-only `~/.khaos/authorityd/`, private AF_UNIX peer credentials, independent authorityd, Ed25519 receipt key, effective policy and typed catalog | `CLOSED` is valid without Apple membership only after exact-SHA evidence/provenance verification; local JSONL audit is diagnostic, not WORM |
| `native-production` — macOS Signed Distribution Profile | Explicit opt-in for signed macOS distribution; existing Linux/Windows native deployments keep their contract | launchd/XPC or platform-native identity, Team ID/designated requirement, protected key, native service, independent audit, native proof | `OPTIONAL_PROFILE_NOT_ENABLED` / `NOT CERTIFIED` when not enabled; enabled-but-missing evidence is `FAIL` |

The Community Local Trust Root is:

```text
local user/runtime identity
  -> trusted state directory ownership and permissions
  -> protected local capability and AF_UNIX peer identity
  -> Runtime Authority / khaos-authorityd
  -> local Ed25519 authority key
  -> effective policy + typed catalog digest
  -> approval -> verification -> signed receipt -> audit
```

The Community implementation fixes authority state below
`~/.khaos/authorityd/` and rejects symlinked, non-owner, group/other-writable,
or project-controlled socket, key, public-key, catalog, and audit paths. The
socket is exactly `0600`; the client checks the socket and verifies the signed
receipt against the published Ed25519 public key. Unknown profile values,
missing state, policy/catalog mismatch, unauthenticated peers, missing
approval/verification/audit evidence, and all in-process/TCP/host fallbacks
fail closed.

The transport status vocabulary is deliberately finite:

```text
PASS | FAIL | BLOCKED_EXTERNAL | NOT_APPLICABLE | NOT_RUN |
OPTIONAL_PROFILE_NOT_ENABLED
```

The native workflow publishes these values in
`deployment-profile-results.json`. `KHAOS_NATIVE_MACOS_E2E=true` preserves the
signed workflow and its required Team ID/certificate checks; it does not create
a fake identity when secrets or a real native runner are absent.

## Audit result

The local-profile audit covered:

- arbitrary OS-user access: rejected by owner/peer-UID checks;
- world-writable runtime directories and symlinked state: rejected by the
  local trust-root validator;
- project-controlled authority paths and repository config injection: rejected
  because production Community paths are fixed beneath `~/.khaos/authorityd/`;
- unauthenticated RPC and arbitrary runtime impersonation: rejected by the
  separate authorityd protocol, peer credentials, typed principal/grant
  checks, policy/catalog digest, receipt signature, and effect lifecycle;
- host/in-process fallback: unavailable in production;
- disabled approval, audit, or verification: required by the existing Trust
  Kernel and authorityd state machine.

Community is intentionally a same-UID personal boundary. A hostile process
with the same UID can still impersonate a local client; this residual is
explicitly outside the Community claim and is the reason the signed profile
remains available. It is not evidence that the Community path bypasses the
Trust Kernel.

## Closure mapping

PR #216's historical Memory V2 A-Y evidence remains authoritative and is not
recomputed as a second Memory Core design. The new Z boundary is deployment
profile-scoped:

- Community Z: `CLOSED` only when the local trust-root, security regression,
  runtime, RPC, exact commit, and required aggregate gates are verified by the
  local closure evaluator. Apple signing is not a prerequisite.
- Signed macOS Z: `OPTIONAL_PROFILE_NOT_ENABLED` / `NOT CERTIFIED` until the
  profile is explicitly enabled; once enabled, all native signing, protected
  key, launchd/XPC, notarization, and artifact gates are required.
- Full generic M6 closure remains a separate evidence claim and is not silently
  upgraded by Community Z. See `docs/m6-security-closure-report.md`.

## Consequences

- Open-source contributors can run a real local authority deployment without
  inventing Apple identity or weakening Memory/Runtime security.
- Native signing evidence remains preserved and fail-closed when selected.
- Local JSONL audit is useful for diagnostics but cannot claim independent WORM
  retention.
- The same-UID Community threat-model limitation must remain visible in release
  and maintainer documentation.

## Verification

- `python/tests/security/test_local_trust.py`
- `python/tests/security/test_authority_transport.py`
- `python/tests/security/test_authorityd_protocol.py`
- `python/tests/security/test_ci_security_policy.py`
- `python/tests/memory/test_memory_v2.py`
- `python/tests/memory/test_memory_v2_production_surfaces.py`
- `python/tests/memory/test_memory_v2_closure_edges.py`
- `.github/workflows/native-authority-production-e2e.yml`
