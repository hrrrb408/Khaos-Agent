# ADR-024: Explicit Authority Transport Profiles

Status: Accepted

## Context

Khaos is primarily a single-operator local agent.  The macOS launchd/XPC
frontend is a useful hardening option, but it requires a Team ID, a signing
certificate, and a Keychain deployment that an open-source contributor cannot
reasonably be expected to own.  Inferring that native path from
`sys.platform == "darwin"` made every production-looking local run depend on
unavailable Apple credentials and caused the native CI job to fail before it
could test any Khaos authority behavior.

The transport choice must therefore be explicit and owned by one module.  A
missing or unknown profile must not silently create an in-process broker or a
different network transport.

## Decision

`python/khaos/security/authority_transport.py` is the single transport
selection boundary.  It supports two profiles:

| Profile | macOS | Linux | Windows | Audit boundary |
| --- | --- | --- | --- | --- |
| `community` | private AF_UNIX socket, same-user peer credentials | private AF_UNIX socket when explicitly selected | rejected | local append-only JSONL; no WORM claim |
| `native-production` | launchd/XPC frontend plus authority-owned backend socket | existing dedicated-UID AF_UNIX deployment | Service-SID/Named-Pipe frontend | independent HTTPS/WORM writer |

On macOS, the unset profile intentionally selects `community`, because that
is the usable personal-installation baseline.  Selecting
`KHAOS_AUTHORITY_PROFILE=native-production` is mandatory for the launchd/XPC
path and its Team ID/signing contract.  Linux and Windows preserve their
existing production behavior when the variable is unset.  Any explicit
unknown value fails closed.

Both profiles retain the authority daemon as a separate process.  The
community profile does **not** re-enable the old in-process HMAC broker: the
Agent still connects to `khaos-authorityd`, which owns the Ed25519 signing
key, receipt TTL/nonce/replay state, revocation state, resource scope, and
effective-policy digest.  The difference is the OS identity boundary and the
audit durability claim, not the authority protocol or effect lifecycle.

The native profile remains available for signed releases and deployments that
need process identity stronger than same-user local IPC.  Its existing
launchd/XPC and Windows Service-SID code, packaging, challenge-response
proofs, and native E2E artifacts are unchanged except for the explicit
profile marker.

## Consequences and residual risk

- A community process running as the same user can impersonate another local
  process of that user.  The private socket and kernel peer UID prevent
  cross-user access, but they do not provide code-signing or multi-user
  isolation.
- A local JSONL audit file is crash-durable diagnostic evidence, not an
  independent WORM authority.  Deployments requiring tamper-resistant audit
  retention must use `native-production` (or a separately provisioned remote
  writer).
- A missing authority daemon, key, socket, policy digest, or typed resource
  catalog still fails closed.  There is no implicit in-process, TCP, or
  platform fallback.
- Native macOS evidence is now an optional deployment capability for the
  community profile, not a prerequisite for ordinary local functionality.
