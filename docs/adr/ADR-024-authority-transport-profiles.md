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

The Community Local Profile has a fixed local trust root at
`~/.khaos/authorityd/`. Socket, signing key, public key, typed resource
catalog, and local audit paths must be owner-held descendants of that root;
symlinks, group/other writable paths, project-controlled authority state, and
non-private sockets are rejected. The client verifies Community receipts with
the daemon's published Ed25519 public key before returning them to callers.
The complete chain remains local user/runtime identity -> protected state
directory -> peer credentials -> Runtime Authority -> Ed25519 key -> policy /
catalog digest -> approval / verification / audit. Apple code signing is not
part of this chain.

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
- The same-UID limitation is an explicit Community threat-model boundary, not
  a hidden claim of runtime impersonation resistance. Cross-user access,
  repository-selected authority paths, symlink replacement, unauthenticated
  RPC, policy/catalog injection, and missing approval/verification/audit
  postconditions remain fail-closed conditions.
- A local JSONL audit file is crash-durable diagnostic evidence, not an
  independent WORM authority.  Deployments requiring tamper-resistant audit
  retention must use `native-production` (or a separately provisioned remote
  writer).
- A missing authority daemon, key, socket, policy digest, or typed resource
  catalog still fails closed.  There is no implicit in-process, TCP, or
  platform fallback.
- Authority daemon startup never replaces an apparently live Unix endpoint:
  an existing socket is connect-probed, only an `ECONNREFUSED` stale inode may
  be removed, and a bind race fails closed.  Explicit revocation of an unknown
  grant is also rejected; retries for a grant already recorded in a terminal
  tombstone remain idempotent.
- Native macOS evidence is now an optional deployment capability for the
  community profile, not a prerequisite for ordinary local functionality.
- Profile evidence uses the statuses `pass`, `fail`, `blocked_external`,
  `not_applicable`, `not_run`, and `optional_profile_not_enabled`. The optional
  signed distribution profile is `NOT CERTIFIED` when not enabled; it becomes a
  required fail-closed gate only after explicit enablement.
