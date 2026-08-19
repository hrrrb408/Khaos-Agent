# ADR-022: Native Authority Backend Ownership

Status: Accepted

## Context

M6 shipped native authority *frontends*: the macOS launchd/XPC listener
(`packaging/macos/khaos-authorityd-xpc.m`) and the Windows Service-SID
Named-Pipe listener (`rust/khaos-core/src/bin/khaos-authorityd-windows.rs`).
Both frontends forward requests to a "backend" channel named by
`KHAOS_AUTHORITYD_BACKEND_SOCKET` / `KHAOS_AUTHORITYD_BACKEND_PIPE`.

The problem: **no backend actually exists in production on those platforms.**
`python/khaos/security/authorityd.py::serve_unix()` refuses to run on darwin
and Windows, so the documented chain

```
Agent -> XPC client -> launchd frontend -> KHAOS_AUTHORITYD_BACKEND_SOCKET -> ???
```

dead-ends at an unbound socket. The transport probe could therefore only
prove that a native listener answers; it could never prove that a real
authority (grant registry, receipt state machine, signing key, WORM audit)
executed a transaction. Calling that probe "Production E2E" overstated the
evidence.

## Decision

Keep the two-layer frontend/backend architecture, and make every link of it
real and mutually authenticated:

```
Agent (agent identity)
  -> native client executable (XPC / Named Pipe client)
  -> Native Frontend (platform TCB, authority identity)
       * authenticates the Agent peer (audit token + code requirement /
         process token SID)
       * verifies the backend channel belongs to the authority identity
  -> Authority Backend (Python AuthorityDaemon, authority identity)
       * owns grant registry, delegation registry, receipt state machine,
         policy decision, Ed25519 signing key, WORM audit
       * authenticates the frontend peer on every connection (LOCAL_PEERCRED
         UID on darwin; client process token SID on Windows)
       * never accepts a connection from the agent identity
```

The backend is the *same* `AuthorityDaemon` control plane used on Linux.
`serve_unix()` gains a backend mode: on darwin it serves
`KHAOS_AUTHORITYD_BACKEND_SOCKET` and requires every connecting peer to hold
the authority UID (kernel-verified via `LOCAL_PEERCRED`; the socket and its
parent directory are 0600/0700 owned by the authority user, so the agent UID
cannot connect). On Windows a new `serve_windows_backend()` serves
`KHAOS_AUTHORITYD_BACKEND_PIPE` as a message-mode Named Pipe whose DACL grants
access only to `NT AUTHORITY\SYSTEM` and the authority Service SID, and
validates the connecting client's process-token SID against the Service SID.

Deployment ownership rules:

- The backend socket/pipe, the signing key, and all authority state are
  owned by the authority identity (dedicated launchd `UserName` on darwin;
  the service account behind the Service SID on Windows). The agent identity
  has no path to them.
- The frontend verifies the backend channel before forwarding: on darwin it
  lstats the backend socket (must be a socket, owned by the frontend's own
  euid — the authority user — with mode 0600); on Windows it resolves the
  backend pipe's server process and verifies that process's token SID equals
  the configured Service SID.
- The backend verifies the frontend peer on every connection (UID/SID as
  above), so a wrong-identity process that somehow reaches the channel is
  rejected.
- Restart/recovery: the backend is a launchd job / Windows service with
  `KeepAlive`; durable ownership comes from the socket/pipe path and key
  path being fixed in the authority-owned deployment configuration.
- There is **no** same-user Python fallback, no host backend fallback, and no
  dev-mode production fallback: if the native transport or the backend is
  missing, requests fail closed.

Evidence is split into two levels, honestly named:

1. `scripts/run_native_authority_identity_probe.py` — proves the native
   transport identity chain only (peer identity, service identity,
   protected-key presence, transport ACL).
2. `scripts/run_native_authority_e2e.py` — proves a *full authority
   transaction* through the native transport: `grant -> prepare -> claim ->
   bounded test effect -> complete(success)`, plus the negative paths
   (`grant -> revoke -> prepare rejected`; `prepare -> claim -> backend
   unavailable -> UNKNOWN/QUARANTINED, never SUCCESS`; replay rejection).

A transport identity probe alone must never be recorded as a full
production E2E.

## Consequences

- `serve_unix()` no longer blanket-rejects darwin; it rejects darwin *unless*
  running in backend mode behind the native frontend. Linux behavior is
  unchanged.
- A new backend launchd plist (`com.khaos.authorityd.backend.plist`) and
  Windows service configuration run the Python backend under the authority
  identity.
- CI native workflows must start the backend, run both probes, and bind
  artifacts to `GITHUB_SHA`/`GITHUB_RUN_ID`.
- The native authority proof gains challenge-response semantics (see
  ADR-023) so a captured proof cannot be replayed.
