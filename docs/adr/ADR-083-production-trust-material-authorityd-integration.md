# ADR-083: Production trust material and authorityd integration

Status: accepted

Date: 2026-08-31

## Decision

The production runtime and `khaos-authorityd` are two independent consumers of
operator-provisioned trust material. They do not select security inputs from a
task, workspace, repository, model response, or local test default. Each side
loads and validates the same typed catalog and effective-policy identity, then
the runtime completes a bounded handshake before any effect broker is exposed.

The handshake binds this complete, non-secret tuple:

```text
protocol version
authority issuer id
effective policy digest
typed catalog semantic digest
authority public-key fingerprint
deployment environment digest (platform/profile/transport)
```

`READY` is a protocol result, not a local boolean. A missing, malformed, stale,
or mismatching value rejects startup. Workspace, network, and execution
consumers receive the exact same READY broker object; none may construct a
production default broker.

The handshake also binds the runtime session identity
(`runtime_id`, `principal_id`, `project_id`, and `principal_kind`) to a fresh
authorityd channel nonce. Every subsequent request carries the same identity,
binding, and nonce; a request with a different runtime identity is rejected.
The session identity is intentionally channel-scoped rather than part of the
deployment-wide catalog/policy binding digest, so multiple independently
identified runtimes can share one authority deployment without sharing a
request channel.

Subagent RPC admission is the one lifecycle exception: the child runtime does
not exist when the spawn request is authorized. The delegation issuer therefore
opens a short-lived READY channel bound to the authenticated ingress principal,
issues the narrow child delegation, and closes that channel before the child is
started. The child then performs its own READY handshake for effect work. This
keeps delegation on the production authority chain without creating an
unbound client or granting the child access to trust material.

## Trust-material ownership

| Material | Producer | Independent consumers | Owner and boundary |
| --- | --- | --- | --- |
| Effective policy | operator policy files compiled by `EffectiveSecurityPolicy` | runtime factory and authorityd | host-controlled policy compiler; immutable for one runtime |
| Typed resource catalog | `scripts/generate_typed_resource_catalog.py` | runtime factory and authorityd | operator-controlled absolute file; no symlink/traversal/writable parent; bounded and digestable; Win32 owner/DACL checked in native production |
| Authority signing key | authorityd deployment | authorityd only | authority/native key store; never enters the Agent or audit records; Win32 owner/DACL checked in native production |
| Authority public key | authorityd publishes the public half; operator mounts/provisions it | runtime/native adapter and receipt launcher | owner-held immutable verification anchor; fingerprint is handshake-bound; Win32 owner/DACL checked in native production |
| Authority socket/native endpoint | deployment profile and service manager | runtime transport client | service-owned Unix socket, XPC, or Service-SID Named Pipe; no TCP or Python fallback |
| Identity contract | service manager / deployment environment | runtime, authorityd, native frontend | independent OS identity boundary; malformed or incomplete contracts fail closed |
| Remote audit writer | deployment operator | authorityd | authority-side WORM/remote owner; local SQLite/JSONL is never substituted in native production |

The catalog file is semantic material rather than a pathname authority. Its
entries contain canonical concrete filesystem, network, Git, execution, and
credential scopes. The digest is recomputed from the parsed snapshot, and the
runtime additionally compares it with the catalog compiled from the effective
policy. A catalog path is only a deployment input and cannot be selected by a
task or workspace.

## Startup and failure contract

The required order is:

```text
trusted directories
  -> independent catalog load and deep validation
  -> catalog semantic digest
  -> effective policy and policy digest
  -> key/public-key validation and fingerprint
  -> authorityd transport selection
  -> authorityd handshake
  -> READY runtime composition
  -> RPC/request admission
```

Before `READY`, no effectful RPC is admitted. Production startup cleanup
retains or quarantines every partially initialized owner; it never reports a
failed authority channel as a usable local broker. Effective authority stays
the intersection of policy, catalog, runtime permission/approval, plan,
workspace, principal, and sandbox controls.

Catalog or policy mutation during a runtime is not a live configuration
reload. The deployment must restart the authority and runtime together. A
future watcher may trigger that restart, but it must not silently replace the
immutable snapshot or preserve a READY channel across a digest change.

## Platform profiles

Linux production uses the dedicated authority UID and Unix transport. macOS
community uses the explicit private same-user Unix profile; macOS
`native-production` uses the launchd/XPC frontend. Windows uses the
Service-SID/Named-Pipe frontend and its protected key boundary. The Python
backend is never an agent-reachable fallback for a native frontend, and the
community profile does not claim multi-user or code-signing isolation.

## Consequences

- A local unit-test daemon may keep its legacy symbolic-digest compatibility
  surface, but that surface is not reachable from a production composition.
- A deployment with missing native artifacts, identity proof, remote audit, or
  exact-SHA CI evidence remains `UNKNOWN`/`BLOCKED_EXTERNAL`, not `CLOSED`.
- Rotation is an explicit restart operation: provision the new key/catalog,
  publish the matching public anchor, restart authorityd, then restart the
  runtime and verify a new handshake binding.
