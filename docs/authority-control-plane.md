# Authority Control Plane and Execution Receipt Closure

This document is the authoritative boundary for the M4 control-plane work.
It deliberately separates code-enforced guarantees from deployment and
organization prerequisites.  A local SQLite database, JSONL trail, or Python
object is never described as an independent authority or WORM audit.

## Execution protocol

```text
agent intent
    -> khaos-authorityd issuer/policy-digest/family gate + identity check
    -> remote/WORM append(execution.prepare)
    -> Ed25519 signed PREPARED receipt
    -> CLAIMED immediately before the effect starts
    -> native helper verifies receipt from already-open descriptors
    -> helper returns result digest
    -> remote/WORM append(execution.success|failed|unknown)
```

The receipt binds `principal_id`, `project_id`, `runtime_id`, `task_id`,
`workspace_id`, `operation`, `resource_digest`, `policy_digest`, `nonce`,
`authorization_epoch`, `expires_at`, and `audit_intent_digest`.  A missing
authority daemon or unavailable audit writer refuses `prepare`; a result that
cannot be committed is `unknown`/quarantined and must not be reported as
success.

The signed wire representation encodes `issued_at` and `expires_at` as
non-negative integer milliseconds.  Python callers decode those values back to
seconds, but the integer contract is required because Python and Rust JSON
float serializers do not promise identical signed bytes.

`AuthorityGrant` (`AuthorityEnvelope` is the compatibility class name) is the
long-lived, broker-owned context. It contains an opaque grant id and expiry,
but the live grant registry remains in the broker/authorityd owner; copying or
mutating a stale Python object cannot mint a new capability. The grant binds a
single operation family, initial resource scope, workspace generation, policy
digest, and authorization epoch. Direct effects must stay inside that initial
scope; a resource transition is accepted only through a live parent narrow
transaction. Explicit revoke, authorization-epoch rotation, and
workspace-generation rotation atomically invalidate the live record plus every
still-launchable `PREPARING`/`PREPARED`/`NARROWING` descendant before a stale
object can issue or claim again. The daemon records a bounded grant tombstone
and `execution.revoked-by-grant` evidence for each invalidated receipt.
`EffectCapability` is a short-lived,
one-shot receipt handle. Expiry blocks a new claim, but a receipt that was
already claimed may commit `success`, `failed`, or `unknown` after the
300-second launch TTL. Prepared expiry is garbage-collected into a bounded
tombstone inventory; global and per-principal pending quotas prevent memory
growth.

The lifecycle distinction is intentional: `PREPARED` is still a launch ticket
and is retroactively denied by grant/epoch/generation invalidation, while
`CLAIMED` has crossed the effect boundary and remains completable for terminal
accounting. This daemon is an issuer, family gate, and production typed-resource
PDP. Its production builder requires an immutable catalog whose `policy_digest`
equals `KHAOS_EFFECTIVE_POLICY_DIGEST`; the catalog is loaded from
`KHAOS_TYPED_RESOURCE_CATALOG_PATH` by both the Agent runtime and authorityd.
Development/test adapters may omit the catalog, but they cannot be used as
production evidence. Independent-review/governance work remains tracked in
issue #169.

Narrowing creates a child resource digest from the parent digest, target
operation, and requested scope in legacy adapters; with the production typed
catalog the canonical child scope digest is signed directly. Authorityd
enforces same-family transitions, verifies that the exact target action is in
the requested scope, and re-runs that check when an expired receipt is renewed.
A successful narrowing consumes the parent receipt and records a `narrowed`
terminal tombstone. Both the child prepare event and parent terminal event
reserve bounded audit capacity before either authority transition can become
irreversible.

The typed policy authority can be supplied to `AuthorityPolicyKernel` as an
immutable `TypedResourcePartialOrder`. Its catalog contains canonical digests
for concrete `FilesystemScope`, `NetworkScope`, `GitRefScope`,
`ExecutionScope`, and `CredentialScope` values. When configured, a narrowing
must resolve both the parent digest and requested child scope and prove the
child is contained by the parent; unknown, malformed, cross-kind, and
cross-family transitions fail closed. The signed receipt remains opaque on the
wire, while the semantic decision is explicit and independently testable.
The manifest also carries a stable `catalog_digest`; malformed, unknown,
cross-kind, cross-family, action-forbidden, or policy-mismatched entries fail
closed. `EffectiveSecurityPolicy` deterministically compiles the baseline
filesystem/Git/network catalog at startup, and
`scripts/generate_typed_resource_catalog.py` persists that exact snapshot for
the independent authorityd process. The Agent rejects a manifest whose
`catalog_digest` differs from the locally compiled snapshot. Workspace/Git and
NetworkBroker production owners resolve their canonical scope through this
catalog; native execution still keeps its separate exact launch-binding digest.
For deployments that want the typed catalog to bind Git path effects as well
as refs, `KHAOS_WORKTREE_AUTHORITY_ROOT` must be set to the same absolute
private root before both the effective-policy compiler and
`WorkspaceManager` start. The compiler then emits that root in `GitRefScope`
and the runner requires the exact matching root. If the variable is absent,
the catalog deliberately makes no pathname claim; `TrustedGitRunner` still
enforces its own private authority root as the final local TCB, so this
compatibility mode must not be reported as independently reviewed
cross-process path-binding evidence.
Credential use now has a trusted `CredentialBroker` owner: a registered
provider loader issues a short-lived lease bound to the typed scope, target,
operation, policy digest, and principal, while secret material is materialized
only for the final trusted execution environment and is absent from the
lease/audit identity. Production deployments must still register a real
provider adapter; an unregistered provider fails closed rather than falling
back to ambient environment variables or model-visible secrets. Production
deployments must pass the same
policy-bound manifest to the Agent and `build_production_daemon`; an absent or
divergent catalog refuses startup rather than silently claiming typed coverage.
The standalone file loader also verifies the absolute path, every parent
component, owner boundary (root or the current service identity),
single-link regular-file type, and absence of group/other write permission;
symlinked or writable catalog paths are rejected before JSON parsing. Linux
systemd deployments should keep the catalog root-owned and read-only under
`/etc/khaos`; non-Linux deployments must provide the equivalent native ACL or
read-only mount guarantee. A root-owned sticky system temporary directory may
occur above a private test/development directory; it does not relax the
final-file or private-descendant checks used by production catalog paths.

Narrowing is an owned transaction rather than an untracked lock gap. The
daemon records the parent receipt, child intent, descendant reservation, and
one audit reservation in a `NarrowTransaction`. It moves through child
preparation and commit states under the authority lock; grant revoke, epoch
rotation, workspace-generation rotation, and expiry atomically move any
in-flight transaction to an aborted state, terminalize its parent/child
receipts, and bind the existing audit reservation to one
`execution.narrow-aborted-by-grant` event. The abort event is therefore
owned by the invalidation path, is idempotent, and cannot leave an anonymous
quota reservation after the grant record is forgotten. The invalidation path
commits the exact planned abort event/reason; it does not replace
`explicit-revoke`, `authorization-epoch-rotated`,
`workspace-generation-rotated`, or `expired` with a generic terminal label.

Git state changes use a separate exact-effect kernel. `update-ref` binds the
concrete ref and expected old/new object IDs; worktree add/move/remove binds
the concrete paths and no-checkout shape; those paths must be strict
descendants of the runner's private authority root and cannot be the root or
escape through a symlink; index/tree operations bind their exact arguments;
and stdin/file-producing effects bind a SHA-256 digest and length of the
payload. The runner rechecks the argv, repository/admin-dir/work-tree, Git
operation class, typed `GitRefScope` (including approved task-ref namespaces),
and file digest immediately before spawn. Every binary, bounded-output, and
synchronous runner entry point rejects these state-changing commands unless
it goes through that same exact-effect path.

Agent orchestration phase snapshots are a separate evidence layer. The
immutable `TurnPhaseSnapshot` and `ToolPhaseSnapshot` bind phase transitions to
the admitted turn/tool identity and canonical evidence digests; they reject
skipped edges and post-admission call drift. A phase digest is not an
`AuthorityGrant`, `EffectCapability`, approval binding, or external effect
result. The first physical extraction now includes `TurnAdmission`,
`TurnFinalizer`, and `ToolPhaseCoordinator`, while preserving the existing
AgentLoop and ToolScheduler APIs. Full decomposition into independent phase
inputs/outputs and an effect ledger remains staged work; this is an incremental
boundary, not a claim that either orchestration owner is already small.

Python callers use `AuthorityDaemonClient` through `AuthorityDaemonBroker` in
production.  `AuthorityBroker()` remains a test-only in-process broker; the
default production factory only permits it under the explicit development
profile.  The Rust execution launcher accepts the receipt and authorityd
public key through inherited file descriptors, verifies Ed25519, and rejects
raw Python objects, SQLite rows, pathname references, or caller-supplied key
paths.

For host execution, production deployment sets
`KHAOS_REQUIRE_AUTHORITY_RECEIPT=1` and
`KHAOS_AUTHORITYD_PUBLIC_KEY_PATH` to the separately provisioned trust anchor.
`ProcessSupervisor` derives an exact `exec.host` intent from the immutable
`ExecutionAuthority`, passes only the signed receipt and the already-open
public-key descriptors to the launcher, and commits a result digest after the
child is reaped.  `KHAOS_EFFECTIVE_POLICY_DIGEST` is loaded by authorityd from
its independently compiled policy; a client-supplied digest that does not
match is rejected before signing.  If that result commit is unavailable, the
returned outcome is `unknown`; it is never converted into `passed`.  A
production host spawn without the immutable execution authority, authorityd
receipt, public-key anchor, or native launcher is refused.

The daemon is an independent issuer and policy-digest/operation-family gate;
the Agent runtime, TaskWorkspace, exact command binding, and platform backend
remain separate effect-policy authorities.  The daemon does not claim to
reimplement those higher-level policy decisions.

## OS identity contract

Transport selection is owned by `python/khaos/security/authority_transport.py`
and documented in ADR-024. `KHAOS_AUTHORITY_PROFILE=community` is the
same-user local profile for personal macOS/POSIX installs: it keeps the
separate daemon, private socket, kernel peer credentials, signed receipts and
policy/resource checks, but intentionally does not claim code-signing,
multi-user isolation, or remote WORM durability. The native rules below apply
when `native-production` is selected.

The daemon is a separate service, not merely another process in the Agent's
UID:

- Linux requires distinct Agent, authorityd, and job UIDs, a private `0600`
  Unix socket, `SO_PEERCRED` validation, and bwrap `--unshare-user` with the
  configured job UID/GID.  The job identity is namespace-visible; a distinct
  host UID is not claimed unless native host mapping evidence proves it.
- macOS `native-production` deployment must provide launchd/XPC service identity,
  signed daemon code, and Keychain/Secure Enclave access-group ACLs.
- Windows production deployment must provide a service SID, Named Pipe ACL,
  and CNG/DPAPI-protected key reference.

The repository now contains the native transport clients and service packages
under `packaging/macos/` and
`rust/khaos-core/src/bin/khaos-authorityd-windows.rs`. The Python
`NativeAuthorityProof` adapter accepts a production request only after the
native client has proved the launchd/XPC or Service-SID/Named-Pipe boundary.
The native services are deliberately separate from the Agent and keep the
authority backend/key boundary outside the Agent process. Missing signed
artifacts, missing protected key, identity mismatch, stale proof, or an
unavailable native platform service still makes `native-production`
authority-backed execution unavailable. The community profile has an explicit
Unix-socket path, but neither profile permits TCP or an in-process production
fallback.

The native source and manifests are implementation inputs, not runtime
evidence by themselves. A real macOS or Windows runner must install the
platform service and produce the native probe artifact before M6 can claim
cross-platform production closure.

## Community Local Trust Root and profile-scoped closure

`community` is a deliberate `Community Local Profile`, not an unsigned
shortcut around the Trust Kernel. Its local trust chain is:

```text
local user/runtime identity
  -> owner-only ~/.khaos/authorityd state directory
  -> protected local socket/key/catalog/audit paths
  -> AF_UNIX peer UID check and 0600 socket
  -> Runtime Authority / independent khaos-authorityd process
  -> authority-owned Ed25519 signing key and public verification key
  -> effective-policy digest + typed resource catalog
  -> approval -> verification -> signed receipt -> audited effect
```

The daemon rejects a Community socket, signing key, public key, typed catalog,
or local audit path that is outside `~/.khaos/authorityd`, a symlink, not
owner-held, or exposed through group/other write permissions. The client
validates the socket before connecting and verifies every Community receipt
against the published Ed25519 key. Production authorityd remains a separate
process and requires the existing policy, typed resource, grant, approval,
verification, and audit gates; it never falls back to the in-process broker,
TCP, host execution, or repository-controlled configuration.

This boundary intentionally protects a personal same-UID local deployment,
not code-signing or multi-user identity. A same-UID hostile process is an
explicit residual risk of `community`, not an unrecorded security claim; a
different OS user, a project-controlled path, a world-writable runtime
directory, an unauthenticated RPC peer, or a missing approval/audit/verification
postcondition is rejected. The Apple Signing Root is an additional chain for
`native-production`, not the root of Community local security.

Closure status is profile-scoped: `pass`, `fail`, `blocked_external`,
`not_applicable`, `not_run`, and `optional_profile_not_enabled`. The
Community result can be `PASS` without Apple membership. The optional signed
distribution result is `OPTIONAL_PROFILE_NOT_ENABLED`/`NOT CERTIFIED` when its
Team ID, certificate, Keychain, launchd/XPC, or notarization workflow is not
enabled; if explicitly enabled and any required secret or native proof is
missing, it fails closed. The historical Memory V2 A-Y evidence from PR #216
is preserved; the new Z result is no longer coupled to optional Apple signing.

## Independent audit prerequisite

`RemoteWormAuditWriter` requires an HTTPS append-only endpoint and has no local
fallback.  The deployment must use object-lock compliance mode, a separate
append-only service, or an equivalent independently administered log.  The
local SQLite hash chain and JSONL file remain useful diagnostic evidence but
cannot defend against a same-UID actor that can rewrite both local stores.
The explicit community profile uses that JSONL writer by design and reports
only local diagnostic durability; it must not be described as WORM evidence.

The Windows helper uses the same ownership rule at the process boundary:
pending spawn, active process, and orphan/quarantine records are retained until
terminal wait and output-pipe proof is complete. Repeated cancellation is
drained behind a shielded cleanup task; a helper is never removed from the
ownership graph merely because the caller observed cancellation.

## Governance prerequisite

The repository includes security-sensitive CODEOWNERS, exact-commit gate
evidence, release SBOM/provenance workflows, and signed-tag verification.
Independent approval, administrator-bypass prohibition, two-person
break-glass, and third-party penetration testing require GitHub organization
settings and people outside this repository.  Until a second maintainer and
external assessment exist, release material must label those controls
`not_proven`; code and CI must not claim Codex-equivalent organizational
assurance.
