# Platform Security Guarantees

These guarantees are deliberately narrower than “absolute security”. A claim
is valid only for a commit whose required `Security Closure Gate` passed with
complete provenance-backed evidence.

The independent authority daemon, signed receipt, OS identity, and remote
audit boundaries are specified in
[`docs/authority-control-plane.md`](authority-control-plane.md).  Local audit
chains remain tamper-evident rather than tamper-proof.

## Trusted Git workspace bootstrap

Host Git is a control-plane dependency, not a trust boundary. Khaos pins the
Git executable and authority root, rejects Git checkout/filter/textconv and
external-diff extensions, and uses a bounded allowlist of plumbing operations.
Tracked content is materialized from raw tree/blob objects into a pending
worktree. Publication occurs only after bounded entry/byte/path-depth/symlink/
duration accounting, object-id verification, protected-metadata validation and
stable storage observation. Any cancellation, malformed object, hash mismatch,
quota violation, disk error or child failure removes the pending worktree and
does not register a usable `TaskWorkspace`.

Git submodules are an explicit current limitation: tree entries with mode
`160000` are rejected with a fail-closed diagnostic. Khaos does not run
`git submodule update` during bootstrap and therefore does not claim submodule
materialization support.

ChangeSet artifacts are also bounded resources: each workspace may register at
most 64 artifacts and 256 MiB total. Each artifact is exclusive-created,
length/digest checked, owned by the workspace registry, exportable only below
the private authority root, and removed during workspace cleanup or a failed
build.

## Trust Boundary Axiom

The guarantees below defend the host against **untrusted repository content**,
**model-generated commands**, **cross-project authority drift**, and **peer
processes outside the relevant OS identity**. They are not a claim of
isolation from every local adversary.

> **The operating-system identity assigned to each control-plane role is a trust boundary.**
>
> In development mode, the local broker and its caller intentionally remain
> same-user test components. In production, host execution requires the Agent,
> authorityd, and job roles to use distinct native identities; authorityd and
> the result sink are not replaced by a same-UID Python process.

Concretely, a process running as the Agent UID can still impersonate Agent
client behavior and access Agent-owned 0600 state; that role is not an
anti-malware boundary. It cannot satisfy the authorityd socket's peer-UID
check when authorityd runs under its dedicated UID, and it cannot forge an
Ed25519 receipt without the authorityd key. The file-mode, peer-UID,
socket-ownership and capability-file checks still defend against *other* OS
users, the model, repository payloads, path traversal and rogue Gateways.
macOS and Windows use the same fail-closed rule but require their native
launchd/XPC or Named Pipe service packages; the repository does not emulate
those transports.

The HTTP Gateway authenticates a single principal derived from the API key
digest (`api-key:<sha256>`). All clients holding the same key are the *same*
security subject. The Gateway is therefore a single-instance authentication
boundary suitable for a single-user local Agent, one trusted Gateway, and a
local browser UI. It is **not** multi-tenant, does not provide per-user
independent authorization, per-device revocation, or per-client least
privilege.

## Effect capabilities and managed egress

`AuthorityEnvelope` is an immutable context record, not an effect grant, and
its public constructor is closed: only the owning `AuthorityBroker` can issue
an envelope that can enter the capability chain. Git and network effect
boundaries require a broker-issued `EffectCapability`. The
`AuthorityBroker` keeps the signing secret and live revocation registry in a
separate spawned process; the capability handle is opaque to its public
constructor, and every boundary validates operation, resource, generation,
expiry and revocation against that broker. This is a same-user control-plane
boundary, not a claim that Python can defeat a hostile process with the same
OS identity.

`NetworkBroker` is the generic terminal/tool egress authority. It accepts only
brokered capabilities, authenticates each proxy connection, resolves DNS
itself, pins the selected address, enforces domain/port/protocol allowlists,
rejects unsafe address classes, bounds concurrency/bytes/idle time, and emits
allow/deny audit events. A `NetworkLease` is itself attested to the exact
endpoint and policy digest and is revalidated at every connection. Linux
execution requires the lease's real kernel-network-namespace join contract;
the tempting loopback lease plus `--unshare-net` combination is rejected
because it would not actually reach the broker.

| Platform | Production guarantee | Unsupported behavior |
|---|---|---|
| Linux | non-root, zero-capability Python; bwrap filesystem isolation with a dedicated job user namespace UID/GID; cgroup v2 budgets; root Rust helper as the sole netns/veth/nft/cgroup authority; default-deny browser egress | missing launcher/helper/cgroup delegation/user namespace rejects execution; no Host, `ip`, `nft`, or proxy-only fallback |
| macOS | `sandbox-exec` Seatbelt profile restricts content, metadata, directory listing, credential roots, Mach services, network and writable workspace boundaries | no browser kernel namespace claim; a failed probe or invalid launcher rejects execution |
| Windows | native helper after a passing probe: native commands and trusted Python under `network=none` use an OS-issued AppContainer low-box; trusted Python stages the resolved base executable and grants exact temporary ACLs only to the disposable runtime tree; brokered mode uses a restricted primary token and exact loopback-only WFP rules; all paths use child-process policy, a one-process Job Object, and transactional workspace ACL | missing helper/probe evidence, non-native command, ACL/firewall/token/AppContainer failure, or unsupported network endpoint rejects execution; never falls back to Host |

For the production Docker composition, `khaos-agent` requires three
host-reviewed, hash-pinned outer profile declarations supplied through
`KHAOS_DOCKER_SECCOMP_OPT`, `KHAOS_DOCKER_APPARMOR_OPT`, and
`KHAOS_DOCKER_SYSTEMPATHS_OPT`; `compose.prod.yaml` fails closed if any is
missing. The operator must run
`python scripts/validate_docker_outer_profiles.py --manifest <manifest>`
before `docker compose`; the manifest must match all three exact options,
hash each seccomp/AppArmor source file, and pin `systempaths=default`. Docker
uses `name=value` syntax. Docker's default outer restrictions
can block the unprivileged namespace and mount-propagation syscalls needed to
create the bwrap boundary. These profiles are container-composition
compatibility controls, not payload authorization: the Agent remains UID
10001, receives no `SYS_ADMIN` capability through Compose, and the Rust
launcher, bwrap mount boundary, Landlock, seccomp, cgroup, and authority receipt
checks remain mandatory. The disposable composition probe may explicitly use
`seccomp=unconfined`, `apparmor=unconfined`, and `systempaths=unconfined` on its
temporary CI host only; the compose probe validates that exception explicitly,
and those values are not production defaults. Deployments
that cannot preserve an equivalent passing composition must refuse production
execution; they must not grant `SYS_ADMIN` to Python or fall back to Host
execution. Khaos does not ship one universal hardened outer profile because
seccomp/AppArmor behavior and nested-user-namespace compatibility are
host-runtime-specific; the manifest is the deployment pin and evidence
boundary rather than an unreviewed universal default.

The coding execution path and browser authority path use separate launcher
inodes. `KHAOS_EXECUTION_SANDBOX_LAUNCHER` points to the capability-free copy
used by `ExecutionService`; `KHAOS_SANDBOX_LAUNCHER` points to the distinct
browser launcher whose file capability is reserved for the authenticated
browser helper transition. Missing or invalid execution-launcher packaging
fails closed; coding execution never falls back to the browser authority
binary.

The composition probe runs the exact `ExecutionService` ->
`ProcessSupervisor` -> native launcher -> bwrap path with `network=none`, and
uses an external `/proc` oracle over the supervisor-owned process tree. The
production Agent receives a separate host-reviewed delegated cgroup v2 subtree
through `KHAOS_EXECUTION_CGROUP_SOURCE`, mounted at
`/run/khaos-execution-cgroup`; the
Compose deployment must set `KHAOS_EXECUTION_CGROUP_PARENT` to that same
delegated cgroup parent so the Agent's Docker cgroup and its execution leaves
share a delegated common ancestor;
Compose service uses the host cgroup namespace because a private container
cgroup namespace cannot migrate into a host-delegated subtree; the Agent still
receives only that explicit bind mount as writable and has no `SYS_ADMIN`
capability. The
production helper's cgroup subtree is independent. The composition probe
preflights the required controllers and fails closed when the execution
delegation is absent or incomplete. Its `/app/data` workspace must expose a
block-backed device that accepts `io.max`; the Docker CI path supplies this
through `KHAOS_PRODUCTION_DATA_SOURCE` and rejects overlay/pseudo-device
sources before startup. The real-kernel Linux security gate remains
the authority for the broader
`--unshare-net` and network-policy matrix.

`KHAOS_DEV_MODE=1` is an explicit development-only mode. It is not a weaker
production profile and must never generate production security evidence.

Production Go-to-Python JSON-line RPC also requires an authenticated
`RPC.Initialize` negotiation before service dispatch. The selected protocol,
method schema, feature set, required security fields, and reject-unknown-fields
policy are HMAC-bound; a missing or incompatible negotiation fails closed.

Audit integrity is layered: SQLite append-only triggers and `prev_hash` are
checked against a local independent chain-head anchor in `~/.khaos/audit/`.
This detects local rollback/history edits but is not a remote WORM service and
does not defend against an actor who can rewrite both trusted stores.

Before a production TaskWorkspace subprocess starts, `ExecutionService` binds
the worktree and cwd device/inode identities into the request.  POSIX backends
open the root and cwd with `O_DIRECTORY | O_NOFOLLOW` (relative cwd components
are opened from the pinned root FD); the supervisor passes those descriptors to
the child, rechecks their identities, and uses `fchdir` immediately before
`exec`.  Linux bubblewrap uses the inherited root FD as its bind source through
`/proc/self/fd`.  A path swap or symlinked cwd component therefore fails closed
before the payload runs.  After bubblewrap has created the final Linux mount
namespace, the Rust launcher installs a required Landlock filesystem allowlist
and then the seccomp deny-list; missing Landlock support or any malformed
allowlist rejects the payload. macOS Seatbelt still uses its platform
path-based profile for allowlisted read/write rules, so real Linux/macOS
sandbox acceptance remains a platform capability and CI gate.

Gateway `/api/config` is operator-level state.  Authentication alone does not
grant access: GET and PUT require a principal in the explicit
`KHAOS_CONFIG_ADMIN_PRINCIPALS`/`--config-admin-principals` allowlist, and an
empty allowlist fails closed.

The Linux native installer places only the Rust launcher/helper in privileged
TCB locations. Python must run as the dedicated `khaos` user. The launcher has
only `CAP_SYS_ADMIN=ep` for its one validated `setns` transition and clears
capabilities before payload execution. The helper is root, but accepts only
the configured agent daemon process tree and requires a secret-backed runtime
capability on every operation.
