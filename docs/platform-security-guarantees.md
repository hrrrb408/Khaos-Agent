# Platform Security Guarantees

These guarantees are deliberately narrower than “absolute security”. A claim
is valid only for a commit whose required `Security Closure Gate` passed with
complete provenance-backed evidence.

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
processes outside the OS-user identity**. They are not a claim of isolation
from every local adversary.

> **The operating-system user account is a trust boundary.**
>
> Khaos protects the host from untrusted repository content, model-generated
> commands and cross-project authority drift. Khaos does **not** claim to
> isolate itself from arbitrary malicious processes already executing as the
> same OS user.

Concretely, a process already running as the same OS user can typically read
the user's 0600 files (API keys, capability files, `~/.khaos` state), call the
same-UID Unix domain socket, access workspaces the user owns, and impersonate
the local CLI/TUI user. The file-mode, peer-UID, socket-ownership and
capability-file checks throughout Khaos defend against *other* OS users, the
model, repository payloads, path traversal and rogue Gateways — not against a
same-UID attacker. Defending against a hostile same-UID process would require
running the complete state writer and credential store under a separate OS
identity, which is out of scope for the single-user local deployment model.

The HTTP Gateway authenticates a single principal derived from the API key
digest (`api-key:<sha256>`). All clients holding the same key are the *same*
security subject. The Gateway is therefore a single-instance authentication
boundary suitable for a single-user local Agent, one trusted Gateway, and a
local browser UI. It is **not** multi-tenant, does not provide per-user
independent authorization, per-device revocation, or per-client least
privilege.

## Effect capabilities and managed egress

`AuthorityEnvelope` is an immutable context record, not an effect grant. Git
and network effect boundaries require a broker-issued `EffectCapability`. The
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
| Linux | non-root, zero-capability Python; bwrap filesystem isolation; cgroup v2 budgets; root Rust helper as the sole netns/veth/nft/cgroup authority; default-deny browser egress | missing launcher/helper/cgroup delegation rejects execution; no Host, `ip`, `nft`, or proxy-only fallback |
| macOS | `sandbox-exec` Seatbelt profile restricts content, metadata, directory listing, credential roots, Mach services, network and writable workspace boundaries | no browser kernel namespace claim; a failed probe or invalid launcher rejects execution |
| Windows | native helper after a passing probe: native commands and trusted Python under `network=none` use an OS-issued AppContainer low-box; trusted Python launches the resolved base executable with exact runtime-root/file ACLs; brokered mode uses a restricted primary token and exact loopback-only WFP rules; all paths use child-process policy, a one-process Job Object, and transactional workspace ACL | missing helper/probe evidence, non-native command, ACL/firewall/token/AppContainer failure, or unsupported network endpoint rejects execution; never falls back to Host |

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
