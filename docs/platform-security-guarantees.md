# Platform Security Guarantees

These guarantees are deliberately narrower than “absolute security”. A claim
is valid only for a commit whose required `Security Closure Gate` passed with
complete provenance-backed evidence.

| Platform | Production guarantee | Unsupported behavior |
|---|---|---|
| Linux | non-root, zero-capability Python; bwrap filesystem isolation; cgroup v2 budgets; root Rust helper as the sole netns/veth/nft/cgroup authority; default-deny browser egress | missing launcher/helper/cgroup delegation rejects execution; no Host, `ip`, `nft`, or proxy-only fallback |
| macOS | `sandbox-exec` Seatbelt profile restricts content, metadata, directory listing, credential roots, Mach services, network and writable workspace boundaries | no browser kernel namespace claim; a failed probe or invalid launcher rejects execution |
| Windows | explicit fail-closed `UnsupportedBackend` | no AppContainer/Job Object sandbox is claimed; unsupported never falls back to Host and never reports isolated |

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
before the payload runs.  macOS Seatbelt still uses its platform path-based
profile for allowlisted read/write rules, so real Linux/macOS sandbox
acceptance remains a platform capability and CI gate.

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
