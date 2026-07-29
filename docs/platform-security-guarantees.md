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

The Linux native installer places only the Rust launcher/helper in privileged
TCB locations. Python must run as the dedicated `khaos` user. The launcher has
only `CAP_SYS_ADMIN=ep` for its one validated `setns` transition and clears
capabilities before payload execution. The helper is root, but accepts only
the configured agent daemon process tree and requires a secret-backed runtime
capability on every operation.
