# Security Platform Support Boundary

Khaos currently claims sandboxed Coding execution only on Linux and macOS,
subject to the platform-specific capability probes and the corresponding
real-kernel CI gates.

| Platform | Coding execution | Product boundary |
| --- | --- | --- |
| Linux | Supported when the launcher, bubblewrap, Landlock, cgroup and browser helper checks pass | Python runs non-root; missing isolation fails closed |
| macOS | Supported through the Seatbelt backend when its probe passes | No Linux namespace/browser-kernel claim |
| Windows | Not supported | `UnsupportedBackend` rejects execution; there is no Host fallback or false `isolated` result |

Host execution on supported POSIX systems requires a trusted
`khaos-exec-launcher`. The loader accepts a root-owned or current-EUID-owned
binary only when its binary and parent chain are not group/world-writable;
production packaging must additionally make it root-owned/read-only (or bind
an equivalent digest gate). It receives pinned directory descriptors and
resource budgets, performs identity checks and limits outside the Python
interpreter, then replaces itself with the requested command. A missing or
untrusted launcher fails closed; the standalone Python boundary is available
only with the explicit `KHAOS_DEV_MODE=1` development switch.

The Windows contract is intentionally explicit: Windows can run non-execution
parts of the application, but it must not be presented as Codex-equivalent
Coding support until an AppContainer/Job Object backend and its hosted security
tests exist.

The current Gateway API key is a single-instance authentication boundary. It
does not provide multi-tenant identity, per-user credentials, or tenant
isolation. Deployments that require those properties must put an independent
identity-aware gateway in front of Khaos and keep the local API key private.

In Docker, the Gateway runs as UID 10002 with a read-only root filesystem,
no capabilities, a private PID namespace, and only a read-only runtime
volume plus the secret group access it needs. The Agent remains UID 10001;
its runtime directory is a root-group setgid directory, and the Agent UDS is
mode 0660 with an explicit Gateway UID/GID check, so group access cannot be
turned into directory write access. The
privileged browser kernel helper is a separate, narrowly scoped authority and
is the only service that intentionally shares the Agent PID/network namespace.
Compose deployments must provide an already delegated cgroup v2 subtree through
`KHAOS_BROWSER_HELPER_CGROUP_SOURCE` (default
`/sys/fs/cgroup/khaos-browser`). It is mounted only at the helper's
`/run/khaos-helper/cgroup`; the helper rejects a normal directory, symlink, or
missing cgroup controllers, so a Docker Desktop/host without that delegated
subtree fails closed instead of silently running without process isolation.

Long-lived state is bounded by maintenance policy: terminal chat streams,
terminal turn journals, no-effect tool-operation claims, and approval events
have explicit retention windows. Applied/partial/unknown operation rows remain
replay-suppression tombstones. SQLite receives a passive WAL checkpoint during
maintenance; the secondary JSONL audit trail rotates into trusted segments at
64 MiB and stops accepting secondary writes at its explicit disk ceiling until
an operator performs the signed gzip archive/tombstone workflow. Operators
must export/archive before shortening a retention window. The SQLite audit
chain also has an explicit signed gzip export; it never deletes rows, so
database rotation remains a separately approved administrative action. The
SQLite audit hash chain and independent anchor remain the authoritative
tamper-evidence record; these controls are not a remote WORM service.
