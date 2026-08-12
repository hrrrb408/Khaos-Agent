# Security Platform Support Boundary

Khaos claims sandboxed Coding execution on Linux, macOS, and Windows only after
the platform-specific capability probe and corresponding real-platform CI gate
pass for the current commit.

| Platform | Coding execution | Product boundary |
| --- | --- | --- |
| Linux | Supported when the launcher, bubblewrap, Landlock, cgroup and browser helper checks pass | Python runs non-root; missing isolation fails closed |
| macOS | Supported through the Seatbelt backend when its probe passes | No Linux namespace/browser-kernel claim |
| Windows | Supported when the native helper probe passes | Native commands and trusted Python use an OS-issued no-network AppContainer; trusted Python launches the resolved base executable directly with temporary runtime RX ACLs, while brokered mode uses the restricted primary token plus exact loopback-only WFP rules; all paths use child-process policy, transactional workspace ACLs, a one-process Job Object, and fail closed |

Host execution on supported POSIX systems requires a trusted
`khaos-exec-launcher`. The loader accepts a root-owned or current-EUID-owned
binary only when its binary and parent chain are not group/world-writable;
production packaging must additionally make it root-owned/read-only (or bind
an equivalent digest gate). It receives pinned directory descriptors and
resource budgets, performs identity checks and limits outside the Python
interpreter, then replaces itself with the requested command. A missing or
untrusted launcher fails closed; the standalone Python boundary is available
only with the explicit `KHAOS_DEV_MODE=1` development switch.

The Windows backend is intentionally narrow: native commands and the trusted
Khaos Python interpreter under `network=none` run in an OS-issued AppContainer
with no declared network capability. Trusted Python launches the resolved base
executable directly, and only the venv/base runtime roots receive temporary
read/execute grants; this prevents a venv redirector from becoming an
uncontained child while preserving the workspace write boundary. Brokered mode
uses the restricted primary token and exact loopback-only WFP rules. All paths
keep the child-process policy, inherited-handle allowlist, kill-on-close Job
Object with an active-process limit of one, and transactional workspace ACL.
The TCB may temporarily enable
`SeSecurityPrivilege` only to snapshot/restore integrity SACLs and restores
its prior state before returning; the restricted child receives no such
privilege. Brokered network access is limited to the exact IPv4 loopback proxy
endpoint and is not implemented by granting a child general network
capability. The helper probe and the hosted Windows security job are
mandatory; a missing helper, failed probe, non-native command, or cleanup
failure is an infrastructure refusal rather than a Host fallback.

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
