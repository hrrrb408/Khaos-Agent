# Security Platform Support Boundary

Khaos claims sandboxed Coding execution on Linux, macOS, and Windows only after
the platform-specific capability probe and corresponding real-platform CI gate
pass for the current commit.

| Platform | Coding execution | Product boundary |
| --- | --- | --- |
| Linux | Supported when the launcher, bubblewrap, Landlock, cgroup and browser helper checks pass | Python runs non-root; missing isolation fails closed |
| macOS | Supported through the Seatbelt backend when its probe passes | No Linux namespace/browser-kernel claim |
| Windows | Supported when the native helper probe passes | Native commands and trusted Python use an OS-issued no-network AppContainer; trusted Python stages the resolved base executable and grants temporary runtime RX ACLs only to the disposable tree, while brokered mode uses the restricted primary token plus exact loopback-only WFP rules; all paths use child-process policy, transactional workspace ACLs, a one-process Job Object, and fail closed |

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
executable into a disposable private runtime tree, and only that tree receives
temporary read/execute grants; this prevents a venv redirector from becoming
an uncontained child while preserving the workspace write boundary. Brokered mode
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
Compose deployments must provide two independent, already delegated cgroup v2
subtrees. `KHAOS_EXECUTION_CGROUP_SOURCE` is required for the non-root Agent and
is mounted only at `/run/khaos-execution-cgroup`; the Agent creates its
per-execution leaves there with `KHAOS_CGROUP_ROOT` fixed to that mount. The
required `KHAOS_EXECUTION_CGROUP_PARENT` must identify the same host cgroup
parent, so the Docker service cgroup is created below the delegated boundary
and cgroup v2 migration never crosses an undelegated common ancestor. The
production Compose Agent uses the host cgroup namespace so the kernel accepts
the migration into this host-delegated subtree; this does not grant the Agent
write access to the rest of the cgroup hierarchy because only the explicit
subtree bind mount is writable and the Agent has no `SYS_ADMIN` capability. The
backend verifies through `/proc/self/mountinfo` that the destination is a real
cgroup2 mount, rather than trusting a directory marker. The source must be a
real non-symlink subtree with `cpu`, `memory`, `pids`, and `io` controllers
enabled, and it must be delegated to the image's exact Agent UID 10001.
The production exact-effect probe places its temporary workspace in
`/app/data`, so `io.max` is checked against a real block-backed device rather
than a container overlay filesystem. The Docker CI path sets
`KHAOS_PRODUCTION_DATA_SOURCE` to a loop-backed ext4 host directory; a normal
deployment may retain the Compose-managed volume only when its actual device
supports the same cgroup write, otherwise the probe fails closed.
`KHAOS_BROWSER_HELPER_CGROUP_SOURCE` (default `/sys/fs/cgroup/khaos-browser`)
is separate and is mounted only at the privileged helper's
`/run/khaos-helper/cgroup`. A Docker Desktop/host without both reviewed
delegations fails closed instead of silently running without process isolation.
The production `khaos-agent` service requires three host-reviewed, hash-pinned
profiles through `KHAOS_DOCKER_SECCOMP_OPT`,
`KHAOS_DOCKER_APPARMOR_OPT`, and `KHAOS_DOCKER_SYSTEMPATHS_OPT`; missing any
variable makes Compose fail closed. Run
`python scripts/validate_docker_outer_profiles.py --manifest <manifest>`
before startup; it matches the exact options, hashes seccomp/AppArmor source
files, and requires `systempaths=default`. Docker uses `name=value` syntax.
Docker's
default outer restrictions can block the unprivileged namespace and
mount-propagation syscalls required by bwrap. These settings do not grant
`SYS_ADMIN` to the Agent; they preserve the non-root outer identity while the
Rust launcher, bwrap, Landlock, seccomp, cgroup, and authority receipt checks
enforce the inner boundary. The disposable composition probe may explicitly
use the three `*=unconfined` values on its temporary CI host only; the script
validates that exception explicitly and they are not production defaults.
Removing or replacing any setting requires an equivalent profile manifest that
passes the real composition probe; otherwise production execution must fail
closed. Khaos does not claim a universal Docker outer profile because the
required nested-namespace compatibility is host-runtime-specific. The probe
runs the exact `ExecutionService` ->
`ProcessSupervisor` -> native launcher -> bwrap path with `network=none` and
checks the supervisor-owned process tree through an external `/proc` identity
oracle. The real-kernel Linux security gate owns the broader network-policy
matrix.

The Docker and systemd coding paths select the dedicated capability-free
`khaos-execution-sandbox-launcher`. The separate
`khaos-sandbox-launcher` is reserved for the browser authority transition and
is the only launcher that may carry its narrowly scoped file capability.
Missing or invalid execution-launcher packaging fails closed; coding execution
does not fall back to the browser authority launcher.

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
SQLite audit hash chain and independent anchor remain local diagnostic and
forensic tamper-evidence records; they are not an independent effect authority
or remote WORM service.  Remote WORM evidence is a separate production
prerequisite for authorityd receipt prepare/claim/result events.
