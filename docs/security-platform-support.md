# Security Platform Support Boundary

Khaos currently claims sandboxed Coding execution only on Linux and macOS,
subject to the platform-specific capability probes and the corresponding
real-kernel CI gates.

| Platform | Coding execution | Product boundary |
| --- | --- | --- |
| Linux | Supported when the launcher, bubblewrap, cgroup and browser helper checks pass | Python runs non-root; missing isolation fails closed |
| macOS | Supported through the Seatbelt backend when its probe passes | No Linux namespace/browser-kernel claim |
| Windows | Not supported | `UnsupportedBackend` rejects execution; there is no Host fallback or false `isolated` result |

Host execution on supported POSIX systems requires the root-owned/read-only
`khaos-exec-launcher` in production. It receives pinned directory descriptors
and resource budgets, performs identity checks and limits outside the Python
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

Long-lived state is bounded by maintenance policy: terminal chat streams,
terminal turn journals, terminal/unknown tool-operation claims, and approval
events have explicit retention windows. SQLite receives a passive WAL
checkpoint during maintenance; the secondary JSONL audit trail rotates into
trusted, non-deleted segments at 64 MiB. Operators must export/archive before
shortening a retention window. The SQLite audit hash chain and independent
anchor remain the authoritative tamper-evidence record; these controls are not
a remote WORM service.
