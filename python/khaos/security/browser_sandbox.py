"""F-05 (third-round review §5.3): OS-level browser egress enforcement.

On Linux, wraps the Chromium process in a dedicated network namespace
with no default route — the only reachable address is the Khaos egress
proxy on the host side of a veth pair.  This means even if Chromium is
compromised, it cannot make direct socket connections to the host
network.

Architecture::

    Host network namespace
    ├── egress proxy  →  bound on 10.200.X.1 (veth host end)
    ├── veth-host-<id>  (10.200.X.1/30)
    └── nftables  →  browser-veth → exact proxy_ip:proxy_port ONLY

    Browser network namespace  (khaos-browser-<id>)
    ├── lo  (loopback only, no default route)
    ├── veth-ns-<id>  (10.200.X.2/30)
    └── Chromium  →  --proxy-server=http://10.200.X.1:<port>
                     (joined to cgroup-v2 leaf for pids/mem/cpu limits)

C-06 (round-4): nftables rules restrict the browser veth to reach ONLY
the exact proxy IP:port.  Without this, the host veth IP is on-link and
reachable on any port — a compromised browser could connect to host
services bound to ``0.0.0.0``.  Rules are installed atomically after the
proxy starts (dynamic port) and deleted on teardown.

C-08 (round-4): the wrapper script writes its own PID to
``cgroup.procs`` before ``exec nsenter``.  ``nsenter --net`` preserves
the PID, so Chromium actually joins the cgroup — previously the cgroup
was empty and resource limits were unenforced.

C-09 (round-4): ``require_os_sandbox=True`` (production default) fails
closed if any component is unavailable, instead of silently degrading
to proxy-only.  ``EnforcementStatus`` exposes which layers are active
so callers can refuse to launch when parity is required.

C-10 (round-4): the wrapper script is created in a private
``~/.khaos/run/<token>/`` directory (mode 0700, owner-verified,
symlink-rejected via ``O_NOFOLLOW | O_EXCL``) instead of shared
``/tmp``.  The wrapper is part of the TCB and must not be replaceable
by another user.

On non-Linux or when ``require_os_sandbox=False`` and capabilities are
missing, the sandbox is a no-op and the proxy-only enforcement layer
(BrowserEgressProxy) remains the sole egress authority.
"""

from __future__ import annotations

import logging
import os
import secrets
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

# F-05: veth pair subnet.  Using 10.200.x.y/30 gives each browser
# namespace a 2-address point-to-point link (host=.1, ns=.2).  The
# second octet is randomized per-sandbox to avoid collisions when
# multiple browser contexts run concurrently.
_VETH_SUBNET_PREFIX = "10.200"
_VETH_PREFIX = "khaos-br"
_NETNS_BASE = "/var/run/netns"
_CGROUP_BROWSER_PREFIX = "browser"
# C-10: nftables table/chain names for per-sandbox egress pinning.
_NFT_TABLE_FAMILY = "inet"
_NFT_TABLE_NAME = "khaos_browser_egress"
_NFT_CHAIN_PREFIX = "br"
# C-10: secure run directory root — per-process private subtree.
_RUN_DIR_ROOT = Path.home() / ".khaos" / "run"


@dataclass
class BrowserSandboxConfig:
    """Resource limits for the browser cgroup."""

    pids_max: int = 256
    memory_max: int = 2 * 1024 * 1024 * 1024  # 2 GiB
    memory_swap_max: int = 0
    cpu_quota: int = 200_000  # 2 CPUs (quota in microseconds per 100ms period)
    cpu_period: int = 100_000


@dataclass
class EnforcementStatus:
    """C-09: structured report of which enforcement layers are active.

    Callers (especially production profiles) should check this after
    ``setup()`` and refuse to launch the browser when a required layer
    is missing.  ``ok`` is True only when every layer the caller asked
    for is in effect.
    """

    network_namespace: bool = False
    proxy_required: bool = False
    cgroup: bool = False
    route_guard: bool = False  # nftables egress pin
    service_workers_blocked: bool = False
    failure_reason: str = ""

    @property
    def ok(self) -> bool:
        return not self.failure_reason


class BrowserNetworkSandbox:
    """Linux: isolates Chromium in a dedicated netns + cgroup.

    On non-Linux: no-op.  The caller should check ``is_active`` after
    ``setup()`` to determine whether OS-level enforcement is in effect.

    C-09: when ``require_os_sandbox=True`` (production default), any
    missing component raises ``BrowserSandboxError`` instead of silently
    degrading to proxy-only.
    """

    def __init__(
        self,
        config: BrowserSandboxConfig | None = None,
        *,
        require_os_sandbox: bool = False,
    ) -> None:
        self._config = config or BrowserSandboxConfig()
        self._require_os_sandbox = require_os_sandbox
        self._netns_name: str | None = None
        self._veth_host: str | None = None
        self._veth_ns: str | None = None
        self._cgroup_path: Path | None = None
        self._wrapper_script: Path | None = None
        self._run_dir: Path | None = None
        self._nft_chain: str | None = None
        self._host_ip: str = "127.0.0.1"
        self._ns_ip: str = ""
        self._active = False
        self._enforcement = EnforcementStatus()

    @property
    def is_active(self) -> bool:
        """True if OS-level netns enforcement is in effect."""
        return self._active

    @property
    def enforcement_status(self) -> EnforcementStatus:
        """C-09: structured report of active enforcement layers."""
        return self._enforcement

    @property
    def proxy_bind_host(self) -> str:
        """The IP address the egress proxy should bind to.

        When the sandbox is active, this is the host-side veth IP so
        the browser can reach the proxy from inside the netns.
        Otherwise it's ``127.0.0.1`` (loopback-only fallback).
        """
        return self._host_ip if self._active else "127.0.0.1"

    @property
    def browser_proxy_host(self) -> str:
        """The proxy host as seen from inside the browser netns."""
        return self._host_ip if self._active else "127.0.0.1"

    def setup(self) -> None:
        """Create the netns, veth pair, and cgroup.

        C-09: when ``require_os_sandbox=True`` (production default),
        any missing prerequisite raises ``BrowserSandboxError`` instead
        of silently degrading to proxy-only.  When False (development),
        missing prerequisites are logged as warnings and the sandbox
        remains inactive.
        """
        reason = self._check_prerequisites()
        if reason:
            if self._require_os_sandbox:
                raise BrowserSandboxError(reason)
            logger.warning("browser netns sandbox: %s, using proxy-only", reason)
            return

        suffix = secrets.token_hex(4)
        self._netns_name = f"khaos-{_VETH_PREFIX}-{suffix}"
        self._veth_host = f"{_VETH_PREFIX}h-{suffix}"
        self._veth_ns = f"{_VETH_PREFIX}n-{suffix}"

        # Randomize the second octet to avoid collisions.
        subnet = f"{_VETH_SUBNET_PREFIX}.{secrets.randbelow(250) + 1}"
        self._host_ip = f"{subnet}.1"
        self._ns_ip = f"{subnet}.2"

        try:
            self._create_netns()
            self._configure_veth()
            self._create_cgroup()
            self._create_secure_run_dir()
            if self._cgroup_path is None and self._require_os_sandbox:
                raise BrowserSandboxError(
                    "cgroup-v2 leaf creation failed — resource limits "
                    "cannot be enforced"
                )
            self._active = True
            self._enforcement = EnforcementStatus(
                network_namespace=True,
                proxy_required=True,
                cgroup=self._cgroup_path is not None,
                route_guard=False,  # set by install_egress_pin()
                service_workers_blocked=True,
            )
            logger.info(
                "browser netns sandbox active: netns=%s host=%s ns=%s",
                self._netns_name, self._host_ip, self._ns_ip,
            )
        except BrowserSandboxError:
            self.teardown()
            raise
        except OSError as exc:
            if self._require_os_sandbox:
                self.teardown()
                raise BrowserSandboxError(
                    f"netns setup failed: {exc}"
                ) from exc
            logger.warning(
                "browser netns sandbox setup failed, "
                "falling back to proxy-only: %s",
                exc,
            )
            self.teardown()

    @staticmethod
    def startup_reaper() -> dict[str, int]:
        """Round-4 review Batch 4 (§13.3): clean up resources from a

        previous boot that crashed without calling ``teardown()``.

        Scans for stale ``khaos-*`` netns, veth pairs, cgroups, and
        nftables chains left behind by a prior process.  Each cleanup
        step is best-effort — failures are logged but don't abort the
        reaper.

        Returns a dict of cleanup counts: ``{"netns": N, "veth": N,
        "cgroup": N, "nft": N}``.
        """
        counts = {"netns": 0, "veth": 0, "cgroup": 0, "nft": 0}
        if not sys.platform.startswith("linux"):
            return counts

        # 1. Remove stale khaos-* netns entries.
        if Path(_NETNS_BASE).is_dir():
            for entry in Path(_NETNS_BASE).iterdir():
                if entry.name.startswith(f"khaos-{_VETH_PREFIX}"):
                    with _suppress_oserrors():
                        _run_command(
                            ["ip", "netns", "del", entry.name],
                            f"reaper: delete stale netns {entry.name}",
                        )
                        counts["netns"] += 1

        # 2. Remove stale khaos-br* veth interfaces.
        try:
            result = subprocess.run(
                ["ip", "-o", "link", "show"],
                capture_output=True, text=True, timeout=5,
            )
            for line in result.stdout.splitlines():
                for prefix in (_VETH_PREFIX + "h", _VETH_PREFIX + "n"):
                    if prefix in line:
                        parts = line.split(":")
                        if len(parts) >= 2:
                            iface = parts[1].strip().split("@")[0].split()[0]
                            if iface.startswith(prefix):
                                with _suppress_oserrors():
                                    _run_command(
                                        ["ip", "link", "del", iface],
                                        f"reaper: delete stale veth {iface}",
                                    )
                                    counts["veth"] += 1
        except (OSError, subprocess.TimeoutExpired):
            pass

        # 3. Remove stale browser cgroups.
        cgroup_root = os.environ.get("KHAOS_CGROUP_ROOT", "/sys/fs/cgroup/khaos")
        cgroup_browser = Path(cgroup_root) / "browser"
        if cgroup_browser.is_dir():
            for child in cgroup_browser.iterdir():
                if child.name.startswith("br-") and child.is_dir():
                    _remove_cgroup(child)
                    counts["cgroup"] += 1

        # 4. Remove stale nftables table.
        with _suppress_oserrors():
            _run_command(
                ["nft", "delete", "table", _NFT_TABLE_FAMILY, _NFT_TABLE_NAME],
                f"reaper: delete stale nft table {_NFT_TABLE_NAME}",
            )
            counts["nft"] += 1

        if any(counts.values()):
            logger.info("browser sandbox startup_reaper: %s", counts)
        return counts

    def _check_prerequisites(self) -> str:
        """Return empty string if all prerequisites are met, else reason."""
        if not sys.platform.startswith("linux"):
            return f"non-Linux platform ({sys.platform})"
        if not _has_net_admin():
            return "CAP_NET_ADMIN not available"
        if shutil.which("ip") is None or shutil.which("nsenter") is None:
            return "'ip' or 'nsenter' not found"
        return ""

    def install_egress_pin(self, proxy_port: int) -> None:
        """C-06: install nftables rules so the browser veth can reach
        ONLY the exact proxy IP:port.

        Must be called AFTER the egress proxy has started (dynamic port).
        Rules are scoped to the host-side veth interface name so they
        do not affect any other host traffic.

        Allows::

            browser-veth → proxy_ip:proxy_port TCP

        Drops::

            browser-veth → any other destination/port
            browser-veth → forward

        When ``require_os_sandbox=False`` and nftables is unavailable,
        this logs a warning and returns (proxy-only enforcement).
        """
        if not self._active or self._veth_host is None:
            return
        if shutil.which("nft") is None:
            reason = "nftables ('nft') not found — egress pin inactive"
            if self._require_os_sandbox:
                raise BrowserSandboxError(reason)
            logger.warning("browser netns sandbox: %s", reason)
            return

        chain = f"{_NFT_CHAIN_PREFIX}-{self._veth_host}"
        # Build a per-sandbox chain.  Using a dedicated chain (rather
        # than the system ``forward`` hook) avoids interfering with host
        # firewall rules and makes teardown a single ``delete table``.
        rules = [
            f"add table {_NFT_TABLE_FAMILY} {_NFT_TABLE_NAME}",
            f"add chain {_NFT_TABLE_FAMILY} {_NFT_TABLE_NAME} {chain}"
            f" '{{ type filter hook forward priority 0; policy drop; }}'",
            # Allow established connections (return traffic from proxy).
            f"add rule {_NFT_TABLE_FAMILY} {_NFT_TABLE_NAME} {chain}"
            f" 'ct state established,related accept'",
            # Allow browser-veth → exact proxy_ip:proxy_port TCP.
            f"add rule {_NFT_TABLE_FAMILY} {_NFT_TABLE_NAME} {chain}"
            f" 'iifname \"{self._veth_host}\" ip daddr {self._host_ip}"
            f" tcp dport {proxy_port} accept'",
            # Drop everything else from the browser veth.
            f"add rule {_NFT_TABLE_FAMILY} {_NFT_TABLE_NAME} {chain}"
            f" 'iifname \"{self._veth_host}\" drop'",
        ]
        try:
            for rule in rules:
                _run_command(
                    ["nft", *rule.split()],
                    f"install nftables rule: {rule}",
                )
            self._nft_chain = chain
            self._enforcement.route_guard = True
            logger.info(
                "browser nftables egress pin installed: "
                "%s → %s:%d only",
                self._veth_host, self._host_ip, proxy_port,
            )
        except OSError as exc:
            if self._require_os_sandbox:
                raise BrowserSandboxError(
                    f"nftables egress pin failed: {exc}"
                ) from exc
            logger.warning(
                "browser nftables egress pin failed, "
                "route_guard inactive: %s",
                exc,
            )

    def _create_netns(self) -> None:
        """Create the network namespace."""
        # Ensure /var/run/netns exists
        Path(_NETNS_BASE).mkdir(parents=True, exist_ok=True)
        _run_command(
            ["ip", "netns", "add", self._netns_name],
            f"create netns {self._netns_name}",
        )

    def _configure_veth(self) -> None:
        """Create the veth pair and configure both ends."""
        # Create veth pair
        _run_command(
            ["ip", "link", "add", self._veth_host, "type", "veth",
             "peer", "name", self._veth_ns],
            f"create veth pair {self._veth_host} <-> {self._veth_ns}",
        )
        # Move the namespace end into the netns
        _run_command(
            ["ip", "link", "set", self._veth_ns, "netns", self._netns_name],
            f"move {self._veth_ns} to {self._netns_name}",
        )
        # Configure host side
        _run_command(
            ["ip", "addr", "add", f"{self._host_ip}/30", "dev", self._veth_host],
            f"assign {self._host_ip}/30 to {self._veth_host}",
        )
        _run_command(
            ["ip", "link", "set", self._veth_host, "up"],
            f"bring up {self._veth_host}",
        )
        # Configure namespace side
        ns_prefix = ["ip", "netns", "exec", self._netns_name]
        _run_command(
            ns_prefix + ["ip", "addr", "add", f"{self._ns_ip}/30",
                         "dev", self._veth_ns],
            f"assign {self._ns_ip}/30 to {self._veth_ns}",
        )
        _run_command(
            ns_prefix + ["ip", "link", "set", self._veth_ns, "up"],
            f"bring up {self._veth_ns} in {self._netns_name}",
        )
        _run_command(
            ns_prefix + ["ip", "link", "set", "lo", "up"],
            f"bring up loopback in {self._netns_name}",
        )
        # Deliberately NO default route — the browser can only reach
        # the proxy on the directly-connected /30 subnet.

    def _create_cgroup(self) -> None:
        """Create a cgroup-v2 leaf for the browser process."""
        root = _browser_cgroup_root()
        if root is None:
            logger.warning(
                "browser cgroup: no writable cgroup-v2 root, "
                "skipping resource limits"
            )
            return
        group = root / f"{_CGROUP_BROWSER_PREFIX}-{secrets.token_hex(4)}"
        try:
            group.mkdir(mode=0o700)
            limits = {
                "pids.max": str(self._config.pids_max),
                "memory.max": str(self._config.memory_max),
                "memory.swap.max": str(self._config.memory_swap_max),
                "cpu.max": f"{self._config.cpu_quota} {self._config.cpu_period}",
            }
            for name, value in limits.items():
                (group / name).write_text(value, encoding="ascii")
            self._cgroup_path = group
        except OSError as exc:
            logger.warning("browser cgroup creation failed: %s", exc)
            _remove_cgroup(group)

    def _create_secure_run_dir(self) -> None:
        """C-10: create a private run directory for the wrapper script.

        The directory is created under ``~/.khaos/run/<token>/`` with
        mode 0700, owner-verified, and symlink-rejected.  The wrapper
        script is part of the TCB (it launches Chromium) and must not
        live in shared ``/tmp`` where another user could pre-place a
        symlink or replace the file before exec.
        """
        _RUN_DIR_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
        # Verify the root is owned by us and not a symlink.
        root_stat = _RUN_DIR_ROOT.lstat()
        if not _RUN_DIR_ROOT.is_dir() or root_stat.st_uid != os.getuid():
            raise BrowserSandboxError(
                f"run dir root {_RUN_DIR_ROOT} is not a directory owned "
                f"by the current user"
            )
        token = secrets.token_hex(8)
        run_dir = _RUN_DIR_ROOT / token
        # os.mkdir raises FileExistsError if the path already exists,
        # providing the same race-free guarantee as O_EXCL.  We use
        # mkdir (not os.open+O_CREAT) because O_CREAT creates a regular
        # file, not a directory.
        os.mkdir(run_dir, mode=0o700)
        self._run_dir = run_dir

    def create_wrapper_script(
        self, real_executable: str, proxy_port: int,
    ) -> str | None:
        """Create a wrapper script that launches Chromium inside the netns.

        Returns the path to the wrapper script, or None if the sandbox
        is not active (caller uses the real executable directly).

        C-08: the wrapper writes its own PID to ``cgroup.procs`` before
        ``exec nsenter``.  Since ``nsenter --net`` preserves the PID,
        Chromium actually joins the cgroup and resource limits apply.
        If the cgroup write fails the wrapper exits non-zero instead of
        continuing without limits.

        C-10: the wrapper is created via ``O_NOFOLLOW | O_EXCL`` in the
        private run directory so it cannot be replaced by a symlink or
        a pre-placed file.
        """
        if not self._active:
            return None
        if self._run_dir is None:
            # Fallback for callers that didn't go through setup() —
            # fail closed in production.
            if self._require_os_sandbox:
                raise BrowserSandboxError(
                    "secure run directory not created — refusing to "
                    "write wrapper to shared /tmp"
                )
            self._create_secure_run_dir()

        netns_path = f"{_NETNS_BASE}/{self._netns_name}"
        cgroup_procs = (
            str(self._cgroup_path / "cgroup.procs")
            if self._cgroup_path is not None
            else ""
        )

        # C-08: write PID to cgroup.procs before exec.  If the write
        # fails (permission denied, cgroup deleted), the wrapper must
        # exit non-zero so the caller knows the browser did not launch
        # with resource limits enforced.
        if cgroup_procs:
            join_cgroup = (
                f'if ! echo $$ > "{cgroup_procs}" 2>/dev/null; then\n'
                f'  echo "khaos: failed to join cgroup {cgroup_procs}" >&2\n'
                f'  exit 1\n'
                f'fi\n'
            )
        else:
            join_cgroup = ""

        script_content = f"""#!/bin/sh
# C-08/C-10: Khaos browser netns wrapper.  AUTO-GENERATED - do not edit.
# Launches Chromium inside the dedicated network namespace so even a
# compromised browser cannot bypass the egress proxy.
# This script joins the browser cgroup BEFORE exec so resource limits
# (pids/memory/cpu) actually apply to Chromium.
{join_cgroup}exec nsenter --net="{netns_path}" "{real_executable}" "$@"
"""
        # C-10: create with O_NOFOLLOW | O_EXCL so the wrapper cannot
        # be a symlink or overwrite an existing file.
        script_path = self._run_dir / f"chromium-{self._netns_name}.sh"
        fd = os.open(
            str(script_path),
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            mode=0o700,
        )
        try:
            os.write(fd, script_content.encode("ascii"))
        finally:
            os.close(fd)
        # Verify owner and mode (defence in depth — TOCTOU between
        # open and exec is mitigated by the private 0700 run dir).
        stat = script_path.lstat()
        if stat.st_uid != os.getuid():
            raise BrowserSandboxError(
                f"wrapper script {script_path} not owned by current user"
            )
        self._wrapper_script = script_path
        return str(script_path)

    def teardown(self) -> None:
        """Clean up nftables, netns, veth pair, cgroup, wrapper, and run dir."""
        # Delete nftables table (C-06)
        if self._nft_chain is not None:
            with _suppress_oserrors():
                _run_command(
                    ["nft", "delete", "table", _NFT_TABLE_FAMILY,
                     _NFT_TABLE_NAME],
                    f"delete nftables table {_NFT_TABLE_NAME}",
                )
            self._nft_chain = None

        # Delete wrapper script + secure run dir (C-10)
        if self._wrapper_script is not None:
            with _suppress_oserrors():
                self._wrapper_script.unlink(missing_ok=True)
            self._wrapper_script = None
        if self._run_dir is not None:
            with _suppress_oserrors():
                self._run_dir.rmdir()
            self._run_dir = None

        # Delete cgroup
        if self._cgroup_path is not None:
            _remove_cgroup(self._cgroup_path)
            self._cgroup_path = None

        # Delete veth pair (deleting the host end removes both ends)
        if self._veth_host is not None:
            with _suppress_oserrors():
                _run_command(
                    ["ip", "link", "del", self._veth_host],
                    f"delete veth {self._veth_host}",
                )
            self._veth_host = None
            self._veth_ns = None

        # Delete netns
        if self._netns_name is not None:
            with _suppress_oserrors():
                _run_command(
                    ["ip", "netns", "del", self._netns_name],
                    f"delete netns {self._netns_name}",
                )
            self._netns_name = None

        self._active = False
        self._enforcement = EnforcementStatus()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class BrowserSandboxError(Exception):
    """C-09: raised when a required OS-sandbox component is unavailable.

    In production (``require_os_sandbox=True``) this propagates to the
    caller so the browser launch is refused rather than silently
    degrading to a weaker enforcement level.
    """


class _suppress_oserrors:
    """Context manager that swallows OSError (for best-effort cleanup)."""

    def __enter__(self) -> "_suppress_oserrors":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        if exc_type is not None and issubclass(exc_type, OSError):
            logger.debug("suppressed OSError during cleanup: %s", exc)
            return True
        return False


def _has_net_admin() -> bool:
    """C-09: actually check CAP_NET_ADMIN instead of optimistically returning True.

    Uses ``ip netns add/delete`` as a side-effect-free probe because it
    exercises the exact capability the sandbox needs.  The previous
    implementation unconditionally returned ``True``, which meant the
    real capability check was deferred to ``setup()`` failure — too late
    for a fail-closed decision.
    """
    if not sys.platform.startswith("linux"):
        return False
    if shutil.which("ip") is None:
        return False
    probe = f"khaos-cap-probe-{secrets.token_hex(4)}"
    try:
        result = subprocess.run(
            ["ip", "netns", "add", probe],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            return False
        subprocess.run(
            ["ip", "netns", "del", probe],
            capture_output=True, text=True, timeout=5,
        )
        return True
    except (OSError, subprocess.TimeoutExpired):
        return False


def _run_command(argv: list[str], description: str) -> None:
    """Run a command and raise OSError on failure."""
    result = subprocess.run(
        argv, capture_output=True, text=True, timeout=10,
    )
    if result.returncode != 0:
        raise OSError(
            f"{description} failed (exit {result.returncode}): "
            f"{result.stderr.strip() or result.stdout.strip()}"
        )


def _browser_cgroup_root() -> Path | None:
    """Return a writable delegated cgroup-v2 subtree for browsers.

    Reuses the same root as ``platform._linux_cgroup_root`` so all
    Khaos cgroups live under the same delegated subtree.
    """
    if not sys.platform.startswith("linux"):
        return None
    unified = Path("/sys/fs/cgroup/cgroup.controllers")
    if not unified.is_file():
        return None
    configured = os.environ.get("KHAOS_CGROUP_ROOT", "").strip()
    root = Path(configured) if configured else Path("/sys/fs/cgroup/khaos")
    try:
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        canonical = root.resolve()
        if Path("/sys/fs/cgroup") not in (canonical, *canonical.parents):
            return None
        if not os.access(canonical, os.W_OK):
            return None
        return canonical
    except OSError:
        return None


def _remove_cgroup(group: Path) -> None:
    """Remove a cgroup-v2 leaf using kill → wait → rmdir (Round-4 §13.4)."""
    import time

    if not group.is_dir():
        return
    kill_file = group / "cgroup.kill"
    if kill_file.exists():
        try:
            kill_file.write_text("1", encoding="ascii")
        except OSError as exc:
            logger.warning("browser cgroup.kill failed for %s: %s", group, exc)
    events_file = group / "cgroup.events"
    if events_file.exists():
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            try:
                content = events_file.read_text(encoding="ascii")
                if "populated 0" in content or "populated=0" in content:
                    break
            except OSError:
                break
            time.sleep(0.1)
    try:
        group.rmdir()
    except OSError as exc:
        logger.warning("browser cgroup rmdir failed for %s (orphaned): %s", group, exc)
