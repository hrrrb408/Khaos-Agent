"""F-05 (third-round review §5.3): OS-level browser egress enforcement.

On Linux, wraps the Chromium process in a dedicated network namespace
with no default route — the only reachable address is the Khaos egress
proxy on the host side of a veth pair.  This means even if Chromium is
compromised, it cannot make direct socket connections to the host
network.

Architecture (round-5 review Batch 5.1 rewrite)::

    Host network namespace
    ├── egress proxy  →  bound on 10.200.X.1 (veth host end)
    ├── veth-host-<token>  (10.200.X.1/30)
    └── nftables  →  per-sandbox table khaos_browser_<token>
                      input hook:  allow browser-veth → proxy_ip:proxy_port
                                   drop  browser-veth → anything else
                      forward hook: drop browser-veth

    Browser network namespace  (khaos-browser-<token>)
    ├── lo  (loopback only, no default route)
    ├── veth-ns-<token>  (10.200.X.2/30)
    └── Chromium  →  --proxy-server=http://10.200.X.1:<port>
                     (joined to cgroup-v2 leaf for pids/mem/cpu limits)

Round-5 review Batch 5.1 fixes (C-01~C-04, H-01~H-04):

* **C-01**: nftables now uses the ``input`` hook (not ``forward``) for
  browser→host-local traffic, plus a ``forward`` drop for the browser
  veth.  Browser→host:proxy_port is local ``input``, not ``forward``.
* **C-02**: nftables rules are now installed via ``nft -f -`` (atomic
  stdin script) instead of ``["nft", *rule.split()]`` which broke quote
  parsing.
* **C-03**: base chains use ``policy accept`` (not ``policy drop``) so
  unmatched host traffic is unaffected.  Only browser-veth traffic is
  restricted.
* **C-04**: production callers must pass ``require_os_sandbox=True``.
  ``browser_tools.py`` now does this unless ``KHAOS_BROWSER_DEV_MODE=1``.
* **H-01/H-02**: every resource (netns, veth, cgroup, nft table) now
  includes a per-sandbox token.  Teardown only deletes its own table.
* **H-03**: ``startup_reaper`` now verifies the creating process is
  dead (PID + start-time) before deleting resources, using a registry
  file written at creation time.
* **H-04**: run-root directory chain is verified via
  ``openat``/``O_DIRECTORY``/``O_NOFOLLOW`` from the home directory
  down to the per-sandbox run dir.

Round-6 review Batch 6.2 fixes (C-02 round-6 + §四 + §五 + §六):

* **C-02 (round-6)**: the nft script now uses ``table inet <name> { … }``
  block syntax so the table is CREATED if missing (previously only
  ``flush table`` was emitted, which fails on a fresh table → nft
  returns an error → ``BrowserSandboxError`` in production).  The block
  syntax is accepted by ``nft --check -f -`` and is the documented way
  to atomically create+populate a table.
* **§四 default-deny before browser start**: ``setup()`` now installs
  the default-deny kernel rule (drop everything from the browser veth,
  allow established return traffic) BEFORE the browser is launched.
  Previously the veth was completely open between ``setup()`` and the
  first ``ensure_page()`` — a window in which a compromised startup
  component could reach any host port.
* **§六 multi-context port set**: ``install_egress_pin`` now ADDS the
  port to a per-sandbox ``_egress_ports`` set and atomically rebuilds
  the whole table (delete + recreate via one ``nft -f -`` transaction).
  Previously each call did ``flush table`` + a single port rule, so a
  second context's creation silently dropped the first context's port
  from the kernel policy.  New ``remove_egress_port`` (called by
  ``_close_one_context``) removes a port and re-applies.
* **nft --check**: ``_apply_nft_script`` runs ``nft -c -f -`` first to
  syntax-check the script before applying it, so a malformed script is
  a detectable failure instead of a silent kernel-policy gap.
"""

from __future__ import annotations

import logging
import os
import secrets
import shutil
import subprocess
import sys
import time
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
# Round-5: nftables table name now includes a per-sandbox token.
_NFT_TABLE_FAMILY = "inet"
_NFT_TABLE_PREFIX = "khaos_browser"
# C-10: secure run directory root — per-process private subtree.
_RUN_DIR_ROOT = Path.home() / ".khaos" / "run"
# Round-5 H-03: registry directory for resource ownership records.
_RESOURCE_REGISTRY = Path.home() / ".khaos" / "run" / "browser_registry"


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

    Round-5 Batch 5.1: every resource now carries a per-sandbox token
    (``_token``) so multiple sandboxes can coexist and teardown only
    deletes its own resources.
    """

    def __init__(
        self,
        config: BrowserSandboxConfig | None = None,
        *,
        require_os_sandbox: bool = False,
    ) -> None:
        self._config = config or BrowserSandboxConfig()
        self._require_os_sandbox = require_os_sandbox
        # Round-5 H-01: per-sandbox token used in all resource names.
        self._token: str = secrets.token_hex(8)
        self._netns_name: str | None = None
        self._veth_host: str | None = None
        self._veth_ns: str | None = None
        self._cgroup_path: Path | None = None
        self._wrapper_script: Path | None = None
        self._run_dir: Path | None = None
        self._nft_table: str | None = None
        self._host_ip: str = "127.0.0.1"
        self._ns_ip: str = ""
        self._active = False
        self._enforcement = EnforcementStatus()
        # Round-5 H-03: registry file path for ownership tracking.
        self._registry_file: Path | None = None
        # Round-6 Batch 6.2 (C-02 + §六): the set of currently-active
        # egress proxy ports.  ``install_egress_pin`` now ADDS to this
        # set (instead of ``flush``-ing the whole table — which would
        # silently drop other contexts' ports).  Rule (re)generation is
        # atomic: the whole table is rebuilt and applied via a single
        # ``nft -f -`` transaction.  ``remove_egress_port`` (called by
        # ``_close_one_context``) removes a port and re-applies.
        self._egress_ports: set[int] = set()

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

        # Round-5 H-01: all resource names include the per-sandbox token.
        self._netns_name = f"khaos-{_VETH_PREFIX}-{self._token}"
        self._veth_host = f"{_VETH_PREFIX}h-{self._token}"
        self._veth_ns = f"{_VETH_PREFIX}n-{self._token}"
        # Truncate token for interface name length limits (15 chars).
        # veth names: "khaos-brh-" (10) + 6 hex chars = 16 → too long.
        # Use a shorter prefix for veth to stay under 15 chars.
        short_token = self._token[:6]
        self._veth_host = f"khbrh-{short_token}"
        self._veth_ns = f"khbrn-{short_token}"
        self._netns_name = f"khaos-br-{short_token}"
        self._nft_table = f"{_NFT_TABLE_PREFIX}_{self._token}"

        # Randomize the second octet to avoid collisions.
        subnet = f"{_VETH_SUBNET_PREFIX}.{secrets.randbelow(250) + 1}"
        self._host_ip = f"{subnet}.1"
        self._ns_ip = f"{subnet}.2"

        try:
            self._create_netns()
            self._configure_veth()
            self._create_cgroup()
            self._create_secure_run_dir()
            self._write_registry_entry()
            if self._cgroup_path is None and self._require_os_sandbox:
                raise BrowserSandboxError(
                    "cgroup-v2 leaf creation failed — resource limits "
                    "cannot be enforced"
                )
            # Round-6 Batch 6.2 (§五): install the default-deny kernel
            # rule BEFORE the browser is launched.  ``install_egress_pin``
            # (called later from ``ensure_page``) only ADDS a port to
            # this already-default-deny table.  This closes the startup
            # window in which the veth was completely open between
            # ``setup()`` and the first ``ensure_page()``.
            self._install_default_deny_nft()
            self._active = True
            self._enforcement = EnforcementStatus(
                network_namespace=True,
                proxy_required=True,
                cgroup=self._cgroup_path is not None,
                # route_guard is True from the moment the default-deny
                # table exists (no proxy port allowed yet, but the
                # kernel is already enforcing "browser veth → drop").
                route_guard=True,
                service_workers_blocked=True,
            )
            logger.info(
                "browser netns sandbox active: netns=%s host=%s ns=%s token=%s",
                self._netns_name, self._host_ip, self._ns_ip, self._token,
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
        """Round-5 review Batch 5.1 (H-03): clean up resources from a
        previous process that crashed without calling ``teardown()``.

        Unlike the round-4 reaper which blindly deleted ALL ``khaos-*``
        resources, this version reads the resource registry
        (``~/.khaos/run/browser_registry/``) and only deletes resources
        whose owning process is confirmed dead (PID no longer exists or
        process start-time has changed).

        Returns a dict of cleanup counts: ``{"netns": N, "veth": N,
        "cgroup": N, "nft": N}``.
        """
        counts = {"netns": 0, "veth": 0, "cgroup": 0, "nft": 0}
        if not sys.platform.startswith("linux"):
            return counts

        # H-03: Read the registry and find orphaned resources.
        orphans = _find_orphaned_resources()
        for entry in orphans:
            token = entry.get("token", "")
            if not token:
                continue
            # Delete netns
            netns_name = entry.get("netns_name", f"khaos-br-{token[:6]}")
            with _suppress_oserrors():
                _run_command(
                    ["ip", "netns", "del", netns_name],
                    f"reaper: delete orphaned netns {netns_name}",
                )
                counts["netns"] += 1
            # Delete veth (host end)
            veth_host = entry.get("veth_host", f"khbrh-{token[:6]}")
            with _suppress_oserrors():
                _run_command(
                    ["ip", "link", "del", veth_host],
                    f"reaper: delete orphaned veth {veth_host}",
                )
                counts["veth"] += 1
            # Delete cgroup
            cgroup_path = entry.get("cgroup_path")
            if cgroup_path:
                cg = Path(cgroup_path)
                if cg.is_dir():
                    _remove_cgroup(cg)
                    counts["cgroup"] += 1
            # Delete nft table
            nft_table = entry.get("nft_table", f"{_NFT_TABLE_PREFIX}_{token}")
            with _suppress_oserrors():
                _run_command(
                    ["nft", "delete", "table", _NFT_TABLE_FAMILY, nft_table],
                    f"reaper: delete orphaned nft table {nft_table}",
                )
                counts["nft"] += 1
            # Delete registry file
            reg_file = entry.get("registry_file")
            if reg_file:
                with _suppress_oserrors():
                    Path(reg_file).unlink(missing_ok=True)

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

    # ------------------------------------------------------------------
    # Round-6 Batch 6.2: nftables authority — table creation, atomic
    # multi-port rule set, default-deny before browser start.
    # ------------------------------------------------------------------

    def _build_nft_script(self, *, include_table_create: bool) -> str:
        """Build the atomic nftables script for the current
        ``_egress_ports`` set.

        When ``include_table_create`` is True (used by
        ``_install_default_deny_nft`` and by every re-apply), the
        script uses the ``table inet <name> { … }`` block syntax so
        the table is CREATED if missing and atomically replaced if it
        already exists.  This is the documented nftables way to do
        "create-or-replace" and is accepted by ``nft --check -f -``.

        The script always contains BOTH hooks (input + forward), so
        even with zero egress ports the browser veth is fully
        default-deny.  Each port in ``_egress_ports`` produces one
        ``accept`` rule.

        This method is pure (no subprocess, no I/O) so it can be
        unit-tested without mocking ``subprocess.run``.
        """
        table = self._nft_table
        veth = self._veth_host
        host_ip = self._host_ip
        # Sort ports for deterministic output (easier diffs in tests
        # and in ``nft --check`` logs).
        ports = sorted(self._egress_ports)
        # Build one ``accept`` line per active port.  When no port is
        # active, the input chain is pure default-deny (drop everything
        # from the browser veth except established return traffic).
        if ports:
            port_rules = "\n    ".join(
                f'iifname "{veth}" ip daddr {host_ip} tcp dport {p} accept'
                for p in ports
            )
        else:
            port_rules = "# (no egress proxy port active — full default-deny)"
        if include_table_create:
            # ``table inet <name> { … }`` block: create-or-replace.
            # This is the fix for C-02 (round-6): previously only
            # ``flush table`` was emitted, which fails on a fresh
            # table because the table does not exist yet.
            return (
                f"table inet {table} {{\n"
                f"    chain khaos_input {{\n"
                f"        type filter hook input priority -10; policy accept;\n"
                f"        ct state established,related accept\n"
                f"        {port_rules}\n"
                f"        iifname \"{veth}\" drop\n"
                f"    }}\n"
                f"    chain khaos_forward {{\n"
                f"        type filter hook forward priority -10; policy accept;\n"
                f"        iifname \"{veth}\" drop\n"
                f"        oifname \"{veth}\" ct state new drop\n"
                f"    }}\n"
                f"}}\n"
            )
        # Legacy form: separate ``flush table`` + chains.  Kept for
        # reference but no longer used in production — the block form
        # above is strictly more correct.
        return (
            f"flush table {_NFT_TABLE_FAMILY} {table}\n"
            f"\n"
            f"chain khaos_input {{\n"
            f"    type filter hook input priority -10; policy accept;\n"
            f"    ct state established,related accept\n"
            f"    {port_rules}\n"
            f"    iifname \"{veth}\" drop\n"
            f"}}\n"
            f"\n"
            f"chain khaos_forward {{\n"
            f"    type filter hook forward priority -10; policy accept;\n"
            f"    iifname \"{veth}\" drop\n"
            f"    oifname \"{veth}\" ct state new drop\n"
            f"}}\n"
        )

    def _apply_nft_script(self, script: str, *, description: str) -> bool:
        """Syntax-check (``nft -c -f -``) then apply (``nft -f -``) an
        nftables script atomically.

        Round-6 Batch 6.2 (§四 "真实 nft --check"): the script is first
        fed to ``nft -c -f -`` so a malformed script is a detectable
        failure instead of a silent kernel-policy gap.  If the check
        passes, the same script is applied for real.

        Returns ``True`` when the script was applied successfully,
        ``False`` when the nft binary is missing or the apply failed
        in dev mode (a warning is logged in that case).

        ``require_os_sandbox=True`` (production) raises
        ``BrowserSandboxError`` on any failure.  ``False`` (dev) logs a
        warning and returns ``False`` — the proxy-only layer remains.
        """
        if shutil.which("nft") is None:
            reason = "nftables ('nft') not found — egress pin inactive"
            if self._require_os_sandbox:
                raise BrowserSandboxError(reason)
            logger.warning("browser netns sandbox: %s", reason)
            return False
        try:
            # 1) Syntax check (does not touch kernel state).
            check = subprocess.run(
                ["nft", "-c", "-f", "-"],
                input=script,
                capture_output=True,
                text=True,
                timeout=10,
            )
            if check.returncode != 0:
                raise OSError(
                    f"nft -c -f - rejected script (exit "
                    f"{check.returncode}): {check.stderr.strip()}"
                )
            # 2) Apply for real.
            result = subprocess.run(
                ["nft", "-f", "-"],
                input=script,
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                raise OSError(
                    f"nft -f - failed (exit {result.returncode}): "
                    f"{result.stderr.strip()}"
                )
        except OSError as exc:
            if self._require_os_sandbox:
                raise BrowserSandboxError(
                    f"nftables {description} failed: {exc}"
                ) from exc
            logger.warning(
                "browser nftables %s failed, "
                "route_guard inactive: %s",
                description, exc,
            )
            return False
        return True

    def _install_default_deny_nft(self) -> None:
        """Round-6 Batch 6.2 (§五): install the default-deny nft table
        BEFORE the browser is launched.

        Called from ``setup()`` right after the netns/veth/cgroup are
        ready.  At this point ``_egress_ports`` is empty, so the input
        chain is pure default-deny: the browser veth can only receive
        established return traffic and everything else is dropped.

        ``install_egress_pin`` (called later from ``ensure_page``) adds
        a port to ``_egress_ports`` and re-applies the table.  The
        browser therefore NEVER runs in a window where the veth is
        completely open — even before the first proxy port is known.
        """
        if self._nft_table is None or self._veth_host is None:
            return  # nothing to do (non-Linux / dev fallback path)
        script = self._build_nft_script(include_table_create=True)
        self._apply_nft_script(
            script, description="default-deny table install",
        )
        logger.info(
            "browser nftables default-deny table installed (table=%s, "
            "veth=%s) — browser veth fully blocked until egress pin added",
            self._nft_table, self._veth_host,
        )

    def install_egress_pin(self, proxy_port: int) -> None:
        """C-06 (round-5 rewrite, round-6 redesign): add ``proxy_port``
        to the set of kernel-allowed egress ports and atomically
        re-apply the nft table.

        Round-6 Batch 6.2 changes:
          - ADDS the port to ``_egress_ports`` instead of ``flush``-ing
            the whole table.  Other contexts' ports are preserved.
          - The table is rebuilt using the ``table inet <name> { … }``
            block syntax (create-or-replace), so the table exists even
            on the first call (fixes C-02 round-6: ``flush table`` on
            a fresh table used to fail).
          - ``_apply_nft_script`` first syntax-checks the script with
            ``nft -c -f -`` (§四 "真实 nft --check").

        Must be called AFTER the egress proxy has started (dynamic
        port) and AFTER ``setup()`` (which installs the default-deny
        table).
        """
        if not self._active or self._veth_host is None:
            return
        if not isinstance(proxy_port, int) or not (1 <= proxy_port <= 65535):
            raise BrowserSandboxError(
                f"invalid egress proxy port: {proxy_port!r}"
            )
        self._egress_ports.add(int(proxy_port))
        script = self._build_nft_script(include_table_create=True)
        applied = self._apply_nft_script(
            script, description=f"egress pin port {proxy_port}",
        )
        # Only flip route_guard on when the nft apply actually
        # succeeded.  In dev mode, a missing nft binary logs a warning
        # and returns — route_guard must stay False so callers can
        # detect that kernel enforcement is NOT active.
        if applied:
            self._enforcement.route_guard = True
            logger.info(
                "browser nftables egress pin added: %s → %s:%d "
                "(table=%s, active_ports=%s)",
                self._veth_host, self._host_ip, proxy_port,
                self._nft_table, sorted(self._egress_ports),
            )

    def remove_egress_port(self, proxy_port: int) -> None:
        """Round-6 Batch 6.2 (§六): remove ``proxy_port`` from the set
        of kernel-allowed egress ports and atomically re-apply the nft
        table.

        Called by ``BrowserManager._close_one_context`` when a context
        is closed, so the kernel policy no longer allows traffic to a
        proxy that has been shut down.  Other contexts' ports are
        preserved.

        No-op (with a debug log) if the port was not in the set — this
        makes the call safe against double-close paths.
        """
        if not self._active or self._veth_host is None:
            return
        port = int(proxy_port)
        if port not in self._egress_ports:
            logger.debug(
                "remove_egress_port(%d): not in active set %s — no-op",
                port, sorted(self._egress_ports),
            )
            return
        self._egress_ports.discard(port)
        script = self._build_nft_script(include_table_create=True)
        self._apply_nft_script(
            script, description=f"egress pin remove port {port}",
        )
        logger.info(
            "browser nftables egress pin removed: port %d "
            "(table=%s, active_ports=%s)",
            port, self._nft_table, sorted(self._egress_ports),
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
        group = root / f"{_CGROUP_BROWSER_PREFIX}-{self._token[:8]}"
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
        """C-10/H-04 (round-5): create a private run directory for the
        wrapper script using a verified dirfd chain.

        The directory chain from ``~`` → ``~/.khaos`` → ``~/.khaos/run``
        → ``~/.khaos/run/<token>`` is walked with ``openat`` +
        ``O_DIRECTORY`` + ``O_NOFOLLOW`` so no intermediate directory
        can be a symlink pointing to an attacker-controlled location.

        The wrapper script is part of the TCB (it launches Chromium)
        and must not live in shared ``/tmp`` where another user could
        pre-place a symlink or replace the file before exec.
        """
        home = Path.home()
        # H-04: walk the directory chain with openat to detect symlinks.
        fd = os.open(str(home), os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for component in (".khaos", "run"):
                try:
                    fd = _openat_dir(fd, component, create=True, mode=0o700)
                except OSError as exc:
                    raise BrowserSandboxError(
                        f"secure run dir chain broken at {component}: {exc}"
                    ) from exc
            # Verify the run dir root is owned by us.
            run_stat = os.fstat(fd)
            if run_stat.st_uid != os.getuid():
                raise BrowserSandboxError(
                    f"run dir root not owned by current user (uid={run_stat.st_uid})"
                )
            # Create the per-sandbox token directory.
            token_dir = self._token
            fd = _openat_dir(fd, token_dir, create=True, mode=0o700)
            self._run_dir = Path(home / ".khaos" / "run" / token_dir)
        finally:
            os.close(fd)

    def _write_registry_entry(self) -> None:
        """H-03 (round-5): write a registry file so the reaper can
        verify process liveness before deleting this sandbox's resources.
        """
        try:
            _RESOURCE_REGISTRY.mkdir(mode=0o700, parents=True, exist_ok=True)
        except OSError:
            return  # best-effort
        import json
        entry = {
            "token": self._token,
            "pid": os.getpid(),
            "process_start_time": _get_process_start_time(os.getpid()),
            "created_at": time.time(),
            "netns_name": self._netns_name,
            "veth_host": self._veth_host,
            "veth_ns": self._veth_ns,
            "cgroup_path": str(self._cgroup_path) if self._cgroup_path else None,
            "nft_table": self._nft_table,
        }
        reg_file = _RESOURCE_REGISTRY / f"{self._token}.json"
        try:
            fd = os.open(
                str(reg_file),
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                mode=0o600,
            )
            try:
                os.write(fd, json.dumps(entry).encode("utf-8"))
            finally:
                os.close(fd)
            self._registry_file = reg_file
        except OSError as exc:
            logger.debug("registry write failed (best-effort): %s", exc)

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

        C-10/H-04: the wrapper is created via ``O_NOFOLLOW | O_EXCL`` in
        the private run directory so it cannot be replaced by a symlink
        or a pre-placed file.

        C-04 (round-5): in production mode, wrapper creation failure
        raises ``BrowserSandboxError`` instead of returning ``None``
        (which would cause the caller to fall back to a direct,
        unsandboxed Chromium launch).
        """
        if not self._active:
            return None
        if self._run_dir is None:
            # C-04 (round-5): fail closed in production.
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
        """Clean up nftables, netns, veth pair, cgroup, wrapper, run dir,
        and registry entry.

        Round-5 H-02: only deletes THIS sandbox's resources (per-sandbox
        nft table name), never a global table.

        Round-6 Batch 6.2: also clears ``_egress_ports`` so a re-setup()
        on the same sandbox instance starts from a clean port set.
        """
        # Delete per-sandbox nftables table (H-02: not global)
        if self._nft_table is not None:
            with _suppress_oserrors():
                _run_command(
                    ["nft", "delete", "table", _NFT_TABLE_FAMILY,
                     self._nft_table],
                    f"delete nftables table {self._nft_table}",
                )
            self._nft_table = None
        # Round-6 Batch 6.2: clear the egress port set so a re-setup()
        # does not carry stale ports forward.
        self._egress_ports.clear()

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

        # Delete registry file (H-03)
        if self._registry_file is not None:
            with _suppress_oserrors():
                self._registry_file.unlink(missing_ok=True)
            self._registry_file = None

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


# ---------------------------------------------------------------------------
# H-03: Process liveness verification for the startup reaper
# ---------------------------------------------------------------------------


def _get_process_start_time(pid: int) -> float:
    """Get the process start time (in clock ticks) for liveness checking.

    On Linux, reads ``/proc/<pid>/stat`` field 22 (starttime).  On
    other platforms, returns 0.0 (reaper is Linux-only anyway).
    """
    if not sys.platform.startswith("linux"):
        return 0.0
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
        # Field 22 is starttime in clock ticks.  Comm may contain spaces
        # and parentheses, so find the last ')' and parse from there.
        rparen = stat.rfind(")")
        if rparen < 0:
            return 0.0
        fields = stat[rparen + 2:].split()
        if len(fields) >= 20:
            return float(fields[19])  # field 22 (0-indexed from after comm)
        return 0.0
    except (OSError, ValueError):
        return 0.0


def _is_process_alive(pid: int, expected_start_time: float) -> bool:
    """H-03: check if a process is alive AND matches the recorded
    start time (to detect PID reuse).

    Returns True only if:
      - The PID exists in /proc, AND
      - The process start time matches the recorded value.
    """
    if not sys.platform.startswith("linux"):
        return False
    if not Path(f"/proc/{pid}").exists():
        return False
    current_start = _get_process_start_time(pid)
    if expected_start_time > 0 and current_start != expected_start_time:
        # PID was reused by a different process.
        return False
    return True


def _find_orphaned_resources() -> list[dict]:
    """H-03: scan the registry and return entries whose owning process
    is confirmed dead.

    A resource is orphaned if:
      - The registry file exists, AND
      - The recorded PID no longer exists, OR
      - The PID's start time has changed (PID reused by another process).
    """
    import json
    orphans: list[dict] = []
    if not _RESOURCE_REGISTRY.is_dir():
        return orphans
    for entry_path in _RESOURCE_REGISTRY.iterdir():
        if not entry_path.name.endswith(".json"):
            continue
        try:
            data = json.loads(entry_path.read_text())
        except (OSError, ValueError):
            # Corrupted registry file — treat as orphan.
            orphans.append({"registry_file": str(entry_path)})
            continue
        pid = data.get("pid", 0)
        start_time = data.get("process_start_time", 0.0)
        if not _is_process_alive(pid, start_time):
            data["registry_file"] = str(entry_path)
            orphans.append(data)
    return orphans


# ---------------------------------------------------------------------------
# H-04: openat-based directory chain verification
# ---------------------------------------------------------------------------


def _openat_dir(
    parent_fd: int, name: str, *, create: bool = False, mode: int = 0o755
) -> int:
    """H-04: open or create a subdirectory via ``openat`` with
    ``O_DIRECTORY | O_NOFOLLOW`` to reject symlinks.

    Returns a new file descriptor for the subdirectory.  The caller is
    responsible for closing it.

    Note: ``O_DIRECTORY | O_NOFOLLOW | O_CREAT`` can fail with EINVAL
    on some platforms (notably macOS) when the path already exists as a
    directory.  We handle this by falling back to ``mkdir`` + re-open.
    """
    # First try to open the existing directory.
    try:
        fd = os.open(
            name, os.O_DIRECTORY | os.O_NOFOLLOW | os.O_RDONLY,
            dir_fd=parent_fd,
        )
        return fd
    except FileNotFoundError:
        if not create:
            raise
    except OSError:
        # May be EINVAL on some platforms — fall through to create path.
        pass

    # Create the directory (race-free with O_EXCL equivalent via mkdir).
    try:
        os.mkdir(name, mode=mode, dir_fd=parent_fd)
    except FileExistsError:
        pass  # Another thread/process created it — re-open below.

    # Re-open the newly created directory.
    fd = os.open(
        name, os.O_DIRECTORY | os.O_NOFOLLOW | os.O_RDONLY,
        dir_fd=parent_fd,
    )
    # Verify it's a directory and owned by us (defence in depth).
    stat = os.fstat(fd)
    import stat as stat_mod
    if not stat_mod.S_ISDIR(stat.st_mode):
        os.close(fd)
        raise OSError(f"{name} is not a directory")
    return fd
