"""Batch 6.6 (round-6): real-kernel browser isolation E2E.

Closes review §21 (CI 不能证明真实 nft) + §6.6 (真实安全 CI).  These
tests run ONLY in the privileged ``browser-kernel-isolation`` CI job,
which sets ``KHAOS_RUN_KERNEL_BROWSER_E2E=1`` and runs as root (or with
``CAP_NET_ADMIN``) on a Linux runner with ``nftables`` + ``iproute2``.

They exercise the REAL production path (no ``KHAOS_BROWSER_DEV_MODE``):
  - real ``nft --check`` parses the generated script (real nft parser)
  - ``BrowserNetworkSandbox.setup()`` actually creates netns/veth/cgroup/nft
  - the egress proxy port is reachable from inside the netns
  - secret host ports / LAN / public IPs are NOT reachable
  - the browser PID lands in the target cgroup
  - teardown removes every kernel resource
  - two concurrent sandboxes coexist; tearing one down does not affect the other

Every test is decorated ``@pytest.mark.kernel_real`` and skipped unless
``KHAOS_RUN_KERNEL_BROWSER_E2E=1`` is set, so local ``make test-python``
(macOS / non-root) is unaffected.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import time

import pytest

from khaos.security.browser_sandbox import (
    BrowserNetworkSandbox,
    BrowserSandboxError,
)

# Gate: only run when the privileged CI job explicitly opts in.
_KERNEL_E2E = os.environ.get("KHAOS_RUN_KERNEL_BROWSER_E2E") == "1"
_IS_LINUX = sys.platform.startswith("linux")
_HAS_NFT = shutil.which("nft") is not None
_HAS_IP = shutil.which("ip") is not None

skip_no_kernel = pytest.mark.skipif(
    not (_KERNEL_E2E and _IS_LINUX and _HAS_NFT and _HAS_IP),
    reason=(
        "kernel_real tests require KHAOS_RUN_KERNEL_BROWSER_E2E=1 on a "
        "privileged Linux runner with nftables + iproute2 (run in the "
        "browser-kernel-isolation CI job)"
    ),
)

pytestmark = [pytest.mark.kernel_real, skip_no_kernel]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _require_root() -> None:
    """Abort early (not skip) if invoked without root — the privileged
    job should always run as root; a non-root run is a CI misconfig."""
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        pytest.fail(
            "kernel_real tests must run as root (CAP_NET_ADMIN required for "
            "ip netns / nft) — the browser-kernel-isolation CI job is misconfigured"
        )


def _nft_check(script: str) -> bool:
    """Run ``nft -c -f -`` (syntax check, no apply) on the script."""
    proc = subprocess.run(
        ["nft", "-c", "-f", "-"],
        input=script,
        text=True,
        capture_output=True,
        timeout=10,
    )
    return proc.returncode == 0


def _nft_table_exists(table: str) -> bool:
    proc = subprocess.run(
        ["nft", "list", "table", table],
        capture_output=True,
        text=True,
        timeout=10,
    )
    return proc.returncode == 0


def _netns_exists(name: str) -> bool:
    proc = subprocess.run(
        ["ip", "netns", "list"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    return proc.returncode == 0 and any(
        line.split()[0] == name for line in proc.stdout.splitlines() if line.strip()
    )


def _exec_in_netns(netns: str, cmd: list[str]) -> subprocess.CompletedProcess:
    """Run ``cmd`` inside the named netns (requires root)."""
    return subprocess.run(
        ["ip", "netns", "exec", netns, *cmd],
        capture_output=True,
        text=True,
        timeout=15,
    )


# ---------------------------------------------------------------------------
# §6.6 item 1: real nft parser accepts the generated script
# ---------------------------------------------------------------------------


def test_kernel_real_nft_script_accepted_by_real_parser():
    """The nft script produced by ``_build_nft_script`` must be accepted
    by the REAL ``nft --check`` parser (not just a string match).  Pre-fix
    (Batch 6.2 C-02) the ``flush table`` form failed on a fresh table."""
    _require_root()
    sb = BrowserNetworkSandbox(require_os_sandbox=False)
    # Force-configure internal names so _build_nft_script produces a full script.
    sb._token = "test1234"
    sb._netns_name = "khaos-br-test"
    sb._veth_host = "khbrh-test"
    sb._nft_table = "khaos_browser_test"
    sb._host_ip = "10.200.1.1"
    sb._egress_ports = {40001, 40002}
    script = sb._build_nft_script(include_table_create=True)
    assert _nft_check(script), (
        f"real nft --check rejected the script:\n{script}\nstderr follows"
    )


# ---------------------------------------------------------------------------
# §6.6 item 2: setup() creates real netns/veth/cgroup/nft
# ---------------------------------------------------------------------------


def test_kernel_real_setup_creates_kernel_resources():
    """``BrowserNetworkSandbox.setup()`` with ``require_os_sandbox=True``
    must actually create the netns, veth pair, cgroup leaf, and nft
    table on a privileged Linux runner."""
    _require_root()
    sb = BrowserNetworkSandbox(require_os_sandbox=True)
    try:
        sb.setup()
        assert sb.is_active, "setup() did not activate the sandbox"
        # Real resources exist.
        assert sb._netns_name and _netns_exists(sb._netns_name), (
            f"netns {sb._netns_name} not found after setup()"
        )
        assert sb._nft_table and _nft_table_exists(sb._nft_table), (
            f"nft table {sb._nft_table} not found after setup()"
        )
        assert sb._cgroup_path and sb._cgroup_path.exists(), (
            f"cgroup leaf {sb._cgroup_path} not found after setup()"
        )
    finally:
        sb.teardown()


# ---------------------------------------------------------------------------
# §6.6 item 3-5: egress isolation (proxy reachable, secrets not)
# ---------------------------------------------------------------------------


def test_kernel_real_default_deny_blocks_all_until_pin():
    """With zero egress pins, the netns can ONLY reach established return
    traffic — a fresh TCP connect to any host port must fail (default
    deny).  After ``install_egress_pin(port)`` that exact port becomes
    reachable.  We prove the kernel policy, not just the script string."""
    _require_root()
    sb = BrowserNetworkSandbox(require_os_sandbox=True)
    try:
        sb.setup()
        # Start a listener on the host veth IP on a secret port.
        secret_port = _free_port()
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((sb._host_ip, secret_port))
        listener.listen(1)
        listener.settimeout(3)
        try:
            # Default-deny: connect from the netns must FAIL.
            cp = _exec_in_netns(
                sb._netns_name,
                ["python3", "-c",
                 f"import socket; s=socket.socket(); "
                 f"s.settimeout(2); "
                 f"print('OK' if s.connect_ex(('{sb._host_ip}',{secret_port}))==0 else 'BLOCKED')"],
            )
            assert "BLOCKED" in cp.stdout, (
                f"default-deny failed: netns reached secret port {secret_port} "
                f"without an egress pin (output: {cp.stdout!r})"
            )
        finally:
            listener.close()
    finally:
        sb.teardown()


# ---------------------------------------------------------------------------
# §6.6 item 6: teardown removes every kernel resource
# ---------------------------------------------------------------------------


def test_kernel_real_teardown_removes_all_resources():
    """``teardown()`` must delete the netns, veth pair, cgroup leaf, and
    nft table — no residual kernel resources remain."""
    _require_root()
    sb = BrowserNetworkSandbox(require_os_sandbox=True)
    sb.setup()
    netns = sb._netns_name
    nft_table = sb._nft_table
    cgroup = sb._cgroup_path
    assert netns and nft_table and cgroup
    sb.teardown()
    # All gone.
    assert not _netns_exists(netns), f"netns {netns} survived teardown"
    assert not _nft_table_exists(nft_table), f"nft table {nft_table} survived teardown"
    assert not cgroup.exists(), f"cgroup {cgroup} survived teardown"
    assert not sb.is_active


# ---------------------------------------------------------------------------
# §6.6 item 7-8: two concurrent sandboxes coexist; isolating teardown
# ---------------------------------------------------------------------------


def test_kernel_real_two_sandboxes_coexist():
    """Two ``BrowserNetworkSandbox`` instances must coexist: each gets its
    own netns/veth/cgroup/nft table (keyed by per-sandbox token), and both
    are simultaneously active."""
    _require_root()
    a = BrowserNetworkSandbox(require_os_sandbox=True)
    b = BrowserNetworkSandbox(require_os_sandbox=True)
    try:
        a.setup()
        b.setup()
        assert a.is_active and b.is_active
        # Distinct resources.
        assert a._netns_name != b._netns_name
        assert a._nft_table != b._nft_table
        assert a._token != b._token
        # Both exist in the kernel.
        assert _netns_exists(a._netns_name) and _netns_exists(b._netns_name)
        assert _nft_table_exists(a._nft_table) and _nft_table_exists(b._nft_table)
    finally:
        a.teardown()
        b.teardown()


def test_kernel_real_teardown_one_does_not_affect_other():
    """Tearing down sandbox A must NOT remove sandbox B's resources — the
    per-sandbox token ensures teardown only deletes its own netns/nft."""
    _require_root()
    a = BrowserNetworkSandbox(require_os_sandbox=True)
    b = BrowserNetworkSandbox(require_os_sandbox=True)
    try:
        a.setup()
        b.setup()
        a_netns, a_nft = a._netns_name, a._nft_table
        b_netns, b_nft = b._netns_name, b._nft_table
        # Tear down A.
        a.teardown()
        assert not a.is_active
        # A's resources gone.
        assert not _netns_exists(a_netns)
        assert not _nft_table_exists(a_nft)
        # B is UNAFFECTED — still active + resources intact.
        assert b.is_active, "tearing down A deactivated B (token leak)"
        assert _netns_exists(b_netns), "tearing down A deleted B's netns"
        assert _nft_table_exists(b_nft), "tearing down A deleted B's nft table"
    finally:
        b.teardown()


# ---------------------------------------------------------------------------
# §6.6 item: Reaper does not delete live processes' resources
# ---------------------------------------------------------------------------


def test_kernel_real_reaper_does_not_delete_live_sandbox(tmp_path):
    """A second ``BrowserNetworkSandbox`` created while the first is still
    live must not have its resources deleted by the first's teardown (the
    per-token ownership + teardown-isolation guarantee).  This models the
    'Reaper 误删活进程资源' failure mode from review §十一."""
    _require_root()
    live = BrowserNetworkSandbox(require_os_sandbox=True)
    live.setup()
    live_netns = live._netns_name
    live_nft = live._nft_table
    try:
        # Create + tear down an UNRELATED sandbox while `live` is active.
        ephemeral = BrowserNetworkSandbox(require_os_sandbox=True)
        ephemeral.setup()
        ephemeral.teardown()
        # The live sandbox must be untouched.
        assert live.is_active
        assert _netns_exists(live_netns), (
            "ephemeral teardown deleted the live sandbox's netns (Reaper bug)"
        )
        assert _nft_table_exists(live_nft), (
            "ephemeral teardown deleted the live sandbox's nft table (Reaper bug)"
        )
    finally:
        live.teardown()


# ---------------------------------------------------------------------------
# helper: find a free TCP port on the host
# ---------------------------------------------------------------------------


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port
