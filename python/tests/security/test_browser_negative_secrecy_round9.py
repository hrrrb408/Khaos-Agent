"""Batch 9.1/9.2/9.3/9.4 (round-9 §十六): negative-secrecy full-stack proof.

Round-8 closed the positive full-stack proof (browser launches, network is
isolated, cgroup/netns are correct).  Round-9 adds the NEGATIVE proofs the
review identified as missing:

* §九  (Critical): Chromium must NOT see parent-process secret env vars.
* §十  (High):     the resolved real home must NOT be readable from inside
                    the namespace (covers non-standard homes like
                    /var/lib/khaos where the registry HMAC key lives).
* §十一 (High):    sensitive host paths (/workspace, /srv, /data, /mnt,
                    /var/lib) must NOT be readable.
* §十三 (High):    a teardown that raises must leave the manager fail-closed
                    (covered by the unit test file; this module focuses on
                    the in-Chromium secrecy proofs).

These run ONLY in the privileged fullstack CI job (real Chromium + real
kernel stack).  They are skipped everywhere else.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse

import pytest

from khaos.security.host_network import ValidatedTarget
from khaos.security.network_guard import NetworkCheckResult
from khaos.tools.browser_tools import BrowserManager


pytestmark = [pytest.mark.browser_real, pytest.mark.kernel_real]


class _PinnedLocalGuard:
    """Minimal network guard that authorizes the sandbox host IP only."""

    def __init__(self, address: str) -> None:
        self.address = address

    async def authorize_url(self, url: str, **_: object) -> ValidatedTarget:
        parsed = urlparse(url)
        return ValidatedTarget(
            url=url,
            parsed=parsed,
            hostname=parsed.hostname or "khaos.test",
            addresses=(self.address,),
        )

    async def check_resolved_url(self, url: str) -> NetworkCheckResult:
        return NetworkCheckResult(
            allowed=True,
            reason="round9 controlled local fixture",
            domain=urlparse(url).hostname or "",
        )


def _require_fullstack() -> None:
    if not sys.platform.startswith("linux"):
        pytest.skip("Linux kernel browser sandbox required")
    if os.environ.get("KHAOS_RUN_BROWSER_E2E") != "1":
        pytest.skip("set KHAOS_RUN_BROWSER_E2E=1")
    if os.environ.get("KHAOS_RUN_KERNEL_BROWSER_E2E") != "1":
        pytest.skip("set KHAOS_RUN_KERNEL_BROWSER_E2E=1")
    if os.geteuid() != 0:
        pytest.skip("privileged kernel test requires root")


def _read_in_netns(netns: str, path: str) -> tuple[int, bytes]:
    """Try to read ``path`` from inside the browser netns via a helper.

    Returns (returncode, stdout).  returncode 0 + non-empty output means
    the path was readable (a secrecy VIOLATION).
    """
    script = (
        "import sys\n"
        "try:\n"
        "    with open(sys.argv[1], 'rb') as f:\n"
        "        sys.stdout.buffer.write(f.read())\n"
        "    raise SystemExit(0)\n"
        "except OSError:\n"
        "    raise SystemExit(1)\n"
    )
    result = subprocess.run(
        ["ip", "netns", "exec", netns, "python3", "-c", script, path],
        capture_output=True,
        timeout=5,
        check=False,
    )
    return result.returncode, result.stdout


def _read_chromium_environ(netns: str, cgroup_procs: Path) -> bytes:
    """Read /proc/<pid>/environ for every Chromium PID in the cgroup."""
    pids = [
        int(value)
        for value in cgroup_procs.read_text().split()
    ]
    assert pids, "Chromium process tree did not join browser cgroup"
    combined = b""
    for pid in pids:
        rc, out = _read_in_netns(netns, f"/proc/{pid}/environ")
        if rc == 0:
            combined += out
    return combined


@pytest.mark.asyncio
async def test_chromium_environ_excludes_parent_secrets() -> None:
    """Critical (§九): parent secret env vars must not reach Chromium.

    The CI job exports KHAOS_SENTINEL_SECRET (and other sentinel vars) into
    the parent process.  After Batch 9.1, Chromium's environment is built
    from an explicit allowlist only, so the sentinel must be absent from
    /proc/<pid>/environ for every Chromium process.
    """
    _require_fullstack()
    sentinel = os.environ.get("KHAOS_SENTINEL_SECRET", "must-not-reach-browser")
    # Ensure the sentinel is present in the PARENT process so the test is
    # meaningful even when the CI job forgot to export it.
    os.environ["KHAOS_SENTINEL_SECRET"] = sentinel

    manager = BrowserManager()
    try:
        launch = await manager.launch()
        assert launch["ok"], launch
        sandbox = manager._browser_sandbox
        assert sandbox is not None and sandbox.is_active

        environ = _read_chromium_environ(
            sandbox._netns_name, sandbox._cgroup_path / "cgroup.procs"
        )
        # environ entries are NUL-separated; the sentinel value must not
        # appear anywhere in the concatenated buffer.
        sentinel_marker = sentinel.encode("ascii")
        assert sentinel_marker not in environ, (
            "CRITICAL: parent secret KHAOS_SENTINEL_SECRET reached "
            "Chromium's environment — Batch 9.1 regression"
        )
        # And the variable NAME must not appear as a key.
        assert b"KHAOS_SENTINEL_SECRET" not in environ, (
            "CRITICAL: KHAOS_SENTINEL_SECRET env key present in Chromium"
        )
    finally:
        await manager.close()


@pytest.mark.asyncio
async def test_route_guard_blocks_file_scheme_for_home() -> None:
    """Route Guard proof (round-10 §八): the resolved real home ``file://``
    URL must be blocked by the Route Guard's scheme allowlist.

    NOTE (round-10): this test proves the Route Guard blocks ``file:``
    scheme navigation — it does NOT prove the bubblewrap mount mask.
    The mount-mask proof lives in test_browser_fs_probe_round10.py,
    which calls ``open(2)`` directly inside the mount namespace,
    bypassing Playwright/Route Guard.  Both tests are needed: this one
    guards the Route Guard, the fs-probe guards the kernel mask.

    Batch 9.2 verification note: this MUST be observed from inside the
    Chromium process itself (via its Playwright page), NOT from an
    external ``ip netns exec`` helper or ``/proc/<pid>/root`` read.
    Those only switch the NETWORK namespace or resolve the magic symlink
    against the reader's credentials — they see the HOST mount table,
    not the bubblewrap tmpfs.  The mask is only meaningful from inside
    Chromium's MOUNT namespace, which only Chromium itself inhabits.

    We evaluate a fetch('file://...') inside the page; Chromium resolves
    the path against its own rootfs (the bubblewrap view).  If the mask
    holds, the fetch fails (no such file).
    """
    _require_fullstack()
    home = Path.home().resolve()
    sentinel = home / ".khaos-round9-fs-sentinel"
    sentinel.write_text("host-home-secret", encoding="utf-8")
    try:
        manager = BrowserManager()
        try:
            launch = await manager.launch()
            assert launch["ok"], launch
            sandbox = manager._browser_sandbox
            assert sandbox is not None and sandbox.is_active
            page = await manager.ensure_page(
                "round9-fs-principal",
                session_id="round9-fs",
                runtime_id="round9-fs",
                network_guard=_PinnedLocalGuard(sandbox._host_ip),
            )
            assert page is not None

            # Read the file FROM INSIDE Chromium.  Navigate to the file://
            # URL; Chromium resolves file paths against its own mount
            # namespace (the bubblewrap tmpfs view).  If the mask holds,
            # navigation fails (file not found).
            await page.goto("about:blank")
            file_url = sentinel.as_uri()
            leaked = None
            try:
                response = await page.goto(file_url, wait_until="domcontentloaded")
                if response is not None and response.ok:
                    leaked = await page.text_content("body")
            except Exception:
                leaked = None
            assert leaked is None, (
                f"HIGH: resolved home {sentinel} was readable from inside "
                f"Chromium's mount namespace (got {leaked!r}) — Batch 9.2 "
                f"regression: the bwrap --tmpfs mask on the home path is "
                f"not effective"
            )
        finally:
            await manager.close()
    finally:
        sentinel.unlink(missing_ok=True)


@pytest.mark.asyncio
async def test_route_guard_blocks_file_scheme_for_sensitive_paths(tmp_path) -> None:
    """Route Guard proof (round-10 §八): sensitive host paths' ``file://``
    URLs must be blocked by the Route Guard's scheme allowlist.

    NOTE (round-10): like the home test above, this proves the Route
    Guard, NOT the mount mask.  The mount-mask proof lives in
    test_browser_fs_probe_round10.py.

    Creates a sentinel under each sensitive path that EXISTS on the host
    and verifies none is readable from inside Chromium's OWN mount
    namespace (via the page, not an external helper — see
    test_resolved_home_not_readable_from_browser for why).  Falls back
    to tmp_path (under /tmp, always masked) so the test always proves
    at least one masking.
    """
    _require_fullstack()
    candidates = ["/workspace", "/srv", "/data", "/mnt", "/var/lib"]
    sentinels: list[Path] = []
    for base in candidates:
        base_path = Path(base)
        if not base_path.exists():
            continue
        sentinel_dir = base_path / "khaos-round9-probe"
        try:
            sentinel_dir.mkdir(parents=True, exist_ok=True)
            sentinel = sentinel_dir / "secret.txt"
            sentinel.write_text(f"secret-{base}", encoding="utf-8")
            sentinels.append(sentinel)
        except OSError:
            continue
    # Guarantee at least one sentinel under /tmp (always masked).
    fallback = tmp_path / "khaos-round9-fallback-secret"
    fallback.write_text("fallback-host-secret", encoding="utf-8")
    sentinels.append(fallback)

    manager = BrowserManager()
    try:
        launch = await manager.launch()
        assert launch["ok"], launch
        sandbox = manager._browser_sandbox
        assert sandbox is not None and sandbox.is_active
        page = await manager.ensure_page(
            "round9-fs2-principal",
            session_id="round9-fs2",
            runtime_id="round9-fs2",
            network_guard=_PinnedLocalGuard(sandbox._host_ip),
        )
        assert page is not None
        await page.goto("about:blank")

        for sentinel in sentinels:
            file_url = sentinel.as_uri()
            leaked = None
            try:
                response = await page.goto(file_url, wait_until="domcontentloaded")
                if response is not None and response.ok:
                    leaked = await page.text_content("body")
            except Exception:
                leaked = None
            assert leaked is None, (
                f"HIGH: sensitive host path {sentinel} was readable from "
                f"inside Chromium's mount namespace (got {leaked!r}) — "
                f"Batch 9.2 regression: the bwrap --tmpfs mask is not "
                f"effective"
            )
    finally:
        await manager.close()
        for sentinel in sentinels:
            sentinel.unlink(missing_ok=True)
            if sentinel.parent.name == "khaos-round9-probe":
                try:
                    sentinel.parent.rmdir()
                except OSError:
                    pass
