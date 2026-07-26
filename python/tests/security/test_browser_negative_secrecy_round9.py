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

import pytest

from khaos.tools.browser_tools import BrowserManager


pytestmark = [pytest.mark.browser_real, pytest.mark.kernel_real]


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
async def test_resolved_home_not_readable_from_browser() -> None:
    """High (§十): the resolved real home must not be readable.

    Places a sentinel file in the real home and verifies it cannot be read
    from inside the browser netns (the bubblewrap namespace masks it with
    a tmpfs).
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

            rc, out = _read_in_netns(
                sandbox._netns_name, str(sentinel)
            )
            assert rc != 0, (
                f"HIGH: resolved home {sentinel} was readable from the "
                f"browser namespace (got {out!r}) — Batch 9.2 regression"
            )
        finally:
            await manager.close()
    finally:
        sentinel.unlink(missing_ok=True)


@pytest.mark.asyncio
async def test_sensitive_host_paths_not_readable_from_browser(tmp_path) -> None:
    """High (§十一): existing sensitive host paths must be masked.

    Creates a sentinel under each sensitive path that EXISTS on the host
    (the Rust launcher only masks paths that exist — a non-existent path
    holds no secret).  Verifies none of the created sentinels is readable
    from the browser netns.  Falls back to the tmp_path (under /tmp or
    /home, both always masked) if none of the fixed paths exist, so the
    test always proves at least one masking.
    """
    _require_fullstack()
    candidates = ["/workspace", "/srv", "/data", "/mnt", "/var/lib"]
    # Create sentinels under paths that EXIST and are writable.  Only
    # existing paths are masked by the Rust launcher (a non-existent path
    # has no secret to protect and bwrap --tmpfs would fail on it).
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
    # Guarantee at least one sentinel exists: tmp_path is under /tmp or
    # /home (both always masked), so it proves the masking invariant even
    # when none of the fixed sensitive paths exist on the runner.
    fallback = tmp_path / "khaos-round9-fallback-secret"
    fallback.write_text("fallback-host-secret", encoding="utf-8")
    sentinels.append(fallback)

    manager = BrowserManager()
    try:
        launch = await manager.launch()
        assert launch["ok"], launch
        sandbox = manager._browser_sandbox
        assert sandbox is not None and sandbox.is_active

        for sentinel in sentinels:
            rc, out = _read_in_netns(sandbox._netns_name, str(sentinel))
            assert rc != 0, (
                f"HIGH: sensitive host path {sentinel} was readable from "
                f"the browser namespace (got {out!r}) — Batch 9.2 regression"
            )
    finally:
        await manager.close()
        for sentinel in sentinels:
            sentinel.unlink(missing_ok=True)
            # Clean up the probe dir if we created it (not tmp_path).
            if sentinel.parent.name == "khaos-round9-probe":
                try:
                    sentinel.parent.rmdir()
                except OSError:
                    pass
