"""Batch 10.5 (round-10 §八): real mount-namespace secrecy proof.

Round-9's FS secrecy tests used ``page.goto(file://...)`` which could not
distinguish "blocked by Route Guard" from "blocked by mount namespace".
This module uses the Rust launcher's ``--browser-fs-probe`` mode to call
``open(2)`` DIRECTLY from inside the bubblewrap mount namespace, bypassing
Playwright / Route Guard / Web Security entirely.

Runs ONLY in the privileged fullstack CI job (real launcher + real
kernel stack).  Skipped everywhere else.
"""

from __future__ import annotations

import os
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
    if os.geteuid() == 0:
        pytest.fail("production Python browser runtime must be non-root")


@pytest.mark.asyncio
async def test_fs_probe_proves_home_is_masked() -> None:
    """The resolved real home must be UNREADABLE from inside the mount
    namespace (the bubblewrap ``--tmpfs`` mask holds).  This is a direct
    ``open(2)`` proof, not a Playwright navigation."""
    _require_fullstack()
    home = Path.home().resolve()
    sentinel = home / ".khaos-round10-fs-probe-sentinel"
    sentinel.write_text("host-home-secret", encoding="utf-8")
    try:
        manager = BrowserManager()
        try:
            launch = await manager.launch(
                project_id="round10-home", runtime_id="round10-home"
            )
            assert launch["ok"], launch
            sandbox = manager._browser_sandbox
            assert sandbox is not None and sandbox.is_active

            outcomes = sandbox.run_fs_probe([str(sentinel)])
            outcome = outcomes.get(str(sentinel), "MISSING")
            assert outcome != "READABLE", (
                f"HIGH: home sentinel {sentinel} was READABLE from inside "
                f"the mount namespace (outcome={outcome}) — the bwrap "
                f"--tmpfs mask on the home path is NOT effective"
            )
            assert outcome in ("ENOENT", "EACCES", "BLOCKED"), (
                f"unexpected probe outcome {outcome} for {sentinel}"
            )
        finally:
            await manager.close()
    finally:
        sentinel.unlink(missing_ok=True)


@pytest.mark.asyncio
async def test_fs_probe_proves_sensitive_paths_are_masked() -> None:
    """Existing sensitive host paths (/workspace /srv /data /mnt /var/lib)
    must be UNREADABLE from inside the mount namespace."""
    _require_fullstack()
    candidates = ["/workspace", "/srv", "/data", "/mnt", "/var/lib"]
    sentinels: list[Path] = []
    for base in candidates:
        base_path = Path(base)
        if not base_path.exists():
            continue
        sentinel_dir = base_path / "khaos-round10-probe"
        try:
            sentinel_dir.mkdir(parents=True, exist_ok=True)
            sentinel = sentinel_dir / "secret.txt"
            sentinel.write_text(f"secret-{base}", encoding="utf-8")
            sentinels.append(sentinel)
        except OSError:
            continue
    if not sentinels:
        pytest.skip("no writable sensitive host paths to probe")

    manager = BrowserManager()
    try:
        launch = await manager.launch(
            project_id="round10-paths", runtime_id="round10-paths"
        )
        assert launch["ok"], launch
        sandbox = manager._browser_sandbox
        assert sandbox is not None and sandbox.is_active

        outcomes = sandbox.run_fs_probe([str(s) for s in sentinels])
        for sentinel in sentinels:
            outcome = outcomes.get(str(sentinel), "MISSING")
            assert outcome != "READABLE", (
                f"HIGH: sensitive path {sentinel} was READABLE from "
                f"inside the mount namespace (outcome={outcome}) — "
                f"the bwrap --tmpfs mask is NOT effective"
            )
    finally:
        await manager.close()
        for sentinel in sentinels:
            sentinel.unlink(missing_ok=True)
            try:
                sentinel.parent.rmdir()
            except OSError:
                pass


@pytest.mark.asyncio
async def test_fs_probe_detects_unmasked_path() -> None:
    """A path that is NOT masked (e.g. /etc/hostname) must be READABLE —
    this proves the probe is effective and not producing false negatives.
    If this test fails (everything reports ENOENT), the probe itself is
    broken and the negative tests above are meaningless."""
    _require_fullstack()
    # /etc/hostname exists on virtually every Linux and is not in the
    # mask list, so it must be readable from inside the namespace.
    probe_target = "/etc/hostname"
    if not Path(probe_target).exists():
        pytest.skip(f"{probe_target} not present on this host")

    manager = BrowserManager()
    try:
        launch = await manager.launch(
            project_id="round10-positive", runtime_id="round10-positive"
        )
        assert launch["ok"], launch
        sandbox = manager._browser_sandbox
        assert sandbox is not None and sandbox.is_active

        outcomes = sandbox.run_fs_probe([probe_target])
        outcome = outcomes.get(probe_target, "MISSING")
        assert outcome == "READABLE", (
            f"UNMASKED path {probe_target} was not readable (outcome="
            f"{outcome}) — the fs-probe itself may be broken; the "
            f"negative secrecy tests above would then be false positives"
        )
    finally:
        await manager.close()
