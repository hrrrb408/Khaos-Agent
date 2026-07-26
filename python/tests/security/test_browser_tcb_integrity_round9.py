"""Batch 9.3 (round-9 §十二): TCB binary integrity regressions.

The browser launcher, bubblewrap and Chromium runtime form the trusted
computing base of the browser sandbox.  Round-8 left their binary trust to
CI/README convention only — production code accepted any path from
``shutil.which()`` or ``KHAOS_SANDBOX_LAUNCHER`` without checking owner,
mode or symlink status.  A pre-sandbox attacker could plant a malicious
``bwrap`` earlier in PATH and have it execute in the privileged window
(after netns/cgroup join, before mount-namespace + seccomp).

These tests verify the runtime now enforces the TCB invariant.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from khaos.security.browser_sandbox import (
    BrowserNetworkSandbox,
    BrowserSandboxError,
    _validate_tcb_binary,
)


def _make_binary(path: Path, *, mode: int = 0o755, owner: int | None = None) -> Path:
    """Create a minimal regular file at ``path`` with the given mode."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"#!/bin/sh\nexit 0\n")
    os.chmod(path, mode)
    if owner is not None and hasattr(os, "chown"):
        try:
            os.chown(path, owner, owner)
        except PermissionError:
            pytest.skip("cannot chown without root")
    return path


# ---------------------------------------------------------------------------
# _validate_tcb_binary unit tests
# ---------------------------------------------------------------------------

def test_validate_accepts_regular_owner_file(tmp_path) -> None:
    binary = _make_binary(tmp_path / "launcher", mode=0o755)
    # Should not raise.
    _validate_tcb_binary(str(binary), label="test")


def test_validate_rejects_group_writable(tmp_path) -> None:
    binary = _make_binary(tmp_path / "launcher", mode=0o774)
    with pytest.raises(BrowserSandboxError, match="group/other writable"):
        _validate_tcb_binary(str(binary), label="test")


def test_validate_rejects_other_writable(tmp_path) -> None:
    binary = _make_binary(tmp_path / "launcher", mode=0o707)
    with pytest.raises(BrowserSandboxError, match="group/other writable"):
        _validate_tcb_binary(str(binary), label="test")


def test_validate_rejects_symlink(tmp_path) -> None:
    target = _make_binary(tmp_path / "real-launcher", mode=0o755)
    link = tmp_path / "launcher-link"
    link.symlink_to(target)
    with pytest.raises(BrowserSandboxError, match="secure open failed"):
        _validate_tcb_binary(str(link), label="test")


def test_validate_rejects_nonexistent(tmp_path) -> None:
    with pytest.raises(BrowserSandboxError, match="secure open failed"):
        _validate_tcb_binary(str(tmp_path / "missing"), label="test")


def test_validate_rejects_relative_path(tmp_path) -> None:
    binary = _make_binary(tmp_path / "launcher", mode=0o755)
    rel = os.path.relpath(binary, os.getcwd())
    with pytest.raises(BrowserSandboxError, match="must be absolute"):
        _validate_tcb_binary(rel, label="test")


# ---------------------------------------------------------------------------
# _locate_and_validate_browser_launcher integration
# ---------------------------------------------------------------------------

def _active_sandbox(monkeypatch, *, require_os_sandbox: bool) -> BrowserNetworkSandbox:
    sandbox = BrowserNetworkSandbox.__new__(BrowserNetworkSandbox)
    sandbox._active = True
    sandbox._netns_name = "khaos-br-test"
    sandbox._cgroup_path = None
    sandbox._require_os_sandbox = require_os_sandbox
    return sandbox


def test_production_rejects_group_writable_launcher(monkeypatch, tmp_path) -> None:
    """Production (require_os_sandbox=True) rejects a group-writable launcher."""
    launcher = _make_binary(tmp_path / "launcher", mode=0o774)
    sandbox = _active_sandbox(monkeypatch, require_os_sandbox=True)
    monkeypatch.setattr(
        BrowserNetworkSandbox, "_locate_browser_launcher",
        staticmethod(lambda: str(launcher)),
    )
    with pytest.raises(BrowserSandboxError, match="group/other writable"):
        sandbox._locate_and_validate_browser_launcher()


def test_production_rejects_symlink_launcher(monkeypatch, tmp_path) -> None:
    """Production rejects a symlink launcher (O_NOFOLLOW)."""
    target = _make_binary(tmp_path / "real", mode=0o755)
    link = tmp_path / "launcher-link"
    link.symlink_to(target)
    sandbox = _active_sandbox(monkeypatch, require_os_sandbox=True)
    monkeypatch.setattr(
        BrowserNetworkSandbox, "_locate_browser_launcher",
        staticmethod(lambda: str(link)),
    )
    with pytest.raises(BrowserSandboxError, match="secure open failed"):
        sandbox._locate_and_validate_browser_launcher()


def test_production_accepts_trusted_launcher(monkeypatch, tmp_path) -> None:
    """Production accepts a regular, owner-only-writable launcher."""
    launcher = _make_binary(tmp_path / "launcher", mode=0o755)
    sandbox = _active_sandbox(monkeypatch, require_os_sandbox=True)
    monkeypatch.setattr(
        BrowserNetworkSandbox, "_locate_browser_launcher",
        staticmethod(lambda: str(launcher)),
    )
    assert sandbox._locate_and_validate_browser_launcher() == str(launcher)


def test_dev_mode_skips_validation(monkeypatch, tmp_path) -> None:
    """Dev mode (require_os_sandbox=False) does NOT validate the launcher."""
    launcher = _make_binary(tmp_path / "launcher", mode=0o777)
    sandbox = _active_sandbox(monkeypatch, require_os_sandbox=False)
    monkeypatch.setattr(
        BrowserNetworkSandbox, "_locate_browser_launcher",
        staticmethod(lambda: str(launcher)),
    )
    # Should NOT raise despite world-writable (dev mode trusts the developer).
    assert sandbox._locate_and_validate_browser_launcher() == str(launcher)


def test_launcher_environment_validates_chromium_in_production(
    monkeypatch, tmp_path,
) -> None:
    """launcher_environment() validates real_executable (Chromium) in prod."""
    launcher = _make_binary(tmp_path / "launcher", mode=0o755)
    chromium = _make_binary(tmp_path / "chromium", mode=0o774)  # group-writable
    sandbox = _active_sandbox(monkeypatch, require_os_sandbox=True)
    monkeypatch.setattr(
        BrowserNetworkSandbox, "_locate_browser_launcher",
        staticmethod(lambda: str(launcher)),
    )
    with pytest.raises(BrowserSandboxError, match="chromium runtime.*group/other writable"):
        sandbox.launcher_environment(str(chromium))
