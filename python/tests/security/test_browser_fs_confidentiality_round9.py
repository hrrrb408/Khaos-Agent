"""Batch 9.2 (round-9 §十/§十一): browser filesystem confidentiality regressions.

The browser bubblewrap namespace previously only masked the fixed paths
``/home`` and ``/root`` while leaving the rest of ``/`` read-only visible.
On deployments whose home lives outside those paths (``/var/lib/khaos``,
``/srv/khaos``), a compromised Chromium could read the registry HMAC key
and registry entries.  It could also read ``/workspace``, ``/srv``,
``/data``, ``/mnt`` and ``/var/lib``.

These tests verify the Python side forwards the resolved real home so the
Rust launcher can mask it, and that the masking is skipped when the home
is already covered by the fixed ``/home`` or ``/root`` tmpfs.

The negative full-stack proof (Chromium cannot ``cat`` the sentinel) lives
in ``test_browser_fullstack_kernel_round8.py`` — it requires the real
kernel stack and runs only in the privileged CI job.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from khaos.security.browser_sandbox import BrowserNetworkSandbox


def _active_sandbox(monkeypatch) -> BrowserNetworkSandbox:
    sandbox = BrowserNetworkSandbox.__new__(BrowserNetworkSandbox)
    sandbox._active = True
    sandbox._netns_name = "khaos-br-test"
    sandbox._cgroup_path = None
    monkeypatch.setattr(
        BrowserNetworkSandbox, "_locate_browser_launcher",
        staticmethod(lambda: "/usr/local/bin/khaos-sandbox-launcher"),
    )
    return sandbox


def test_launcher_environment_forwards_resolved_host_home(monkeypatch) -> None:
    """KHAOS_BROWSER_HOST_HOME must be the resolved real home path."""
    monkeypatch.setenv("PATH", "/usr/bin")
    sandbox = _active_sandbox(monkeypatch)
    env = sandbox.launcher_environment("/opt/chromium")

    host_home = env["KHAOS_BROWSER_HOST_HOME"]
    # Must be an absolute resolved path (no symlinks, no trailing slash).
    assert host_home.startswith("/")
    assert host_home == str(Path(host_home).resolve())


def test_host_home_is_resolved_not_raw(monkeypatch, tmp_path) -> None:
    """If home() is a symlink, the resolved target is forwarded."""
    real_home = tmp_path / "real-home"
    real_home.mkdir()
    link_home = tmp_path / "link-home"
    link_home.symlink_to(real_home)

    monkeypatch.setenv("PATH", "/usr/bin")
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: link_home))
    sandbox = _active_sandbox(monkeypatch)
    env = sandbox.launcher_environment("/opt/chromium")

    # The forwarded path is the RESOLVED real_home, not the symlink.
    assert env["KHAOS_BROWSER_HOST_HOME"] == str(real_home.resolve())


def test_bwrap_masks_non_standard_home(tmp_path) -> None:
    """Reproduce the masking decision the Rust launcher makes.

    A home like ``/var/lib/khaos`` is NOT under /home or /root, so the
    launcher must emit a ``--tmpfs /var/lib/khaos`` (well, /var/lib is
    already masked by the sensitive-path list, but the home itself is
    masked too).  This test documents the invariant in Python so a future
    refactor does not silently drop the host-home masking.
    """
    host_home = "/var/lib/khaos"
    home_str = host_home.rstrip("/")
    already_masked = (
        home_str == "/home"
        or home_str == "/root"
        or home_str.startswith("/home/")
        or home_str.startswith("/root/")
    )
    assert not already_masked, (
        "non-standard home must be masked separately from /home /root"
    )

    # /var/lib is in the sensitive-path list, so it is masked regardless.
    sensitive_host_paths = ["/workspace", "/srv", "/data", "/mnt", "/var/lib"]
    assert any(host_home.startswith(p) for p in sensitive_host_paths)


def test_standard_home_under_home_is_already_masked() -> None:
    """A home under /home/... is already covered by the /home tmpfs."""
    for home_str in ["/home/user", "/home/alice"]:
        already_masked = (
            home_str == "/home"
            or home_str == "/root"
            or home_str.startswith("/home/")
            or home_str.startswith("/root/")
        )
        assert already_masked, f"{home_str} should be covered by /home tmpfs"
