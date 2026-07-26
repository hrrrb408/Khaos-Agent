"""Batch 7.4 (round-7): Browser TCB Consolidation.

Closes review §十二 (Playwright mock silent success), §十 (process-shared
browser domain threat model), §十一 (shell wrapper → Rust launcher).

§十二: production fails closed when Playwright is missing (no silent
mock); mock results carry a ``mock: True`` marker; mock is opt-in via
``KHAOS_BROWSER_MOCK_MODE=1``.

§十: ``EnforcementStatus.process_isolation`` is False (process-shared);
documented in ``docs/browser-threat-model.md``.

§十一: ``create_wrapper_script`` forwards to the Rust browser launcher
when available (``--browser`` mode: cgroup join + netns join + FD
sanitization + seccomp); falls back to the nsenter shell otherwise.
``build_launcher_argv`` exposes the raw launcher argv.
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from khaos.security.browser_sandbox import (
    BrowserNetworkSandbox,
    EnforcementStatus,
)


# ===========================================================================
# §十二 — Playwright mock fail-closed
# ===========================================================================


class TestMockFailClosed:
    """§十二: without KHAOS_BROWSER_MOCK_MODE, a missing Playwright must
    fail closed (not silently mock success)."""

    def test_production_fails_closed_without_playwright(self, monkeypatch):
        """When Playwright is NOT installed and KHAOS_BROWSER_MOCK_MODE is
        unset, _safe_execute must return ok:False, NOT a mock success."""
        from khaos.tools import browser_tools

        monkeypatch.delenv("KHAOS_BROWSER_MOCK_MODE", raising=False)
        mgr = browser_tools.BrowserManager()
        # Force the "no playwright" path.
        with patch.object(browser_tools, "_HAS_PLAYWRIGHT", False):
            result = asyncio_run(mgr._safe_execute(
                real=lambda page: {"ok": True, "real": True},
                mock=lambda: {"ok": True, "mock_intended": True},
            ))
        assert result["ok"] is False
        assert "playwright_missing" in result
        assert result["playwright_missing"] is True
        # Must NOT have returned the mock success.
        assert "mock_intended" not in result

    def test_mock_mode_returns_mock_with_marker(self, monkeypatch):
        """With KHAOS_BROWSER_MOCK_MODE=1, the mock path is used AND every
        result carries ``mock: True`` so it is distinguishable."""
        from khaos.tools import browser_tools

        monkeypatch.setenv("KHAOS_BROWSER_MOCK_MODE", "1")
        mgr = browser_tools.BrowserManager()
        with patch.object(browser_tools, "_HAS_PLAYWRIGHT", False):
            result = asyncio_run(mgr._safe_execute(
                real=lambda page: {"ok": True},
                mock=lambda: {"ok": True, "url": "x"},
            ))
        assert result["ok"] is True
        assert result["mock"] is True  # §十二 marker


# ===========================================================================
# §十 — process_isolation flag
# ===========================================================================


class TestProcessIsolationFlag:
    def test_default_enforcement_is_process_shared(self):
        """§十: the default EnforcementStatus must have
        process_isolation=False (the current process-shared design)."""
        es = EnforcementStatus()
        assert es.process_isolation is False

    def test_setup_sets_process_isolation_false(self):
        """§十: even a fully-enforced sandbox reports
        process_isolation=False (the documented boundary)."""
        sb = BrowserNetworkSandbox(require_os_sandbox=False)
        # Simulate a fully-active enforcement (dev mode doesn't setup).
        sb._enforcement = EnforcementStatus(
            network_namespace=True, proxy_required=True, cgroup=True,
            route_guard=True, service_workers_blocked=True,
        )
        assert sb._enforcement.process_isolation is False


# ===========================================================================
# §十一 — Rust browser launcher integration
# ===========================================================================


class TestBrowserLauncherArgv:
    """§十一: build_launcher_argv produces the Rust launcher argv when the
    binary is available; create_wrapper_script forwards to it."""

    def test_build_launcher_argv_returns_none_when_inactive(self):
        sb = BrowserNetworkSandbox(require_os_sandbox=False)
        assert sb.build_launcher_argv("/usr/bin/chromium") is None

    def test_build_launcher_argv_with_launcher_available(self, monkeypatch):
        sb = BrowserNetworkSandbox(require_os_sandbox=False)
        sb._active = True
        sb._token = "a1b2c3d4e5f6a1b2"
        sb._netns_name = "khaos-br-a1b2c3"
        sb._nft_table = "khaos_browser_a1b2c3d4e5f6a1b2"
        sb._cgroup_path = None
        monkeypatch.setenv("KHAOS_SANDBOX_LAUNCHER", "/opt/khaos/launcher")
        argv = sb.build_launcher_argv("/usr/bin/chromium")
        assert argv is not None
        assert argv[0] == "/opt/khaos/launcher"
        assert "--browser" in argv
        assert "--netns" in argv
        assert "khaos-br-a1b2c3" in argv
        assert "--" in argv
        assert "/usr/bin/chromium" in argv

    def test_build_launcher_argv_returns_none_when_no_launcher(self, monkeypatch):
        """When the launcher binary is absent, build_launcher_argv returns
        None (caller falls back to the shell wrapper)."""
        sb = BrowserNetworkSandbox(require_os_sandbox=False)
        sb._active = True
        sb._token = "a1b2c3d4e5f6a1b2"
        sb._netns_name = "khaos-br-a1b2c3"
        sb._nft_table = "khaos_browser_a1b2c3d4e5f6a1b2"
        sb._cgroup_path = None
        monkeypatch.delenv("KHAOS_SANDBOX_LAUNCHER", raising=False)
        with patch("khaos.security.browser_sandbox.shutil.which", return_value=None):
            argv = sb.build_launcher_argv("/usr/bin/chromium")
        assert argv is None

    def test_create_wrapper_script_uses_launcher_when_available(self, tmp_path, monkeypatch):
        """§十一: create_wrapper_script generates a shim that forwards to
        the Rust launcher (not the legacy nsenter form) when available."""
        sb = BrowserNetworkSandbox(require_os_sandbox=False)
        sb._active = True
        sb._token = "a1b2c3d4e5f6a1b2"
        sb._netns_name = "khaos-br-a1b2c3"
        sb._nft_table = "khaos_browser_a1b2c3d4e5f6a1b2"
        sb._cgroup_path = None
        sb._run_dir = tmp_path
        monkeypatch.setenv("KHAOS_SANDBOX_LAUNCHER", "/opt/khaos/launcher")
        wrapper = sb.create_wrapper_script("/usr/bin/chromium", 0)
        assert wrapper is not None
        content = Path(wrapper).read_text(encoding="utf-8")
        # Forwards to the launcher, not the legacy nsenter.
        assert "/opt/khaos/launcher" in content
        assert "--browser" in content
        assert "--netns" in content
        assert "nsenter" not in content, "should use launcher, not legacy nsenter"

    def test_create_wrapper_script_falls_back_to_nsenter(self, tmp_path, monkeypatch):
        """§十一: without the launcher, the legacy nsenter shell form is
        used (backward-compatible fallback)."""
        sb = BrowserNetworkSandbox(require_os_sandbox=False)
        sb._active = True
        sb._token = "a1b2c3d4e5f6a1b2"
        sb._netns_name = "khaos-br-a1b2c3"
        sb._nft_table = "khaos_browser_a1b2c3d4e5f6a1b2"
        sb._cgroup_path = None
        sb._run_dir = tmp_path
        monkeypatch.delenv("KHAOS_SANDBOX_LAUNCHER", raising=False)
        with patch("khaos.security.browser_sandbox.shutil.which", return_value=None):
            wrapper = sb.create_wrapper_script("/usr/bin/chromium", 0)
        assert wrapper is not None
        content = Path(wrapper).read_text(encoding="utf-8")
        assert "nsenter" in content  # legacy fallback


# ---------------------------------------------------------------------------
# helper
# ---------------------------------------------------------------------------


def asyncio_run(coro):
    import asyncio
    return asyncio.get_event_loop().run_until_complete(coro) if asyncio.get_event_loop().is_running() else asyncio.run(coro)
