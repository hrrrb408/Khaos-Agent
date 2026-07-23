"""Shared test fixtures."""
from __future__ import annotations

import os
import asyncio
import sqlite3
import shutil
import sys

import pytest

# Force mock mode for all tests — prevent accidentally hitting real APIs
os.environ.setdefault("KHAOS_NO_CONFIG", "1")
# M4 batch 3.1.16A-1: tests legitimately need to create databases in
# ``tmp_path`` without each test constructing a state-root path.  This
# bypasses the state-root enforcement in ``state_root.py`` so that
# ``Database(tmp_path / "khaos.db")`` and ``serve_json_lines(socket,
# str(tmp_path / "khaos.db"), ...)`` continue to work unchanged.
# Production code never sets this variable.
os.environ.setdefault("KHAOS_ALLOW_PROJECT_DB", "1")
# Round 5 Batch 5.1: production BrowserNetworkSandbox defaults to
# ``require_os_sandbox=True`` (fail-closed — Firefox/WebKit refuse to
# launch and Chromium requires the netns wrapper).  CI / local test
# runners are non-Linux (darwin) and have no netns/cgroup/nft support,
# so the production path would raise ``BrowserSandboxError``.  Tests opt
# into the dev-mode proxy-only fallback, which is the documented escape
# hatch.  Production code never sets this variable.
os.environ.setdefault("KHAOS_BROWSER_DEV_MODE", "1")

# Round-5 Batch 5.5: auto-enable the heavy E2E test suites when the
# required runtime is present on the developer's machine.  Both flags
# default off so CI matrices and fresh checkouts stay green without
# downloading Playwright/Chromium or running a Docker daemon.  A
# developer who has the runtimes installed gets the full suite by
# default; CI can still opt out by setting the flag to "0".
def _auto_enable_e2e_suites() -> None:
    # Browser E2E: needs Playwright + the Chromium binary.  Detect both
    # before opting in so a bare ``pip install -e .[test]`` checkout
    # does not suddenly start collecting slow browser tests.
    if os.environ.get("KHAOS_RUN_BROWSER_E2E") is None:
        try:
            import playwright  # noqa: F401
            from playwright._impl._driver import compute_driver_executable  # noqa: F401
            # Chromium binary lives in the OS-specific cache dir.  The
            # exact folder name is version-pinned (e.g. chromium-1187),
            # so we just check for any ``chromium-*`` entry.
            if sys.platform == "darwin":
                cache_root = os.path.expanduser("~/Library/Caches/ms-playwright")
            elif sys.platform.startswith("linux"):
                cache_root = os.path.expanduser("~/.cache/ms-playwright")
            else:
                cache_root = ""
            if cache_root and os.path.isdir(cache_root):
                if any(name.startswith("chromium-") for name in os.listdir(cache_root)):
                    os.environ["KHAOS_RUN_BROWSER_E2E"] = "1"
        except Exception:
            pass

    # Production sandbox E2E: needs the Docker daemon.  Detect the CLI
    # and a running daemon before opting in.
    if os.environ.get("KHAOS_RUN_PRODUCTION_SANDBOX") is None:
        if shutil.which("docker"):
            import subprocess
            try:
                result = subprocess.run(
                    ["docker", "info"],
                    capture_output=True,
                    timeout=5,
                )
                if result.returncode == 0:
                    os.environ["KHAOS_RUN_PRODUCTION_SANDBOX"] = "1"
            except Exception:
                pass


_auto_enable_e2e_suites()


@pytest.fixture(autouse=True)
def _close_test_event_loops(monkeypatch):
    """Close private event loops created by synchronous test adapters."""
    event_loops: list[asyncio.AbstractEventLoop] = []
    original_new_event_loop = asyncio.new_event_loop

    def tracked_new_event_loop():
        loop = original_new_event_loop()
        event_loops.append(loop)
        return loop

    monkeypatch.setattr(asyncio, "new_event_loop", tracked_new_event_loop)
    yield
    for loop in reversed(event_loops):
        if not loop.is_closed():
            loop.run_until_complete(loop.shutdown_asyncgens())
            loop.close()


@pytest.fixture(autouse=True)
async def _close_test_databases(monkeypatch, _close_test_event_loops):
    """Close async and raw SQLite connections before the test loop ends."""
    import aiosqlite

    from khaos.db import Database

    instances: list[Database] = []
    async_connections: list[aiosqlite.Connection] = []
    raw_connections: list[sqlite3.Connection] = []
    original_init = Database.__init__
    original_async_init = aiosqlite.Connection.__init__
    original_connect = sqlite3.connect

    def tracked_init(self, *args, **kwargs):
        original_init(self, *args, **kwargs)
        instances.append(self)

    def tracked_connect(*args, **kwargs):
        # Worker-thread tests intentionally pass connections across thread
        # boundaries.  Keep that explicit test behavior cleanup-safe too.
        kwargs.setdefault("check_same_thread", False)
        connection = original_connect(*args, **kwargs)
        raw_connections.append(connection)
        return connection

    def tracked_async_init(self, *args, **kwargs):
        original_async_init(self, *args, **kwargs)
        async_connections.append(self)

    monkeypatch.setattr(Database, "__init__", tracked_init)
    # Patch the constructor rather than only ``aiosqlite.connect``: callers
    # may retain a previously imported alias to the factory, which otherwise
    # escapes per-test cleanup and is only reported by Python 3.13 much later.
    monkeypatch.setattr(aiosqlite.Connection, "__init__", tracked_async_init)
    monkeypatch.setattr(sqlite3, "connect", tracked_connect)
    yield
    for database in reversed(instances):
        await database.close()
    for connection in reversed(async_connections):
        if connection._connection is not None:
            await connection.close()
    for connection in reversed(raw_connections):
        connection.close()
