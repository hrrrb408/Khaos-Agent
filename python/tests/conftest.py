"""Shared test fixtures."""
from __future__ import annotations

import asyncio
import os
import secrets
import shutil
import sqlite3
import subprocess
import sys
import time

import pytest
from khaos.coding.execution.docker import DEFAULT_DOCKER_IMAGE

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
os.environ.setdefault("KHAOS_DEV_MODE", "1")
# Batch 7.4 (round-7 §十二): browser tools fail-closed when Playwright is
# missing (production never silently mocks).  Tests opt into the mock
# fallback so a bare ``pip install -e .[test]`` checkout without
# Playwright can still exercise the browser-tool logic paths.
os.environ.setdefault("KHAOS_BROWSER_MOCK_MODE", "1")

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
            if cache_root and os.path.isdir(cache_root) and any(
                name.startswith("chromium-") for name in os.listdir(cache_root)
            ):
                os.environ["KHAOS_RUN_BROWSER_E2E"] = "1"
        except (ImportError, OSError, RuntimeError):
            pass

    # Production sandbox E2E: needs both the Docker daemon and the exact
    # pinned image.  A daemon alone is not enough: the production backend
    # deliberately never pulls a missing image.
    if (
        os.environ.get("KHAOS_RUN_PRODUCTION_SANDBOX") is None
        and shutil.which("docker")
    ):
        try:
            daemon = subprocess.run(
                ["docker", "info"],
                capture_output=True,
                timeout=5,
                check=False,
            )
            image = subprocess.run(
                ["docker", "image", "inspect", DEFAULT_DOCKER_IMAGE],
                capture_output=True,
                timeout=5,
                check=False,
            )
            if daemon.returncode == 0 and image.returncode == 0:
                os.environ["KHAOS_RUN_PRODUCTION_SANDBOX"] = "1"
        except (OSError, subprocess.SubprocessError):
            pass


_auto_enable_e2e_suites()


_DOCKER_IMAGE_ANCHOR: str | None = None
_DOCKER_EXECUTABLE: str | None = None


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    """Skip opt-in Docker tests when auto-capability detection found no image."""
    _ = config
    if os.environ.get("KHAOS_RUN_PRODUCTION_SANDBOX") == "1":
        return
    reason = (
        "Docker production E2E is disabled because the daemon and pinned image "
        "were not both available at test collection"
    )
    skip = pytest.mark.skip(reason=reason)
    for item in items:
        if (
            item.get_closest_marker("docker_sandbox_real")
            or item.get_closest_marker("production_sandbox_real")
        ):
            item.add_marker(skip)


def _docker_command(*args: str) -> subprocess.CompletedProcess[bytes] | None:
    """Run one bounded Docker CLI query for test capability management."""
    docker = _DOCKER_EXECUTABLE or shutil.which("docker")
    if docker is None:
        return None
    try:
        return subprocess.run(
            [docker, *args],
            capture_output=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None


def _docker_image_present() -> bool:
    """Return whether the exact production image is locally inspectable."""
    for attempt in range(10):
        result = _docker_command("image", "inspect", DEFAULT_DOCKER_IMAGE)
        if result is not None and result.returncode == 0:
            return True
        if attempt < 9:
            time.sleep(0.25)
    return False


def _prepare_docker_image_anchor() -> None:
    """Keep Docker Desktop's digest-only image alive for the test session.

    Docker Desktop can expire a digest-only image reference while retaining
    the mutable repository tag.  A session-owned running container anchors
    the exact image without mounting the workspace, changing the production
    digest, or pulling anything automatically.
    """
    global _DOCKER_IMAGE_ANCHOR
    anchor = (
        "khaos-test-image-anchor-"
        f"{os.getpid()}-{secrets.token_hex(4)}"
    )
    tagged = _docker_command(
        "run", "--detach", "--rm", "--pull=never", "--name", anchor,
        DEFAULT_DOCKER_IMAGE, "python", "-c", "import time; time.sleep(7200)",
    )
    if tagged is None or tagged.returncode != 0:
        pytest.exit(
            "could not create the test-owned Docker image anchor; "
            "the pinned image remains required and no pull was attempted",
            returncode=2,
        )
    _DOCKER_IMAGE_ANCHOR = anchor
    if not _docker_image_present():
        pytest.exit(
            "pinned Docker image became unavailable while preparing its test anchor",
            returncode=2,
        )


def pytest_sessionstart(session: pytest.Session) -> None:
    """Validate Docker authority and stabilize the pinned test image."""
    _ = session
    global _DOCKER_EXECUTABLE
    if os.environ.get("KHAOS_RUN_PRODUCTION_SANDBOX") != "1":
        return
    _DOCKER_EXECUTABLE = shutil.which("docker")
    if _DOCKER_EXECUTABLE is None:
        pytest.exit(
            "KHAOS_RUN_PRODUCTION_SANDBOX=1 requires the Docker CLI",
            returncode=2,
        )
    if not _docker_image_present():
        pytest.exit(
            "KHAOS_RUN_PRODUCTION_SANDBOX=1 requires the pinned Docker image "
            "to be preloaded; automatic pull is disabled",
            returncode=2,
        )
    daemon = _docker_command("info", "--format", "{{.ID}}")
    if daemon is None or daemon.returncode != 0:
        pytest.exit(
            "KHAOS_RUN_PRODUCTION_SANDBOX=1 requires an inspectable Docker daemon",
            returncode=2,
        )
    _prepare_docker_image_anchor()


def pytest_runtest_setup(item: pytest.Item) -> None:
    """Fail closed if a real Docker test loses its preloaded authority."""
    if not (
        item.get_closest_marker("docker_sandbox_real")
        or item.get_closest_marker("production_sandbox_real")
    ):
        return
    image_present = _docker_image_present()
    if not image_present:
        pytest.exit(
            "the preloaded pinned Docker image disappeared during "
            f"the test session; automatic pull is disabled "
            f"(docker={_DOCKER_EXECUTABLE!r}, image_present={image_present})",
            returncode=2,
        )


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    """Remove only the running image anchor owned by this test session."""
    _ = (session, exitstatus)
    if _DOCKER_IMAGE_ANCHOR is None:
        return
    _docker_command("rm", "--force", _DOCKER_IMAGE_ANCHOR)


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
