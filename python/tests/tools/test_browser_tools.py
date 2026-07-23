"""Tests for Playwright-backed browser tools (mock fallback path).

The CI environment does not ship Playwright / browser binaries, so these
tests exercise the mock fallback path exclusively. We pin ``_HAS_PLAYWRIGHT``
to ``False`` to guarantee deterministic behaviour regardless of whether the
host happens to have Playwright installed.
"""

from __future__ import annotations

import asyncio
import json
import os

import pytest

from khaos.tools import browser_tools
from khaos.tools.browser_tools import (
    BrowserManager,
    browser_click,
    browser_close,
    browser_evaluate,
    browser_file_upload,
    browser_launch,
    browser_navigate,
    browser_screenshot,
    browser_scroll,
    browser_snapshot,
    browser_type,
    browser_vision,
    reset_browser_state,
)
from khaos.tools.registry import create_runtime_registry


# ---------------------------------------------------------------------------
# Fixtures: force the mock fallback path for every test in this module.
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def force_mock_fallback(monkeypatch):
    """Pin ``_HAS_PLAYWRIGHT = False`` so all tools take the mock branch."""
    monkeypatch.setattr(browser_tools, "_HAS_PLAYWRIGHT", False)
    # The global manager caches nothing between tests, but reset state anyway.
    reset_browser_state()
    yield
    reset_browser_state()


# ---------------------------------------------------------------------------
# Mock fallback sanity
# ---------------------------------------------------------------------------


async def test_browser_navigate_updates_mock_url():
    result = await browser_navigate("https://example.com")
    assert result == {"ok": True, "url": "https://example.com"}
    # Subsequent snapshot reflects the navigate.
    snapshot = await browser_snapshot()
    assert snapshot["url"] == "https://example.com"


async def test_browser_click_records_click():
    result = await browser_click("#submit")
    assert result == {"ok": True, "selector": "#submit"}
    snapshot = await browser_snapshot()
    assert snapshot["clicks"] == ["#submit"]


async def test_browser_click_records_multiple_in_order():
    await browser_click("#a")
    await browser_click("#b")
    snapshot = await browser_snapshot()
    assert snapshot["clicks"] == ["#a", "#b"]


async def test_browser_type_records_typed_text():
    result = await browser_type("#q", "khaos")
    assert result == {"ok": True, "selector": "#q", "text": "khaos"}
    snapshot = await browser_snapshot()
    assert snapshot["typed"] == {"#q": "khaos"}


async def test_browser_type_with_press_enter_still_records_text():
    # Mock path ignores press_enter but still records the typed text.
    result = await browser_type("#q", "query", press_enter=True)
    assert result["ok"] is True
    assert result["text"] == "query"


async def test_browser_snapshot_returns_full_mock_state():
    await browser_navigate("https://khaos.dev")
    await browser_click(".nav")
    await browser_type("input", "hi")
    snapshot = await browser_snapshot()
    assert snapshot["ok"] is True
    assert snapshot["url"] == "https://khaos.dev"
    assert snapshot["clicks"] == [".nav"]
    assert snapshot["typed"] == {"input": "hi"}


async def test_browser_vision_returns_mock_description():
    await browser_navigate("https://khaos.dev")
    vision = await browser_vision()
    assert vision["ok"] is True
    assert vision["url"] == "https://khaos.dev"
    assert "https://khaos.dev" in vision["description"]


async def test_browser_evaluate_unavailable_in_mock_mode():
    result = await browser_evaluate("1 + 1")
    assert result["ok"] is False
    assert "not available" in result["error"].lower()


async def test_browser_evaluate_blocks_network_apis_even_before_mock_check():
    """The network-API guard runs before the mock fallback, so it always wins."""
    for expr in ["fetch('/x')", "new XMLHttpRequest()", "new WebSocket('wss://x')"]:
        result = await browser_evaluate(expr)
        assert result["ok"] is False
        assert "blocked" in result["error"].lower()


async def test_browser_screenshot_unavailable_in_mock_mode():
    result = await browser_screenshot()
    assert result["ok"] is False
    assert "not available" in result["error"].lower()


async def test_browser_scroll_returns_confirmation():
    result = await browser_scroll(direction="down", amount=5)
    assert result == {"ok": True, "direction": "down", "amount": 5}


async def test_browser_scroll_defaults():
    result = await browser_scroll(direction="up")
    assert result["amount"] == 3
    assert result["direction"] == "up"


async def test_browser_file_upload_records_in_mock(tmp_path):
    """B1: ``browser_file_upload`` requires ``network_policy`` and a
    ``workspace_root`` for path containment validation.  The handler
    rejects when network is not authorised (defense in depth on top of
    the capability broker) and when the file is outside the workspace
    root (no arbitrary host file exfiltration).
    """
    workspace = tmp_path / "ws"
    workspace.mkdir()
    f = workspace / "upload.txt"
    f.write_text("hello", encoding="utf-8")
    # Must pass network_policy + workspace_root to reach the mock upload path.
    result = await browser_file_upload(
        "input[type=file]",
        str(f),
        workspace_root=str(workspace),
        network_policy="unrestricted-with-approval",
    )
    if hasattr(os, "O_NOFOLLOW"):
        assert result == {
            "ok": True,
            "selector": "input[type=file]",
            "file": str(f),
        }
    else:
        assert result["ok"] is False
        assert "no-follow" in result["error"]


# ---------------------------------------------------------------------------
# BrowserManager
# ---------------------------------------------------------------------------


async def test_browser_manager_launch_returns_error_without_playwright(monkeypatch):
    monkeypatch.setattr(browser_tools, "_HAS_PLAYWRIGHT", False)
    manager = BrowserManager()
    result = await manager.launch()
    assert result["ok"] is False
    assert "playwright not installed" in result["error"]
    assert manager.is_ready is False


async def test_browser_manager_is_ready_false_by_default():
    manager = BrowserManager()
    assert manager.is_ready is False


async def test_browser_manager_current_url_falls_back_to_mock():
    reset_browser_state()
    manager = BrowserManager()
    # No page → current_url reads the shared mock state.
    assert manager.current_url == "about:blank"
    # Tools mutate the shared _MOCK_STATE via the module-level manager, so a
    # separate BrowserManager instance observes the change through the fallback.
    await browser_navigate("https://changed.test")
    assert manager.current_url == "https://changed.test"
    assert browser_tools._MOCK_STATE.url == "https://changed.test"


async def test_browser_manager_close_is_idempotent():
    manager = BrowserManager()
    result = await manager.close()
    assert result["ok"] is True


async def test_browser_manager_ensure_page_returns_none_without_playwright(monkeypatch):
    monkeypatch.setattr(browser_tools, "_HAS_PLAYWRIGHT", False)
    manager = BrowserManager()
    page = await manager.ensure_page()
    assert page is None


async def test_browser_manager_concurrent_first_use_creates_one_context(monkeypatch):
    """M2: concurrent first use of one key must coalesce under its lock."""
    monkeypatch.setattr(browser_tools, "_HAS_PLAYWRIGHT", True)

    class FakePage:
        url = "about:blank"

        def set_default_timeout(self, timeout):
            self.timeout = timeout

    class FakeContext:
        def __init__(self):
            self.page = FakePage()

        async def new_page(self):
            await asyncio.sleep(0)
            return self.page

        async def close(self):
            return None

    class FakeBrowser:
        def __init__(self):
            self.calls = 0
            self.context = FakeContext()

        async def new_context(self, **kwargs):
            self.calls += 1
            await asyncio.sleep(0)
            return self.context

        async def close(self):
            return None

    manager = BrowserManager()
    manager._browser = FakeBrowser()

    first, second = await asyncio.gather(
        manager.ensure_page("p", session_id="s", runtime_id="r"),
        manager.ensure_page("p", session_id="s", runtime_id="r"),
    )

    assert first is second
    assert manager._browser.calls == 1
    assert len(manager._contexts) == 1
    await manager.close()


async def test_context_close_failure_retains_owner_for_retry():
    """H4: a failed ctx.close cannot delete the lifecycle owner."""
    class FailingContext:
        async def close(self):
            raise RuntimeError("context still running")

    manager = BrowserManager()
    key = manager._context_key("p", "s", "r")
    manager._contexts[key] = {
        "context": FailingContext(), "page": object(), "refcount": 1,
        "_runtime_owners": {"r"},
    }

    with pytest.raises(RuntimeError, match="still running"):
        await manager.close_runtime("r")
    assert key in manager._contexts
    assert "r" in manager._contexts[key]["_runtime_owners"]


async def test_repeated_context_close_failure_forces_browser_generation_closed():
    """H4: the third Context failure may terminate the owning Browser."""
    class FailingContext:
        async def close(self):
            raise RuntimeError("context still running")

    class Browser:
        def __init__(self):
            self.closed = 0

        async def close(self):
            self.closed += 1

    manager = BrowserManager()
    browser = Browser()
    manager._browser = browser
    key = manager._context_key("p", "s", "r")
    manager._contexts[key] = {
        "context": FailingContext(), "page": object(), "refcount": 1,
        "_runtime_owners": {"r"},
    }

    for _ in range(2):
        with pytest.raises(RuntimeError, match="still running"):
            await manager.close_runtime("r")
    result = await manager.close_runtime("r")
    assert result["forced_browser_close"] is True
    assert browser.closed == 1
    assert not manager._contexts


async def test_context_lifecycle_has_no_unbounded_per_key_lock_table():
    """M2: completed Context keys must not accumulate lock objects."""
    manager = BrowserManager()
    assert not hasattr(manager, "_context_locks")


async def test_browser_manager_concurrent_launch_starts_one_browser(monkeypatch):
    """M2: the lifecycle lock turns concurrent launch into one launch task."""
    monkeypatch.setattr(browser_tools, "_HAS_PLAYWRIGHT", True)

    class FakeBrowser:
        async def close(self):
            return None

    class FakeChromium:
        def __init__(self):
            self.calls = 0
            self.browser = FakeBrowser()

        async def launch(self, *, headless, **kwargs):
            self.calls += 1
            await asyncio.sleep(0)
            return self.browser

    class FakePlaywright:
        def __init__(self):
            self.chromium = FakeChromium()

    fake_playwright = FakePlaywright()

    class FakeStarter:
        async def start(self):
            await asyncio.sleep(0)
            return fake_playwright

    monkeypatch.setattr(browser_tools, "async_playwright", lambda: FakeStarter())
    manager = BrowserManager()

    first, second = await asyncio.gather(manager.launch(), manager.launch())

    assert first["ok"] and second["ok"]
    assert fake_playwright.chromium.calls == 1


@pytest.mark.skipif(not hasattr(os, "O_NOFOLLOW"), reason="requires POSIX no-follow")
def test_upload_dirfd_chain_rejects_nested_parent_symlink(tmp_path):
    """M1: every parent below the fixed Workspace root is no-follow."""
    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside"
    workspace.mkdir()
    outside.mkdir()
    (outside / "secret.txt").write_text("host-secret", encoding="utf-8")
    (workspace / "bundle").symlink_to(outside, target_is_directory=True)

    result = browser_tools._read_upload_bytes(
        str(workspace / "bundle" / "secret.txt"), str(workspace)
    )

    assert isinstance(result, dict)
    assert result["ok"] is False
    assert "secure workspace-relative open failed" in result["error"]


# ---------------------------------------------------------------------------
# reset_browser_state
# ---------------------------------------------------------------------------


async def test_reset_browser_state_clears_all_fields():
    # Seed some state via the mock fallback path.
    await browser_navigate("https://x.test")
    await browser_click("#a")
    await browser_type("#q", "v")
    await browser_file_upload("input", "/p")

    reset_browser_state()
    state = browser_tools._MOCK_STATE
    assert state.url == "about:blank"
    assert state.typed == {}
    assert state.clicks == []
    assert state.uploaded == []


# ---------------------------------------------------------------------------
# Every tool returns a dict (the scheduler JSON-encodes it)
# ---------------------------------------------------------------------------


async def test_all_tools_return_dict():
    results = [
        await browser_launch(),
        await browser_close(),
        await browser_navigate("https://x.test"),
        await browser_click("#a"),
        await browser_type("#a", "t"),
        await browser_snapshot(),
        await browser_screenshot(),
        await browser_scroll(direction="down"),
        await browser_vision(),
        await browser_evaluate("1+1"),
        await browser_file_upload("#f", "/p"),
    ]
    for result in results:
        assert isinstance(result, dict)
        # Every result must be JSON-serialisable (scheduler json.dumps it).
        json.dumps(result)


# ---------------------------------------------------------------------------
# Registry wiring
# ---------------------------------------------------------------------------


def test_runtime_registry_binds_all_browser_tools_to_both_modes():
    registry = create_runtime_registry()
    expected = {
        "browser_launch",
        "browser_close",
        "browser_navigate",
        "browser_click",
        "browser_type",
        "browser_snapshot",
        "browser_screenshot",
        "browser_scroll",
        "browser_vision",
        "browser_evaluate",
        "browser_file_upload",
    }
    for name in expected:
        tool = registry.get(name)
        assert tool.handler is not None, f"{name} has no handler"
        assert "office" in tool.modes, f"{name} missing office mode"
        assert "coding" in tool.modes, f"{name} missing coding mode"


def test_runtime_registry_browser_permission_levels():
    registry = create_runtime_registry()
    read_tools = {
        "browser_launch",
        "browser_close",
        "browser_navigate",
        "browser_click",
        "browser_snapshot",
        "browser_screenshot",
        "browser_scroll",
        "browser_vision",
    }
    write_tools = {"browser_type", "browser_evaluate", "browser_file_upload"}
    for name in read_tools:
        assert registry.get(name).permission_level == "read", name
    for name in write_tools:
        assert registry.get(name).permission_level == "write", name


def test_browser_screenshot_has_no_filesystem_write_argument():
    """M3: screenshot is read-only because it can only return base64."""
    tool = create_runtime_registry().get("browser_screenshot")
    assert tool.permission_level == "read"
    assert "save_path" not in tool.parameters.get("properties", {})


# ---------------------------------------------------------------------------
# M1: upload hard-link inode escape
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "link"),
    reason="requires POSIX no-follow and hard-link support",
)
def test_upload_rejects_hardlink_to_outside_file(tmp_path):
    """M1: a Workspace file hard-linked to an outside secret must be rejected.

    The dirfd chain defeats symlinks and parent-replacement races, but a
    same-UID process can still ``link(~/.ssh/id_rsa, workspace/upload.txt)``.
    Every component is legitimate and the final inode is an owner-held
    regular file, so without an explicit link-count check we would read and
    upload the linked secret.  ``st_nlink != 1`` must fail the upload BEFORE
    any bytes leave the process.
    """
    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside"
    workspace.mkdir()
    outside.mkdir()
    secret = outside / "id_rsa"
    secret.write_text("HOST-PRIVATE-KEY", encoding="utf-8")
    upload = workspace / "upload.txt"
    os.link(str(secret), str(upload))

    result = browser_tools._read_upload_bytes(str(upload), str(workspace))

    assert isinstance(result, dict)
    assert result["ok"] is False
    assert "hard link" in result["error"]
    assert result["nlink"] == 2


# ---------------------------------------------------------------------------
# H1: BrowserManager.close() is a permanent terminal state
# ---------------------------------------------------------------------------


async def test_browser_manager_close_is_permanent():
    """H1: after ``close()`` the manager must never relaunch or serve a page.

    A detached subagent task whose cancellation races with server teardown
    must not be able to spin up a fresh Browser generation after the shared
    authority has been dismantled.
    """
    manager = BrowserManager()
    closed = await manager.close()
    assert closed["ok"] is True

    # launch() must refuse with an explicit closed-state error.
    launch_result = await manager.launch()
    assert launch_result["ok"] is False
    assert "permanently closed" in launch_result["error"]

    # ensure_page() must return None and surface the same reason.
    page = await manager.ensure_page("p1", session_id="s1", runtime_id="r1")
    assert page is None
    assert "permanently closed" in manager._last_ensure_error

    # A second close() is still idempotent.
    again = await manager.close()
    assert again["ok"] is True
