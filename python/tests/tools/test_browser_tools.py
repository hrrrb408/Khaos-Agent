"""Tests for Playwright-backed browser tools (mock fallback path).

The CI environment does not ship Playwright / browser binaries, so these
tests exercise the mock fallback path exclusively. We pin ``_HAS_PLAYWRIGHT``
to ``False`` to guarantee deterministic behaviour regardless of whether the
host happens to have Playwright installed.
"""

from __future__ import annotations

import json

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
    assert result == {"ok": True, "selector": "input[type=file]", "file": str(f)}


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
