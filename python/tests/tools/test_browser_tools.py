from khaos.tools.browser_tools import (
    browser_click,
    browser_navigate,
    browser_snapshot,
    browser_type,
    browser_vision,
    reset_browser_state,
)
from khaos.tools.registry import create_runtime_registry


async def test_browser_navigate_snapshot_and_vision():
    reset_browser_state()

    await browser_navigate("https://example.com")
    snapshot = await browser_snapshot()
    vision = await browser_vision()

    assert snapshot["url"] == "https://example.com"
    assert "example.com" in vision["description"]


async def test_browser_click_and_type():
    reset_browser_state()

    await browser_click("#submit")
    await browser_type("#q", "khaos")
    snapshot = await browser_snapshot()

    assert snapshot["clicks"] == ["#submit"]
    assert snapshot["typed"]["#q"] == "khaos"


def test_runtime_registry_binds_browser_tools_to_office():
    registry = create_runtime_registry()

    assert registry.get("browser_navigate").handler is not None
    assert "office" in registry.get("browser_navigate").modes
    assert registry.get("browser_snapshot").permission_level == "read"

