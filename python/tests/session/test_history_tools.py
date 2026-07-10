"""Tests for history tool definitions."""

from __future__ import annotations

from khaos.tools.history_tools import HISTORY_TOOLS
from khaos.tools.registry import create_runtime_registry


def test_history_tools_definitions() -> None:
    names = {spec["name"] for spec in HISTORY_TOOLS}
    assert names == {"history_search", "history_browse", "history_read"}

    registry = create_runtime_registry()
    for name in names:
        tool = registry.get(name)
        assert tool.handler is not None, f"{name} has no handler"
