"""Mockable browser control tools for office mode."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class BrowserState:
    url: str = "about:blank"
    typed: dict[str, str] = field(default_factory=dict)
    clicks: list[str] = field(default_factory=list)


_STATE = BrowserState()


async def browser_navigate(url: str) -> dict[str, Any]:
    """Navigate the mock browser to a URL."""
    _STATE.url = url
    return {"url": _STATE.url, "ok": True}


async def browser_click(selector: str) -> dict[str, Any]:
    """Record a click against a selector."""
    _STATE.clicks.append(selector)
    return {"selector": selector, "ok": True}


async def browser_type(selector: str, text: str) -> dict[str, Any]:
    """Record typed text against a selector."""
    _STATE.typed[selector] = text
    return {"selector": selector, "text": text, "ok": True}


async def browser_snapshot() -> dict[str, Any]:
    """Return the current mock browser state."""
    return {"url": _STATE.url, "typed": dict(_STATE.typed), "clicks": list(_STATE.clicks)}


async def browser_vision() -> dict[str, Any]:
    """Return a simple visual summary placeholder."""
    return {"url": _STATE.url, "description": f"Mock browser view for {_STATE.url}"}


def reset_browser_state() -> None:
    """Reset browser state for tests."""
    _STATE.url = "about:blank"
    _STATE.typed.clear()
    _STATE.clicks.clear()

