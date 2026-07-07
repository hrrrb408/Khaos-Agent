"""Message rendering helpers for the TUI.

These functions turn Khaos :class:`Message` objects into plain-text or Rich
renderables. Kept dependency-light (``rich`` is imported lazily so importing
this module never requires the TUI stack) and pure, so they are straightforward
to unit-test.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from khaos.agent.core import Message


@dataclass
class RenderedLine:
    """One line of TUI output with a style tag."""

    text: str
    style: str = ""  # e.g. "assistant", "tool", "error", "system"


def render_message(message: Message) -> list[RenderedLine]:
    """Convert one agent message into styled lines.

    Maps SSE event semantics:
    - text chunk (message event) -> assistant style, content verbatim
    - tool_call -> tool style, name + arguments summary
    - tool_result -> tool style, success/error + output summary
    - permission_request -> system style, prompting the user
    - error -> error style
    - done -> system style, summary
    """
    event = message.event or _infer_event(message)
    if event == "tool_call":
        return [_render_tool_call(message.metadata)]
    if event == "tool_result":
        return [_render_tool_result(message.metadata)]
    if event == "permission_request":
        return [_render_permission(message.metadata)]
    if event == "error":
        return [_render_error(message.metadata, message.content)]
    if event == "done":
        return [_render_done(message)]
    # plain assistant/user text
    style = "user" if message.role == "user" else "assistant"
    return [RenderedLine(text=message.content or "", style=style)]


def _infer_event(message: Message) -> str:
    if message.role == "system" and message.content == "done":
        return "done"
    if message.role == "system" and message.stop_reason == "error":
        return "error"
    if message.role == "tool":
        return "tool_result"
    return "message"


def _render_tool_call(meta: dict[str, Any]) -> RenderedLine:
    name = meta.get("name", "tool")
    args = meta.get("arguments", {})
    summary = _summarize_arguments(args)
    return RenderedLine(
        text=f"⚙ call {name}({summary})",
        style="tool",
    )


def _render_tool_result(meta: dict[str, Any]) -> RenderedLine:
    name = meta.get("name", "tool")
    success = meta.get("success", False)
    output = meta.get("output", "")
    error = meta.get("error", "")
    duration = meta.get("duration_ms", 0)
    if success:
        body = _truncate(str(output), 200)
        return RenderedLine(text=f"✓ {name} ({duration}ms): {body}", style="tool")
    return RenderedLine(
        text=f"✗ {name} failed ({duration}ms): {error or 'unknown error'}",
        style="error",
    )


def _render_permission(meta: dict[str, Any]) -> RenderedLine:
    name = meta.get("name", "tool")
    target = meta.get("target", "")
    level = meta.get("level", "")
    reason = meta.get("reason", "")
    text = f"⛔ permission requested: {name} [{level}] on {target}"
    if reason:
        text += f" — {reason}"
    return RenderedLine(text=text, style="system")


def _render_error(meta: dict[str, Any], fallback: str) -> RenderedLine:
    if meta:
        code = meta.get("code", "ERROR")
        msg = meta.get("message", "")
        return RenderedLine(text=f"✗ {code}: {msg}", style="error")
    return RenderedLine(text=fallback or "error", style="error")


def _render_done(message: Message) -> RenderedLine:
    tokens = message.token_count or message.metadata.get("total_tokens", 0)
    stop = message.stop_reason or message.metadata.get("stop_reason", "end_turn")
    return RenderedLine(text=f"✓ done ({tokens} tokens, {stop})", style="system")


def _summarize_arguments(args: Any, max_chars: int = 80) -> str:
    if isinstance(args, dict):
        parts = [f"{k}={_truncate(repr(v), 40)}" for k, v in args.items()]
        text = ", ".join(parts)
    else:
        text = str(args)
    return _truncate(text, max_chars)


def _truncate(text: str, limit: int) -> str:
    text = text.replace("\n", " ").strip()
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"


def to_rich(rendered: list[RenderedLine]):
    """Convert rendered lines into a Rich :class:`Text` (lazy import).

    Returns a :class:`rich.text.Text` with per-line styling. When ``rich`` is
    not installed, returns the plain concatenated string.
    """
    try:
        from rich.text import Text
    except ImportError:
        return "\n".join(line.text for line in rendered)

    text = Text()
    for line in rendered:
        text.append(line.text + "\n", style=_rich_style(line.style))
    return text


def markdown_to_rich(text: str):
    """Render a Markdown string via rich.markdown (lazy import)."""
    try:
        from rich.markdown import Markdown
    except ImportError:
        return text
    return Markdown(text)


_STYLE_MAP = {
    "user": "cyan",
    "assistant": "white",
    "tool": "yellow",
    "system": "dim",
    "error": "bold red",
}


def _rich_style(style: str) -> str:
    return _STYLE_MAP.get(style, "")


__all__ = [
    "RenderedLine",
    "render_message",
    "to_rich",
    "markdown_to_rich",
]
