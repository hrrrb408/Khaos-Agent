"""Tests for TUI message rendering (pure functions)."""

from __future__ import annotations

from khaos.agent.core import Message
from khaos.tui.markdown import RenderedLine, render_message, to_rich


def test_renders_assistant_text():
    msg = Message(role="assistant", content="hello world")

    lines = render_message(msg)

    assert len(lines) == 1
    assert lines[0].text == "hello world"
    assert lines[0].style == "assistant"


def test_renders_user_text():
    msg = Message(role="user", content="hi")

    lines = render_message(msg)

    assert lines[0].style == "user"


def test_renders_tool_call_with_argument_summary():
    msg = Message(
        role="assistant",
        content="",
        event="tool_call",
        metadata={"name": "read_file", "arguments": {"path": "/tmp/x"}},
    )

    line = render_message(msg)[0]

    assert line.style == "tool"
    assert "read_file" in line.text
    assert "path" in line.text


def test_renders_successful_tool_result():
    msg = Message(
        role="tool",
        content="",
        event="tool_result",
        metadata={"name": "read_file", "success": True, "output": "contents", "duration_ms": 5},
    )

    line = render_message(msg)[0]

    assert line.style == "tool"
    assert "✓" in line.text
    assert "read_file" in line.text
    assert "5ms" in line.text


def test_renders_failed_tool_result():
    msg = Message(
        role="tool",
        content="",
        event="tool_result",
        metadata={"name": "terminal", "success": False, "error": "boom", "duration_ms": 3},
    )

    line = render_message(msg)[0]

    assert line.style == "error"
    assert "✗" in line.text
    assert "boom" in line.text


def test_renders_permission_request():
    msg = Message(
        role="system",
        content="",
        event="permission_request",
        metadata={"name": "terminal", "target": "rm -rf /", "level": "execute", "reason": "danger"},
    )

    line = render_message(msg)[0]

    assert line.style == "system"
    assert "permission" in line.text
    assert "rm -rf /" in line.text


def test_renders_error_event():
    msg = Message(
        role="system",
        content="",
        event="error",
        metadata={"code": "MODEL_TIMEOUT", "message": "timed out"},
    )

    line = render_message(msg)[0]

    assert line.style == "error"
    assert "MODEL_TIMEOUT" in line.text
    assert "timed out" in line.text


def test_renders_done_event():
    msg = Message(role="system", content="done", token_count=42, stop_reason="end_turn")

    line = render_message(msg)[0]

    assert line.style == "system"
    assert "done" in line.text
    assert "42" in line.text


def test_truncates_long_tool_output():
    long_output = "x" * 1000
    msg = Message(
        role="tool",
        content="",
        event="tool_result",
        metadata={"name": "t", "success": True, "output": long_output, "duration_ms": 1},
    )

    line = render_message(msg)[0]

    assert "…" in line.text
    assert len(line.text) < 300  # truncated to a sane summary


def test_to_rich_returns_rich_text_when_available():
    lines = [RenderedLine(text="hello", style="assistant")]
    out = to_rich(lines)

    # If rich is installed (it is in our env), we get a rich.text.Text; otherwise
    # the plain string. Either way the content is present.
    rendered = str(out)
    assert "hello" in rendered
