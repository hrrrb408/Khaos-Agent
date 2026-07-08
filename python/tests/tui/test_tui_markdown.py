"""Tests for TUI message rendering (pure functions)."""

from __future__ import annotations

from io import StringIO
from pathlib import Path

from rich.console import Console
from rich.markdown import Markdown

from khaos.agent.core import Message
from khaos.tui.brand import brand_art
from khaos.tui.chat_panel import ChatPanel
from khaos.tui.markdown import RenderedLine, markdown_to_rich, render_message, to_rich


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


def test_renders_error_event_with_empty_message():
    msg = Message(
        role="system",
        content="",
        event="error",
        metadata={"code": "INTERNAL_ERROR", "message": "", "detail": {"type": "AssertionError"}},
    )

    line = render_message(msg)[0]

    assert line.style == "error"
    assert "INTERNAL_ERROR" in line.text
    assert "AssertionError" in line.text


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


def test_markdown_to_rich_renders_bold_list_chinese_and_emoji():
    sample = (
        "**自主编码** 的方式协助你：\n"
        "- 🚀 实现: 根据你的需求直接生成完整、可运行的代码。\n"
        "- 🧪 测试：自动编写测试用例并验证代码逻辑。"
    )

    renderable = markdown_to_rich(sample)
    output = _render_to_text(renderable)

    assert isinstance(renderable, Markdown)
    assert "**" not in output
    assert "自主编码" in output
    assert "🚀 实现" in output
    assert "🧪 测试" in output


def test_markdown_to_rich_renders_fenced_code_blocks():
    renderable = markdown_to_rich("```python\nprint('你好')\n```")
    output = _render_to_text(renderable)

    assert "print" in output
    assert "你好" in output
    assert "```" not in output


def test_chat_panel_buffers_streamed_assistant_markdown_until_done(monkeypatch):
    panel = ChatPanel()
    writes = []
    monkeypatch.setattr(ChatPanel.__mro__[1], "write", lambda _self, renderable: writes.append(renderable))
    monkeypatch.setattr(ChatPanel.__mro__[1], "clear", lambda _self: writes.append("CLEAR"))

    panel.append_message(Message(role="assistant", content="**自主"))
    panel.append_message(Message(role="assistant", content="编码**\n- 🚀 实现"))

    assert "CLEAR" in writes
    assert _render_to_text(panel._entries[0]).strip() == "● Khaos\n**自主编码**\n- 🚀 实现"

    panel.append_message(Message(role="system", content="done", event="done", stop_reason="end_turn"))

    output = _render_to_text(panel._entries[0])
    assert "Khaos" in output
    assert "**" not in output
    assert "自主编码" in output
    assert "🚀 实现" in output


def test_chat_panel_redraw_preserves_user_echo_when_stream_updates(monkeypatch):
    panel = ChatPanel()
    writes = []
    monkeypatch.setattr(ChatPanel.__mro__[1], "write", lambda _self, renderable: writes.append(renderable))
    monkeypatch.setattr(ChatPanel.__mro__[1], "clear", lambda _self: writes.append("CLEAR"))

    panel.append_user_echo("你好 [literal]")
    panel.append_message(Message(role="assistant", content="**Kha"))
    panel.append_message(Message(role="assistant", content="os**"))

    assert len(panel._entries) == 2
    assert "›" in _render_to_text(panel._entries[0])
    assert "[literal]" in _render_to_text(panel._entries[0])
    assert _render_to_text(panel._entries[1]).strip() == "● Khaos\n**Khaos**"


def test_chat_panel_welcome_dashboard_contains_runtime_context(monkeypatch):
    panel = ChatPanel()
    writes = []
    monkeypatch.setattr(ChatPanel.__mro__[1], "write", lambda _self, renderable: writes.append(renderable))

    panel.append_welcome_dashboard(
        mode="office",
        model="qwen/qwen3.5-122b-a10b",
        session_id="abcdef123456",
        project_root=Path("/tmp/khaos"),
    )

    output = _render_to_text(panel._entries[0])
    assert "Khaos Agent" in output
    assert "office" in output
    assert "qwen/qwen3.5-122b-a10b" in output
    assert "/tmp/khaos" in output


def test_brand_art_renders_image_mark_without_caption():
    output = _render_to_text(brand_art())

    assert len(output.strip()) > 100
    assert "FEIYUAN" not in output


def _render_to_text(renderable) -> str:
    buffer = StringIO()
    console = Console(file=buffer, force_terminal=True, color_system=None, width=100)
    console.print(renderable)
    return buffer.getvalue()
