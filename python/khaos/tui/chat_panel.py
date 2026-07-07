"""Scrolling chat log that renders agent messages."""

from __future__ import annotations

from rich.text import Text
from textual.widgets import RichLog

from khaos.agent.core import Message
from khaos.tui.markdown import markdown_to_rich, render_message, to_rich


class ChatPanel(RichLog):
    """A RichLog that renders Khaos messages with streaming support."""

    DEFAULT_CSS = """
    ChatPanel {
        border: round $accent;
        padding: 0 1;
        margin: 0 0 0 0;
    }
    """

    def __init__(self) -> None:
        super().__init__(wrap=True, auto_scroll=True)
        self._code_block_buffer: list[str] = []
        self._inside_code_block: bool = False

    def append_message(self, message: Message) -> None:
        """Render one agent message into the log.

        For assistant text chunks, we stream character-by-character to give
        a typing effect.  When inside a fenced code block (```) we buffer
        until the closing fence so that syntax highlighting works correctly.
        """
        if message.event is None and message.role == "assistant" and message.content:
            self._stream_chunk(message.content)
            return

        # Non-text message (tool/error/done) — flush any pending code block first
        self.flush_code_block()
        rendered = render_message(message)
        if message.event is None and message.role == "user" and message.content:
            self.write(markdown_to_rich(message.content))
        else:
            self.write(to_rich(rendered))

    def _stream_chunk(self, chunk: str) -> None:
        """Stream a text chunk, buffering inside code blocks for correct rendering."""
        if not self._inside_code_block:
            # Check if this chunk starts a code block
            if "```" in chunk:
                parts = chunk.split("```", 2)
                # Write text before the code fence
                if parts[0]:
                    self.write(Text(parts[0]))
                # Start buffering the code block (include language tag)
                self._inside_code_block = True
                self._code_block_buffer = ["```\n"]
                if len(parts) > 1:
                    self._code_block_buffer.append(parts[1])
                # If there's a closing fence in the same chunk, handle it
                if len(parts) > 2:
                    self._code_block_buffer.append("```")
                    self._code_block_buffer.append(parts[2])
                    if "```" not in parts[2]:
                        # Properly closed, flush immediately
                        self._inside_code_block = False
                        self.flush_code_block()
                return

            # Normal text — stream directly as plain text (fast)
            self.write(Text(chunk))
            return

        # Inside a code block — accumulate
        self._code_block_buffer.append(chunk)
        if "```" in chunk:
            # Count fences to handle nested/escaped backticks
            fence_count = self._whole_buffer().count("```")
            if fence_count >= 2:
                self._inside_code_block = False
                self.flush_code_block()

    def _whole_buffer(self) -> str:
        return "".join(self._code_block_buffer)

    def flush_code_block(self) -> None:
        """Flush any buffered code block as a single Markdown renderable."""
        if not self._code_block_buffer:
            return
        text = self._whole_buffer()
        self._code_block_buffer.clear()
        self._inside_code_block = False
        if text.strip():
            self.write(markdown_to_rich(text))

    def append_text(self, text: str, *, markdown: bool = False) -> None:
        """Append a free-form string (used for command echoes)."""
        self.flush_code_block()
        if markdown:
            self.write(markdown_to_rich(text))
        else:
            self.write(Text.from_markup(text))

    def append_error(self, text: str) -> None:
        self.flush_code_block()
        self.write(Text(text, style="bold red"))

    def clear_chat(self) -> None:
        """Clear all chat content and reset buffers."""
        self._code_block_buffer.clear()
        self._inside_code_block = False
