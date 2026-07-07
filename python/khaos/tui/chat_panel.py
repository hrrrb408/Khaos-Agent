"""Scrolling chat log that renders agent messages."""

from __future__ import annotations

from rich.text import Text
from textual.widgets import RichLog

from khaos.agent.core import Message
from khaos.tui.markdown import markdown_to_rich, render_message, to_rich


class ChatPanel(RichLog):
    """A RichLog that renders Khaos messages with styling."""

    DEFAULT_CSS = """
    ChatPanel {
        border: round $accent;
        padding: 0 1;
        margin: 0 0 0 0;
    }
    """

    def __init__(self) -> None:
        super().__init__(wrap=True, auto_scroll=True)
        self._assistant_markdown_buffer: list[str] = []

    def append_message(self, message: Message) -> None:
        """Render one agent message into the log."""
        if message.event is None and message.role == "assistant" and message.content:
            self._assistant_markdown_buffer.append(message.content)
            return
        self.flush_markdown()
        rendered = render_message(message)
        # Plain text content is rendered as Markdown for nice code blocks; meta
        # events (tool/permission/error/done) use the styled Rich text.
        if message.event is None and message.role == "user" and message.content:
            self.write(markdown_to_rich(message.content))
        else:
            self.write(to_rich(rendered))

    def append_text(self, text: str, *, markdown: bool = False) -> None:
        """Append a free-form string (used for command echoes)."""
        self.flush_markdown()
        if markdown:
            self.write(markdown_to_rich(text))
        else:
            self.write(Text.from_markup(text))

    def append_error(self, text: str) -> None:
        self.flush_markdown()
        self.write(Text(text, style="bold red"))

    def flush_markdown(self) -> None:
        """Write any buffered assistant stream as one Markdown renderable."""
        if not self._assistant_markdown_buffer:
            return
        text = "".join(self._assistant_markdown_buffer)
        self._assistant_markdown_buffer.clear()
        if text.strip():
            self.write(markdown_to_rich(text))
