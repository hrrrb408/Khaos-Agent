"""Scrolling chat log that renders agent messages."""

from __future__ import annotations

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
        super().__init__(markup=True, wrap=True, auto_scroll=True)

    def append_message(self, message: Message) -> None:
        """Render one agent message into the log."""
        rendered = render_message(message)
        # Plain text content is rendered as Markdown for nice code blocks; meta
        # events (tool/permission/error/done) use the styled Rich text.
        if message.event is None and message.role in {"assistant", "user"} and message.content:
            self.write(markdown_to_rich(message.content))
        else:
            self.write(to_rich(rendered))

    def append_text(self, text: str, *, markdown: bool = False) -> None:
        """Append a free-form string (used for command echoes)."""
        if markdown:
            self.write(markdown_to_rich(text))
        else:
            self.write(text)

    def append_error(self, text: str) -> None:
        self.write(f"[bold red]{text}[/]")
