"""Input area with slash-command support and multi-line entry."""

from __future__ import annotations

from textual import events
from textual.message import Message as TextualMessage
from textual.widgets import Input


class InputPanel(Input):
    """Single-line Input that emits a Submitted message on Enter.

    Textual's own Input already supports multi-line paste; explicit Shift+Enter
    newline insertion is not generally possible in a single-line widget, so the
    app offers a separate multi-line toggle. The widget focuses on slash-command
    highlighting and emitting the user's text to the app.
    """

    DEFAULT_CSS = """
    InputPanel {
        dock: bottom;
        margin: 1 0 0 0;
        border: round $accent;
    }
    InputPanel:focus {
        border: round $accent-lighten-2;
    }
    """

    class Submitted(TextualMessage):
        """Posted when the user submits input."""

        def __init__(self, value: str) -> None:
            self.value = value
            super().__init__()

    def __init__(self) -> None:
        super().__init__(placeholder="Message Khaos…  (/help for commands)", id="input")

    def _on_key(self, event: events.Key) -> None:  # type: ignore[override]
        # Enter submits; let Input handle everything else.
        if event.key == "enter":
            value = self.value
            if value.strip():
                self.post_message(self.Submitted(value))
                self.value = ""
            event.prevent_default()
            event.stop()
