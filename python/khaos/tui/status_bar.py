"""Bottom status bar widget."""

from __future__ import annotations

from textual.containers import Horizontal
from textual.widgets import Static


class StatusBar(Horizontal):
    """Shows current mode, model, session id and live token count."""

    DEFAULT_CSS = """
    StatusBar {
        dock: bottom;
        height: 1;
        background: $boost;
        color: $text-muted;
    }
    StatusBar Static {
        padding: 0 2;
        width: 1fr;
    }
    """

    def __init__(self) -> None:
        super().__init__()
        self._mode = Static("office", id="sb-mode")
        self._model = Static("mock", id="sb-model")
        self._session = Static("(no session)", id="sb-session")
        self._tokens = Static("0 tok", id="sb-tokens")

    def compose(self):  # type: ignore[override]
        yield self._mode
        yield self._model
        yield self._session
        yield self._tokens

    def set_mode(self, mode: str) -> None:
        self._mode.update(f"◎ {mode}")

    def set_model(self, model: str) -> None:
        self._model.update(f"🤖 {model}")

    def set_session(self, session_id: str) -> None:
        self._session.update(f"🔗 {session_id}")

    def set_tokens(self, total: int) -> None:
        self._tokens.update(f"🯸 {total} tok")
