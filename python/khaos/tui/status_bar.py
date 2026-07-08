"""Bottom status bar widget."""

from __future__ import annotations

from textual.widgets import Static


class StatusBar(Static):
    """Shows current mode, model, session id and live token count."""

    DEFAULT_CSS = """
    StatusBar {
        dock: bottom;
        height: 1;
        margin: 0 2 0 2;
        background: #0d0d0d;
        color: #a3a3a3;
        border-bottom: solid #d99021;
    }
    """

    def __init__(self) -> None:
        super().__init__("")
        self._mode = "office"
        self._model = "mock"
        self._session = "(no session)"
        self._tokens = 0

    def set_mode(self, mode: str) -> None:
        self._mode = mode
        self._render()

    def set_model(self, model: str) -> None:
        self._model = model
        self._render()

    def set_session(self, session_id: str) -> None:
        self._session = session_id[:8]
        self._render()

    def set_tokens(self, total: int) -> None:
        self._tokens = total
        self._render()

    def _render(self) -> None:
        self.update(
            f"$ {self._model} | mode {self._mode} | session {self._session} | {self._tokens} tok"
        )
