"""Smoke test: the Textual app constructs cleanly and wires its runtime.

Driving a full interactive pilot against a live aiosqlite database is flaky in
CI/headless environments (the db worker thread outlives the textual event loop).
Instead we verify the app imports, constructs, and exposes the expected
widgets/runtime — which is what catches composition regressions. Live TUI
behavior is validated manually via ``make dev``.
"""

from __future__ import annotations

import pytest

try:
    import textual  # noqa: F401

    _TEXTUAL_AVAILABLE = True
except ImportError:
    _TEXTUAL_AVAILABLE = False

pytestmark = pytest.mark.skipif(not _TEXTUAL_AVAILABLE, reason="textual not installed")


def test_app_constructs_with_runtime(tmp_path):
    from khaos.tui.app import KhaosApp

    app = KhaosApp(db_path=str(tmp_path / "khaos.db"), project_root=tmp_path)

    # Construction wires the runtime handles without needing a live DB.
    assert app.session_id  # a uuid was generated
    assert app.router is None
    assert app.skill_manager is not None
    # The default mode reflects the override-free state.
    assert app._mode_label() == "office"


def test_app_build_context_is_well_formed(tmp_path):
    """The context handed to command dispatch carries every handle."""
    from khaos.tui.app import KhaosApp

    app = KhaosApp(db_path=str(tmp_path / "khaos.db"), project_root=tmp_path)
    # Pre-bootstrap: most handles are still None; that's fine, the context
    # tolerates it. After bootstrap they would be populated.
    ctx = app._build_context()

    assert ctx.session_id == app.session_id
    assert ctx.skill_manager is app.skill_manager
    # on_quit is wired to app.exit.
    assert ctx.on_quit is not None


def test_app_help_text_advertises_all_commands():
    from khaos.tui.commands import HELP_TEXT

    for cmd in ["/mode", "/skills", "/memory", "/tools", "/model", "/session", "/help", "/clear", "/quit"]:
        assert cmd in HELP_TEXT


@pytest.mark.asyncio
async def test_app_token_header_accumulates_session_total(tmp_path, monkeypatch):
    from khaos.tui.app import HeaderBar, KhaosApp
    from khaos.tui.chat_panel import ChatPanel
    from khaos.tui.status_bar import StatusBar

    app = KhaosApp(db_path=str(tmp_path / "khaos.db"), project_root=tmp_path)
    chat = _FakeChat()
    status = _FakeStatusBar()
    header = _FakeHeaderBar()
    app.agent_loop = _FakeAgentLoop([31, 116])

    def query_one(widget_type):
        if widget_type is ChatPanel:
            return chat
        if widget_type is StatusBar:
            return status
        if widget_type is HeaderBar:
            return header
        raise AssertionError(f"unexpected widget lookup: {widget_type!r}")

    monkeypatch.setattr(app, "query_one", query_one)

    await app._run_turn_impl("hello")
    await app._run_turn_impl("introduce yourself")

    assert app._total_tokens == 147
    assert status.tokens == 147
    assert header.tokens == 147
    assert [message.token_count for message in chat.messages] == [31, 116]


class _FakeAgentLoop:
    def __init__(self, token_counts: list[int]) -> None:
        self._token_counts = token_counts

    async def run(self, _user_input: str, _session_id: str):
        from khaos.agent.core import Message

        token_count = self._token_counts.pop(0)
        yield Message(role="system", content="done", token_count=token_count)


class _FakeChat:
    def __init__(self) -> None:
        self.messages = []
        self.errors = []

    def append_message(self, message) -> None:
        self.messages.append(message)

    def append_error(self, text: str) -> None:
        self.errors.append(text)


class _FakeStatusBar:
    def __init__(self) -> None:
        self.tokens = 0

    def set_mode(self, _mode: str) -> None:
        pass

    def set_session(self, _session_id: str) -> None:
        pass

    def set_tokens(self, total: int) -> None:
        self.tokens = total

    def set_model(self, _model: str) -> None:
        pass


class _FakeHeaderBar:
    def __init__(self) -> None:
        self.tokens = 0

    def set_state(self, _mode: str, _model: str, _session_id: str, tokens: int) -> None:
        self.tokens = tokens
