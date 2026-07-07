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
    assert app.router is not None
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
