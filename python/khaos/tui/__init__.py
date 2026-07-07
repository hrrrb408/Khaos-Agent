"""Khaos Textual TUI (FR-015).

The full-screen interface lives under ``tui/``. Pure helpers (command dispatch
and message rendering) are importable without Textual so they can be unit
tested on minimal environments; the widgets import Textual lazily.
"""

from khaos.tui.commands import HELP_TEXT, CommandResult, TuiContext, handle_command, is_command
from khaos.tui.markdown import RenderedLine, render_message

__all__ = [
    "CommandResult",
    "HELP_TEXT",
    "RenderedLine",
    "TuiContext",
    "handle_command",
    "is_command",
    "render_message",
]
