"""Tests for ChatPanel diff rendering.

These exercise :func:`build_diff_renderable` directly (the pure formatter
backing :meth:`ChatPanel.append_diff`) by rendering it through an off-screen
Rich console and asserting the per-line colour styling.
"""

from __future__ import annotations

import io

import pytest
from rich.console import Console

try:
    import textual  # noqa: F401

    _TEXTUAL_AVAILABLE = True
except ImportError:
    _TEXTUAL_AVAILABLE = False

pytestmark = pytest.mark.skipif(not _TEXTUAL_AVAILABLE, reason="textual not installed")


DIFF_SAMPLE = """\
diff --git a/note.txt b/note.txt
index 1234567..89abcde 100644
--- a/note.txt
+++ b/note.txt
@@ -1,3 +1,4 @@
 context line
-removed line
+added line
 context line
"""


def _styled_lines(renderable) -> list[tuple[str, str]]:
    """Render ``renderable`` and fold segments into (line_text, style) pairs.

    The style for each line is the last non-empty segment style on that line —
    which, for the diff formatter, is the line's dominant colour.
    """
    console = Console(
        file=io.StringIO(),
        force_terminal=False,
        width=120,
        highlight=False,
        color_system="truecolor",
    )
    lines: list[tuple[str, str]] = []
    current_text = ""
    current_style = ""
    for segment in console.render(renderable, console.options):
        text = segment.text
        style = str(segment.style) if segment.style else ""
        if "\n" in text:
            head, _, tail = text.partition("\n")
            current_text += head
            if style:
                current_style = style
            lines.append((current_text, current_style))
            current_text = ""
            current_style = ""
            if tail:
                current_text = tail
        else:
            current_text += text
            if style:
                current_style = style
    if current_text:
        lines.append((current_text, current_style))
    return lines


def test_build_diff_renderable_tints_additions_green_and_deletions_red():
    from khaos.tui.chat_panel import build_diff_renderable

    renderable = build_diff_renderable("note.txt", DIFF_SAMPLE)
    lines = _styled_lines(renderable)

    added = [text for text, _ in lines if text.startswith("+added line")]
    removed = [text for text, _ in lines if text.startswith("-removed line")]
    assert added and removed

    added_style = next(style for text, style in lines if text.startswith("+added line"))
    removed_style = next(style for text, style in lines if text.startswith("-removed line"))
    assert "green" in added_style.lower()
    assert "red" in removed_style.lower()


def test_build_diff_renderable_tints_hunk_header_yellow():
    from khaos.tui.chat_panel import build_diff_renderable

    renderable = build_diff_renderable("note.txt", DIFF_SAMPLE)
    lines = _styled_lines(renderable)

    hunk_style = next(
        style for text, style in lines if text.startswith("@@ -1,3 +1,4 @@")
    )
    assert "yellow" in hunk_style.lower()


def test_build_diff_renderable_header_and_footer_are_dim():
    from khaos.tui.chat_panel import build_diff_renderable

    renderable = build_diff_renderable("note.txt", DIFF_SAMPLE)
    lines = _styled_lines(renderable)

    header_style = next(style for text, style in lines if "diff: note.txt" in text)
    assert "dim" in header_style.lower()
    # Footer rule is a line of dashes at the end.
    footer = [text for text, style in lines if set(text.strip()) == {"─"}]
    assert footer, "expected a trailing dashes rule"


def test_build_diff_renderable_empty_diff_shows_no_changes_note():
    from khaos.tui.chat_panel import build_diff_renderable

    renderable = build_diff_renderable("clean.txt", "")
    lines = _styled_lines(renderable)

    joined = " ".join(text for text, _ in lines)
    assert "no changes" in joined.lower()


def test_build_diff_renderable_context_lines_keep_neutral_style():
    from khaos.tui.chat_panel import build_diff_renderable

    renderable = build_diff_renderable("note.txt", DIFF_SAMPLE)
    lines = _styled_lines(renderable)

    # Context lines start with a space in unified diff output.
    context_styles = {
        style for text, style in lines if text.startswith(" context line")
    }
    # None of the context-line styles should be green/red/yellow.
    for style in context_styles:
        lowered = style.lower()
        assert "green" not in lowered
        assert "red" not in lowered
        assert "yellow" not in lowered
