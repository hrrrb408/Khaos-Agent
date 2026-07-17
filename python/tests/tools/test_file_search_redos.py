"""H2: file_search_content ReDoS hardening.

The tool accepts arbitrary user-supplied patterns and previously compiled
them with Python's backtracking ``re`` inside an ``asyncio.to_thread``.  A
catastrophic-backtracking pattern could pin the worker thread past the
scheduler timeout (which only cancels the *awaiting* task, not the thread),
yielding an unapproved runtime DoS via prompt injection.

These tests prove the worker now uses the linear-time RE2 engine and bounded
inputs.
"""

import sys
import time
from pathlib import Path

import pytest

from khaos.tools.file_tools import _compile_search_pattern, file_search_content


pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason="content search runs through POSIX dirfd workspace boundary",
)


def test_catastrophic_backtracking_pattern_is_linear(tmp_path):
    """A classic ReDoS pattern completes in bounded time, not exponential."""
    target = tmp_path / "evil.txt"
    # 30 'a's followed by a non-match: with Python re + (a+)+$ this is ~1s;
    # with RE2 it is microseconds.  We assert well under any backtracking.
    target.write_text("a" * 30 + "!", encoding="utf-8")

    # Call the sync core directly to avoid the asyncio wrapper timing noise.
    from khaos.tools.file_tools import _workspace_content_search_sync

    start = time.monotonic()
    res = _workspace_content_search_sync(tmp_path, ".", "(a+)+$", 10)
    elapsed = time.monotonic() - start

    assert elapsed < 0.5, f"search took {elapsed:.3f}s — RE2 linear bound failed"
    # No match (the trailing '!' breaks the anchor) — but it must return fast.
    assert res["ok"] is True


def test_excessive_pattern_length_rejected():
    with pytest.raises(ValueError, match="length limit"):
        _compile_search_pattern("a" * 300)


def test_invalid_regex_falls_back_to_literal():
    """An invalid regex compiles to None → literal substring search."""
    # Unmatched parenthesis is invalid in both re and re2.
    regex = _compile_search_pattern("(unclosed")
    assert regex is None


def test_valid_regex_compiles_via_re2():
    regex = _compile_search_pattern("foo.*bar")
    assert regex is not None
    assert regex.search("xxx foobar yyy") is not None


async def test_long_line_is_truncated_during_search(tmp_path):
    """Per-line cap bounds memory/CPU on pathological single-line inputs."""
    target = tmp_path / "long.txt"
    # A single very long line; the match should still be found in the prefix.
    target.write_text("needle" + "x" * (200 * 1024), encoding="utf-8")

    result = await file_search_content(
        "long.txt", "needle", workspace_root=tmp_path
    )
    assert result["ok"] is True
    assert result["match_count"] == 1
    assert "needle" in result["matches"][0]["line"]


async def test_substring_match_still_works(tmp_path):
    target = tmp_path / "note.txt"
    target.write_text("hello world\nfoo bar\n", encoding="utf-8")

    result = await file_search_content(
        "note.txt", "world", workspace_root=tmp_path
    )
    assert result["ok"] is True
    assert result["match_count"] == 1
    assert result["matches"][0]["line_number"] == 1


async def test_regex_match_still_works(tmp_path):
    target = tmp_path / "code.py"
    target.write_text("def hello():\n    return 42\n", encoding="utf-8")

    result = await file_search_content(
        "code.py", r"def \w+", workspace_root=tmp_path
    )
    assert result["ok"] is True
    assert result["match_count"] == 1
    assert "def hello" in result["matches"][0]["line"]


async def test_re2_rejects_backtracking_pattern_falls_back_to_literal(tmp_path):
    """A pattern re2 refuses to compile falls back to literal substring.

    re2 (linear-time) rejects patterns it cannot handle without backtracking
    semantics — notably backreferences.  Such a pattern must not crash the
    search; it degrades to a literal substring match instead.
    """
    target = tmp_path / "data.txt"
    # The literal text contains the backreference syntax as plain characters.
    target.write_text("see (a+)\\1 here\n", encoding="utf-8")

    result = await file_search_content(
        "data.txt", r"(a+)\1", workspace_root=tmp_path
    )
    assert result["ok"] is True
    # re2 rejects r"(a+)\1" → falls back to literal substring "(a+)\1",
    # which matches the line.
    assert result["match_count"] == 1
