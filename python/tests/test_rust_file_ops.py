"""Python integration tests for the Rust file-ops handlers + fallbacks."""

from __future__ import annotations

import os

import pytest

from khaos.rust_bridge import (
    RustToolExecutor,
    rust_available,
    rust_read_file,
    rust_write_file,
)

pytestmark = pytest.mark.skipif(not rust_available(), reason="Rust extension not built")


def test_rust_write_then_read(tmp_path):
    path = tmp_path / "sub" / "dir" / "out.txt"
    RustToolExecutor().write_file(str(path), "hello\nworld\n")

    assert path.read_text(encoding="utf-8") == "hello\nworld\n"
    assert RustToolExecutor().read_file(str(path)) == "hello\nworld\n"


def test_rust_read_with_offset_and_limit(tmp_path):
    path = tmp_path / "lines.txt"
    path.write_text("a\nb\nc\nd\ne", encoding="utf-8")

    out = RustToolExecutor().read_file(str(path), offset=2, limit=2)

    assert out == "b\nc"


def test_rust_read_missing_file_raises(tmp_path):
    with pytest.raises(OSError):
        RustToolExecutor().read_file(str(tmp_path / "nope.txt"))


def test_rust_write_creates_parents(tmp_path):
    path = tmp_path / "deep" / "nested" / "path" / "file.txt"
    RustToolExecutor().write_file(str(path), "deep content")

    assert path.read_text(encoding="utf-8") == "deep content"


def test_rust_read_file_helper_roundtrip(tmp_path):
    """The module-level rust_read_file helper wraps the executor."""
    path = tmp_path / "h.txt"
    rust_write_file(str(path), "via helper")

    assert rust_read_file(str(path)) == "via helper"


def test_python_fallback_read_when_rust_unavailable(tmp_path, monkeypatch):
    """When the extension is reported unavailable, helpers use pure Python."""
    path = tmp_path / "fallback.txt"
    path.write_text("line1\nline2\nline3", encoding="utf-8")
    monkeypatch.setattr("khaos.rust_bridge.RustToolExecutor", _raise_runtime_error)

    content = rust_read_file(str(path), offset=2, limit=1)

    assert content == "line2\n"


def test_python_fallback_write_when_rust_unavailable(tmp_path, monkeypatch):
    path = tmp_path / "out" / "fallback.txt"
    monkeypatch.setattr("khaos.rust_bridge.RustToolExecutor", _raise_runtime_error)

    result = rust_write_file(str(path), "fallback content")

    assert path.read_text(encoding="utf-8") == "fallback content"
    assert "wrote" in result
    assert str(path) in result


class _RaiseRuntimeError:
    """Stand-in that always raises RuntimeError to simulate a missing build."""

    def __init__(self, *args, **kwargs):
        raise RuntimeError("Rust extension not available")


def _raise_runtime_error(*args, **kwargs):
    return _RaiseRuntimeError()
