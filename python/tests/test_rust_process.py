"""Python integration tests for the Rust process handler + fallback."""

from __future__ import annotations

import pytest

from khaos.rust_bridge import (
    RustToolExecutor,
    rust_available,
    rust_exec_process,
    subprocess_error,
)

pytestmark = pytest.mark.skipif(not rust_available(), reason="Rust extension not built")


def test_exec_echo_captures_stdout():
    result = RustToolExecutor().exec_process("echo", args=["khaos"])

    assert result["exit_code"] == 0
    assert result["stdout"].strip() == "khaos"
    assert result["stderr"] == ""


def test_exec_reports_nonzero_exit_code():
    # `false` exits with status 1 on POSIX.
    result = RustToolExecutor().exec_process("sh", args=["-c", "exit 7"])

    assert result["exit_code"] == 7


def test_exec_timeout_raises():
    with pytest.raises(subprocess_error):
        RustToolExecutor().exec_process("sleep", args=["5"], timeout_ms=100)


def test_exec_captures_stderr():
    result = RustToolExecutor().exec_process(
        "sh", args=["-c", "echo err >&2"]
    )

    assert result["stderr"].strip() == "err"


def test_exec_with_workdir(tmp_path):
    workdir = tmp_path / "wd"
    workdir.mkdir()
    (workdir / "marker.txt").write_text("here", encoding="utf-8")

    # `pwd` should reflect the workdir we passed.
    result = RustToolExecutor().exec_process("pwd", workdir=str(workdir))

    assert str(workdir) in result["stdout"]


def test_exec_helper_roundtrip():
    """The module-level helper wraps the executor."""
    result = rust_exec_process("echo", args=["helper"])

    assert result["stdout"].strip() == "helper"


def test_python_fallback_exec_when_rust_unavailable(monkeypatch):
    monkeypatch.setattr("khaos.rust_bridge.RustToolExecutor", _raise_runtime_error)

    result = rust_exec_process("echo", args=["fallback"])

    assert result["stdout"].strip() == "fallback"


class _RaiseRuntimeError:
    def __init__(self, *args, **kwargs):
        raise RuntimeError("not built")


def _raise_runtime_error(*args, **kwargs):
    return _RaiseRuntimeError()
