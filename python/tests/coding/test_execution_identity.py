"""Executable identity binding tests."""

from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path

from khaos.coding.execution.identity import (
    executable_identity,
    trusted_system_executable,
)
from khaos.coding.execution.models import ExecutionRequest


def test_executable_identity_changes_when_file_content_changes(tmp_path):
    executable = tmp_path / "tool"
    executable.write_bytes(b"first")
    first = executable_identity((str(executable),))
    request = ExecutionRequest((str(executable),), tmp_path)
    assert request.executable_identity == first

    executable.write_bytes(b"second")
    second = executable_identity((str(executable),))
    assert second != first
    assert replace(request, executable_identity=second).executable_identity == second


def test_trusted_system_executable_rejects_workspace_shadow(tmp_path):
    shadow = tmp_path / "ls"
    shadow.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    shadow.chmod(0o755)

    assert not trusted_system_executable(("ls",), {"PATH": str(tmp_path)})


def test_trusted_system_executable_requires_trusted_script_path(tmp_path):
    script = tmp_path / "read-only-helper"
    script.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    script.chmod(0o755)

    assert not trusted_system_executable((str(script),), {"PATH": "/usr/bin:/bin"})


def _platform_system_binary() -> Path:
    if os.name == "nt":
        return Path(os.environ.get("SystemRoot", "C:/Windows")) / "System32" / "cmd.exe"
    for candidate in (Path("/bin/ls"), Path("/usr/bin/ls")):
        if candidate.is_file():
            return candidate
    raise AssertionError("no platform system binary is available for this test")


def test_trusted_system_executable_accepts_platform_binary():
    binary = _platform_system_binary()
    assert trusted_system_executable(
        (str(binary),), {"PATH": os.environ.get("PATH", os.defpath)}
    )
