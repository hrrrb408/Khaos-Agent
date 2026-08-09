"""Executable identity binding tests."""

from __future__ import annotations

from dataclasses import replace

from khaos.coding.execution.identity import executable_identity
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
