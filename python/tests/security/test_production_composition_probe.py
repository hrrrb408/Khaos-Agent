import os
import subprocess
from pathlib import Path

from khaos.security import production_composition_probe


def test_spawn_probe_process_uses_popen_stream_pipes(monkeypatch, tmp_path: Path) -> None:
    captured: dict[str, object] = {}
    expected_process = object()
    closed: list[int] = []

    def fake_popen(*args: object, **kwargs: object) -> object:
        captured["args"] = args
        captured.update(kwargs)
        return expected_process

    monkeypatch.setattr(production_composition_probe.os, "pipe", lambda: (41, 42))
    monkeypatch.setattr(production_composition_probe.os, "close", closed.append)
    monkeypatch.setattr(production_composition_probe.subprocess, "Popen", fake_popen)

    process, info_fd = production_composition_probe._spawn_probe_process(
        ("bwrap",), ("/bin/sh",), tmp_path
    )

    assert process is expected_process
    assert info_fd == 41
    assert captured["args"] == (("bwrap", "--info-fd", "42", "--", "/bin/sh"),)
    assert captured["stdout"] is subprocess.PIPE
    assert captured["stderr"] is subprocess.PIPE
    assert captured["pass_fds"] == (42,)
    assert "capture_output" not in captured
    assert closed == [42]


def test_mapping_contains_expected_namespace_and_host_ids() -> None:
    mapping = "0 65534 1\n10004 10001 1\n"

    assert production_composition_probe._mapping_contains_pair(mapping, 10004, 10001)
    assert not production_composition_probe._mapping_contains_pair(mapping, 10003, 10001)
    assert not production_composition_probe._mapping_contains_pair(mapping, 10004, 10003)


def test_read_bwrap_child_pid_accepts_multiline_info_metadata() -> None:
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, b'{\n    "child-pid": 123\n}\n')
    finally:
        os.close(write_fd)

    assert production_composition_probe._read_bwrap_child_pid(read_fd) == 123
