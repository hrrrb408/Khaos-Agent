import subprocess
from pathlib import Path

from khaos.security import production_composition_probe


def test_spawn_probe_process_uses_popen_stream_pipes(monkeypatch, tmp_path: Path) -> None:
    captured: dict[str, object] = {}
    expected_process = object()

    def fake_popen(*args: object, **kwargs: object) -> object:
        captured["args"] = args
        captured.update(kwargs)
        return expected_process

    monkeypatch.setattr(production_composition_probe.subprocess, "Popen", fake_popen)

    process = production_composition_probe._spawn_probe_process(
        ("bwrap",), ("/bin/sh",), tmp_path
    )

    assert process is expected_process
    assert captured["args"] == (("bwrap", "--", "/bin/sh"),)
    assert captured["stdout"] is subprocess.PIPE
    assert captured["stderr"] is subprocess.PIPE
    assert "capture_output" not in captured
