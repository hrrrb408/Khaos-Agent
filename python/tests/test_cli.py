"""CLI entry point tests."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from khaos.cli.main import build_command_parser, cmd_start


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    """Run the package CLI in a subprocess."""
    project_root = Path(__file__).resolve().parents[2]
    return subprocess.run(
        [sys.executable, "-m", "khaos.cli", *args],
        capture_output=True,
        cwd=str(project_root),
        env={"PYTHONPATH": str(project_root / "python")},
        text=True,
        timeout=10,
    )


def test_version():
    result = run_cli("version")

    assert result.returncode == 0
    assert "Khaos" in result.stdout


def test_no_command():
    result = run_cli()

    assert result.returncode == 0
    assert "usage:" in result.stdout


def test_test_help():
    result = run_cli("test", "--help")

    assert result.returncode == 0
    assert "Run tests" in result.stdout


def test_chat_parser_exposes_interactive_options():
    parser = build_command_parser()
    args = parser.parse_args(["chat", "--mode", "coding", "--no-tui", "--yes"])

    assert args.command == "chat"
    assert args.mode == "coding"
    assert args.no_tui is True
    assert args.yes is True


def test_managed_gateway_receives_capability_by_inherited_fd(
    tmp_path, monkeypatch,
):
    project = tmp_path / "project"
    (project / "go").mkdir(parents=True)
    (project / ".cache").mkdir(mode=0o700)
    observed: dict[str, object] = {}

    def fake_build(command, **kwargs):
        observed["build"] = (command, kwargs)
        return subprocess.CompletedProcess(command, 0)

    class FakeGatewayProcess:
        pid = 4242

        def __init__(self, command, **kwargs):
            observed["command"] = command
            observed["environment"] = kwargs["env"]
            observed["pass_fds"] = kwargs["pass_fds"]
            fd = kwargs["pass_fds"][0]
            observed["capability"] = __import__("os").read(fd, 4096).decode().strip()

        def terminate(self):
            observed["terminated"] = True

    async def fake_serve(*args, **kwargs):
        observed["serve"] = (args, kwargs)

    monkeypatch.setattr("khaos.cli.main._project_root", lambda: project)
    monkeypatch.setattr("khaos.cli.main.subprocess.run", fake_build)
    monkeypatch.setattr("khaos.cli.main.subprocess.Popen", FakeGatewayProcess)
    monkeypatch.setattr("khaos.grpc_server.serve_json_lines", fake_serve)
    monkeypatch.setenv("KHAOS_PYTHON_CAPABILITY", "legacy-env-secret" * 3)
    args = build_command_parser().parse_args([
        "start", "--gateway", "--socket", str(tmp_path / "agent.sock"),
        "--db", str(tmp_path / "khaos.db"), "--config", str(tmp_path / "config.yaml"),
    ])

    cmd_start(args)

    assert len(str(observed["capability"])) >= 32
    environment = observed["environment"]
    assert "KHAOS_PYTHON_CAPABILITY" not in environment
    assert environment["KHAOS_PYTHON_CAPABILITY_FD"] == str(observed["pass_fds"][0])
    assert observed["serve"][1]["gateway_pid"] == 4242
    assert observed["serve"][1]["gateway_capability"] == observed["capability"]
    assert observed["terminated"] is True
