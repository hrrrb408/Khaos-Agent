"""CLI entry point tests."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from khaos.cli import supervision_commands
from khaos.cli.main import _apply_initial_mode, build_command_parser, cmd_start
from khaos.modes import Mode


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    """Run the package CLI in a subprocess."""
    project_root = Path(__file__).resolve().parents[2]
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(project_root / "python")
    return subprocess.run(
        [sys.executable, "-m", "khaos.cli", *args],
        capture_output=True,
        cwd=str(project_root),
        env=environment,
        check=False,
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


def test_trusted_git_doctor_parser_exposes_json_mode():
    args = build_command_parser().parse_args(["doctor", "trusted-git", "--json"])

    assert args.command == "doctor"
    assert args.doctor_command == "trusted-git"
    assert args.as_json is True


def test_chat_parser_exposes_interactive_options():
    parser = build_command_parser()
    args = parser.parse_args(["chat", "--mode", "coding", "--no-tui", "--yes"])

    assert args.command == "chat"
    assert args.mode == "coding"
    assert args.no_tui is True
    assert args.yes is True


def test_setup_parser_exposes_local_first_setup_entrypoint():
    args = build_command_parser().parse_args(["setup"])

    assert args.command == "setup"


async def test_chat_initial_mode_is_applied_by_shared_entrypoint():
    class FakeModeManager:
        def __init__(self):
            self.requested = None

        async def switch(self, mode):
            self.requested = mode

    manager = FakeModeManager()

    await _apply_initial_mode(manager, "coding")

    assert manager.requested is Mode.CODING


def test_m8_6_task_control_parser_is_typed_and_owner_scoped():
    parser = build_command_parser()
    args = parser.parse_args([
        "task", "--json", "pause", "task-1",
        "--command-id", "cmd-1", "--expected-revision", "4",
    ])

    assert args.command == "task"
    assert args.task_command == "pause"
    assert args.task_id == "task-1"
    assert args.command_id == "cmd-1"
    assert args.expected_revision == 4
    assert args.as_json is True


async def test_task_control_does_not_treat_task_diagnostic_as_not_found(
    monkeypatch, capsys,
):
    """A persisted task diagnostic must not block a cancel command."""

    class FakeDatabase:
        closed = False

        async def close(self):
            self.closed = True

    class FakeTaskService:
        def __init__(self):
            self.cancel_call = None

        async def get(self, _context, task_id):
            return {
                "id": task_id,
                "error": "interrupted by process restart",
                "status": "blocked",
            }

        async def cancel(
            self, _context, task_id, *, command_id=None, expected_revision=None,
        ):
            self.cancel_call = (task_id, command_id, expected_revision)
            return {"ok": True, "task_id": task_id}

    database = FakeDatabase()
    service = FakeTaskService()

    async def fake_open(_args):
        return database, service, object()

    monkeypatch.setattr(supervision_commands, "_open", fake_open)
    args = build_command_parser().parse_args([
        "task", "--json", "cancel", "task-1",
        "--command-id", "cancel-1", "--expected-revision", "7",
    ])

    result = await supervision_commands._task_command_async(args)

    assert result == 0
    assert service.cancel_call == ("task-1", "cancel-1", 7)
    assert database.closed is True
    assert '"ok": true' in capsys.readouterr().out


def test_m8_6_checkpoint_and_rewind_parsers_expose_digest_bindings():
    parser = build_command_parser()
    checkpoint = parser.parse_args([
        "checkpoint", "create", "task-1", "before", "merge",
        "--idempotency-key", "cp-1",
    ])
    rewind = parser.parse_args([
        "rewind", "execute", "rw-1", "--task-id", "task-1",
        "--plan-digest", "a" * 64,
    ])

    assert checkpoint.checkpoint_command == "create"
    assert checkpoint.label == ["before", "merge"]
    assert checkpoint.idempotency_key == "cp-1"
    assert rewind.rewind_command == "execute"
    assert rewind.plan_digest == "a" * 64


@pytest.mark.posix_host
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
