import asyncio
from types import SimpleNamespace

import pytest

from khaos.coding.execution import ExecutionService, HostExecutionBackend
from khaos.tools.terminal_tools import (
    BackgroundProcessAuthority,
    check_command_safety,
    evaluate_command_safety,
    is_read_only_command,
    process,
    terminal,
    terminal_argv,
    terminal_shell,
)


def _execution_service() -> ExecutionService:
    """Minimal ExecutionService for read-only terminal tests (no workspace)."""
    return ExecutionService(HostExecutionBackend())


def test_evaluate_command_safety_read_only_pipeline():
    safety = evaluate_command_safety("echo hello | wc -c")

    assert safety["read_only"] is True
    assert safety["requires_confirmation"] is False


def test_evaluate_command_safety_mutating_redirection():
    safety = evaluate_command_safety("echo hello > out.txt")

    assert safety["read_only"] is False
    assert safety["requires_confirmation"] is True


def test_evaluate_command_safety_blocks_dangerous_command():
    safety = evaluate_command_safety("rm -rf /")

    assert safety["blocked"] is True


def test_is_read_only_command():
    assert is_read_only_command("pwd")
    assert not is_read_only_command("touch x")


def test_shell_capable_text_tools_are_never_classified_read_only():
    assert not is_read_only_command("sed -i 's/a/b/' file")
    assert not is_read_only_command("find . -exec sh -c 'touch pwned' ';'")
    assert not is_read_only_command("awk 'BEGIN { system(\"touch pwned\") }'")


@pytest.mark.posix_host
async def test_terminal_foreground_success(tmp_path):
    result = await terminal(
        "echo hello", cwd=str(tmp_path), timeout=5, execution_service=_execution_service()
    )

    assert result["returncode"] == 0
    assert result["stdout"] == "hello\n"


@pytest.mark.posix_host
async def test_terminal_blocks_dangerous_command(tmp_path):
    result = await terminal("rm -rf /", cwd=str(tmp_path), timeout=5)

    assert result["ok"] is False
    assert "blocked" in result["error"]


def test_check_command_safety_blocks_when_enabled():
    result = check_command_safety("sudo su")

    assert result["safe"] is False
    assert result["risk_level"] == "blocked"


def test_terminal_security_has_no_runtime_disable_switch():
    from khaos.tools import terminal_tools

    assert not hasattr(terminal_tools, "enable_security")
    assert not hasattr(terminal_tools, "_SECURITY_ENABLED")


@pytest.mark.posix_host
async def test_terminal_without_execution_service_fails_closed(tmp_path):
    """Coding Agent reachable terminal() must fail closed without ExecutionService."""
    result = await terminal("echo hello", cwd=str(tmp_path), timeout=5)

    assert result["ok"] is False
    assert "ExecutionService unavailable" in result["error"]
    assert result["risk_level"] == "blocked"


@pytest.mark.posix_host
async def test_terminal_background_without_execution_service_fails_closed(tmp_path):
    """Background terminal spawn must also fail closed without ExecutionService."""
    result = await terminal("echo background", cwd=str(tmp_path), background=True)

    assert result["ok"] is False
    assert "ExecutionService unavailable" in result["error"]
    assert result["risk_level"] == "blocked"


async def test_process_poll_unknown_raises():
    authority = BackgroundProcessAuthority()
    try:
        await process(
            "poll",
            "missing",
            process_authority=authority,
            principal_id="principal-a",
            project_id="project-a",
            runtime_id="runtime-a",
            task_id="task-a",
            workspace_id="workspace-a",
        )
    except KeyError as exc:
        assert "unknown process" in str(exc)
    else:
        raise AssertionError("expected KeyError")


async def test_process_control_rejects_cross_runtime_replay():
    class _Handle:
        def __init__(self) -> None:
            self.stdout = asyncio.StreamReader()
            self.stdout.feed_eof()
            self.stderr_text = ""
            self.returncode = None

        async def wait(self):
            self.returncode = 0
            return 0

        async def aclose(self) -> None:
            self.returncode = -15

    class _Service:
        async def start_managed_process(self, _request):
            return _Handle()

    request = SimpleNamespace(
        workspace_id="workspace-a",
        task_id="task-a",
        correlation_id="owned-process",
    )
    authority = BackgroundProcessAuthority()
    process_id = await authority.start(
        _Service(),
        request,
        principal_id="principal-a",
        project_id="project-a",
        runtime_id="runtime-a",
    )

    with pytest.raises(PermissionError, match="different runtime authority"):
        await process(
            "poll",
            process_id,
            process_authority=authority,
            principal_id="principal-a",
            project_id="project-a",
            runtime_id="runtime-b",
            task_id="task-a",
            workspace_id="workspace-a",
        )
    await authority.shutdown()


@pytest.mark.posix_host
async def test_terminal_argv_never_parses_shell_operators(tmp_path):
    result = await terminal_argv(
        ["echo", "hello | touch escaped"],
        cwd=str(tmp_path),
        timeout_seconds=5,
        execution_service=_execution_service(),
    )
    assert result["stdout"] == "hello | touch escaped\n"
    assert not (tmp_path / "escaped").exists()


async def test_terminal_shell_requires_explicit_absolute_shell(tmp_path):
    with pytest.raises(PermissionError, match="absolute shell"):
        await terminal_shell(
            "bash", "echo hello", cwd=str(tmp_path),
            execution_service=_execution_service(),
        )
