from khaos.coding.execution import ExecutionService, HostExecutionBackend
from khaos.tools.terminal_tools import (
    check_command_safety,
    enable_security,
    evaluate_command_safety,
    is_read_only_command,
    process,
    terminal,
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


async def test_terminal_foreground_success(tmp_path):
    result = await terminal(
        "echo hello", cwd=str(tmp_path), timeout=5, execution_service=_execution_service()
    )

    assert result["returncode"] == 0
    assert result["stdout"] == "hello\n"


async def test_terminal_blocks_dangerous_command(tmp_path):
    result = await terminal("rm -rf /", cwd=str(tmp_path), timeout=5)

    assert result["ok"] is False
    assert "blocked" in result["error"]


def test_check_command_safety_blocks_when_enabled():
    enable_security(True)

    result = check_command_safety("sudo su")

    assert result["safe"] is False
    assert result["risk_level"] == "blocked"


async def test_terminal_security_disabled_allows_command(tmp_path):
    enable_security(False)
    try:
        result = await terminal(
            "echo safe", cwd=str(tmp_path), timeout=5, execution_service=_execution_service()
        )
    finally:
        enable_security(True)

    assert result["returncode"] == 0
    assert result["stdout"] == "safe\n"


async def test_terminal_without_execution_service_fails_closed(tmp_path):
    """Coding Agent reachable terminal() must fail closed without ExecutionService."""
    result = await terminal("echo hello", cwd=str(tmp_path), timeout=5)

    assert result["ok"] is False
    assert "ExecutionService unavailable" in result["error"]
    assert result["risk_level"] == "blocked"


async def test_terminal_background_without_execution_service_fails_closed(tmp_path):
    """Background terminal spawn must also fail closed without ExecutionService."""
    result = await terminal("echo background", cwd=str(tmp_path), background=True)

    assert result["ok"] is False
    assert "ExecutionService unavailable" in result["error"]
    assert result["risk_level"] == "blocked"


async def test_process_poll_unknown_raises():
    try:
        await process("poll", "missing")
    except KeyError as exc:
        assert "unknown process" in str(exc)
    else:
        raise AssertionError("expected KeyError")
