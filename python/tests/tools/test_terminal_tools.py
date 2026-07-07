from khaos.tools.terminal_tools import (
    evaluate_command_safety,
    is_read_only_command,
    process,
    terminal,
)


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


async def test_terminal_foreground_success(tmp_path):
    result = await terminal("echo hello", cwd=str(tmp_path), timeout=5)

    assert result["returncode"] == 0
    assert result["stdout"] == "hello\n"


async def test_terminal_blocks_dangerous_command(tmp_path):
    try:
        await terminal("rm -rf /", cwd=str(tmp_path), timeout=5)
    except PermissionError as exc:
        assert "blocked" in str(exc)
    else:
        raise AssertionError("expected PermissionError")


async def test_terminal_background_wait_and_log(tmp_path):
    started = await terminal("echo background", cwd=str(tmp_path), background=True)

    waited = await process("wait", started["id"], timeout=5)
    logs = await process("log", started["id"])

    assert waited["returncode"] == 0
    assert "background" in logs["stdout"]


async def test_process_poll_unknown_raises():
    try:
        await process("poll", "missing")
    except KeyError as exc:
        assert "unknown process" in str(exc)
    else:
        raise AssertionError("expected KeyError")

