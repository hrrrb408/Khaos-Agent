from khaos.security.command_guard import CommandGuard


def test_safe_commands():
    guard = CommandGuard()

    for command in ["ls -la", "cat file.txt", "echo hello"]:
        result = guard.check(command)

        assert result.safe is True
        assert result.risk_level == "safe"


def test_blocked_commands():
    guard = CommandGuard()

    for command in ["sudo su", "rm -rf /", "shutdown now"]:
        result = guard.check(command)

        assert result.safe is False
        assert result.risk_level in {"blocked", "dangerous"}


def test_risky_commands():
    guard = CommandGuard()

    for command in ["DROP TABLE users", "rm -r build", "git push --force origin main"]:
        result = guard.check(command)

        assert result.safe is True
        assert result.risk_level == "risky"


def test_pipe_injection():
    result = CommandGuard().check("ls | sudo su")

    assert result.safe is False
    assert result.risk_level == "blocked"


def test_shell_injection():
    result = CommandGuard().check("echo ok; rm -rf /")

    assert result.safe is False
    assert result.risk_level == "dangerous"


def test_subshell_injection():
    result = CommandGuard().check("echo $(rm -rf /)")

    assert result.safe is False
    assert result.risk_level == "dangerous"


def test_backtick_injection():
    result = CommandGuard().check("echo `rm -rf /`")

    assert result.safe is False
    assert result.risk_level == "dangerous"


def test_safe_pipe():
    result = CommandGuard().check("cat file | grep pattern")

    assert result.safe is True
    assert result.risk_level == "safe"


def test_empty_command():
    result = CommandGuard().check("")

    assert result.safe is True
    assert result.risk_level == "safe"


def test_custom_allowed_commands():
    guard = CommandGuard(allowed_commands=frozenset({"ls"}))

    assert guard.check("ls -la").safe is True
    blocked = guard.check("cat file.txt")
    assert blocked.safe is False
    assert blocked.risk_level == "blocked"
