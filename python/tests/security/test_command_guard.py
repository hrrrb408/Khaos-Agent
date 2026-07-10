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


def test_extra_blocked_blocks_command():
    """extra_blocked adds an instance-level block for a normally-safe command."""
    guard = CommandGuard(extra_blocked=frozenset({"mymockcmd"}))

    result = guard.check("mymockcmd --flag")

    assert result.safe is False
    assert result.risk_level == "blocked"
    assert "mymockcmd" in result.reason


def test_extra_blocked_does_not_leak_to_other_instances():
    """A guard's extra_blocked must not affect a fresh default guard."""
    configured = CommandGuard(extra_blocked=frozenset({"mymockcmd"}))
    # The configured guard blocks mymockcmd...
    assert configured.check("mymockcmd --flag").safe is False

    # ...but a brand-new default guard is unaffected (mymockcmd is not globally
    # blocked). This is the test-isolation guarantee the refactor provides.
    fresh = CommandGuard()
    assert fresh.check("mymockcmd --flag").safe is True


def test_extra_blocked_catches_pipe_injection():
    """extra_blocked also applies to commands reached via a pipe."""
    guard = CommandGuard(extra_blocked=frozenset({"mymockcmd"}))

    result = guard.check("echo hi | mymockcmd --flag")

    assert result.safe is False


def test_extra_blocked_combines_with_global():
    """extra_blocked adds to (does not replace) the built-in blocked set."""
    guard = CommandGuard(extra_blocked=frozenset({"mymockcmd"}))

    # Built-in block (sudo) still works alongside the extra (mymockcmd).
    assert guard.check("sudo su").safe is False
    assert guard.check("mymockcmd --flag").safe is False


def test_blocks_arbitrary_python_entrypoints():
    guard = CommandGuard()
    assert not guard.check("python").safe
    assert not guard.check("python -c 'print(1)'").safe
    assert not guard.check("python -m http.server").safe
    assert guard.check("python -m pytest -q").safe
