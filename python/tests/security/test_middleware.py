from khaos.security.middleware import SecurityMiddleware
from khaos.security.sandbox import Sandbox, SandboxMode


async def test_pre_check_safe_command():
    middleware = SecurityMiddleware()

    result = await middleware.pre_check("terminal", {"command": "echo hello"})

    assert result.allowed is True
    assert result.risk_level == "safe"


async def test_pre_check_blocked_command():
    middleware = SecurityMiddleware()

    result = await middleware.pre_check("terminal", {"command": "sudo su"})

    assert result.allowed is False
    assert result.risk_level == "blocked"
    assert result.check_type == "command"


async def test_pre_check_path_write_protected():
    middleware = SecurityMiddleware()

    result = await middleware.pre_check("write_file", {"path": "/etc/khaos.conf"})

    assert result.allowed is False
    assert result.risk_level == "protected"
    assert result.check_type == "path_write"


async def test_pre_check_path_read_sensitive():
    middleware = SecurityMiddleware()

    result = await middleware.pre_check("read_file", {"path": "/etc/shadow"})

    assert result.allowed is False
    assert result.risk_level == "sensitive"
    assert result.check_type == "path_read"


async def test_pre_check_safe_write():
    middleware = SecurityMiddleware()

    result = await middleware.pre_check("write_file", {"path": "~/khaos-safe.txt"})

    assert result.allowed is True
    assert result.risk_level == "safe"


async def test_post_check_no_secrets():
    middleware = SecurityMiddleware()

    result, output = await middleware.post_check("terminal", {"stdout": "hello"})

    assert result.has_secrets is False
    assert output == {"stdout": "hello"}


async def test_post_check_with_secrets():
    middleware = SecurityMiddleware()

    result, output = await middleware.post_check(
        "terminal",
        {"stdout": "api_key=abcd1234abcd1234abcd1234"},
    )

    assert result.has_secrets is True
    assert "abcd1234abcd1234abcd1234" not in str(output)
    assert result.secrets[0].category == "API Key"


async def test_disabled():
    middleware = SecurityMiddleware(enabled=False)

    pre = await middleware.pre_check("terminal", {"command": "sudo su"})
    post, output = await middleware.post_check("terminal", {"stdout": "api_key=abcd1234abcd1234abcd1234"})

    assert pre.allowed is True
    assert post.has_secrets is False
    assert "abcd1234abcd1234" in str(output)


async def test_workspace_write_sandbox_blocks_office_write_outside_root(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    middleware = SecurityMiddleware(
        sandbox=Sandbox(SandboxMode.WORKSPACE_WRITE, workspace)
    )

    result = await middleware.pre_check(
        "write_file", {"path": str(tmp_path / "outside.txt")}
    )

    assert result.allowed is False
    assert result.check_type == "sandbox_path"


async def test_workspace_write_sandbox_checks_copy_and_move_endpoints(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    middleware = SecurityMiddleware(
        sandbox=Sandbox(SandboxMode.WORKSPACE_WRITE, workspace)
    )

    copy_result = await middleware.pre_check(
        "copy_file", {"src": "inside.txt", "dst": str(tmp_path / "outside")}
    )
    move_result = await middleware.pre_check(
        "move_file", {"src": str(tmp_path / "outside"), "dst": "inside.txt"}
    )
    relative_result = await middleware.pre_check(
        "write_file", {"path": "inside.txt"}
    )

    assert copy_result.allowed is False
    assert move_result.allowed is False
    assert relative_result.allowed is True


async def test_sandbox_blocks_every_office_read_tool_outside_root(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    middleware = SecurityMiddleware(
        sandbox=Sandbox(SandboxMode.WORKSPACE_WRITE, workspace)
    )

    calls = (
        ("read_file", {"path": str(tmp_path / "outside.txt")}),
        ("file_info", {"path": str(tmp_path / "outside.txt")}),
        ("tree_view", {"path": str(tmp_path)}),
        ("list_directory", {"path": str(tmp_path)}),
        ("file_search_content", {"path": str(tmp_path)}),
        ("search_files", {"root": str(tmp_path)}),
    )
    for tool_name, arguments in calls:
        result = await middleware.pre_check(tool_name, arguments)
        assert result.allowed is False, tool_name
        assert result.check_type == "sandbox_path"


# ---- M1: EffectiveSecurityPolicy.commands_allowed reaches CommandGuard ---- #


async def test_effective_policy_commands_allowed_enforced(tmp_path):
    """M1: ``EffectiveSecurityPolicy.commands_allowed`` threads into the
    production CommandGuard as a real whitelist.

    Previously ``_merge_source_policy()`` synthesised a ``SandboxPolicy``
    view with only ``denied_paths`` + ``commands_blocked`` and dropped
    ``commands_allowed`` on the floor, leaving
    ``CommandGuard._allowed_commands`` at its default ``None`` (no
    whitelist). A policy like::

        commands:
          allow: [git, pytest]

    therefore had no effect — any command not in ``DANGEROUS_COMMANDS``
    would pass. This test proves the allow-list now reaches the guard and
    blocks commands outside it.
    """
    from khaos.security.effective_policy import compile_effective_policy
    from khaos.security.policy import SandboxPolicy

    project = SandboxPolicy(
        mode="workspace-write",
        commands_allowed=["git", "pytest"],
    )
    eff = compile_effective_policy(project, workspace_root=tmp_path)
    middleware = SecurityMiddleware(effective_policy=eff)

    # Command in the allow-list → allowed.
    ok = await middleware.pre_check("terminal", {"command": "git status"})
    assert ok.allowed, f"git should be allowed: {ok.reason}"

    # Another allow-listed command → allowed.
    ok2 = await middleware.pre_check("terminal", {"command": "pytest -x"})
    assert ok2.allowed, f"pytest should be allowed: {ok2.reason}"

    # Command NOT in the allow-list → blocked by the whitelist.
    blocked = await middleware.pre_check("terminal", {"command": "ls"})
    assert blocked.allowed is False
    assert blocked.risk_level == "blocked"
    assert blocked.check_type == "command"
    assert "allowlist" in blocked.reason


async def test_effective_policy_empty_commands_allowed_does_not_lock_down(
    tmp_path,
):
    """M1: an empty ``commands_allowed`` must NOT enforce an empty whitelist.

    A policy that only configures ``commands.block`` (or nothing at all)
    must leave the guard in "no whitelist" mode so ordinary commands like
    ``ls`` still pass. An empty frozenset would otherwise block every
    command, which is not the intended semantics of "unset" — the guard
    treats ``None`` as "no whitelist" and only engages the whitelist when
    the list is non-empty.
    """
    from khaos.security.effective_policy import compile_effective_policy
    from khaos.security.policy import SandboxPolicy

    project = SandboxPolicy(mode="workspace-write")  # no commands.allow
    eff = compile_effective_policy(project, workspace_root=tmp_path)
    middleware = SecurityMiddleware(effective_policy=eff)

    # ``ls`` is not in any allow-list, but with commands_allowed empty the
    # whitelist is NOT engaged, so it should pass.
    result = await middleware.pre_check("terminal", {"command": "ls"})
    assert result.allowed, (
        f"empty commands_allowed must not lock down: {result.reason}"
    )


async def test_effective_policy_commands_allowed_with_blocked_list(tmp_path):
    """M1: ``commands_allowed`` and ``commands_blocked`` compose correctly.

    A command in the allow-list that is also in the block-list is blocked
    (block-list wins — defense in depth). A command in the allow-list but
    not the block-list is allowed.
    """
    from khaos.security.effective_policy import compile_effective_policy
    from khaos.security.policy import SandboxPolicy

    project = SandboxPolicy(
        mode="workspace-write",
        commands_allowed=["git", "pytest"],
        commands_blocked=["git"],  # git is both allowed AND blocked
    )
    eff = compile_effective_policy(project, workspace_root=tmp_path)
    middleware = SecurityMiddleware(effective_policy=eff)

    # git is in both lists — block-list wins.
    blocked = await middleware.pre_check("terminal", {"command": "git status"})
    assert blocked.allowed is False
    assert blocked.risk_level == "blocked"

    # pytest is allowed and not blocked → passes.
    ok = await middleware.pre_check("terminal", {"command": "pytest -x"})
    assert ok.allowed, f"pytest should be allowed: {ok.reason}"
