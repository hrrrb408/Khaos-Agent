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
