"""Tests for the capability-based sandbox."""

from __future__ import annotations

from pathlib import Path

from khaos.security.sandbox import Sandbox, SandboxMode


# ---------------------------------------------------------------------------
# check_tool (capability enforcement)
# ---------------------------------------------------------------------------


def test_read_only_blocks_write() -> None:
    sandbox = Sandbox(mode=SandboxMode.READ_ONLY, workspace_root=Path("/tmp"))

    result = sandbox.check_tool("write_file")

    assert result.allowed is False
    assert "write_file" in result.reason
    assert "read-only" in result.reason


def test_read_only_allows_read() -> None:
    sandbox = Sandbox(mode=SandboxMode.READ_ONLY, workspace_root=Path("/tmp"))

    result = sandbox.check_tool("read_file")

    assert result.allowed is True


def test_workspace_write_allows_workspace() -> None:
    """check_write_path allows a path inside the workspace."""
    sandbox = Sandbox(
        mode=SandboxMode.WORKSPACE_WRITE, workspace_root=Path("/tmp/proj")
    )

    result = sandbox.check_write_path("/tmp/proj/src/main.py")

    assert result.allowed is True


def test_workspace_write_blocks_outside() -> None:
    """check_write_path blocks a path outside the workspace."""
    sandbox = Sandbox(
        mode=SandboxMode.WORKSPACE_WRITE, workspace_root=Path("/tmp/proj")
    )

    result = sandbox.check_write_path("/etc/khaos.conf")

    assert result.allowed is False
    assert "outside workspace" in result.reason


def test_full_access_allows_all() -> None:
    sandbox = Sandbox(mode=SandboxMode.FULL_ACCESS, workspace_root=Path("/tmp"))

    # Every tool, even exotic ones, is allowed under full-access.
    for tool in ("write_file", "terminal", "anything_weird"):
        assert sandbox.check_tool(tool).allowed is True


def test_yolo_allows_all() -> None:
    sandbox = Sandbox(mode=SandboxMode.YOLO, workspace_root=Path("/tmp"))

    assert sandbox.check_tool("write_file").allowed is True
    assert sandbox.check_tool("terminal").allowed is True


def test_from_policy_mode_invalid() -> None:
    """An unknown mode string falls back to workspace-write."""
    sandbox = Sandbox.from_policy_mode("not-a-real-mode")

    assert sandbox.mode == SandboxMode.WORKSPACE_WRITE


def test_from_policy_mode_valid() -> None:
    sandbox = Sandbox.from_policy_mode("read-only")
    assert sandbox.mode == SandboxMode.READ_ONLY


def test_capability_terminal_in_workspace() -> None:
    """terminal is in the workspace-write capability set."""
    sandbox = Sandbox(mode=SandboxMode.WORKSPACE_WRITE, workspace_root=Path("/tmp"))

    assert sandbox.check_tool("terminal").allowed is True


def test_capability_terminal_not_in_readonly() -> None:
    """terminal is NOT in the read-only capability set."""
    sandbox = Sandbox(mode=SandboxMode.READ_ONLY, workspace_root=Path("/tmp"))

    assert sandbox.check_tool("terminal").allowed is False


def test_capability_git_push_in_workspace() -> None:
    """git_push is in the workspace-write capability set."""
    sandbox = Sandbox(mode=SandboxMode.WORKSPACE_WRITE, workspace_root=Path("/tmp"))

    assert sandbox.check_tool("git_push").allowed is True


def test_read_only_blocks_write_path() -> None:
    """read-only mode blocks ALL writes, regardless of path."""
    sandbox = Sandbox(mode=SandboxMode.READ_ONLY, workspace_root=Path("/tmp"))

    result = sandbox.check_write_path("/tmp/inside.txt")

    assert result.allowed is False
    assert "read-only" in result.reason


def test_default_mode_is_workspace_write() -> None:
    """The default Sandbox() is workspace-write."""
    sandbox = Sandbox()

    assert sandbox.mode == SandboxMode.WORKSPACE_WRITE
