"""Tests for the branch/push/pr-body git workflow tools."""

from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

from khaos.tools.git_tools import git_create_branch, git_pr_body, git_push, prepare_destructive_git_approval, prepare_remote_git_approval
from khaos.agent.approval import ApprovalBroker
from khaos.tools.registry import create_runtime_registry
from khaos.coding.execution.host import HostExecutionBackend
from khaos.coding.execution.models import NetworkPolicy
from khaos.coding.execution.service import ExecutionService
from khaos.coding.workspace.models import WorkspaceState


class _LocalRemoteBackend(HostExecutionBackend):
    """Test-only backend that permits a local bare remote without public network."""

    async def execute(self, request):
        return await super().execute(replace(request, network_policy=NetworkPolicy.NONE))


def _ctx(repo, access_mode="vcs.destructive-write"):
    workspace = SimpleNamespace(
        task_id="task",
        worktree_path=repo,
        repository_root=repo.parent / "main-worktree",
        branch_name="main",
        state=WorkspaceState.RUNNING,
    )
    manager = SimpleNamespace(get=lambda workspace_id: workspace if workspace_id == "workspace" else None)
    service = ExecutionService(_LocalRemoteBackend(), manager)
    return {"task_id": "task", "workspace_id": "workspace", "access_mode": access_mode, "execution_service": service}


async def _approved_ctx(repo, tool_name, arguments):
    context = _ctx(repo)
    context["execution_service"].workspace_manager.get("workspace").branch_name = (
        await _git(repo, "branch", "--show-current")
    ).strip()
    broker = ApprovalBroker()
    tool_context = {
        **context,
        "approval_broker": broker,
        "network_policy": "unrestricted-with-approval",
    }
    approval = await prepare_destructive_git_approval(
        tool_name,
        arguments,
        tool_context,
        requester="session",
        approval_id="approval",
    )
    if approval is None:
        approval = await prepare_remote_git_approval(
            tool_name,
            arguments,
            tool_context,
            requester="session",
            approval_id="approval",
        )
    assert approval is not None
    assert await broker.approve_operation("approval", "session")
    context["approval_context"] = approval
    context["network_policy"] = "unrestricted-with-approval"
    return context


async def _git(repo, *args):
    process = await asyncio.create_subprocess_exec(
        "git",
        *args,
        cwd=str(repo),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await process.communicate()
    if process.returncode != 0:
        pytest.skip(f"git unavailable or failed: {stderr.decode()}")
    return stdout.decode()


async def _repo_with_main(tmp_path):
    """Create a repo on ``main`` with one initial commit."""
    await _git(tmp_path, "init", "-b", "main")
    await _git(tmp_path, "config", "user.email", "test@example.com")
    await _git(tmp_path, "config", "user.name", "Tester")
    (tmp_path / "README.md").write_text("# demo\n", encoding="utf-8")
    await _git(tmp_path, "add", "README.md")
    await _git(tmp_path, "commit", "-m", "initial commit")
    return tmp_path


def test_new_git_tools_registered() -> None:
    """All three new tools must be registered with concrete handlers."""
    registry = create_runtime_registry()
    for name in ("git_create_branch", "git_push", "git_pr_body"):
        tool = registry.get(name)
        assert tool is not None, f"{name} not registered"
        assert tool.handler is not None, f"{name} has no handler"


async def test_create_branch(tmp_path) -> None:
    repo = await _repo_with_main(tmp_path)

    context = await _approved_ctx(
        repo, "git_create_branch", {"cwd": str(repo), "branch_name": "feat/cool", "from_base": "main"}
    )
    result = json.loads(await git_create_branch(str(repo), "feat/cool", **context))

    assert result["created"] is True
    assert result["branch"] == "feat/cool"
    assert result["base"] == "main"
    # We should now be on the new branch.
    current = await _git(repo, "branch", "--show-current")
    assert current.strip() == "feat/cool"


async def test_create_branch_requires_name(tmp_path) -> None:
    repo = await _repo_with_main(tmp_path)

    result = json.loads(await git_create_branch(str(repo), "", **_ctx(repo)))

    assert "error" in result


async def test_create_branch_missing_base(tmp_path) -> None:
    repo = await _repo_with_main(tmp_path)

    result = json.loads(
        await git_create_branch(str(repo), "feat/x", from_base="nonexistent", **_ctx(repo))
    )

    assert result["created"] is False
    assert "not found" in result["error"]


async def test_push_branch(tmp_path) -> None:
    """Push against a bare remote set up in the same tmp_path."""
    repo = tmp_path / "repo"
    repo.mkdir()
    await _repo_with_main(repo)
    context = await _approved_ctx(
        repo, "git_create_branch", {"cwd": str(repo), "branch_name": "feat/push", "from_base": "main"}
    )
    await git_create_branch(str(repo), "feat/push", **context)

    # Set up a bare remote and point origin at it.
    remote = tmp_path / "remote.git"
    await _git(remote.parent, "init", "--bare", str(remote))
    await _git(repo, "remote", "add", "origin", str(remote))

    context = await _approved_ctx(
        repo, "git_push", {"cwd": str(repo), "remote": "origin", "branch": ""}
    )
    result = json.loads(await git_push(str(repo), **context))

    assert result["pushed"] is True
    assert result["branch"] == "feat/push"
    assert result["remote"] == "origin"


async def test_push_no_remote_fails_gracefully(tmp_path) -> None:
    repo = await _repo_with_main(tmp_path)
    await _git(repo, "checkout", "-b", "task/no-remote")

    context = _ctx(repo, "vcs.remote-write")
    context["execution_service"].workspace_manager.get("workspace").branch_name = "task/no-remote"
    context["network_policy"] = "unrestricted-with-approval"
    result = json.loads(await git_push(str(repo), **context))

    assert result["pushed"] is False
    assert "error" in result


async def test_pr_body_generation(tmp_path) -> None:
    repo = await _repo_with_main(tmp_path)
    context = await _approved_ctx(
        repo, "git_create_branch", {"cwd": str(repo), "branch_name": "feat/pr", "from_base": "main"}
    )
    await git_create_branch(str(repo), "feat/pr", **context)
    # Add a couple of conventional commits on the feature branch.
    (repo / "a.py").write_text("x = 1\n", encoding="utf-8")
    await _git(repo, "add", "a.py")
    await _git(repo, "commit", "-m", "feat(api): add endpoint")
    (repo / "b.py").write_text("y = 2\n", encoding="utf-8")
    await _git(repo, "add", "b.py")
    await _git(repo, "commit", "-m", "fix(api): handle null")

    result = json.loads(await git_pr_body(str(repo), **_ctx(repo, "read-only")))

    # git log lists newest-first; the title reflects the most recent
    # conventional-commit subject on the branch.
    assert result["title"] == "fix(api): handle null"
    assert "add endpoint" in result["body"]
    assert "handle null" in result["body"]
    assert "a.py" in result["files"]
    assert "b.py" in result["files"]


async def test_pr_body_empty_branch(tmp_path) -> None:
    """A branch with no commits ahead of main yields an empty title."""
    repo = await _repo_with_main(tmp_path)
    context = await _approved_ctx(
        repo, "git_create_branch", {"cwd": str(repo), "branch_name": "feat/empty", "from_base": "main"}
    )
    await git_create_branch(str(repo), "feat/empty", **context)

    result = json.loads(await git_pr_body(str(repo), **_ctx(repo, "read-only")))

    assert result["title"] == ""
    assert result["files"] == []
