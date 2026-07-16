import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from khaos.tools.git_tools import (
    git_branch,
    git_commit,
    git_diff,
    git_log,
    git_smart_commit,
    git_status,
    git_undo,
    prepare_destructive_git_approval,
)
from khaos.agent.approval import ApprovalBroker
from khaos.tools.registry import create_runtime_registry
from khaos.coding.execution.host import HostExecutionBackend
from khaos.coding.execution.service import ExecutionService
from khaos.coding.workspace.models import WorkspaceState


def _ctx(repo, access_mode="vcs.write"):
    workspace = SimpleNamespace(
        task_id="task",
        worktree_path=repo,
        repository_root=repo.parent / "main-worktree",
        branch_name="task/test",
        state=WorkspaceState.RUNNING,
    )
    manager = SimpleNamespace(
        get=lambda workspace_id: workspace if workspace_id == "workspace" else None,
        verify_git_identity=AsyncMock(),
    )
    service = ExecutionService(HostExecutionBackend(), manager)
    return {"task_id": "task", "workspace_id": "workspace", "access_mode": access_mode, "execution_service": service}


async def _approved_ctx(repo, tool_name, arguments):
    context = _ctx(repo, "vcs.destructive-write")
    context["execution_service"].workspace_manager.get("workspace").branch_name = (
        await _git(repo, "branch", "--show-current")
    ).strip()
    broker = ApprovalBroker()
    tool_context = {**context, "approval_broker": broker}
    approval = await prepare_destructive_git_approval(
        tool_name, arguments, tool_context, requester="session", approval_id="approval"
    )
    assert approval is not None
    assert await broker.approve_operation("approval", "session")
    context["approval_context"] = approval
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


async def _repo(tmp_path):
    await _git(tmp_path, "init")
    await _git(tmp_path, "config", "user.email", "test@example.com")
    await _git(tmp_path, "config", "user.name", "Tester")
    (tmp_path / "a.txt").write_text("one\n", encoding="utf-8")
    await _git(tmp_path, "add", "a.txt")
    await _git(tmp_path, "commit", "-m", "initial")
    await _git(tmp_path, "checkout", "-b", "task/test")
    return tmp_path


async def test_git_diff(tmp_path):
    repo = await _repo(tmp_path)
    (repo / "a.txt").write_text("two\n", encoding="utf-8")

    result = await git_diff(str(repo), **_ctx(repo, "read-only"))

    assert result["returncode"] == 0
    assert "-one" in result["stdout"]


async def test_git_commit_and_log(tmp_path):
    repo = await _repo(tmp_path)
    (repo / "b.txt").write_text("b\n", encoding="utf-8")
    await _git(repo, "add", "b.txt")

    commit = await git_commit(str(repo), "add b", **_ctx(repo))
    log = await git_log(str(repo), limit=1, **_ctx(repo, "read-only"))

    assert commit["returncode"] == 0
    assert "add b" in log["stdout"]


async def test_git_commit_stays_in_task_worktree_and_skips_hooks(tmp_path):
    main = tmp_path / "main"
    task = tmp_path / "task"
    main.mkdir()
    await _git(main, "init", "-b", "main")
    await _git(main, "config", "user.email", "test@example.com")
    await _git(main, "config", "user.name", "Tester")
    (main / "tracked.txt").write_text("base\n", encoding="utf-8")
    await _git(main, "add", "tracked.txt")
    await _git(main, "commit", "-m", "initial")
    await _git(main, "branch", "task/test")
    await _git(main, "worktree", "add", str(task), "task/test")
    marker = tmp_path / "hook-ran"
    hook = main / ".git" / "hooks" / "pre-commit"
    hook.write_text(f"#!/bin/sh\ntouch '{marker}'\nexit 1\n", encoding="utf-8")
    hook.chmod(0o755)
    (task / "tracked.txt").write_text("task change\n", encoding="utf-8")
    await _git(task, "add", "tracked.txt")
    workspace = SimpleNamespace(
        task_id="task",
        worktree_path=task,
        repository_root=main,
        branch_name="task/test",
        state=WorkspaceState.RUNNING,
    )
    manager = SimpleNamespace(
        get=lambda workspace_id: workspace if workspace_id == "workspace" else None,
        verify_git_identity=AsyncMock(),
    )
    context = {
        "task_id": "task",
        "workspace_id": "workspace",
        "execution_service": ExecutionService(HostExecutionBackend(), manager),
    }

    result = await git_commit(str(task), "feat: task-only", **context)

    assert result["returncode"] == 0
    assert not marker.exists()
    assert (main / "tracked.txt").read_text(encoding="utf-8") == "base\n"
    assert (await _git(main, "status", "--porcelain")).strip() == ""
    assert (await _git(task, "branch", "--show-current")).strip() == "task/test"


async def test_git_branch_show_current(tmp_path):
    repo = await _repo(tmp_path)

    result = await git_branch(str(repo), **_ctx(repo, "read-only"))

    assert result["returncode"] == 0
    assert result["stdout"].strip() == "task/test"


def test_runtime_registry_binds_git_tools():
    registry = create_runtime_registry()

    assert registry.get("git_diff").handler is not None
    assert registry.get("git_commit").permission_level == "write"


# ---------------------------------------------------------------------------
# git_status
# ---------------------------------------------------------------------------


async def test_git_status_clean_repo(tmp_path):
    repo = await _repo(tmp_path)

    result = json.loads(await git_status(str(repo), **_ctx(repo, "read-only")))

    assert result["branch"] == "task/test"
    assert result["is_clean"] is True
    assert result["modified"] == []
    assert result["untracked"] == []
    assert result["staged"] == []


async def test_git_status_classifies_changes(tmp_path):
    repo = await _repo(tmp_path)
    (repo / "a.txt").write_text("changed\n", encoding="utf-8")  # modified
    (repo / "new.txt").write_text("n\n", encoding="utf-8")  # untracked
    (repo / "b.txt").write_text("b\n", encoding="utf-8")  # untracked
    await _git(repo, "add", "b.txt")  # now staged/new

    result = json.loads(await git_status(str(repo), **_ctx(repo, "read-only")))

    assert result["is_clean"] is False
    assert "a.txt" in result["modified"]
    assert "new.txt" in result["untracked"]
    assert "b.txt" in result["added"]
    assert "b.txt" in result["staged"]


# ---------------------------------------------------------------------------
# git_smart_commit
# ---------------------------------------------------------------------------


async def test_git_smart_commit_nothing_to_commit(tmp_path):
    repo = await _repo(tmp_path)

    result = json.loads(await git_smart_commit(str(repo), **_ctx(repo)))

    assert result == {"message": "Nothing to commit."}


async def test_git_smart_commit_auto_message_for_new_file(tmp_path):
    repo = await _repo(tmp_path)
    (repo / "feature.py").write_text("print('hi')\n", encoding="utf-8")

    result = json.loads(await git_smart_commit(str(repo), **_ctx(repo)))

    assert result["files_changed"] == 1
    assert result["message"].startswith("feat")
    assert "feature.py" in result["message"]
    assert result["branch"] == "task/test"
    # git's default short hash is 7-12 hex chars depending on repo size.
    assert len(result["commit"]) >= 7
    assert all(c in "0123456789abcdef" for c in result["commit"])
    # Confirm the commit actually landed.
    log = await git_log(str(repo), limit=1, **_ctx(repo, "read-only"))
    assert result["commit"] in log["stdout"]


async def test_git_smart_commit_custom_message(tmp_path):
    repo = await _repo(tmp_path)
    (repo / "fix.txt").write_text("fix\n", encoding="utf-8")

    result = json.loads(
        await git_smart_commit(str(repo), message="fix: custom msg", **_ctx(repo))
    )

    assert result["message"] == "fix: custom msg"
    assert result["files_changed"] == 1


async def test_git_smart_commit_test_file_type(tmp_path):
    repo = await _repo(tmp_path)
    # Only test files are touched → commit type should be "test".
    (repo / "test_things.py").write_text("# tests\n", encoding="utf-8")
    (repo / "test_more.py").write_text("# more\n", encoding="utf-8")

    result = json.loads(await git_smart_commit(str(repo), **_ctx(repo)))

    assert result["message"].startswith("test")


# ---------------------------------------------------------------------------
# git_undo
# ---------------------------------------------------------------------------


async def test_git_undo_restores_changes_staged(tmp_path):
    repo = await _repo(tmp_path)
    (repo / "c.txt").write_text("c\n", encoding="utf-8")
    await git_smart_commit(str(repo), message="feat: add c", **_ctx(repo))

    context = await _approved_ctx(repo, "git_undo", {"cwd": str(repo)})
    result = json.loads(await git_undo(str(repo), **context))

    assert "Undone commit" in result["message"]
    assert "c.txt" in result["files"]
    # The file content survives the soft reset.
    assert (repo / "c.txt").read_text(encoding="utf-8") == "c\n"
    # And it should be staged again after undo.
    status = json.loads(await git_status(str(repo), **_ctx(repo, "read-only")))
    assert "c.txt" in status["staged"]


async def test_git_undo_without_commits_returns_error(tmp_path):
    await _git(tmp_path, "init")

    result = json.loads(await git_undo(str(tmp_path), **_ctx(tmp_path, "vcs.destructive-write")))

    assert "error" in result


# ---------------------------------------------------------------------------
# registry wiring for new tools
# ---------------------------------------------------------------------------


def test_runtime_registry_binds_new_git_and_test_tools():
    registry = create_runtime_registry()

    assert registry.get("git_status").handler is not None
    assert registry.get("git_smart_commit").handler is not None
    assert registry.get("git_undo").handler is not None
    assert registry.get("test_run").handler is not None
    assert registry.get("git_status").permission_level == "read"
    assert registry.get("git_smart_commit").permission_level == "write"
    assert registry.get("git_undo").permission_level == "write"
    assert registry.get("test_run").permission_level == "write"
