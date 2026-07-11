"""Deterministic Coding Agent -> verification -> ChangeSet approval evidence."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from khaos.agent import AgentConfig, AgentLoop, Message
from khaos.agent.approval import ApprovalBroker
from khaos.coding.execution import ExecutionService, HostExecutionBackend
from khaos.coding.verification import VerificationPipeline
from khaos.coding.verification.models import VerificationPlan, VerificationStep
from khaos.coding.workspace.application import ChangeSetApplicationService
from khaos.coding.workspace.apply import OutputMode
from khaos.coding.workspace.manager import WorkspaceError, WorkspaceManager
from khaos.db import Database
from khaos.modes import Mode, ModeManager
from khaos.permissions import PermissionEngine
from khaos.coding.task_manager import TaskManager
from khaos.tools import create_runtime_registry
from khaos.tools.scheduler import ToolScheduler


def _repo(path: Path) -> Path:
    path.mkdir()
    for command in (
        ["git", "init", "-q"],
        ["git", "config", "user.email", "test@example.com"],
        ["git", "config", "user.name", "Test"],
    ):
        subprocess.run(command, cwd=path, check=True)
    (path / "README.txt").write_text("before\n", encoding="utf-8")
    prompts = path / "prompts"
    prompts.mkdir()
    (prompts / "office.md").write_text("office", encoding="utf-8")
    (prompts / "coding.md").write_text("coding", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=path, check=True)
    subprocess.run(["git", "commit", "-qm", "base"], cwd=path, check=True)
    return path


class _FakeRouter:
    def __init__(self, responses: list[list[Message]]) -> None:
        self.responses = responses
        self.calls = 0

    async def call(self, _function, _messages, **_kwargs):
        response = self.responses[self.calls]
        self.calls += 1
        for item in response:
            yield item


async def _runtime(tmp_path: Path, repository: Path, responses: list[list[Message]]):
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    await db.create_session("session", mode="coding")
    modes = ModeManager(db, project_root=repository)
    await modes.switch(Mode.CODING)
    manager = WorkspaceManager(tmp_path / "worktrees")
    execution = ExecutionService(HostExecutionBackend(), manager)
    scheduler = ToolScheduler(create_runtime_registry(), PermissionEngine(db))
    loop = AgentLoop(
        AgentConfig(max_turns=4), modes, _FakeRouter(responses), db,
        tool_scheduler=scheduler, confirm_callback=lambda _request: {"approved": True},
        task_manager=TaskManager(), workspace_manager=manager,
        execution_service=execution, project_root=repository,
    )
    return db, manager, execution, loop


@pytest.mark.asyncio
async def test_fake_agent_runtime_changes_only_worktree_then_approved_apply(tmp_path: Path):
    repository = _repo(tmp_path / "repository")
    responses = [
        [Message(role="assistant", content="", tool_calls=[{
            "id": "write", "name": "write_file", "arguments": {"path": "README.txt", "content": "after\n"},
        }], stop_reason="tool_use")],
        [Message(role="assistant", content="", tool_calls=[{
            "id": "terminal", "name": "terminal", "arguments": {"command": "cat README.txt", "cwd": "PLACEHOLDER"},
        }], stop_reason="tool_use")],
        [Message(role="assistant", content="done", stop_reason="end_turn")],
    ]
    db, manager, execution, loop = await _runtime(tmp_path, repository, responses)
    # The model sees an absolute cwd only in this deterministic fixture.  The
    # scheduler still resolves and verifies it against the active Workspace.
    original_create = manager.create

    async def create_and_fill(*args, **kwargs):
        workspace = await original_create(*args, **kwargs)
        responses[1][0].tool_calls[0]["arguments"]["cwd"] = str(workspace.worktree_path)
        return workspace

    manager.create = create_and_fill  # type: ignore[method-assign]
    events = [event async for event in loop.run("change README", "session")]
    task = next(iter(loop.task_manager._tasks.values()))
    workspace = manager.get(task.metadata["workspace_id"])
    assert workspace is not None
    assert workspace.task_id == task.id
    assert workspace.base_sha
    assert (workspace.worktree_path / "README.txt").read_text(encoding="utf-8") == "after\n"
    assert (repository / "README.txt").read_text(encoding="utf-8") == "before\n"
    assert subprocess.run(["git", "status", "--porcelain"], cwd=repository, capture_output=True, text=True, check=True).stdout == ""
    assert any(event.metadata.get("name") == "terminal" and event.metadata.get("success") for event in events if event.event == "tool_result")

    pipeline = VerificationPipeline(execution_service=execution)
    plan = VerificationPlan((VerificationStep("check", "unit-test", (sys.executable, "-c", "assert open('README.txt').read() == 'after\\n'"), workspace.worktree_path),))
    report = await pipeline.run(plan, task_id=task.id, workspace_id=workspace.id)
    assert report[0].status == "passed"
    changeset = await manager.build_changeset(workspace.id)
    assert changeset.base_sha == workspace.base_sha
    assert changeset.content_hash
    assert changeset.changed_files == ("README.txt",)

    approvals = ApprovalBroker()
    application = ChangeSetApplicationService(manager, approvals)
    with pytest.raises(PermissionError, match="approval"):
        await application.apply(task_id=task.id, workspace_id=workspace.id, changeset=changeset, operation=OutputMode.APPLY_TO_CURRENT_BRANCH, approval_key=changeset.approval_key(OutputMode.APPLY_TO_CURRENT_BRANCH.value), expiry=10**12, requester="session")
    key = await application.request_approval(task_id=task.id, workspace_id=workspace.id, changeset=changeset, operation=OutputMode.APPLY_TO_CURRENT_BRANCH, requester="session", expiry=10**12)
    assert await approvals.approve_operation(key, "session")
    assert await application.apply(task_id=task.id, workspace_id=workspace.id, changeset=changeset, operation=OutputMode.APPLY_TO_CURRENT_BRANCH, approval_key=key, expiry=10**12, requester="session") == "applied"
    assert (repository / "README.txt").read_text(encoding="utf-8") == "after\n"
    with pytest.raises(PermissionError):
        await application.apply(task_id=task.id, workspace_id=workspace.id, changeset=changeset, operation=OutputMode.APPLY_TO_CURRENT_BRANCH, approval_key=key, expiry=10**12, requester="session")
    await execution.shutdown()
    await db.close()


@pytest.mark.asyncio
async def test_changeset_approval_rejects_identity_operation_and_diff_drift(tmp_path: Path):
    repository = _repo(tmp_path / "repository")
    manager = WorkspaceManager(tmp_path / "worktrees")
    workspace = await manager.create(repository, "task")
    (workspace.worktree_path / "README.txt").write_text("changed\n", encoding="utf-8")
    changeset = await manager.build_changeset(workspace.id)
    application = ChangeSetApplicationService(manager, ApprovalBroker())
    key = await application.request_approval(task_id="task", workspace_id=workspace.id, changeset=changeset, operation=OutputMode.PATCH_ONLY, requester="one", expiry=10**12)
    assert await application.approval_broker.approve_operation(key, "one")
    with pytest.raises(PermissionError):
        await application.apply(task_id="task", workspace_id=workspace.id, changeset=changeset, operation=OutputMode.PATCH_ONLY, approval_key=key, expiry=10**12, requester="two")
    # A distinct approval becomes stale after any Worktree diff drift.
    key = await application.request_approval(task_id="task", workspace_id=workspace.id, changeset=changeset, operation=OutputMode.PATCH_ONLY, requester="one", expiry=10**12)
    assert await application.approval_broker.approve_operation(key, "one")
    (workspace.worktree_path / "README.txt").write_text("drifted\n", encoding="utf-8")
    with pytest.raises(PermissionError):
        await application.apply(task_id="task", workspace_id=workspace.id, changeset=changeset, operation=OutputMode.PATCH_ONLY, approval_key=key, expiry=10**12, requester="one")


@pytest.mark.asyncio
async def test_output_modes_have_deterministic_changeset_coverage(tmp_path: Path):
    repository = _repo(tmp_path / "repository")
    manager = WorkspaceManager(tmp_path / "worktrees")
    workspace = await manager.create(repository, "task")
    (workspace.worktree_path / "README.txt").write_text("changed\n", encoding="utf-8")
    change = await manager.build_changeset(workspace.id)
    assert change.patch
    # Patch-only is immutable output; commit-in-worktree records only the task branch.
    from khaos.coding.workspace.apply import output_changeset
    assert await output_changeset(manager, workspace.id, change, OutputMode.PATCH_ONLY) == change.patch
    commit = await output_changeset(manager, workspace.id, change, OutputMode.COMMIT_IN_WORKTREE, message="task change")
    assert commit
    assert subprocess.run(["git", "status", "--porcelain"], cwd=repository, capture_output=True, text=True, check=True).stdout == ""
