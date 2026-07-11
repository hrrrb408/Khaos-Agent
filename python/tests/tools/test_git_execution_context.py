from types import SimpleNamespace
import inspect

import pytest

from khaos.coding.execution.models import ExecutionResult, NetworkPolicy
from khaos.coding.workspace.models import WorkspaceState
from khaos.tools.git_tools import (
    git_branch,
    git_commit,
    git_diff,
    git_log,
    git_pr_body,
    git_push,
    git_status,
    git_undo,
)


class _RecordingExecutionService:
    def __init__(self, workspace, outputs=None):
        self.workspace_manager = SimpleNamespace(get=lambda workspace_id: workspace if workspace_id == "w" else None)
        self.requests = []
        self.outputs = iter(outputs or [""])

    async def execute(self, request):
        self.requests.append(request)
        return ExecutionResult("exec", "passed", 0, next(self.outputs, ""), "", 1)


def _read_context(tmp_path, *, task_id="task-a", state=WorkspaceState.RUNNING, outputs=None):
    workspace = SimpleNamespace(task_id="task-a", worktree_path=tmp_path, state=state)
    service = _RecordingExecutionService(workspace, outputs)
    return service, {
        "task_id": task_id,
        "workspace_id": "w",
        "execution_service": service,
        "access_mode": "vcs.remote-write",
        "network_policy": "unrestricted-with-approval",
    }


async def test_git_write_requires_workspace_context(tmp_path):
    with pytest.raises(PermissionError, match="TaskWorkspace"):
        await git_commit(str(tmp_path), "message")


async def test_destructive_and_remote_write_require_workspace_context(tmp_path):
    with pytest.raises(PermissionError, match="TaskWorkspace"):
        await git_undo(str(tmp_path))
    with pytest.raises(PermissionError, match="TaskWorkspace"):
        await git_push(str(tmp_path))


async def test_cross_task_and_cancelled_workspace_are_rejected(tmp_path):
    workspace = SimpleNamespace(task_id="task-a", worktree_path=tmp_path, state=WorkspaceState.RUNNING)
    manager = SimpleNamespace(get=lambda _: workspace)
    service = SimpleNamespace(workspace_manager=manager)
    with pytest.raises(PermissionError, match="binding"):
        await git_commit(str(tmp_path), "message", task_id="task-b", workspace_id="w", execution_service=service)
    workspace.state = WorkspaceState.CANCELLED
    with pytest.raises(PermissionError, match="not available"):
        await git_commit(str(tmp_path), "message", task_id="task-a", workspace_id="w", execution_service=service)


@pytest.mark.parametrize(
    ("handler", "outputs"),
    [
        (lambda context: git_diff(".", **context), ["diff"]),
        (lambda context: git_log(".", **context), ["log"]),
        (lambda context: git_branch(".", **context), ["main\n"]),
        (lambda context: git_status(".", **context), ["main\n", ""]),
        (
            lambda context: git_pr_body(".", **context),
            ["abc\tfeat: change\tTester\n", "file.py\n"],
        ),
    ],
)
async def test_public_git_reads_use_execution_service_with_fixed_policy(
    tmp_path, handler, outputs
):
    service, context = _read_context(tmp_path, outputs=outputs)

    await handler(context)

    assert service.requests
    for request in service.requests:
        assert request.cwd == tmp_path.resolve()
        assert request.access_mode == "read-only"
        assert request.network_policy is NetworkPolicy.NONE
        assert request.writable_roots == ()
        assert request.environment["GIT_TERMINAL_PROMPT"] == "0"
        assert request.environment["GIT_PAGER"] == "cat"
        assert not ({"SSH_AUTH_SOCK", "GITHUB_TOKEN", "GH_TOKEN"} & request.allowed_environment_keys)


async def test_git_read_requires_workspace_and_rejects_other_repo(tmp_path):
    with pytest.raises(PermissionError, match="TaskWorkspace"):
        await git_diff(str(tmp_path))

    service, context = _read_context(tmp_path)
    with pytest.raises(PermissionError, match="repo must match"):
        await git_diff(str(tmp_path.parent), **context)
    assert service.requests == []


@pytest.mark.parametrize(
    "state",
    [WorkspaceState.CANCELLED, WorkspaceState.FAILED, WorkspaceState.CLEANED],
)
async def test_git_read_rejects_inactive_workspace(tmp_path, state):
    _, context = _read_context(tmp_path, state=state)
    with pytest.raises(PermissionError, match="not available"):
        await git_log(".", **context)


async def test_git_read_rejects_cross_task_workspace(tmp_path):
    _, context = _read_context(tmp_path, task_id="task-b")
    with pytest.raises(PermissionError, match="binding"):
        await git_status(".", **context)


async def test_access_mode_cannot_downgrade_branch_write(tmp_path):
    service, context = _read_context(tmp_path)
    context.pop("task_id")
    context.pop("workspace_id")
    context["access_mode"] = "read-only"
    with pytest.raises(PermissionError, match="vcs.write"):
        await git_branch(".", name="feature", **context)


def test_public_git_read_handlers_do_not_create_subprocess():
    for handler in (git_diff, git_log, git_status, git_pr_body, git_branch):
        assert "create_subprocess" not in inspect.getsource(handler)
