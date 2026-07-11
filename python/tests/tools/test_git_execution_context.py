from types import SimpleNamespace
import inspect
import json

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
    git_smart_commit,
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
    workspace = SimpleNamespace(
        task_id="task-a",
        worktree_path=tmp_path,
        repository_root=tmp_path.parent / "main-worktree",
        branch_name="task/test",
        state=state,
    )
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


@pytest.mark.parametrize(
    ("handler", "outputs"),
    [
        (
            lambda context: git_commit(".", "feat: safe; touch /tmp/nope", **context),
            ["task/test\n", "[task/test abcdef1] feat: safe\n"],
        ),
        (
            lambda context: git_branch(".", name="task/next", **context),
            ["task/test\n", ""],
        ),
    ],
)
async def test_local_git_writes_use_execution_service_with_fixed_policy(
    tmp_path, handler, outputs
):
    service, context = _read_context(tmp_path, outputs=outputs)

    result = await handler(context)

    write_request = service.requests[-1]
    assert write_request.access_mode == "workspace-write"
    assert write_request.cwd == tmp_path.resolve()
    assert write_request.writable_roots == (tmp_path.resolve(),)
    assert write_request.network_policy is NetworkPolicy.NONE
    assert write_request.environment["GIT_EDITOR"] == ":"
    assert write_request.environment["GIT_TERMINAL_PROMPT"] == "0"
    assert "HOME" not in write_request.allowed_environment_keys
    assert "--no-verify" in write_request.argv or "branch" in write_request.argv
    assert result["returncode"] == 0


async def test_smart_commit_routes_write_and_internal_reads_separately(tmp_path):
    service, context = _read_context(
        tmp_path,
        outputs=[
            "task/test\n",
            "",
            "A\tfeature.py\n",
            "task/test\n",
            "[task/test abcdef1] feat: add feature\n",
            "task/test\n",
        ],
    )

    result = await git_smart_commit(".", **context)

    payload = json.loads(result)
    assert payload["commit"] == "abcdef1"
    assert [request.access_mode for request in service.requests] == [
        "read-only",
        "workspace-write",
        "read-only",
        "read-only",
        "workspace-write",
        "read-only",
    ]
    assert service.requests[1].argv[-4:] == ("add", "-A", "--", ".")
    assert "--no-ext-diff" in service.requests[2].argv


@pytest.mark.parametrize("branch", ["main", "master"])
async def test_commit_rejects_protected_or_detached_branch(tmp_path, branch):
    service, context = _read_context(tmp_path, outputs=[f"{branch}\n"])
    service.workspace_manager.get("w").branch_name = branch
    with pytest.raises(PermissionError, match="protected"):
        await git_commit(".", "message", **context)

    service, context = _read_context(tmp_path, outputs=[""])
    with pytest.raises(PermissionError, match="detached"):
        await git_commit(".", "message", **context)


@pytest.mark.parametrize(
    "name",
    ["main", "master", "--force", "task/../main", "task//bad", "task/x.lock"],
)
async def test_branch_create_rejects_protected_or_injected_names(tmp_path, name):
    _, context = _read_context(tmp_path)
    with pytest.raises(ValueError):
        await git_branch(".", name=name, **context)


def test_migrated_local_write_handlers_do_not_create_subprocess():
    for handler in (git_commit, git_smart_commit, git_branch):
        assert "create_subprocess" not in inspect.getsource(handler)


@pytest.mark.parametrize(
    "state",
    [WorkspaceState.CANCELLED, WorkspaceState.FAILED, WorkspaceState.CLEANED],
)
async def test_local_git_write_rejects_inactive_workspace(tmp_path, state):
    _, context = _read_context(tmp_path, state=state)
    with pytest.raises(PermissionError, match="not available"):
        await git_commit(".", "message", **context)


async def test_local_git_write_rejects_repo_and_branch_mismatch(tmp_path):
    service, context = _read_context(tmp_path, outputs=["other/task\n"])
    with pytest.raises(PermissionError, match="repo must match"):
        await git_commit(str(tmp_path.parent), "message", **context)
    with pytest.raises(PermissionError, match="does not match"):
        await git_commit(".", "message", **context)
    assert all(request.access_mode == "read-only" for request in service.requests)
