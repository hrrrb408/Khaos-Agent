import asyncio
import hashlib
import inspect
import json
import os
import time
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

pytestmark = pytest.mark.posix_host
from khaos.agent.approval import ApprovalBroker
from khaos.coding.execution.host import HostExecutionBackend
from khaos.coding.execution.models import ExecutionResult, NetworkPolicy
from khaos.coding.execution.service import ExecutionService
from khaos.coding.workspace.models import WorkspaceState
from khaos.tools.git_tools import (
    git_branch,
    git_commit,
    git_create_branch,
    git_diff,
    git_log,
    git_pr_body,
    git_push,
    git_smart_commit,
    git_status,
    git_undo,
    prepare_destructive_git_approval,
    prepare_remote_git_approval,
)
from khaos.tools.registry import create_runtime_registry


class _RecordingLocalRemoteBackend(HostExecutionBackend):
    def __init__(self):
        self.requests = []

    async def execute(self, request):
        self.requests.append(request)
        # Explicitly replace the authoritative profile for this test-only
        # local bare remote. Mutating the legacy network field alone must not
        # downgrade an approved production request.
        local_profile = replace(
            request.permission_profile,
            network=NetworkPolicy.NONE,
            network_broker=None,
        )
        return await super().execute(
            replace(request, permission_profile=local_profile)
        )


class _RecordingExecutionService:
    def __init__(self, workspace, outputs=None):
        self.workspace_manager = SimpleNamespace(
            get=lambda workspace_id: workspace if workspace_id == "w" else None,
            verify_git_identity=AsyncMock(),
        verify_execution_root=AsyncMock(),
        )
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
    manager = SimpleNamespace(
        get=lambda _: workspace, verify_git_identity=AsyncMock(), verify_execution_root=AsyncMock()
    )
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
    _service, context = _read_context(tmp_path)
    context.pop("task_id")
    context.pop("workspace_id")
    context["access_mode"] = "read-only"
    with pytest.raises(PermissionError, match="vcs.write"):
        await git_branch(".", name="feature", **context)


def test_public_git_read_handlers_do_not_create_subprocess():
    for handler in (git_diff, git_log, git_status, git_pr_body, git_branch):
        assert "create_subprocess" not in inspect.getsource(handler)


class _ValidNetworkLease:
    """Test double that passes the deterministic network authority preflight."""

    def validate(self) -> None:
        return None


class _InvalidNetworkLease:
    """Test double whose broker attestation no longer validates."""

    def validate(self) -> None:
        from khaos.security.network_broker import NetworkBrokerError

        raise NetworkBrokerError("network lease attestation rejected")


async def _run_git(repo, *args):
    process = await asyncio.create_subprocess_exec(
        "git", *args, cwd=str(repo), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await process.communicate()
    assert process.returncode == 0, stderr.decode()
    return stdout.decode().strip()


async def _destructive_repo(tmp_path):
    main = tmp_path / "main"
    task = tmp_path / "task"
    main.mkdir()
    await _run_git(main, "init", "-b", "main")
    await _run_git(main, "config", "user.email", "test@example.com")
    await _run_git(main, "config", "user.name", "Tester")
    (main / "file.txt").write_text("base\n", encoding="utf-8")
    await _run_git(main, "add", "file.txt")
    await _run_git(main, "commit", "-m", "base")
    await _run_git(main, "branch", "task/test")
    await _run_git(main, "worktree", "add", str(task), "task/test")
    workspace = SimpleNamespace(
        task_id="task",
        worktree_path=task,
        repository_root=main,
        branch_name="task/test",
        state=WorkspaceState.RUNNING,
    )
    manager = SimpleNamespace(
        get=lambda workspace_id: workspace if workspace_id == "workspace" else None,
        require=lambda workspace_id, **_authority: (
            workspace if workspace_id == "workspace" else None
        ),
        verify_git_identity=AsyncMock(),
        verify_execution_root=AsyncMock(),
    )
    service = ExecutionService(HostExecutionBackend(), manager)
    return main, task, workspace, service


async def _approve_destructive(service, tool_name, arguments, *, requester="session", approval_id="approval"):
    broker = ApprovalBroker()
    context = {
        "task_id": "task",
        "workspace_id": "workspace",
        "execution_service": service,
        "approval_broker": broker,
    }
    approval = await prepare_destructive_git_approval(
        tool_name, arguments, context, requester=requester, approval_id=approval_id
    )
    assert approval is not None
    assert await broker.approve_operation(approval_id, requester)
    return {
        "task_id": "task",
        "workspace_id": "workspace",
        "execution_service": service,
        "approval_context": approval,
    }, broker


async def _remote_repo(tmp_path):
    main, task, workspace, original_service = await _destructive_repo(tmp_path)
    remote = tmp_path / "remote.git"
    remote.mkdir()
    await _run_git(remote, "init", "--bare")
    await _run_git(task, "remote", "add", "origin", str(remote))
    backend = _RecordingLocalRemoteBackend()
    service = ExecutionService(backend, original_service.workspace_manager)
    return main, task, workspace, remote, service, backend


async def _approve_remote(service, task, *, requester="session", approval_id="push", credential_context=None):
    broker = ApprovalBroker()
    tool_context = {
        "task_id": "task",
        "workspace_id": "workspace",
        "execution_service": service,
        "approval_broker": broker,
        "network_policy": "unrestricted-with-approval",
        "credential_context": credential_context,
        "network_lease": _ValidNetworkLease(),
    }
    approval = await prepare_remote_git_approval(
        "git_push",
        {"cwd": str(task), "remote": "origin", "branch": ""},
        tool_context,
        requester=requester,
        approval_id=approval_id,
    )
    assert approval is not None
    assert await broker.approve_operation(approval_id, requester)
    return {
        "task_id": "task",
        "workspace_id": "workspace",
        "execution_service": service,
        "approval_context": approval,
        "network_policy": "unrestricted-with-approval",
        "credential_context": credential_context,
        "network_lease": _ValidNetworkLease(),
    }, broker


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
    assert write_request.environment["GIT_CONFIG_GLOBAL"] == os.devnull
    assert write_request.environment["GIT_CONFIG_SYSTEM"] == os.devnull
    assert write_request.environment["GIT_OPTIONAL_LOCKS"] == "0"
    assert "core.fsmonitor=false" in write_request.argv
    assert "core.untrackedCache=false" in write_request.argv
    assert "core.preloadIndex=false" in write_request.argv
    assert "index.threads=1" in write_request.argv
    if "--no-verify" in write_request.argv:
        assert "--no-status" in write_request.argv
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


def test_destructive_git_handlers_do_not_create_subprocess():
    for handler in (git_undo, git_create_branch, git_branch):
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


async def test_git_undo_uses_execution_service_and_approval_is_one_shot(tmp_path):
    main, task, _, service = await _destructive_repo(tmp_path)
    (task / "second.txt").write_text("second\n", encoding="utf-8")
    await _run_git(task, "add", "second.txt")
    await _run_git(task, "commit", "-m", "second")
    context, _ = await _approve_destructive(service, "git_undo", {"cwd": str(task)})

    result = json.loads(await git_undo(str(task), **context))

    assert result["message"].startswith("Undone commit")
    assert "second.txt" in result["files"]
    assert await _run_git(main, "status", "--porcelain") == ""
    with pytest.raises(PermissionError, match="replayed"):
        await git_undo(str(task), **context)


@pytest.mark.parametrize("drift", ["head", "diff"])
async def test_destructive_approval_rejects_head_or_diff_drift(tmp_path, drift):
    _, task, _, service = await _destructive_repo(tmp_path)
    (task / "second.txt").write_text("second\n", encoding="utf-8")
    await _run_git(task, "add", "second.txt")
    await _run_git(task, "commit", "-m", "second")
    context, _ = await _approve_destructive(service, "git_undo", {"cwd": str(task)})
    if drift == "head":
        (task / "third.txt").write_text("third\n", encoding="utf-8")
        await _run_git(task, "add", "third.txt")
        await _run_git(task, "commit", "-m", "third")
    else:
        (task / "second.txt").write_text("changed after approval\n", encoding="utf-8")

    with pytest.raises(PermissionError, match="stale"):
        await git_undo(str(task), **context)


async def test_destructive_approval_rejects_requester_operation_expiry(tmp_path):
    _, task, _, service = await _destructive_repo(tmp_path)
    (task / "second.txt").write_text("second\n", encoding="utf-8")
    await _run_git(task, "add", "second.txt")
    await _run_git(task, "commit", "-m", "second")

    context, broker = await _approve_destructive(service, "git_undo", {"cwd": str(task)})
    context["approval_context"]["binding"]["requester"] = "other"
    with pytest.raises(PermissionError, match="stale"):
        await git_undo(str(task), **context)

    context, _ = await _approve_destructive(service, "git_undo", {"cwd": str(task)}, approval_id="operation")
    with pytest.raises(PermissionError, match="stale"):
        await git_branch(str(task), name="task/wrong-operation", checkout=True, **context)

    context, broker = await _approve_destructive(service, "git_undo", {"cwd": str(task)}, approval_id="expired")
    broker._operation_approvals["expired"]["expiry"] = time.time() - 1
    with pytest.raises(PermissionError, match="stale"):
        await git_undo(str(task), **context)


async def test_branch_checkout_and_create_branch_are_approved_workspace_operations(tmp_path):
    main, task, workspace, service = await _destructive_repo(tmp_path)
    context, _ = await _approve_destructive(
        service,
        "git_branch",
        {"repo": str(task), "name": "task/next", "checkout": True},
        approval_id="branch",
    )
    result = await git_branch(str(task), name="task/next", checkout=True, **context)
    assert result["returncode"] == 0
    assert workspace.branch_name == "task/next"

    context, _ = await _approve_destructive(
        service,
        "git_create_branch",
        {"cwd": str(task), "branch_name": "task/from-main", "from_base": "main"},
        approval_id="create",
    )
    payload = json.loads(
        await git_create_branch(str(task), "task/from-main", "main", **context)
    )
    assert payload["created"] is True
    assert workspace.branch_name == "task/from-main"
    assert await _run_git(main, "status", "--porcelain") == ""


async def test_destructive_git_requires_approval_and_uses_temporary_home(tmp_path):
    head = "a" * 40
    diff_hash = hashlib.sha256(b"\0").hexdigest()
    workspace = SimpleNamespace(
        task_id="task-a",
        worktree_path=tmp_path,
        repository_root=tmp_path.parent / "main-worktree",
        branch_name="task/test",
        state=WorkspaceState.RUNNING,
    )
    service = _RecordingExecutionService(
        workspace, outputs=[head, "", "", "task/test\n", ""]
    )
    context = {"task_id": "task-a", "workspace_id": "w", "execution_service": service}
    with pytest.raises(PermissionError, match="requires approval"):
        await git_branch(".", name="task/new", checkout=True, **context)

    broker = ApprovalBroker()
    expiry = time.time() + 60
    binding = {
        "task_id": "task-a",
        "workspace_id": "w",
        "operation": "git.create-and-switch",
        "target": f"task/new@{head}",
        "head": head,
        "diff_hash": diff_hash,
        "expiry": expiry,
        "requester": "session",
    }
    await broker.register_operation("approval", binding, expiry)
    assert await broker.approve_operation("approval", "session")
    context["approval_context"] = {
        "approval_broker": broker,
        "approval_id": "approval",
        "binding": binding,
    }
    await git_branch(".", name="task/new", checkout=True, **context)
    request = service.requests[-1]
    assert request.access_mode == "workspace-write"
    assert request.network_policy is NetworkPolicy.NONE
    assert request.environment["HOME"].startswith(os.path.realpath("/"))
    assert not os.path.exists(request.environment["HOME"])
    assert f"core.hooksPath={os.devnull}" in request.argv


async def test_destructive_preflight_rejects_dirty_existing_and_detached(tmp_path):
    _, task, _, service = await _destructive_repo(tmp_path)
    broker = ApprovalBroker()
    tool_context = {
        "task_id": "task",
        "workspace_id": "workspace",
        "execution_service": service,
        "approval_broker": broker,
    }
    (task / "dirty.txt").write_text("dirty\n", encoding="utf-8")
    with pytest.raises(PermissionError, match="clean worktree"):
        await prepare_destructive_git_approval(
            "git_branch",
            {"repo": str(task), "name": "task/new", "checkout": True},
            tool_context,
            requester="session",
            approval_id="dirty",
        )
    (task / "dirty.txt").unlink()
    await _run_git(task, "branch", "task/existing")
    with pytest.raises(PermissionError, match="already exists"):
        await prepare_destructive_git_approval(
            "git_branch",
            {"repo": str(task), "name": "task/existing", "checkout": True},
            tool_context,
            requester="session",
            approval_id="existing",
        )
    await _run_git(task, "checkout", "--detach")
    with pytest.raises(PermissionError, match="detached"):
        await prepare_destructive_git_approval(
            "git_undo",
            {"cwd": str(task)},
            tool_context,
            requester="session",
            approval_id="detached",
        )


@pytest.mark.parametrize(
    "violation",
    ["cross-task", "cancelled", "failed", "cleaned", "main-repo"],
)
async def test_destructive_preflight_rejects_workspace_violations(tmp_path, violation):
    main, task, workspace, service = await _destructive_repo(tmp_path)
    task_id = "task"
    repo = task
    if violation == "cross-task":
        task_id = "other-task"
    elif violation == "main-repo":
        repo = main
    else:
        workspace.state = WorkspaceState(violation)
    with pytest.raises(PermissionError):
        await prepare_destructive_git_approval(
            "git_undo",
            {"cwd": str(repo)},
            {
                "task_id": task_id,
                "workspace_id": "workspace",
                "execution_service": service,
                "approval_broker": ApprovalBroker(),
            },
            requester="session",
            approval_id="invalid",
        )


async def test_git_push_uses_execution_service_and_approval_is_one_shot(tmp_path):
    main, task, _, remote, service, backend = await _remote_repo(tmp_path)
    context, _ = await _approve_remote(service, task)

    result = json.loads(await git_push(str(task), **context))

    assert result["pushed"] is True
    assert result["remote"] == "origin"
    assert result["branch"] == "task/test"
    assert result["remote_host"] == "local"
    push_request = backend.requests[-1]
    assert push_request.network_policy is NetworkPolicy.BROKERED
    assert push_request.permission_profile.network_broker is not None
    assert push_request.argv[-4:] == (
        "push", "--set-upstream", "origin", "task/test:task/test"
    )
    assert not os.path.exists(push_request.environment["HOME"])
    assert not ({"SSH_AUTH_SOCK", "GITHUB_TOKEN", "GH_TOKEN", "AWS_ACCESS_KEY_ID"} & push_request.allowed_environment_keys)
    assert await _run_git(main, "status", "--porcelain") == ""
    assert await _run_git(remote, "show-ref", "--verify", "refs/heads/task/test")

    replay = json.loads(await git_push(str(task), **context))
    assert replay["pushed"] is False
    assert "replayed" in replay["error"]


@pytest.mark.parametrize("drift", ["head", "diff", "remote"])
async def test_git_push_rejects_approval_drift(tmp_path, drift):
    _, task, _, _, service, _ = await _remote_repo(tmp_path)
    context, _ = await _approve_remote(service, task)
    if drift == "head":
        (task / "head.txt").write_text("head\n", encoding="utf-8")
        await _run_git(task, "add", "head.txt")
        await _run_git(task, "commit", "-m", "head drift")
    elif drift == "diff":
        (task / "file.txt").write_text("diff drift\n", encoding="utf-8")
    else:
        replacement = tmp_path / "replacement.git"
        replacement.mkdir()
        await _run_git(replacement, "init", "--bare")
        await _run_git(task, "remote", "set-url", "origin", str(replacement))

    result = json.loads(await git_push(str(task), **context))
    assert result["pushed"] is False
    assert "stale" in result["error"]


async def test_git_push_requires_network_credential_and_approval(tmp_path):
    _, task, _, _, service, _ = await _remote_repo(tmp_path)
    broker = ApprovalBroker()
    base_context = {
        "task_id": "task",
        "workspace_id": "workspace",
        "execution_service": service,
        "approval_broker": broker,
    }
    with pytest.raises(PermissionError, match="network permission"):
        await prepare_remote_git_approval(
            "git_push", {"cwd": str(task)}, base_context,
            requester="session", approval_id="network",
        )

    await _run_git(task, "remote", "set-url", "origin", "git@example.com:org/repo.git")
    with pytest.raises(PermissionError, match="credential authorization"):
        await prepare_remote_git_approval(
            "git_push",
            {"cwd": str(task)},
            {**base_context, "network_policy": "unrestricted-with-approval"},
            requester="session",
            approval_id="credential",
        )

    no_approval = json.loads(await git_push(
        str(task), network_policy="unrestricted-with-approval",
        task_id="task", workspace_id="workspace", execution_service=service,
    ))
    assert no_approval["pushed"] is False
    assert "requires approval" in no_approval["error"]


async def test_git_push_network_policy_is_server_bound_and_backend_fails_closed(tmp_path):
    _, task, _, _, service, _ = await _remote_repo(tmp_path)
    context, _ = await _approve_remote(service, task, approval_id="policy")
    context["network_policy"] = "none"
    denied = json.loads(await git_push(str(task), **context))
    assert denied["pushed"] is False
    assert "server-authorized network policy" in denied["error"]
    context["network_policy"] = "unrestricted-with-approval"
    assert "replayed" in json.loads(await git_push(str(task), **context))["error"]

    host_service = ExecutionService(HostExecutionBackend(), service.workspace_manager)
    context, _ = await _approve_remote(host_service, task, approval_id="backend")
    unsupported = json.loads(await git_push(str(task), **context))
    assert unsupported["pushed"] is False
    assert "host backend only permits" in unsupported["error"]


async def test_git_push_injects_only_single_use_authorized_credential_scope(tmp_path):
    head = "b" * 40
    remote_url = "git@example.com:org/repo.git"
    workspace = SimpleNamespace(
        task_id="task-a",
        worktree_path=tmp_path,
        repository_root=tmp_path.parent / "main-worktree",
        branch_name="task/test",
        state=WorkspaceState.RUNNING,
    )
    service = _RecordingExecutionService(
        workspace,
        outputs=["task/test\n", "task/test\n", remote_url, head, "", "", ""],
    )
    broker = ApprovalBroker()
    expiry = time.time() + 60
    binding = {
        "task_id": "task-a",
        "workspace_id": "w",
        "operation": "git.push-set-upstream",
        "target": "origin/task/test:task/test",
        "remote": "origin",
        "remote_url": remote_url,
        "remote_host": "example.com",
        "local_branch": "task/test",
        "remote_branch": "task/test",
        "head": head,
        "diff_hash": hashlib.sha256(b"\0").hexdigest(),
        "refspec": "task/test:task/test",
        "set_upstream": True,
        "network_policy": "unrestricted-with-approval",
        "credential_scope": "ssh-agent",
        "expiry": expiry,
        "requester": "session",
    }
    await broker.register_operation("credential", binding, expiry)
    assert await broker.approve_operation("credential", "session")
    credential_context = {
        "scope": "ssh-agent",
        "environment": {"SSH_AUTH_SOCK": "/private/tmp/test-agent.sock"},
    }
    result = json.loads(await git_push(
        ".",
        task_id="task-a",
        workspace_id="w",
        execution_service=service,
        approval_context={
            "approval_broker": broker,
            "approval_id": "credential",
            "binding": binding,
        },
        network_policy="unrestricted-with-approval",
        credential_context=credential_context,
        network_lease=_ValidNetworkLease(),
    ))
    assert result["pushed"] is True
    request = service.requests[-1]
    assert request.environment["SSH_AUTH_SOCK"] == "/private/tmp/test-agent.sock"
    assert "GITHUB_TOKEN" not in request.allowed_environment_keys
    assert "GH_TOKEN" not in request.allowed_environment_keys
    assert not os.path.exists(request.environment["HOME"])


async def test_git_push_rejects_requester_operation_and_expiry(tmp_path):
    _, task, _, _, service, _ = await _remote_repo(tmp_path)
    context, _ = await _approve_remote(service, task, approval_id="requester")
    context["approval_context"]["binding"]["requester"] = "other"
    assert "stale" in json.loads(await git_push(str(task), **context))["error"]

    context, broker = await _approve_remote(service, task, approval_id="operation")
    context["approval_context"]["binding"]["operation"] = "git.other"
    broker._operation_approvals["operation"]["binding"]["operation"] = "git.other"
    # The mutable compatibility mirror is not authorization authority. The
    # durable canonical digest remains bound to the real git.push operation.
    result = json.loads(await git_push(str(task), **context))
    assert result["pushed"] is True

    context, broker = await _approve_remote(service, task, approval_id="expired")
    broker._operation_approvals["expired"]["expiry"] = time.time() - 1
    assert "stale" in json.loads(await git_push(str(task), **context))["error"]


@pytest.mark.parametrize(
    ("remote", "branch"),
    [
        ("https://example.com/repo.git", ""),
        ("-c", ""),
        ("origin", "main"),
        ("origin", "--force"),
        ("origin", ":task/test"),
    ],
)
async def test_git_push_rejects_remote_and_refspec_injection(tmp_path, remote, branch):
    _, task, _, _, service, _ = await _remote_repo(tmp_path)
    with pytest.raises((ValueError, PermissionError)):
        await git_push(
            str(task), remote=remote, branch=branch,
            task_id="task", workspace_id="workspace", execution_service=service,
        )


class _CountingCredentialHarness:
    """Recording push harness with a broker-backed counting Git provider."""

    def __init__(self, tmp_path):
        from khaos.security.credential_broker import CredentialBroker
        from khaos.security.resource_scope import CredentialScope

        self.remote_url = "git@example.com:org/repo.git"
        self.head = "c" * 40
        self.workspace = SimpleNamespace(
            task_id="task-a",
            worktree_path=tmp_path,
            repository_root=tmp_path.parent / "main-worktree",
            branch_name="task/test",
            state=WorkspaceState.RUNNING,
        )
        self.loader_calls: list[int] = []
        self.broker = CredentialBroker()
        self.scope = CredentialScope(
            provider="git",
            names=frozenset({"ssh-agent"}),
            operations=frozenset({"git_push"}),
        )
        self.broker.register(self.scope, self._loader)
        self.lease = self.broker.issue_named(
            provider="git",
            name="ssh-agent",
            operation="git_push",
            binding={"remote_url": self.remote_url, "host": "example.com"},
        )

    def _loader(self):
        self.loader_calls.append(1)
        return {"SSH_AUTH_SOCK": "/private/tmp/test-agent.sock"}

    def service(self, outputs):
        return _RecordingExecutionService(self.workspace, outputs=outputs)

    async def prepare(self, approval_broker, approval_id):
        tool_context = {
            "task_id": "task-a",
            "workspace_id": "w",
            "execution_service": self.service(
                ["task/test\n", self.remote_url, self.head, "", ""]
            ),
            "approval_broker": approval_broker,
            "network_policy": "unrestricted-with-approval",
            "credential_lease": self.lease,
            "credential_broker": self.broker,
        }
        return await prepare_remote_git_approval(
            "git_push",
            {"cwd": ".", "remote": "origin", "branch": ""},
            tool_context,
            requester="session",
            approval_id=approval_id,
        )


async def test_git_push_provider_loader_runs_exactly_once_and_only_after_approval(tmp_path):
    """Closure matrix: prepare/reject/consume keep the loader at zero."""
    harness = _CountingCredentialHarness(tmp_path)
    broker = ApprovalBroker()

    # 1. Approval preparation touches credential metadata only.
    approval = await harness.prepare(broker, "push-1")
    assert approval is not None
    assert harness.loader_calls == []
    assert f"credential-lease:{harness.lease.lease_id}" in harness.broker.owned_resources()

    # 2. User rejects: the approval is cancelled and can never reach a push.
    await broker.cancel_operation("push-1")
    assert harness.loader_calls == []
    denied = json.loads(await git_push(
        ".",
        task_id="task-a",
        workspace_id="w",
        execution_service=harness.service(
            ["task/test\n", "task/test\n", harness.remote_url, harness.head, "", ""]
        ),
        approval_context=approval,
        network_policy="unrestricted-with-approval",
        credential_context=harness.lease,
        credential_broker=harness.broker,
        network_lease=_ValidNetworkLease(),
    ))
    assert denied["pushed"] is False
    assert "replayed" in denied["error"] or "stale" in denied["error"]
    assert harness.loader_calls == []
    # The one-shot lease survived rejection untouched.
    assert f"credential-lease:{harness.lease.lease_id}" in harness.broker.owned_resources()

    # 3. Approval consumption also stays metadata-only; only the exact push
    #    runs the provider loader, and it runs exactly once.
    approval = await harness.prepare(broker, "push-2")
    assert await broker.approve_operation("push-2", "session")
    assert harness.loader_calls == []
    result = json.loads(await git_push(
        ".",
        task_id="task-a",
        workspace_id="w",
        execution_service=harness.service(
            ["task/test\n", "task/test\n", harness.remote_url, harness.head, "", "", ""]
        ),
        approval_context=approval,
        network_policy="unrestricted-with-approval",
        credential_context=harness.lease,
        credential_broker=harness.broker,
        network_lease=_ValidNetworkLease(),
    ))
    assert result["pushed"] is True
    assert result["credential_scope"] == "ssh-agent"
    assert harness.loader_calls == [1]
    assert harness.broker.terminal_postcondition()


async def test_git_push_broker_issued_credential_also_loads_exactly_once(tmp_path):
    """Without a pre-issued lease the broker issues and loads exactly once."""
    harness = _CountingCredentialHarness(tmp_path)
    broker = ApprovalBroker()
    harness.broker.revoke(harness.lease)

    tool_context = {
        "task_id": "task-a",
        "workspace_id": "w",
        "execution_service": harness.service(
            ["task/test\n", harness.remote_url, harness.head, "", ""]
        ),
        "approval_broker": broker,
        "network_policy": "unrestricted-with-approval",
        "credential_context": None,
        "credential_broker": harness.broker,
    }
    approval = await prepare_remote_git_approval(
        "git_push",
        {"cwd": ".", "remote": "origin", "branch": ""},
        tool_context,
        requester="session",
        approval_id="push",
    )
    assert approval is not None
    assert await broker.approve_operation("push", "session")
    assert harness.loader_calls == []
    result = json.loads(await git_push(
        ".",
        task_id="task-a",
        workspace_id="w",
        execution_service=harness.service(
            ["task/test\n", "task/test\n", harness.remote_url, harness.head, "", "", ""]
        ),
        approval_context=approval,
        network_policy="unrestricted-with-approval",
        credential_context=None,
        credential_broker=harness.broker,
        network_lease=_ValidNetworkLease(),
    ))
    assert result["pushed"] is True
    assert harness.loader_calls == [1]
    assert harness.broker.terminal_postcondition()


async def test_git_push_lease_with_wrong_effect_metadata_is_rejected_at_prepare(tmp_path):
    """A lease bound to another effect cannot even enter the approval."""
    harness = _CountingCredentialHarness(tmp_path)
    wrong_lease = harness.broker.issue_named(
        provider="git",
        name="ssh-agent",
        operation="git_push",
        binding={"remote_url": harness.remote_url, "host": "other.example"},
    )
    broker = ApprovalBroker()
    tool_context = {
        "task_id": "task-a",
        "workspace_id": "w",
        "execution_service": harness.service(
            ["task/test\n", harness.remote_url, harness.head, "", ""]
        ),
        "approval_broker": broker,
        "network_policy": "unrestricted-with-approval",
        "credential_lease": wrong_lease,
        "credential_broker": harness.broker,
    }
    with pytest.raises(PermissionError, match="does not match"):
        await prepare_remote_git_approval(
            "git_push",
            {"cwd": ".", "remote": "origin", "branch": ""},
            tool_context,
            requester="session",
            approval_id="wrong",
        )
    assert harness.loader_calls == []


def test_git_tools_has_no_direct_subprocess_path():
    import khaos.tools.git_tools as git_tools_module

    assert "create_subprocess_exec" not in inspect.getsource(git_tools_module)
    assert "create_subprocess_shell" not in inspect.getsource(git_tools_module)


async def test_git_push_network_preflight_prevents_provider_invocation(tmp_path):
    """Deterministically-invalid network authority never loads a secret."""
    harness = _CountingCredentialHarness(tmp_path)
    broker = ApprovalBroker()

    async def _push_with(approval_id: str, lease: object) -> dict:
        approval = await harness.prepare(broker, approval_id)
        assert await broker.approve_operation(approval_id, "session")
        result = json.loads(await git_push(
            ".",
            task_id="task-a",
            workspace_id="w",
            execution_service=harness.service(
                ["task/test\n", "task/test\n", harness.remote_url, harness.head, "", "", ""]
            ),
            approval_context=approval,
            network_policy="unrestricted-with-approval",
            credential_context=harness.lease,
            credential_broker=harness.broker,
            network_lease=lease,
        ))
        return result

    missing = await _push_with("preflight-missing", None)
    assert missing["pushed"] is False
    assert "managed network lease" in missing["error"]
    assert harness.loader_calls == []

    malformed = await _push_with("preflight-malformed", object())
    assert malformed["pushed"] is False
    assert "malformed" in malformed["error"]
    assert harness.loader_calls == []

    invalid = await _push_with("preflight-invalid", _InvalidNetworkLease())
    assert invalid["pushed"] is False
    assert "attestation rejected" in invalid["error"]
    assert harness.loader_calls == []

    approved = await _push_with("preflight-valid", _ValidNetworkLease())
    assert approved["pushed"] is True
    assert harness.loader_calls == [1]
    assert harness.broker.terminal_postcondition()


def test_registry_exposes_only_git_push_as_remote_git_tool():
    registry = create_runtime_registry()
    remote_tools = []
    for tool in registry.list_by_mode("coding"):
        capability_names = {capability.name for capability in tool.capabilities}
        if "vcs.remote-write" in capability_names:
            remote_tools.append(tool.name)
            assert {"process.execute", "network.access", "credential.access"}.issubset(capability_names)
    assert remote_tools == ["git_push"]
