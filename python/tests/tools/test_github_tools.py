import hashlib
import inspect
import json
import os
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from khaos.agent.approval import ApprovalBroker
from khaos.coding.execution.models import ExecutionResult, NetworkPolicy
from khaos.coding.workspace.models import WorkspaceState
from khaos.tools.github_tools import (
    GITHUB_TOOL_SPECS,
    github_comment_issue,
    github_create_pr,
    github_read_issue,
    github_request_review,
    prepare_github_approval,
)
from khaos.tools.registry import create_runtime_registry


class _FakeGitHubExecutionService:
    def __init__(self, worktree: Path, *, task_id: str = "task", remote: str = "git@github.com:owner/repo.git"):
        self.workspace = SimpleNamespace(
            task_id=task_id,
            worktree_path=worktree,
            repository_root=worktree.parent / "main",
            branch_name="task/test",
            state=WorkspaceState.RUNNING,
        )
        self.workspace_manager = SimpleNamespace(
            get=lambda workspace_id: self.workspace if workspace_id == "workspace" else None
        )
        self.remote = remote
        self.head = "a" * 40
        self.requests = []
        self.gh_result = ExecutionResult("gh", "passed", 0, "{}", "", 1)
        self.gh_error = None

    async def execute(self, request):
        self.requests.append(request)
        if request.argv[:4] == ("git", "remote", "get-url", "origin"):
            return ExecutionResult("remote", "passed", 0, self.remote, "", 1)
        if request.argv[:4] == ("git", "rev-parse", "--verify", "HEAD"):
            return ExecutionResult("head", "passed", 0, self.head, "", 1)
        if request.argv[:1] == ("gh",):
            if self.gh_error is not None:
                raise self.gh_error
            return self.gh_result
        raise AssertionError(f"unexpected argv: {request.argv}")


def _context(service, *, operations, network_policy="unrestricted-with-approval"):
    return {
        "task_id": "task",
        "workspace_id": "workspace",
        "execution_service": service,
        "network_policy": network_policy,
        "credential_context": {
            "scope": "github-token",
            "host": "github.com",
            "repository": "owner/repo",
            "operations": operations,
            "environment": {"GH_TOKEN": "test-token"},
        },
    }


async def _approved_context(service, tool_name, arguments, *, requester="session", approval_id="approval"):
    broker = ApprovalBroker()
    context = _context(service, operations=[tool_name])
    approval = await prepare_github_approval(
        tool_name,
        arguments,
        {**context, "approval_broker": broker},
        requester=requester,
        approval_id=approval_id,
    )
    assert approval is not None
    assert await broker.approve_operation(approval_id, requester)
    return {**context, "approval_context": approval}, broker


async def test_github_read_issue_uses_execution_service_without_write_approval(tmp_path):
    service = _FakeGitHubExecutionService(tmp_path)
    service.gh_result = ExecutionResult("gh", "passed", 0, '{"number":7}', "", 1)

    result = json.loads(await github_read_issue(7, **_context(service, operations=["github_read_issue"])))

    assert result == {"number": 7}
    request = [request for request in service.requests if request.argv[0] == "gh"][0]
    assert request.network_policy is NetworkPolicy.UNRESTRICTED_WITH_APPROVAL
    assert request.argv == ("gh", "issue", "view", "7", "--json", "number,title,body,state,labels", "--repo", "owner/repo")


@pytest.mark.parametrize(
    ("tool_name", "arguments", "handler"),
    [
        ("github_create_pr", {"title": "Fix", "body": "Body", "draft": True}, lambda context: github_create_pr("Fix", "Body", draft=True, **context)),
        ("github_comment_issue", {"issue_number": 7, "comment": "Looks good"}, lambda context: github_comment_issue(7, "Looks good", **context)),
        ("github_request_review", {"pr_number": 8, "reviewers": ["alice"]}, lambda context: github_request_review(8, ["alice"], **context)),
    ],
)
async def test_github_write_tools_use_execution_service_and_one_shot_approval(tmp_path, tool_name, arguments, handler):
    service = _FakeGitHubExecutionService(tmp_path)
    service.gh_result = ExecutionResult("gh", "passed", 0, "https://github.com/owner/repo/pull/1", "", 1)
    context, _ = await _approved_context(service, tool_name, arguments)

    await handler(context)

    request = [request for request in service.requests if request.argv[0] == "gh"][-1]
    assert request.network_policy is NetworkPolicy.UNRESTRICTED_WITH_APPROVAL
    assert request.environment["GH_TOKEN"] == "test-token"
    assert "GITHUB_TOKEN" not in request.allowed_environment_keys
    assert not os.path.exists(request.environment["HOME"])
    replay = json.loads(await handler(context))
    assert "replayed" in replay.get("error", "")


async def test_github_write_requires_approval_network_and_credential(tmp_path):
    service = _FakeGitHubExecutionService(tmp_path)
    no_approval = json.loads(await github_comment_issue(7, "comment", **_context(service, operations=["github_comment_issue"])))
    assert no_approval["ok"] is False and "requires approval" in no_approval["error"]
    claimed_approval = json.loads(await github_comment_issue(
        7, "comment", approved=True, **_context(service, operations=["github_comment_issue"])
    ))
    assert claimed_approval["ok"] is False and "requires approval" in claimed_approval["error"]

    no_network = json.loads(await github_read_issue(7, **_context(service, operations=["github_read_issue"], network_policy="none")))
    assert "server-authorized network policy" in no_network["error"]

    context = _context(service, operations=["github_read_issue"])
    context["credential_context"] = None
    no_credential = json.loads(await github_read_issue(7, **context))
    assert "credential authorization" in no_credential["error"]


@pytest.mark.parametrize("mutation", ["requester", "operation", "repository", "payload", "head", "expiry"])
async def test_github_approval_binding_rejects_mutation(tmp_path, mutation):
    service = _FakeGitHubExecutionService(tmp_path)
    arguments = {"issue_number": 7, "comment": "approved"}
    context, broker = await _approved_context(service, "github_comment_issue", arguments)
    binding = context["approval_context"]["binding"]
    if mutation == "requester":
        binding["requester"] = "other"
    elif mutation == "operation":
        binding["operation"] = "github.other"
        broker._operation_approvals["approval"]["binding"]["operation"] = "github.other"
    elif mutation == "repository":
        service.remote = "git@github.com:other/repo.git"
        context["credential_context"]["repository"] = "other/repo"
    elif mutation == "payload":
        arguments["comment"] = "changed"
    elif mutation == "head":
        service.head = "b" * 40
    else:
        broker._operation_approvals["approval"]["expiry"] = time.time() - 1

    result = json.loads(await github_comment_issue(7, arguments["comment"], **context))
    if mutation == "operation":
        # Mutating a compatibility mirror cannot alter the durable binding.
        assert result["ok"] is True
        assert any(request.argv[0] == "gh" for request in service.requests)
    else:
        assert result["ok"] is False
        assert "stale" in result["error"]


async def test_github_repo_scope_and_payload_limits_are_enforced(tmp_path):
    service = _FakeGitHubExecutionService(tmp_path)
    context = _context(service, operations=["github_read_issue"])
    with pytest.raises(PermissionError, match="repo must match"):
        await github_read_issue(7, repo="other/repo", **context)
    with pytest.raises(PermissionError, match="cwd must match"):
        await github_read_issue(7, cwd=str(tmp_path.parent), **context)
    with pytest.raises(ValueError, match="exceeds"):
        await github_create_pr("title", "x" * 70000, **context)
    with pytest.raises(ValueError, match="reviewers"):
        await github_request_review(1, ["--hostname=evil"], **context)


async def test_github_payload_is_passed_as_literal_argv(tmp_path):
    service = _FakeGitHubExecutionService(tmp_path)
    title = "Fix; touch /tmp/not-run"
    body = "$(echo not-run)"
    arguments = {"title": title, "body": body}
    context, _ = await _approved_context(service, "github_create_pr", arguments)
    await github_create_pr(title, body, **context)
    argv = [request.argv for request in service.requests if request.argv[0] == "gh"][-1]
    assert title in argv and body in argv
    assert "sh" not in argv and "-c" not in argv


@pytest.mark.parametrize("failure", ["failed", "timed-out", "unsupported"])
async def test_github_temporary_home_is_cleaned_on_failure_and_timeout(tmp_path, failure):
    service = _FakeGitHubExecutionService(tmp_path)
    if failure == "unsupported":
        service.gh_error = PermissionError("unsupported backend")
    else:
        service.gh_result = ExecutionResult("gh", failure, 1 if failure == "failed" else None, "", failure, 1)
    result = json.loads(await github_read_issue(7, **_context(service, operations=["github_read_issue"])))
    assert "error" in result
    request = [request for request in service.requests if request.argv[0] == "gh"][-1]
    assert not os.path.exists(request.environment["HOME"])


def test_github_registry_and_static_process_audit():
    registry = create_runtime_registry()
    expected = {item["name"]: item["classification"] for item in GITHUB_TOOL_SPECS}
    assert expected == {
        "github_create_pr": "remote.write",
        "github_read_issue": "remote.read",
        "github_comment_issue": "remote.write",
        "github_request_review": "remote.write",
    }
    for name, classification in expected.items():
        capabilities = {capability.name for capability in registry.get(name).capabilities}
        assert {classification, "process.execute", "network.access", "credential.access"}.issubset(capabilities)
    import khaos.tools.github_tools as module
    source = inspect.getsource(module)
    for forbidden in ("create_subprocess_exec", "create_subprocess_shell", "subprocess.run", "subprocess.Popen", "os.system", "shell=True"):
        assert forbidden not in source
