"""GitHub remote-platform tools backed by the authenticated ``gh`` CLI."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from khaos.coding.execution.models import ExecutionRequest, NetworkPolicy
from khaos.coding.workspace.models import WorkspaceState

_MAX_TITLE = 256
_MAX_BODY = 65536
_ACTIVE_STATES = frozenset({WorkspaceState.READY, WorkspaceState.RUNNING, WorkspaceState.VERIFYING})
_WRITE_TOOLS = frozenset({"github_create_pr", "github_comment_issue", "github_request_review"})


async def _gh(args: list[str], *, context: dict[str, Any], tool_name: str, payload: dict[str, Any]) -> dict[str, Any]:
    try:
        workspace, cwd, host, repository = await _repository_context(context)
        if context.get("network_policy") != NetworkPolicy.UNRESTRICTED_WITH_APPROVAL.value:
            raise PermissionError("GitHub operation requires server-authorized network policy")
        credential_scope, credential_environment = _credential_material(
            context.get("credential_context"), host, repository, tool_name
        )
        if tool_name in _WRITE_TOOLS:
            await _consume_github_approval(
                context, workspace, host, repository, tool_name, payload
            )
        with tempfile.TemporaryDirectory(prefix="khaos-gh-home-") as temporary_home:
            environment = {
                "PATH": os.environ.get("PATH", ""),
                "LANG": os.environ.get("LANG", "C.UTF-8"),
                "HOME": temporary_home,
                "GH_PROMPT_DISABLED": "1",
                "NO_COLOR": "1",
                **credential_environment,
            }
            request = ExecutionRequest(
                argv=("gh", *args),
                cwd=cwd,
                environment=environment,
                allowed_environment_keys=frozenset(environment),
                network_policy=NetworkPolicy.UNRESTRICTED_WITH_APPROVAL,
                task_id=context.get("task_id"),
                workspace_id=context.get("workspace_id"),
                access_mode="read-only",
            )
            execution = await context["execution_service"].execute(request)
    except PermissionError as exc:
        return {"error": str(exc), "returncode": -1}
    out = execution.stdout.strip()
    result: dict[str, Any] = {
        "returncode": execution.return_code if execution.return_code is not None else -1,
        "stdout": out,
        "stderr": execution.stderr.strip(),
        "host": host,
        "repository": repository,
        "credential_scope": credential_scope,
    }
    if out:
        try:
            result["data"] = json.loads(out)
        except json.JSONDecodeError:
            pass
    return result


async def github_create_pr(title: str, body: str, base: str = "main", head: str = "", draft: bool = False, repo: str = "", cwd: str = ".", **context: Any) -> str:
    _validate_text(title, "title", _MAX_TITLE)
    _validate_text(body, "body", _MAX_BODY)
    _validate_branch(base)
    if head:
        _validate_branch(head)
    args = ["pr", "create", "--title", title, "--body", body, "--base", base]
    if head: args.extend(["--head", head])
    if draft: args.append("--draft")
    repository = await _validated_repo_argument(repo, cwd, context)
    args.extend(["--repo", repository])
    payload = {"title": title, "body": body, "base": base, "head": head, "draft": draft}
    result = await _gh(args, context={**context, "cwd": cwd}, tool_name="github_create_pr", payload=payload)
    if result.get("returncode") != 0:
        return json.dumps({"created": False, "error": result.get("stderr") or result.get("error")}, ensure_ascii=False)
    return json.dumps({"created": True, "url": result.get("stdout", ""), "title": title, "base": base, "head": head}, ensure_ascii=False)


async def github_read_issue(issue_number: int, repo: str = "", cwd: str = ".", **context: Any) -> str:
    _validate_number(issue_number, "issue_number")
    args = ["issue", "view", str(issue_number), "--json", "number,title,body,state,labels"]
    repository = await _validated_repo_argument(repo, cwd, context)
    args.extend(["--repo", repository])
    result = await _gh(args, context={**context, "cwd": cwd}, tool_name="github_read_issue", payload={"issue_number": issue_number})
    return json.dumps(result.get("data") or {"error": result.get("stderr") or result.get("error")}, ensure_ascii=False)


async def github_comment_issue(issue_number: int, comment: str, repo: str = "", cwd: str = ".", **context: Any) -> str:
    _validate_number(issue_number, "issue_number")
    _validate_text(comment, "comment", _MAX_BODY)
    args = ["issue", "comment", str(issue_number), "--body", comment]
    repository = await _validated_repo_argument(repo, cwd, context)
    args.extend(["--repo", repository])
    payload = {"issue_number": issue_number, "comment": comment}
    result = await _gh(args, context={**context, "cwd": cwd}, tool_name="github_comment_issue", payload=payload)
    return json.dumps({"ok": result.get("returncode") == 0, "issue": issue_number, "error": result.get("stderr") or result.get("error", "")}, ensure_ascii=False)


async def github_request_review(pr_number: int, reviewers: list[str] | None = None, repo: str = "", cwd: str = ".", **context: Any) -> str:
    _validate_number(pr_number, "pr_number")
    reviewers = reviewers or []
    if len(reviewers) > 20 or any(not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38}[A-Za-z0-9])?", reviewer) for reviewer in reviewers):
        raise ValueError("invalid reviewers")
    args = ["pr", "edit", str(pr_number), "--add-reviewer", ",".join(reviewers or [])]
    repository = await _validated_repo_argument(repo, cwd, context)
    args.extend(["--repo", repository])
    payload = {"pr_number": pr_number, "reviewers": reviewers}
    result = await _gh(args, context={**context, "cwd": cwd}, tool_name="github_request_review", payload=payload)
    return json.dumps({"ok": result.get("returncode") == 0, "pr": pr_number, "reviewers": reviewers or [], "error": result.get("stderr") or result.get("error", "")}, ensure_ascii=False)


async def prepare_github_approval(
    tool_name: str,
    arguments: dict[str, Any],
    tool_context: dict[str, Any],
    *,
    requester: str,
    approval_id: str,
) -> dict[str, Any] | None:
    """Capture immutable remote-write state before prompting the user."""
    if tool_name not in _WRITE_TOOLS:
        return None
    if tool_context.get("network_policy") != NetworkPolicy.UNRESTRICTED_WITH_APPROVAL.value:
        raise PermissionError("GitHub write requires explicit network permission")
    broker = tool_context.get("approval_broker")
    if broker is None:
        raise PermissionError("GitHub write requires ApprovalBroker")
    await _validated_repo_argument(
        str(arguments.get("repo") or ""), str(arguments.get("cwd") or "."), tool_context
    )
    workspace, _, host, repository = await _repository_context(
        {**tool_context, "cwd": str(arguments.get("cwd") or ".")}
    )
    _credential_material(tool_context.get("credential_context"), host, repository, tool_name)
    payload = _payload_for(tool_name, arguments)
    _validate_payload(tool_name, payload)
    if tool_name == "github_create_pr" and payload["head"] and payload["head"] != workspace.branch_name:
        raise PermissionError("PR head must be the current TaskWorkspace branch")
    head = await _current_head(tool_context)
    expiry = time.time() + 120.0
    binding = {
        "task_id": workspace.task_id,
        "workspace_id": tool_context.get("workspace_id"),
        "operation": _operation(tool_name),
        "target": _target(tool_name, payload),
        "repository_host": host,
        "repository": repository,
        "resource_type": _resource_type(tool_name),
        "resource_id": payload.get("issue_number", payload.get("pr_number", "new")),
        "payload_hash": _payload_hash(payload),
        "head": head,
        "network_policy": NetworkPolicy.UNRESTRICTED_WITH_APPROVAL.value,
        "credential_scope": "github-token",
        "expiry": expiry,
        "requester": requester,
    }
    await broker.register_operation(approval_id, binding, expiry)
    return {"approval_broker": broker, "approval_id": approval_id, "binding": binding}


async def _consume_github_approval(
    context: dict[str, Any],
    workspace: Any,
    host: str,
    repository: str,
    tool_name: str,
    payload: dict[str, Any],
) -> None:
    approval = context.get("approval_context")
    if not isinstance(approval, dict):
        raise PermissionError("GitHub write requires approval")
    binding = dict(approval.get("binding") or {})
    _validate_payload(tool_name, payload)
    if tool_name == "github_create_pr" and payload["head"] and payload["head"] != workspace.branch_name:
        raise PermissionError("PR head must be the current TaskWorkspace branch")
    current = {
        "task_id": workspace.task_id,
        "workspace_id": context.get("workspace_id"),
        "operation": _operation(tool_name),
        "target": _target(tool_name, payload),
        "repository_host": host,
        "repository": repository,
        "resource_type": _resource_type(tool_name),
        "resource_id": payload.get("issue_number", payload.get("pr_number", "new")),
        "payload_hash": _payload_hash(payload),
        "head": await _current_head(context),
        "network_policy": NetworkPolicy.UNRESTRICTED_WITH_APPROVAL.value,
        "credential_scope": "github-token",
        "expiry": binding.get("expiry"),
        "requester": binding.get("requester"),
    }
    broker = approval.get("approval_broker")
    if broker is None or not await broker.consume_operation(approval.get("approval_id", ""), current):
        raise PermissionError("GitHub approval is missing, stale, or replayed")


async def _repository_context(context: dict[str, Any]) -> tuple[Any, Path, str, str]:
    task_id = context.get("task_id")
    workspace_id = context.get("workspace_id")
    service = context.get("execution_service")
    if not task_id or not workspace_id or service is None:
        raise PermissionError("GitHub operation requires active TaskWorkspace")
    manager = service.workspace_manager
    workspace = manager.get(workspace_id) if manager is not None else None
    if workspace is None or workspace.task_id != task_id:
        raise PermissionError("task/workspace binding is invalid")
    if workspace.state not in _ACTIVE_STATES:
        raise PermissionError("TaskWorkspace is not available for GitHub operation")
    cwd = workspace.worktree_path.expanduser().resolve()
    requested_cwd = str(context.get("cwd", "."))
    if requested_cwd not in {"", "."} and Path(requested_cwd).expanduser().resolve() != cwd:
        raise PermissionError("cwd must match the active TaskWorkspace")
    result = await _execute_read(
        service, task_id, workspace_id, cwd,
        ("git", "remote", "get-url", "origin"),
    )
    if result.return_code != 0 or not result.stdout.strip():
        raise PermissionError("current TaskWorkspace has no origin remote")
    host, repository = _parse_repository(result.stdout.strip())
    return workspace, cwd, host, repository


async def _validated_repo_argument(repo: str, cwd: str, context: dict[str, Any]) -> str:
    _, _, _, repository = await _repository_context({**context, "cwd": cwd})
    if repo and repo != repository:
        raise PermissionError("repo must match the active TaskWorkspace repository")
    return repository


async def _current_head(context: dict[str, Any]) -> str:
    workspace, cwd, _, _ = await _repository_context(context)
    result = await _execute_read(
        context["execution_service"], workspace.task_id, context["workspace_id"], cwd,
        ("git", "rev-parse", "--verify", "HEAD"),
    )
    if result.return_code != 0:
        raise PermissionError("unable to resolve current HEAD")
    return result.stdout.strip()


async def _execute_read(service: Any, task_id: str, workspace_id: str, cwd: Path, argv: tuple[str, ...]):
    environment = {"PATH": os.environ.get("PATH", ""), "LANG": os.environ.get("LANG", "C.UTF-8")}
    return await service.execute(ExecutionRequest(
        argv=argv, cwd=cwd, environment=environment,
        allowed_environment_keys=frozenset(environment), network_policy=NetworkPolicy.NONE,
        task_id=task_id, workspace_id=workspace_id, access_mode="read-only",
    ))


def _credential_material(context: Any, host: str, repository: str, operation: str) -> tuple[str, dict[str, str]]:
    if not isinstance(context, dict) or context.get("scope") != "github-token":
        raise PermissionError("credential authorization required: github-token")
    if context.get("host") != host or context.get("repository") != repository:
        raise PermissionError("credential authorization does not match repository")
    operations = context.get("operations")
    if not isinstance(operations, (list, tuple, set)) or operation not in operations:
        raise PermissionError("credential authorization does not cover operation")
    environment = context.get("environment")
    if not isinstance(environment, dict) or len(environment) != 1:
        raise PermissionError("exactly one GitHub token credential is required")
    key, value = next(iter(environment.items()))
    if key not in {"GH_TOKEN", "GITHUB_TOKEN"} or not value:
        raise PermissionError("unauthorized GitHub credential key")
    return "github-token", {str(key): str(value)}


def _parse_repository(remote_url: str) -> tuple[str, str]:
    if re.match(r"^[^/@:]+@[^/:]+:", remote_url):
        host = remote_url.split("@", 1)[1].split(":", 1)[0]
        path = remote_url.split(":", 1)[1]
    else:
        parsed = urlparse(remote_url)
        if parsed.scheme not in {"https", "ssh"} or not parsed.hostname or parsed.username or parsed.password:
            raise PermissionError("unsupported GitHub repository remote")
        host, path = parsed.hostname, parsed.path
    repository = path.strip("/")
    if repository.endswith(".git"):
        repository = repository[:-4]
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise PermissionError("invalid GitHub repository identity")
    return host.lower(), repository


def _payload_for(tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    if tool_name == "github_create_pr":
        payload = {
            "title": str(arguments.get("title", "")), "body": str(arguments.get("body", "")),
            "base": str(arguments.get("base") or "main"), "head": str(arguments.get("head") or ""),
            "draft": bool(arguments.get("draft", False)),
        }
    elif tool_name == "github_comment_issue":
        payload = {"issue_number": int(arguments.get("issue_number", 0)), "comment": str(arguments.get("comment", ""))}
    else:
        payload = {"pr_number": int(arguments.get("pr_number", 0)), "reviewers": list(arguments.get("reviewers") or [])}
    return payload


def _payload_hash(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _validate_payload(tool_name: str, payload: dict[str, Any]) -> None:
    if tool_name == "github_create_pr":
        _validate_text(payload["title"], "title", _MAX_TITLE)
        _validate_text(payload["body"], "body", _MAX_BODY)
        _validate_branch(payload["base"])
        if payload["head"]:
            _validate_branch(payload["head"])
    elif tool_name == "github_comment_issue":
        _validate_number(payload["issue_number"], "issue_number")
        _validate_text(payload["comment"], "comment", _MAX_BODY)
    else:
        _validate_number(payload["pr_number"], "pr_number")
        reviewers = payload["reviewers"]
        if len(reviewers) > 20 or any(
            not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38}[A-Za-z0-9])?", reviewer)
            for reviewer in reviewers
        ):
            raise ValueError("invalid reviewers")


def _operation(tool_name: str) -> str:
    return {
        "github_create_pr": "github.pr.create",
        "github_comment_issue": "github.issue.comment",
        "github_request_review": "github.pr.request-review",
    }[tool_name]


def _resource_type(tool_name: str) -> str:
    return "issue" if tool_name == "github_comment_issue" else "pull-request"


def _target(tool_name: str, payload: dict[str, Any]) -> str:
    if tool_name == "github_create_pr":
        return f"{payload['head'] or 'current'}->{payload['base']}"
    return str(payload.get("issue_number", payload.get("pr_number")))


def _validate_text(value: str, name: str, limit: int) -> None:
    if not value or len(value.encode("utf-8")) > limit:
        raise ValueError(f"{name} is empty or exceeds {limit} bytes")


def _validate_number(value: int, name: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")


def _validate_branch(value: str) -> None:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]*", value) or ".." in value or value.startswith("-"):
        raise ValueError("invalid branch name")


GITHUB_TOOL_SPECS = [
    {"name": "github_create_pr", "classification": "remote.write", "description": "Create a GitHub pull request after pushing a branch.", "parameters": {"type": "object", "properties": {"title": {"type": "string"}, "body": {"type": "string"}, "base": {"type": "string"}, "head": {"type": "string"}, "draft": {"type": "boolean"}, "repo": {"type": "string"}, "cwd": {"type": "string"}}, "required": ["title", "body"]}},
    {"name": "github_read_issue", "classification": "remote.read", "description": "Read a GitHub issue.", "parameters": {"type": "object", "properties": {"issue_number": {"type": "integer"}, "repo": {"type": "string"}, "cwd": {"type": "string"}}, "required": ["issue_number"]}},
    {"name": "github_comment_issue", "classification": "remote.write", "description": "Comment on a GitHub issue.", "parameters": {"type": "object", "properties": {"issue_number": {"type": "integer"}, "comment": {"type": "string"}, "repo": {"type": "string"}, "cwd": {"type": "string"}}, "required": ["issue_number", "comment"]}},
    {"name": "github_request_review", "classification": "remote.write", "description": "Request reviewers on a GitHub pull request.", "parameters": {"type": "object", "properties": {"pr_number": {"type": "integer"}, "reviewers": {"type": "array", "items": {"type": "string"}}, "repo": {"type": "string"}, "cwd": {"type": "string"}}, "required": ["pr_number"]}},
]
