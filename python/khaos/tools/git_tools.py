"""Git tools for coding mode."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from khaos.coding.execution.models import ExecutionRequest, NetworkPolicy
from khaos.coding.workspace.models import WorkspaceState

logger = logging.getLogger(__name__)

_PROTECTED_BRANCHES = frozenset({"main", "master", "develop", "development", "production", "release"})
_WRITABLE_WORKSPACE_STATES = frozenset(
    {WorkspaceState.READY, WorkspaceState.RUNNING, WorkspaceState.VERIFYING}
)
_GIT_SAFE_CONFIG = ("-c", "core.pager=cat", "-c", f"core.hooksPath={os.devnull}")


@dataclass(frozen=True)
class _GitExecutionContext:
    task_id: str | None
    workspace_id: str | None
    access_mode: str
    execution_service: Any
    approval_context: dict[str, Any] | None
    network_policy: str


def _context(task_id: str | None, workspace_id: str | None, access_mode: str, execution_service: Any, approval_context: dict[str, Any] | None, network_policy: str) -> _GitExecutionContext:
    return _GitExecutionContext(task_id, workspace_id, access_mode, execution_service, approval_context, network_policy)


async def git_diff(repo: str = ".", staged: bool = False, *, task_id: str | None = None, workspace_id: str | None = None, access_mode: str = "read-only", execution_service: Any = None, approval_context: dict[str, Any] | None = None, network_policy: str = "none") -> dict[str, Any]:
    """Return git diff output."""
    args = ["git", "-c", "core.pager=cat", "diff", "--no-ext-diff"]
    if staged:
        args.append("--staged")
    return await _git(args, repo, _context(task_id, workspace_id, "read-only", execution_service, approval_context, "none"))


async def git_commit(repo: str = ".", message: str = "", *, task_id: str | None = None, workspace_id: str | None = None, access_mode: str = "vcs.write", execution_service: Any = None, approval_context: dict[str, Any] | None = None, network_policy: str = "none") -> dict[str, Any]:
    """Create a git commit."""
    if not message:
        raise ValueError("commit message is required")
    args = ["git", *_GIT_SAFE_CONFIG, "-c", "commit.gpgSign=false", "commit", "--no-verify", "--no-gpg-sign", "-m", message]
    return await _git(args, repo, _context(task_id, workspace_id, "vcs.write", execution_service, approval_context, "none"))


async def git_branch(repo: str = ".", name: str = "", checkout: bool = False, *, task_id: str | None = None, workspace_id: str | None = None, access_mode: str = "read-only", execution_service: Any = None, approval_context: dict[str, Any] | None = None, network_policy: str = "none") -> dict[str, Any]:
    """List, create, or checkout branches."""
    if name and checkout:
        _validate_branch_name(name)
        context = _context(task_id, workspace_id, "vcs.destructive-write", execution_service, approval_context, "none")
        result = await _git(["git", *_GIT_SAFE_CONFIG, "switch", "-c", name], repo, context)
        if result["returncode"] == 0:
            workspace = execution_service.workspace_manager.get(workspace_id)
            workspace.branch_name = name
        return result
    if name:
        _validate_branch_name(name)
        return await _git(["git", *_GIT_SAFE_CONFIG, "branch", name], repo, _context(task_id, workspace_id, "vcs.write", execution_service, approval_context, "none"))
    return await _git(["git", "branch", "--show-current"], repo, _context(task_id, workspace_id, "read-only", execution_service, approval_context, "none"))


async def git_log(repo: str = ".", limit: int = 10, *, task_id: str | None = None, workspace_id: str | None = None, access_mode: str = "read-only", execution_service: Any = None, approval_context: dict[str, Any] | None = None, network_policy: str = "none") -> dict[str, Any]:
    """Return concise git log."""
    return await _git(["git", "-c", "core.pager=cat", "log", f"--max-count={limit}", "--oneline"], repo, _context(task_id, workspace_id, "read-only", execution_service, approval_context, "none"))


async def git_status(cwd: str = ".", *, task_id: str | None = None, workspace_id: str | None = None, access_mode: str = "read-only", execution_service: Any = None, approval_context: dict[str, Any] | None = None, network_policy: str = "none") -> str:
    """Return a structured ``git status`` snapshot as JSON.

    Parses ``git status --porcelain`` into branch, modified/added/deleted/
    untracked/staged buckets and an ``is_clean`` flag.
    """
    ctx = _context(task_id, workspace_id, "read-only", execution_service, approval_context, "none")
    branch_result = await _git(["git", "branch", "--show-current"], cwd, ctx)
    branch = branch_result["stdout"].strip()

    porcelain = await _git(
        ["git", "status", "--porcelain"], cwd, ctx
    )
    status: dict[str, Any] = {
        "branch": branch,
        "modified": [],
        "added": [],
        "deleted": [],
        "untracked": [],
        "staged": [],
        "is_clean": True,
    }

    for raw in porcelain["stdout"].splitlines():
        if not raw:
            continue
        xy, path = raw[:2], raw[3:]
        x, y = xy[0], xy[1]
        # Index vs worktree columns per porcelain v1.
        if x == "U" or y == "U" or xy in {"AA", "DD", "AU", "UA", "DU", "UD"}:
            status["modified"].append(path)
        if x == "?" or xy == "??":
            status["untracked"].append(path)
        else:
            if x in {"M", "R", "C"}:
                status["modified"].append(path)
            if x == "A":
                status["added"].append(path)
            if x == "D":
                status["deleted"].append(path)
            if y in {"M", "D", "R", "C"} and x != "?":
                # Worktree change on top of an already-indexed file.
                if path not in status["modified"]:
                    status["modified"].append(path)
            status["staged"].append(path)
        status["is_clean"] = False

    return json.dumps(status, ensure_ascii=False)


async def git_smart_commit(cwd: str = ".", message: str = "", *, task_id: str | None = None, workspace_id: str | None = None, access_mode: str = "vcs.write", execution_service: Any = None, approval_context: dict[str, Any] | None = None, network_policy: str = "none") -> str:
    """Stage everything and commit with an inferred or explicit message.

    When ``message`` is empty the change set is inspected (``git diff
    --cached --name-status``) and a conventional-commit message of the form
    ``<type>(<scope>): <description>`` is generated. Returns JSON describing
    the resulting commit, or ``{"message": "Nothing to commit."}`` when the
    tree is clean.
    """
    write_ctx = _context(task_id, workspace_id, "vcs.write", execution_service, approval_context, "none")
    read_ctx = _context(task_id, workspace_id, "read-only", execution_service, approval_context, "none")
    await _git(["git", *_GIT_SAFE_CONFIG, "add", "-A", "--", "."], cwd, write_ctx)
    diff = await _git(
        ["git", "-c", "core.pager=cat", "diff", "--no-ext-diff", "--cached", "--name-status"],
        cwd,
        read_ctx,
    )
    diff_lines = [
        line for line in diff["stdout"].splitlines() if line.strip()
    ]

    if not diff_lines:
        return json.dumps({"message": "Nothing to commit."}, ensure_ascii=False)

    files = [_parse_name_status(line) for line in diff_lines]

    if not message:
        message = _generate_message(files)

    commit = await _git(
        ["git", *_GIT_SAFE_CONFIG, "-c", "commit.gpgSign=false", "commit", "--no-verify", "--no-gpg-sign", "-m", message],
        cwd,
        write_ctx,
    )
    if commit["returncode"] != 0:
        return json.dumps(
            {
                "error": commit["stderr"].strip() or commit["stdout"].strip(),
                "returncode": commit["returncode"],
            },
            ensure_ascii=False,
        )

    branch_result = await _git(["git", "branch", "--show-current"], cwd, read_ctx)
    branch = branch_result["stdout"].strip()
    # ``git commit`` prints "[<branch> (root-commit) <hash>] <subject>"; pull
    # the trailing 7-char hash out of the brackets, fall back to rev-parse.
    revision = _extract_commit_hash(commit["stdout"])
    if not revision:
        rev = await _git(["git", "rev-parse", "--short", "HEAD"], cwd, read_ctx)
        revision = rev["stdout"].strip()
    logger.info("git_smart_commit: %s on %s (%d files)", message, branch, len(files))
    return json.dumps(
        {
            "commit": revision,
            "branch": branch,
            "message": message,
            "files_changed": len(files),
        },
        ensure_ascii=False,
    )


async def git_undo(cwd: str = ".", *, task_id: str | None = None, workspace_id: str | None = None, access_mode: str = "vcs.destructive-write", execution_service: Any = None, approval_context: dict[str, Any] | None = None, network_policy: str = "none") -> str:
    """Undo the last commit, keeping its changes staged (soft reset).

    Returns the hash and message of the commit that was undone plus the list
    of files now staged as a result.
    """
    destructive_ctx = _context(task_id, workspace_id, "vcs.destructive-write", execution_service, approval_context, "none")
    read_ctx = _context(task_id, workspace_id, "read-only", execution_service, approval_context, "none")
    log = await _git(["git", "log", "-1", "--pretty=%H%x09%s"], cwd, read_ctx)
    if log["returncode"] != 0 or not log["stdout"].strip():
        return json.dumps(
            {"error": "no commit history to undo"}, ensure_ascii=False
        )

    revision, sep, subject = log["stdout"].strip().partition("\t")
    if not sep:
        revision, subject = revision, ""

    reset = await _git(["git", *_GIT_SAFE_CONFIG, "reset", "--soft", "HEAD~1"], cwd, destructive_ctx)
    if reset["returncode"] != 0:
        return json.dumps(
            {
                "error": reset["stderr"].strip() or reset["stdout"].strip(),
                "returncode": reset["returncode"],
            },
            ensure_ascii=False,
        )

    porcelain = await _git(["git", "status", "--porcelain"], cwd, read_ctx)
    files = [line[3:] for line in porcelain["stdout"].splitlines() if line.strip()]
    logger.info("git_undo: undid %s (%s)", revision[:8], subject)
    return json.dumps(
        {
            "message": f"Undone commit: {revision[:8]} {subject}".strip(),
            "files": files,
        },
        ensure_ascii=False,
    )


async def git_create_branch(
    cwd: str = ".", branch_name: str = "", from_base: str = "main", *, task_id: str | None = None, workspace_id: str | None = None, access_mode: str = "vcs.destructive-write", execution_service: Any = None, approval_context: dict[str, Any] | None = None, network_policy: str = "none"
) -> str:
    """Create a new branch from ``from_base`` and switch to it.

    Args:
        cwd: Repository working directory.
        branch_name: Target branch name (e.g. ``fix/login-bug``). Required.
        from_base: Base branch to branch off (default ``main``).

    Returns JSON describing the result:

    * ``{"branch", "base", "created": true}`` on success.
    * ``{"branch", "base", "created": false, "error": ...}`` if the branch
      already exists or the base is missing.
    """
    if not branch_name or not branch_name.strip():
        return json.dumps(
            {"error": "branch_name must not be empty"}, ensure_ascii=False
        )

    # Fetch the base so we branch off its latest tip. Missing base is reported
    # explicitly rather than crashing mid-checkout.
    base = from_base or "main"
    _validate_branch_name(branch_name)
    _validate_revision(base)
    destructive_ctx = _context(task_id, workspace_id, "vcs.destructive-write", execution_service, approval_context, "none")
    read_ctx = _context(task_id, workspace_id, "read-only", execution_service, approval_context, "none")
    base_lookup = await _git(["git", "rev-parse", "--verify", f"{base}^{{commit}}"], cwd, read_ctx)
    if base_lookup["returncode"] != 0:
        return json.dumps(
            {
                "branch": branch_name,
                "base": base,
                "created": False,
                "error": f"base branch {base!r} not found",
            },
            ensure_ascii=False,
        )

    existing = await _git(["git", "rev-parse", "--verify", f"refs/heads/{branch_name}"], cwd, read_ctx)
    if existing["returncode"] == 0:
        return json.dumps(
            {"branch": branch_name, "base": base, "created": False, "error": "branch already exists"},
            ensure_ascii=False,
        )
    checkout = await _git(
        ["git", *_GIT_SAFE_CONFIG, "switch", "-c", branch_name, base_lookup["stdout"].strip()],
        cwd,
        destructive_ctx,
    )
    if checkout["returncode"] != 0:
        message = checkout["stderr"].strip() or checkout["stdout"].strip()
        created = "already exists" not in message
        logger.info("git_create_branch: %s from %s — %s", branch_name, base, message)
        return json.dumps(
            {
                "branch": branch_name,
                "base": base,
                "created": created,
                "error": message,
            },
            ensure_ascii=False,
        )

    logger.info("git_create_branch: created %s from %s", branch_name, base)
    workspace = execution_service.workspace_manager.get(workspace_id)
    workspace.branch_name = branch_name
    return json.dumps(
        {"branch": branch_name, "base": base, "created": True},
        ensure_ascii=False,
    )


async def git_push(
    cwd: str = ".", remote: str = "origin", branch: str = "", *, task_id: str | None = None, workspace_id: str | None = None, access_mode: str = "vcs.remote-write", execution_service: Any = None, approval_context: dict[str, Any] | None = None, network_policy: str = "none"
) -> str:
    """Push the current (or named) branch to ``remote``.

    Args:
        cwd: Repository working directory.
        remote: Remote name (default ``origin``).
        branch: Branch to push. Empty pushes the current branch.

    Returns JSON ``{"remote", "branch", "pushed": bool, ...}``.
    """
    remote = remote or "origin"
    ctx = _context(task_id, workspace_id, "vcs.remote-write", execution_service, approval_context, network_policy)
    if not branch:
        branch_result = await _git(["git", "branch", "--show-current"], cwd, ctx)
        branch = branch_result["stdout"].strip() or "HEAD"

    # ``-u`` sets up tracking so future ``git push`` needs no args.
    push = await _git(
        ["git", "push", "-u", remote, branch], cwd, ctx
    )
    pushed = push["returncode"] == 0
    payload: dict[str, Any] = {
        "remote": remote,
        "branch": branch,
        "pushed": pushed,
    }
    if not pushed:
        payload["error"] = (push["stderr"].strip() or push["stdout"].strip())[
            :500
        ]
    logger.info(
        "git_push: %s/%s pushed=%s", remote, branch, pushed
    )
    return json.dumps(payload, ensure_ascii=False)


async def git_pr_body(cwd: str = ".", *, task_id: str | None = None, workspace_id: str | None = None, access_mode: str = "read-only", execution_service: Any = None, approval_context: dict[str, Any] | None = None, network_policy: str = "none") -> str:
    """Generate a PR description draft from the current branch's commits.

    Compares the current branch against ``main`` and assembles:

    * ``title`` — derived from the most significant conventional-commit subject.
    * ``body`` — a bulleted summary of every commit on this branch.
    * ``files`` — the list of changed files (``git diff --name-only``).

    Returns JSON ``{"title", "body", "files"}``. When the branch has no
    commits ahead of main, ``title`` is empty and ``body`` notes that.
    """
    base = "main"
    ctx = _context(task_id, workspace_id, "read-only", execution_service, approval_context, "none")
    # Commits on this branch not on main.
    log = await _git(
        ["git", "-c", "core.pager=cat", "log", f"{base}..HEAD", "--pretty=%H%x09%s%x09%an"],
        cwd, ctx,
    )
    if log["returncode"] != 0:
        # Base branch may not exist yet; fall back to all reachable commits.
        log = await _git(
            ["git", "-c", "core.pager=cat", "log", "--pretty=%H%x09%s%x09%an", "--max-count=20"], cwd, ctx
        )

    commit_lines = [
        line for line in log["stdout"].splitlines() if line.strip()
    ]
    if not commit_lines:
        return json.dumps(
            {
                "title": "",
                "body": "No commits ahead of base branch.",
                "files": [],
            },
            ensure_ascii=False,
        )

    commits = [_parse_commit_line(line) for line in commit_lines]
    title = _pick_pr_title(commits)
    body_lines: list[str] = ["## Summary", ""]
    for commit in commits:
        body_lines.append(f"- {commit['subject']}")
    body_lines.append("")
    body = "\n".join(body_lines)

    diff = await _git(["git", "-c", "core.pager=cat", "diff", "--no-ext-diff", f"{base}...HEAD", "--name-only"], cwd, ctx)
    if diff["returncode"] != 0:
        diff = await _git(["git", "-c", "core.pager=cat", "diff", "--no-ext-diff", "--name-only", "HEAD"], cwd, ctx)
    files = [line for line in diff["stdout"].splitlines() if line.strip()]

    logger.info(
        "git_pr_body: %d commits, %d files", len(commits), len(files)
    )
    return json.dumps(
        {"title": title, "body": body, "files": files},
        ensure_ascii=False,
    )


def _parse_commit_line(line: str) -> dict[str, str]:
    """Split a ``%H\\t%s\\t%an`` log line into hash/subject/author."""
    parts = line.split("\t")
    revision = parts[0] if parts else ""
    subject = parts[1] if len(parts) > 1 else ""
    author = parts[2] if len(parts) > 2 else ""
    return {"revision": revision, "subject": subject, "author": author}


def _pick_pr_title(commits: list[dict[str, str]]) -> str:
    """Choose a PR title from the branch's commits.

    ``commits`` is ordered newest-first (``git log`` default). Prefers the
    first conventional-commit subject (``type(scope): desc``) — i.e. the most
    recent structured commit, which is typically the most relevant headline
    for a reviewer; falls back to the newest commit's subject.
    """
    for commit in commits:
        if re.match(r"^\w+(\([\w-]+\))?:\s", commit["subject"]):
            return commit["subject"]
    return commits[0]["subject"] if commits else ""


def _parse_name_status(line: str) -> dict[str, str]:
    """Parse a ``git diff --name-status`` line into status + path."""
    parts = line.split("\t")
    code = parts[0]
    # Rename/copy codes look like R100/C90; keep the letter.
    kind = code[0] if code else "M"
    if len(parts) >= 3 and kind in {"R", "C"}:
        path = parts[2]
    else:
        path = parts[-1] if parts else ""
    return {"status": kind, "path": path}


def _extract_commit_hash(commit_output: str) -> str:
    """Pull the short hash from ``git commit`` stdout.

    Handles both ``[main (root-commit) abc1234] msg`` and the ordinary
    ``[main abc1234] msg`` shapes.
    """
    bracket = re.search(r"\[[^\]]*\b([0-9a-f]{7,40})\b[^\]]*\]", commit_output)
    return bracket.group(1) if bracket else ""


def _is_test_path(path: str) -> bool:
    """Heuristic: does this path look like a test/spec file?"""
    lower = path.lower()
    return any(token in lower for token in ("test", "spec", "_test.", ".test.", ".spec."))


def _generate_message(files: list[dict[str, str]]) -> str:
    """Infer a conventional-commit type and a terse description from files."""
    statuses = [f["status"] for f in files]
    paths = [f["path"] for f in files]

    has_added = "A" in statuses
    has_deleted = "D" in statuses
    all_tests = bool(paths) and all(_is_test_path(p) for p in paths)
    some_tests = any(_is_test_path(p) for p in paths)

    if all_tests:
        commit_type = "test"
    elif has_deleted:
        commit_type = "refactor"
    elif has_added:
        commit_type = "feat"
    elif some_tests:
        # Test-only modifications mixed with non-test edits still read as test.
        commit_type = "test"
    else:
        commit_type = "fix"

    scope = _infer_scope(paths)
    description = _describe(paths)
    if scope:
        return f"{commit_type}({scope}): {description}"
    return f"{commit_type}: {description}"


def _infer_scope(paths: list[str]) -> str:
    """Pick a scope from the most common top-level dir or file stem."""
    dirs: list[str] = []
    for path in paths:
        parent = Path(path).parent.as_posix()
        stem = Path(path).stem
        if parent and parent != ".":
            dirs.append(parent.split("/", maxsplit=1)[0])
        elif stem:
            dirs.append(stem)
    if not dirs:
        return ""
    # Most frequent token wins; ties resolved by first-seen order.
    counts: dict[str, int] = {}
    for token in dirs:
        counts[token] = counts.get(token, 0) + 1
    scope = max(dirs, key=lambda token: (counts[token], -dirs.index(token)))
    return scope


def _describe(paths: list[str]) -> str:
    """Turn a path list into a short, human-readable description."""
    if not paths:
        return "update files"
    names = sorted({Path(path).name for path in paths})
    if len(names) == 1:
        return f"update {names[0]}"
    preview = ", ".join(names[:3])
    if len(names) > 3:
        preview += f" (+{len(names) - 3} more)"
    return f"update {preview}"


async def _git(args: list[str], repo: str, context: _GitExecutionContext) -> dict[str, Any]:
    if context.access_mode == "read-only":
        return await _git_read_via_execution_service(args, repo, context)
    if context.access_mode == "vcs.write":
        return await _git_write_via_execution_service(args, repo, context)
    if context.access_mode == "vcs.destructive-write":
        return await _git_destructive_via_execution_service(args, repo, context)
    if context.access_mode != "read-only":
        if not context.task_id or not context.workspace_id or context.execution_service is None:
            raise PermissionError(f"{context.access_mode} requires an active TaskWorkspace")
    if context.execution_service is not None and context.workspace_id:
        manager = context.execution_service.workspace_manager
        workspace = manager.get(context.workspace_id) if manager is not None else None
        if workspace is None or workspace.task_id != context.task_id:
            raise PermissionError("task/workspace binding is invalid")
        if workspace.state.value in {"cancelled", "failed", "cleaning", "cleaned"}:
            raise PermissionError("workspace is not available for Git operations")
        cwd = str(workspace.worktree_path.resolve())
    else:
        cwd = str(Path(repo).expanduser().resolve())
    process = await asyncio.create_subprocess_exec(
        *args,
        cwd=cwd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await process.communicate()
    return {
        "command": args,
        "returncode": int(process.returncode or 0),
        "stdout": stdout.decode("utf-8", errors="replace"),
        "stderr": stderr.decode("utf-8", errors="replace"),
    }


async def _git_read_via_execution_service(
    args: list[str], repo: str, context: _GitExecutionContext
) -> dict[str, Any]:
    """Execute a predefined read-only Git argv in the active task worktree."""
    if not context.task_id or not context.workspace_id or context.execution_service is None:
        raise PermissionError("read-only Git operations require an active TaskWorkspace")
    manager = context.execution_service.workspace_manager
    workspace = manager.get(context.workspace_id) if manager is not None else None
    if workspace is None or workspace.task_id != context.task_id:
        raise PermissionError("task/workspace binding is invalid")
    if workspace.state.value in {"cancelled", "failed", "cleaning", "cleaned"}:
        raise PermissionError("workspace is not available for Git operations")

    cwd = workspace.worktree_path.expanduser().resolve()
    if repo not in {"", "."} and Path(repo).expanduser().resolve() != cwd:
        raise PermissionError("repo must match the active TaskWorkspace")

    environment = {
        "PATH": os.environ.get("PATH", ""),
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "GIT_PAGER": "cat",
        "PAGER": "cat",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
    }
    request = ExecutionRequest(
        argv=tuple(args),
        cwd=cwd,
        environment=environment,
        allowed_environment_keys=frozenset(environment),
        network_policy=NetworkPolicy.NONE,
        task_id=context.task_id,
        workspace_id=context.workspace_id,
        access_mode="read-only",
    )
    result = await context.execution_service.execute(request)
    return {
        "command": args,
        "returncode": int(result.return_code) if result.return_code is not None else -1,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


async def _git_write_via_execution_service(
    args: list[str], repo: str, context: _GitExecutionContext
) -> dict[str, Any]:
    """Execute an allowlisted local Git mutation in the active task worktree."""
    workspace, cwd = _resolve_git_workspace(repo, context, require_writable=True)
    _validate_local_write_argv(args)
    await _verify_task_branch(workspace, cwd, context)
    environment = _git_environment()
    request = ExecutionRequest(
        argv=tuple(args),
        cwd=cwd,
        writable_roots=(cwd,),
        environment=environment,
        allowed_environment_keys=frozenset(environment),
        network_policy=NetworkPolicy.NONE,
        task_id=context.task_id,
        workspace_id=context.workspace_id,
        access_mode="workspace-write",
    )
    result = await context.execution_service.execute(request)
    return _legacy_git_result(args, result)


async def _git_destructive_via_execution_service(
    args: list[str], repo: str, context: _GitExecutionContext
) -> dict[str, Any]:
    """Consume a bound approval and execute one allowlisted destructive argv."""
    workspace, cwd = _resolve_git_workspace(repo, context, require_writable=True)
    operation, target = _validate_destructive_argv(args)
    await _consume_destructive_approval(workspace, cwd, context, operation, target)
    with tempfile.TemporaryDirectory(prefix="khaos-git-home-") as temporary_home:
        environment = _git_environment(temporary_home)
        request = ExecutionRequest(
            argv=tuple(args),
            cwd=cwd,
            writable_roots=(cwd,),
            environment=environment,
            allowed_environment_keys=frozenset(environment),
            network_policy=NetworkPolicy.NONE,
            task_id=context.task_id,
            workspace_id=context.workspace_id,
            access_mode="workspace-write",
        )
        result = await context.execution_service.execute(request)
    return _legacy_git_result(args, result)


async def prepare_destructive_git_approval(
    tool_name: str,
    arguments: dict[str, Any],
    tool_context: dict[str, Any],
    *,
    requester: str,
    approval_id: str,
) -> dict[str, Any] | None:
    """Capture immutable Git state before the scheduler asks the user."""
    operation_target = _destructive_operation_target(tool_name, arguments)
    if operation_target is None:
        return None
    broker = tool_context.get("approval_broker")
    if broker is None:
        raise PermissionError("destructive Git operations require ApprovalBroker")
    context = _context(
        tool_context.get("task_id"),
        tool_context.get("workspace_id"),
        "read-only",
        tool_context.get("execution_service"),
        None,
        "none",
    )
    repo = arguments.get("repo", arguments.get("cwd", "."))
    workspace, cwd = _resolve_git_workspace(repo, context, require_writable=True)
    operation, target_hint = operation_target
    branch_result = await _git_read_via_execution_service(
        ["git", "symbolic-ref", "--quiet", "--short", "HEAD"], str(cwd), context
    )
    if branch_result["returncode"] != 0 or not branch_result["stdout"].strip():
        raise PermissionError("detached HEAD is not allowed for destructive Git operations")
    if branch_result["stdout"].strip() != workspace.branch_name:
        raise PermissionError("current branch does not match the TaskWorkspace branch")
    if operation in {"git.create-and-switch", "git.create-branch-from-base"}:
        status = await _git_read_via_execution_service(
            ["git", "status", "--porcelain"], str(cwd), context
        )
        if status["stdout"].strip():
            raise PermissionError("branch switching requires a clean worktree")
        branch_name = target_hint.split("@", 1)[0]
        existing = await _git_read_via_execution_service(
            ["git", "rev-parse", "--verify", f"refs/heads/{branch_name}"], str(cwd), context
        )
        if existing["returncode"] == 0:
            raise PermissionError("target branch already exists")
    head, diff_hash = await _git_state(cwd, context)
    if operation == "git.undo":
        parent = await _git_read_via_execution_service(
            ["git", "rev-parse", "--verify", "HEAD~1^{commit}"], str(cwd), context
        )
        if parent["returncode"] != 0:
            raise PermissionError("no commit history to undo")
        target = parent["stdout"].strip()
    elif operation == "git.create-branch-from-base":
        branch, base = target_hint.split("@", 1)
        base_result = await _git_read_via_execution_service(
            ["git", "rev-parse", "--verify", f"{base}^{{commit}}"], str(cwd), context
        )
        if base_result["returncode"] != 0:
            raise PermissionError("base revision does not exist")
        target = f"{branch}@{base_result['stdout'].strip()}"
    else:
        target = f"{target_hint}@{head}"
    expiry = time.time() + 120.0
    binding = {
        "task_id": workspace.task_id,
        "workspace_id": context.workspace_id,
        "operation": operation,
        "target": target,
        "head": head,
        "diff_hash": diff_hash,
        "expiry": expiry,
        "requester": requester,
    }
    await broker.register_operation(approval_id, binding, expiry)
    return {
        "approval_broker": broker,
        "approval_id": approval_id,
        "binding": binding,
    }


def _destructive_operation_target(
    tool_name: str, arguments: dict[str, Any]
) -> tuple[str, str] | None:
    if tool_name == "git_undo":
        return "git.undo", "HEAD~1"
    if tool_name == "git_branch" and arguments.get("checkout") and arguments.get("name"):
        name = str(arguments["name"])
        _validate_branch_name(name)
        return "git.create-and-switch", name
    if tool_name == "git_create_branch":
        branch = str(arguments.get("branch_name", ""))
        base = str(arguments.get("from_base") or "main")
        _validate_branch_name(branch)
        _validate_revision(base)
        return "git.create-branch-from-base", f"{branch}@{base}"
    return None


async def _consume_destructive_approval(
    workspace: Any,
    cwd: Path,
    context: _GitExecutionContext,
    operation: str,
    target_hint: str,
) -> None:
    approval = context.approval_context
    if not isinstance(approval, dict):
        raise PermissionError("destructive Git operation requires approval")
    binding = dict(approval.get("binding") or {})
    head, diff_hash = await _git_state(cwd, _context(
        context.task_id, context.workspace_id, "read-only", context.execution_service, None, "none"
    ))
    branch_result = await _git_read_via_execution_service(
        ["git", "symbolic-ref", "--quiet", "--short", "HEAD"],
        str(cwd),
        _context(context.task_id, context.workspace_id, "read-only", context.execution_service, None, "none"),
    )
    if branch_result["returncode"] != 0 or not branch_result["stdout"].strip():
        raise PermissionError("detached HEAD is not allowed for destructive Git operations")
    if branch_result["stdout"].strip() != workspace.branch_name:
        raise PermissionError("current branch does not match the TaskWorkspace branch")
    expected_target = target_hint
    if operation == "git.undo":
        expected_target = binding.get("target", "")
    elif operation == "git.create-and-switch":
        expected_target = f"{target_hint}@{head}"
    elif operation == "git.create-branch-from-base":
        branch = target_hint.split("@", 1)[0]
        expected_target = f"{branch}@{target_hint.split('@', 1)[1]}"
    current = {
        "task_id": workspace.task_id,
        "workspace_id": context.workspace_id,
        "operation": operation,
        "target": expected_target,
        "head": head,
        "diff_hash": diff_hash,
        "expiry": binding.get("expiry"),
        "requester": binding.get("requester"),
    }
    broker = approval.get("approval_broker")
    if broker is None or not await broker.consume_operation(approval.get("approval_id", ""), current):
        raise PermissionError("destructive Git approval is missing, stale, or replayed")


async def _git_state(cwd: Path, context: _GitExecutionContext) -> tuple[str, str]:
    head_result = await _git_read_via_execution_service(
        ["git", "rev-parse", "--verify", "HEAD"], str(cwd), context
    )
    if head_result["returncode"] != 0:
        raise PermissionError("unable to resolve current HEAD")
    diff_result = await _git_read_via_execution_service(
        ["git", "diff", "--no-ext-diff", "--binary", "HEAD", "--"], str(cwd), context
    )
    if diff_result["returncode"] != 0:
        raise PermissionError("unable to capture worktree diff")
    status_result = await _git_read_via_execution_service(
        ["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"], str(cwd), context
    )
    if status_result["returncode"] != 0:
        raise PermissionError("unable to capture worktree status")
    digest = hashlib.sha256()
    digest.update(diff_result["stdout"].encode())
    digest.update(b"\0")
    digest.update(status_result["stdout"].encode())
    for entry in status_result["stdout"].split("\0"):
        if not entry.startswith("?? "):
            continue
        path = (cwd / entry[3:]).resolve()
        if path != cwd and cwd not in path.parents:
            raise PermissionError("untracked path escapes the TaskWorkspace")
        if path.is_file() and not path.is_symlink():
            digest.update(path.read_bytes())
    return head_result["stdout"].strip(), digest.hexdigest()


def _validate_destructive_argv(args: list[str]) -> tuple[str, str]:
    if args[-3:] == ["reset", "--soft", "HEAD~1"]:
        return "git.undo", "HEAD~1"
    if len(args) >= 3 and args[-3:-1] == ["switch", "-c"]:
        return "git.create-and-switch", args[-1]
    if len(args) >= 4 and args[-4:-2] == ["switch", "-c"]:
        return "git.create-branch-from-base", f"{args[-2]}@{args[-1]}"
    raise PermissionError("destructive Git argv is not allowlisted")


def _resolve_git_workspace(
    repo: str, context: _GitExecutionContext, *, require_writable: bool
) -> tuple[Any, Path]:
    if not context.task_id or not context.workspace_id or context.execution_service is None:
        raise PermissionError(f"{context.access_mode} requires an active TaskWorkspace")
    manager = context.execution_service.workspace_manager
    workspace = manager.get(context.workspace_id) if manager is not None else None
    if workspace is None or workspace.task_id != context.task_id:
        raise PermissionError("task/workspace binding is invalid")
    if require_writable and workspace.state not in _WRITABLE_WORKSPACE_STATES:
        raise PermissionError("workspace is not available for writable Git operations")
    if not require_writable and workspace.state in {
        WorkspaceState.CANCELLED,
        WorkspaceState.FAILED,
        WorkspaceState.CLEANING,
        WorkspaceState.CLEANED,
    }:
        raise PermissionError("workspace is not available for Git operations")
    cwd = workspace.worktree_path.expanduser().resolve()
    repository_root = workspace.repository_root.expanduser().resolve()
    if cwd == repository_root:
        raise PermissionError("Git writes cannot target the main worktree")
    if repo not in {"", "."} and Path(repo).expanduser().resolve() != cwd:
        raise PermissionError("repo must match the active TaskWorkspace")
    return workspace, cwd


async def _verify_task_branch(
    workspace: Any, cwd: Path, context: _GitExecutionContext
) -> None:
    read_context = _context(
        context.task_id,
        context.workspace_id,
        "read-only",
        context.execution_service,
        context.approval_context,
        "none",
    )
    result = await _git_read_via_execution_service(
        ["git", "symbolic-ref", "--quiet", "--short", "HEAD"], str(cwd), read_context
    )
    branch = result["stdout"].strip()
    if result["returncode"] != 0 or not branch:
        raise PermissionError("detached HEAD is not writable")
    if branch in _PROTECTED_BRANCHES:
        raise PermissionError("commits on protected branches are not allowed")
    if branch != workspace.branch_name:
        raise PermissionError("current branch does not match the TaskWorkspace branch")


def _validate_local_write_argv(args: list[str]) -> None:
    allowed = False
    if args[:1] == ["git"] and "commit" in args:
        allowed = "--no-verify" in args and "--no-gpg-sign" in args and "-m" in args
    elif args[-4:] == ["add", "-A", "--", "."]:
        allowed = True
    elif len(args) >= 2 and args[-2] == "branch":
        _validate_branch_name(args[-1])
        allowed = True
    if not allowed:
        raise PermissionError("Git write argv is not allowlisted")


def _validate_branch_name(name: str) -> None:
    if name in _PROTECTED_BRANCHES:
        raise ValueError("protected branch name is not allowed")
    if (
        not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]*", name)
        or ".." in name
        or "//" in name
        or "@{" in name
        or name.endswith(("/", ".", ".lock"))
        or any(part in {"", ".", ".."} for part in name.split("/"))
    ):
        raise ValueError("invalid branch name")


def _git_environment(home: str | None = None) -> dict[str, str]:
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "GIT_PAGER": "cat",
        "PAGER": "cat",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_EDITOR": ":",
        "GIT_SEQUENCE_EDITOR": ":",
        "GIT_CONFIG_NOSYSTEM": "1",
    }
    if home is not None:
        environment["HOME"] = home
    return environment


def _validate_revision(revision: str) -> None:
    if (
        not revision
        or revision.startswith("-")
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]*", revision)
        or ".." in revision
        or "@{" in revision
        or revision.endswith(("/", ".", ".lock"))
    ):
        raise ValueError("invalid Git revision")


def _legacy_git_result(args: list[str], result: Any) -> dict[str, Any]:
    return {
        "command": args,
        "returncode": int(result.return_code) if result.return_code is not None else -1,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }
