"""Git tools for coding mode."""

from __future__ import annotations

import asyncio
import json
import logging
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


async def git_diff(repo: str = ".", staged: bool = False) -> dict[str, Any]:
    """Return git diff output."""
    args = ["git", "diff"]
    if staged:
        args.append("--staged")
    return await _git(args, repo)


async def git_commit(repo: str = ".", message: str = "") -> dict[str, Any]:
    """Create a git commit."""
    if not message:
        raise ValueError("commit message is required")
    return await _git(["git", "commit", "-m", message], repo)


async def git_branch(repo: str = ".", name: str = "", checkout: bool = False) -> dict[str, Any]:
    """List, create, or checkout branches."""
    if name and checkout:
        return await _git(["git", "checkout", "-b", name], repo)
    if name:
        return await _git(["git", "branch", name], repo)
    return await _git(["git", "branch", "--show-current"], repo)


async def git_log(repo: str = ".", limit: int = 10) -> dict[str, Any]:
    """Return concise git log."""
    return await _git(["git", "log", f"--max-count={limit}", "--oneline"], repo)


async def git_status(cwd: str = ".") -> str:
    """Return a structured ``git status`` snapshot as JSON.

    Parses ``git status --porcelain`` into branch, modified/added/deleted/
    untracked/staged buckets and an ``is_clean`` flag.
    """
    branch_result = await _git(
        ["git", "branch", "--show-current"], cwd
    )
    branch = branch_result["stdout"].strip()

    porcelain = await _git(
        ["git", "status", "--porcelain"], cwd
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


async def git_smart_commit(cwd: str = ".", message: str = "") -> str:
    """Stage everything and commit with an inferred or explicit message.

    When ``message`` is empty the change set is inspected (``git diff
    --cached --name-status``) and a conventional-commit message of the form
    ``<type>(<scope>): <description>`` is generated. Returns JSON describing
    the resulting commit, or ``{"message": "Nothing to commit."}`` when the
    tree is clean.
    """
    await _git(["git", "add", "-A"], cwd)
    diff = await _git(["git", "diff", "--cached", "--name-status"], cwd)
    diff_lines = [
        line for line in diff["stdout"].splitlines() if line.strip()
    ]

    if not diff_lines:
        return json.dumps({"message": "Nothing to commit."}, ensure_ascii=False)

    files = [_parse_name_status(line) for line in diff_lines]

    if not message:
        message = _generate_message(files)

    commit = await _git(["git", "commit", "-m", message], cwd)
    if commit["returncode"] != 0:
        return json.dumps(
            {
                "error": commit["stderr"].strip() or commit["stdout"].strip(),
                "returncode": commit["returncode"],
            },
            ensure_ascii=False,
        )

    branch_result = await _git(["git", "branch", "--show-current"], cwd)
    branch = branch_result["stdout"].strip()
    # ``git commit`` prints "[<branch> (root-commit) <hash>] <subject>"; pull
    # the trailing 7-char hash out of the brackets, fall back to rev-parse.
    revision = _extract_commit_hash(commit["stdout"])
    if not revision:
        rev = await _git(["git", "rev-parse", "--short", "HEAD"], cwd)
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


async def git_undo(cwd: str = ".") -> str:
    """Undo the last commit, keeping its changes staged (soft reset).

    Returns the hash and message of the commit that was undone plus the list
    of files now staged as a result.
    """
    log = await _git(["git", "log", "-1", "--pretty=%H%x09%s"], cwd)
    if log["returncode"] != 0 or not log["stdout"].strip():
        return json.dumps(
            {"error": "no commit history to undo"}, ensure_ascii=False
        )

    revision, sep, subject = log["stdout"].strip().partition("\t")
    if not sep:
        revision, subject = revision, ""

    reset = await _git(["git", "reset", "--soft", "HEAD~1"], cwd)
    if reset["returncode"] != 0:
        return json.dumps(
            {
                "error": reset["stderr"].strip() or reset["stdout"].strip(),
                "returncode": reset["returncode"],
            },
            ensure_ascii=False,
        )

    porcelain = await _git(["git", "status", "--porcelain"], cwd)
    files = [line[3:] for line in porcelain["stdout"].splitlines() if line.strip()]
    logger.info("git_undo: undid %s (%s)", revision[:8], subject)
    return json.dumps(
        {
            "message": f"Undone commit: {revision[:8]} {subject}".strip(),
            "files": files,
        },
        ensure_ascii=False,
    )


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


async def _git(args: list[str], repo: str) -> dict[str, Any]:
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

