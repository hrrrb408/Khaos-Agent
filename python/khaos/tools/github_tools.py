"""GitHub remote-platform tools backed by the authenticated ``gh`` CLI."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any


async def _gh(args: list[str], cwd: str = ".") -> dict[str, Any]:
    try:
        process = await asyncio.create_subprocess_exec(
            "gh", *args, cwd=str(Path(cwd).expanduser().resolve()),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        return {"error": "gh CLI not installed", "returncode": -1}
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=60)
    except asyncio.TimeoutError:
        process.kill()
        await process.wait()
        return {"error": "gh command timed out", "returncode": -1}
    out = stdout.decode(errors="replace").strip()
    result: dict[str, Any] = {"returncode": process.returncode, "stdout": out, "stderr": stderr.decode(errors="replace").strip()}
    if out:
        try:
            result["data"] = json.loads(out)
        except json.JSONDecodeError:
            pass
    return result


async def github_create_pr(title: str, body: str, base: str = "main", head: str = "", draft: bool = False, repo: str = "", cwd: str = ".", **_: Any) -> str:
    args = ["pr", "create", "--title", title, "--body", body, "--base", base]
    if head: args.extend(["--head", head])
    if draft: args.append("--draft")
    if repo: args.extend(["--repo", repo])
    result = await _gh(args, cwd)
    if result.get("returncode") != 0:
        return json.dumps({"created": False, "error": result.get("stderr") or result.get("error")}, ensure_ascii=False)
    return json.dumps({"created": True, "url": result.get("stdout", ""), "title": title, "base": base, "head": head}, ensure_ascii=False)


async def github_read_issue(issue_number: int, repo: str = "", cwd: str = ".", **_: Any) -> str:
    args = ["issue", "view", str(issue_number), "--json", "number,title,body,state,labels"]
    if repo: args.extend(["--repo", repo])
    result = await _gh(args, cwd)
    return json.dumps(result.get("data") or {"error": result.get("stderr") or result.get("error")}, ensure_ascii=False)


async def github_comment_issue(issue_number: int, comment: str, repo: str = "", cwd: str = ".", **_: Any) -> str:
    args = ["issue", "comment", str(issue_number), "--body", comment]
    if repo: args.extend(["--repo", repo])
    result = await _gh(args, cwd)
    return json.dumps({"ok": result.get("returncode") == 0, "issue": issue_number, "error": result.get("stderr", "")}, ensure_ascii=False)


async def github_request_review(pr_number: int, reviewers: list[str] | None = None, repo: str = "", cwd: str = ".", **_: Any) -> str:
    args = ["pr", "edit", str(pr_number), "--add-reviewer", ",".join(reviewers or [])]
    if repo: args.extend(["--repo", repo])
    result = await _gh(args, cwd)
    return json.dumps({"ok": result.get("returncode") == 0, "pr": pr_number, "reviewers": reviewers or [], "error": result.get("stderr", "")}, ensure_ascii=False)


GITHUB_TOOL_SPECS = [
    {"name": "github_create_pr", "description": "Create a GitHub pull request after pushing a branch.", "parameters": {"type": "object", "properties": {"title": {"type": "string"}, "body": {"type": "string"}, "base": {"type": "string"}, "head": {"type": "string"}, "draft": {"type": "boolean"}, "repo": {"type": "string"}, "cwd": {"type": "string"}}, "required": ["title", "body"]}},
    {"name": "github_read_issue", "description": "Read a GitHub issue.", "parameters": {"type": "object", "properties": {"issue_number": {"type": "integer"}, "repo": {"type": "string"}, "cwd": {"type": "string"}}, "required": ["issue_number"]}},
    {"name": "github_comment_issue", "description": "Comment on a GitHub issue.", "parameters": {"type": "object", "properties": {"issue_number": {"type": "integer"}, "comment": {"type": "string"}, "repo": {"type": "string"}, "cwd": {"type": "string"}}, "required": ["issue_number", "comment"]}},
    {"name": "github_request_review", "description": "Request reviewers on a GitHub pull request.", "parameters": {"type": "object", "properties": {"pr_number": {"type": "integer"}, "reviewers": {"type": "array", "items": {"type": "string"}}, "repo": {"type": "string"}, "cwd": {"type": "string"}}, "required": ["pr_number"]}},
]
