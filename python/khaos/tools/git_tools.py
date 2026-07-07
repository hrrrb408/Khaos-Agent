"""Git tools for coding mode."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any


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

