"""Orphan Worktree discovery and conservative recovery."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import subprocess


@dataclass(frozen=True)
class OrphanWorkspace:
    path: Path
    recovery_required: bool
    reason: str


def discover_orphans(root: Path) -> tuple[OrphanWorkspace, ...]:
    found: list[OrphanWorkspace] = []
    if not root.exists():
        return ()
    for path in root.iterdir():
        if not path.is_dir():
            continue
        result = subprocess.run(["git", "status", "--porcelain"], cwd=path, capture_output=True, text=True, check=False)
        dirty = bool(result.stdout.strip())
        found.append(OrphanWorkspace(path, dirty, "uncommitted changes" if dirty else "orphan worktree"))
    return tuple(found)
