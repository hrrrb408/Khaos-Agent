"""Real-path boundary checks for Task Workspace writes."""

from __future__ import annotations

import os
import stat
from pathlib import Path


class WorkspaceBoundaryError(PermissionError):
    pass


def resolve_write_target(worktree: Path, target: str | Path) -> Path:
    root = worktree.expanduser().resolve()
    candidate = Path(target).expanduser()
    if not candidate.is_absolute():
        candidate = root / candidate
    resolved_parent = candidate.parent.resolve()
    resolved = (resolved_parent / candidate.name).resolve()
    if root != resolved and root not in resolved.parents:
        raise WorkspaceBoundaryError("write target is outside task worktree")
    if resolved.exists() and stat.S_ISLNK(resolved.stat().st_mode):
        raise WorkspaceBoundaryError("symlink write target is not allowed")
    if resolved.exists() and not stat.S_ISREG(resolved.stat().st_mode) and not stat.S_ISDIR(resolved.stat().st_mode):
        raise WorkspaceBoundaryError("device, fifo, or socket target is not allowed")
    return resolved
