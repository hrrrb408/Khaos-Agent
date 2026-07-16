"""Conservative TaskWorkspace storage accounting."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path


FileIdentity = tuple[int, int]


@dataclass(frozen=True)
class WorkspaceStorageSnapshot:
    """Allocated bytes by inode plus total directory-entry count."""

    allocated_by_inode: dict[FileIdentity, int]
    entries: int
    complete: bool


def capture_workspace_snapshot(root: Path) -> WorkspaceStorageSnapshot:
    """Scan twice and merge maxima so rename/write races cannot undercount."""
    canonical = root.expanduser().resolve()
    first = _capture_once(canonical)
    second = _capture_once(canonical)
    allocated = dict(first.allocated_by_inode)
    for identity, size in second.allocated_by_inode.items():
        allocated[identity] = max(size, allocated.get(identity, 0))
    return WorkspaceStorageSnapshot(
        allocated,
        max(first.entries, second.entries),
        first.complete or second.complete,
    )


def workspace_storage_delta(
    baseline: WorkspaceStorageSnapshot,
    current: WorkspaceStorageSnapshot,
) -> tuple[int, int]:
    """Return allocated-byte and entry growth relative to a fixed baseline."""
    allocated_growth = sum(
        max(0, size - baseline.allocated_by_inode.get(identity, 0))
        for identity, size in current.allocated_by_inode.items()
    )
    entry_growth = max(0, current.entries - baseline.entries)
    return allocated_growth, entry_growth


def _capture_once(root: Path) -> WorkspaceStorageSnapshot:
    if not root.is_dir():
        return WorkspaceStorageSnapshot({}, 0, False)
    allocated: dict[FileIdentity, int] = {}
    entries = 0
    complete = True
    try:
        iterator = os.walk(root, followlinks=False)
        for directory, subdirectories, files in iterator:
            entries += len(subdirectories) + len(files)
            for name in files:
                try:
                    value = os.stat(
                        Path(directory) / name, follow_symlinks=False
                    )
                except OSError:
                    complete = False
                    continue
                if not stat.S_ISREG(value.st_mode):
                    continue
                identity = (value.st_dev, value.st_ino)
                allocated_bytes = int(getattr(value, "st_blocks", 0)) * 512
                if allocated_bytes <= 0 and value.st_size > 0:
                    allocated_bytes = value.st_size
                allocated[identity] = max(
                    allocated_bytes, allocated.get(identity, 0)
                )
    except OSError:
        complete = False
    return WorkspaceStorageSnapshot(allocated, entries, complete)
