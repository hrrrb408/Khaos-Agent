"""Orphan Worktree discovery and conservative recovery."""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from khaos.coding.workspace.trusted_git import TrustedGitError, TrustedGitRunner
from khaos.security.authority import AuthorityEnvelope
from khaos.security.authority_broker import AuthorityBroker


@dataclass(frozen=True)
class OrphanWorkspace:
    path: Path
    recovery_required: bool
    reason: str


def discover_orphans(root: Path) -> tuple[OrphanWorkspace, ...]:
    found: list[OrphanWorkspace] = []
    if not root.exists():
        return ()
    try:
        authority_root = root.resolve(strict=True)
        root_info = authority_root.stat()
        if (
            not stat.S_ISDIR(root_info.st_mode)
            or root_info.st_uid != os.getuid()
            or root_info.st_mode & 0o022
        ):
            raise TrustedGitError("recovery root is not a private user-owned directory")
        runner = TrustedGitRunner.for_authority_root(
            authority_root,
            (
                int(root_info.st_dev),
                int(root_info.st_ino),
                int(root_info.st_uid),
                int(root_info.st_mode),
            ),
        )
    except (OSError, TrustedGitError) as exc:
        for path in root.iterdir():
            if path.is_dir() and not path.is_symlink():
                found.append(
                    OrphanWorkspace(
                        path,
                        True,
                        f"trusted Git recovery unavailable: {exc}",
                    )
                )
        return tuple(found)
    broker = AuthorityBroker.default()
    for path in root.iterdir():
        if not path.is_dir() or path.is_symlink():
            continue
        authority = AuthorityEnvelope.system(
            operation_class="git.recovery",
            resource_digest=hashlib.sha256(str(path.resolve()).encode("utf-8")).hexdigest(),
            task_id=path.name,
            workspace_id=path.name,
        )
        capability = broker.issue(authority, allowed_operation="git.*")
        try:
            status = runner.run_sync(
                path,
                "status",
                "--porcelain",
                authority=capability,
            )
        except TrustedGitError as exc:
            found.append(
                OrphanWorkspace(path, True, f"trusted Git status unavailable: {exc}")
            )
            continue
        dirty = bool(status)
        found.append(
            OrphanWorkspace(
                path,
                dirty,
                "uncommitted changes" if dirty else "orphan worktree",
            )
        )
    return tuple(found)
