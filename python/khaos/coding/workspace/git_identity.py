"""Pinned Git administrative identity for one linked TaskWorkspace."""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path


_MAX_GIT_POINTER_BYTES = 4096


class GitIdentityError(PermissionError):
    """Raised when linked-worktree Git metadata cannot be trusted."""


@dataclass(frozen=True)
class GitWorktreeIdentity:
    """Immutable identity captured immediately after ``git worktree add``."""

    pointer_path: Path
    pointer_identity: tuple[int, int]
    pointer_digest: str
    pointer_content: bytes
    admin_dir: Path
    admin_identity: tuple[int, int]
    repository_git_dir: Path
    repository_git_identity: tuple[int, int]


def capture_git_worktree_identity(
    repository_root: Path,
    worktree_path: Path,
) -> GitWorktreeIdentity:
    """Capture a linked worktree pointer and its repository-owned admin dir."""
    repository = repository_root.expanduser().resolve(strict=True)
    worktree = worktree_path.expanduser().resolve(strict=True)
    repository_git = (repository / ".git").resolve(strict=True)
    repository_info = os.stat(repository_git, follow_symlinks=False)
    if not stat.S_ISDIR(repository_info.st_mode):
        raise GitIdentityError("repository .git is not a directory")

    pointer = worktree / ".git"
    content, pointer_info = _read_pointer(pointer)
    admin_dir = _parse_admin_dir(content, worktree)
    try:
        admin_dir.relative_to(repository_git / "worktrees")
    except ValueError as exc:
        raise GitIdentityError(
            "linked worktree admin dir is outside repository .git/worktrees"
        ) from exc
    admin_info = os.stat(admin_dir, follow_symlinks=False)
    if not stat.S_ISDIR(admin_info.st_mode):
        raise GitIdentityError("linked worktree admin target is not a directory")
    return GitWorktreeIdentity(
        pointer_path=pointer,
        pointer_identity=(pointer_info.st_dev, pointer_info.st_ino),
        pointer_digest=hashlib.sha256(content).hexdigest(),
        pointer_content=content,
        admin_dir=admin_dir,
        admin_identity=(admin_info.st_dev, admin_info.st_ino),
        repository_git_dir=repository_git,
        repository_git_identity=(repository_info.st_dev, repository_info.st_ino),
    )


def verify_git_worktree_identity(identity: GitWorktreeIdentity) -> None:
    """Revalidate every pinned inode, pointer byte, and resolved admin target."""
    content, pointer_info = _read_pointer(identity.pointer_path)
    if (pointer_info.st_dev, pointer_info.st_ino) != identity.pointer_identity:
        raise GitIdentityError("TaskWorkspace .git pointer identity changed")
    if content != identity.pointer_content or (
        hashlib.sha256(content).hexdigest() != identity.pointer_digest
    ):
        raise GitIdentityError("TaskWorkspace .git pointer content changed")
    if _parse_admin_dir(content, identity.pointer_path.parent) != identity.admin_dir:
        raise GitIdentityError("TaskWorkspace .git admin target changed")

    try:
        admin_info = os.stat(identity.admin_dir, follow_symlinks=False)
        repository_info = os.stat(
            identity.repository_git_dir, follow_symlinks=False
        )
    except OSError as exc:
        raise GitIdentityError("pinned Git administrative path is unavailable") from exc
    if not stat.S_ISDIR(admin_info.st_mode) or (
        admin_info.st_dev, admin_info.st_ino
    ) != identity.admin_identity:
        raise GitIdentityError("linked worktree admin identity changed")
    if not stat.S_ISDIR(repository_info.st_mode) or (
        repository_info.st_dev, repository_info.st_ino
    ) != identity.repository_git_identity:
        raise GitIdentityError("repository Git identity changed")


def restore_git_pointer_for_cleanup(identity: GitWorktreeIdentity) -> None:
    """Restore only the pinned pointer bytes so Git can remove quarantine."""
    parent = identity.pointer_path.parent
    descriptor = os.open(
        parent,
        os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
    )
    temporary = f".git.khaos-cleanup-{os.urandom(12).hex()}"
    temporary_descriptor: int | None = None
    try:
        current = os.stat(".git", dir_fd=descriptor, follow_symlinks=False)
        if stat.S_ISDIR(current.st_mode):
            raise GitIdentityError("refusing to replace a .git directory")
        temporary_descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=descriptor,
        )
        offset = 0
        while offset < len(identity.pointer_content):
            offset += os.write(
                temporary_descriptor, identity.pointer_content[offset:]
            )
        os.fsync(temporary_descriptor)
        os.close(temporary_descriptor)
        temporary_descriptor = None
        os.replace(
            temporary,
            ".git",
            src_dir_fd=descriptor,
            dst_dir_fd=descriptor,
        )
        os.fsync(descriptor)
    except (FileNotFoundError, OSError) as exc:
        raise GitIdentityError("could not restore quarantined .git pointer") from exc
    finally:
        if temporary_descriptor is not None:
            os.close(temporary_descriptor)
        try:
            os.unlink(temporary, dir_fd=descriptor)
        except FileNotFoundError:
            pass
        os.close(descriptor)


def _read_pointer(pointer: Path) -> tuple[bytes, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(pointer, flags)
    except OSError as exc:
        raise GitIdentityError("TaskWorkspace .git pointer is unavailable") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise GitIdentityError(
                "TaskWorkspace .git must be a single-link regular file"
            )
        if before.st_size <= 0 or before.st_size > _MAX_GIT_POINTER_BYTES:
            raise GitIdentityError("TaskWorkspace .git pointer size is invalid")
        content = os.read(descriptor, _MAX_GIT_POINTER_BYTES + 1)
        after = os.fstat(descriptor)
        if len(content) > _MAX_GIT_POINTER_BYTES or (
            before.st_dev,
            before.st_ino,
            before.st_size,
        ) != (after.st_dev, after.st_ino, after.st_size):
            raise GitIdentityError("TaskWorkspace .git changed while reading")
        return content, after
    finally:
        os.close(descriptor)


def _parse_admin_dir(content: bytes, worktree: Path) -> Path:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise GitIdentityError("TaskWorkspace .git pointer is not UTF-8") from exc
    lines = text.splitlines()
    if len(lines) != 1 or not lines[0].startswith("gitdir: "):
        raise GitIdentityError("TaskWorkspace .git pointer format is invalid")
    value = lines[0][len("gitdir: "):]
    if not value or "\x00" in value:
        raise GitIdentityError("TaskWorkspace .git admin path is invalid")
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = worktree / candidate
    try:
        return candidate.resolve(strict=True)
    except OSError as exc:
        raise GitIdentityError("TaskWorkspace .git admin target is unavailable") from exc
