"""Real-path boundary checks for Task Workspace writes."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Callable

from khaos.coding.planning.safe_workspace_path import (
    SafePathError,
    WorkspacePathHandle,
)


class WorkspaceBoundaryError(PermissionError):
    pass


PROTECTED_WORKSPACE_NAMES = frozenset({".git", ".agents", ".codex", ".khaos"})


class SafeWorkspaceFS:
    """Dirfd-anchored filesystem capability for one TaskWorkspace.

    Every lookup is relative to a root directory descriptor and every parent
    component is opened with ``O_NOFOLLOW``. Existing writable/readable files
    must be regular, single-link objects; protected metadata is never exposed.
    """

    def __init__(self, worktree: Path) -> None:
        self.root = worktree.expanduser().resolve(strict=True)
        self._handle = WorkspacePathHandle(self.root)

    def close(self) -> None:
        self._handle.close()

    def _parent(self, relative: str):
        try:
            return self._handle.parent(relative)
        except (OSError, SafePathError) as exc:
            raise WorkspaceBoundaryError(str(exc)) from exc

    def __enter__(self) -> "SafeWorkspaceFS":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def relative(self, target: str | Path) -> str:
        candidate = Path(target).expanduser()
        if candidate.is_absolute():
            absolute = Path(os.path.abspath(candidate))
        else:
            absolute = Path(os.path.abspath(self.root / candidate))
        try:
            relative = absolute.relative_to(self.root)
        except ValueError as exc:
            raise WorkspaceBoundaryError(
                "filesystem target is outside task worktree"
            ) from exc
        if not relative.parts:
            raise WorkspaceBoundaryError("workspace root is not a file target")
        if relative.parts[0] in PROTECTED_WORKSPACE_NAMES:
            raise WorkspaceBoundaryError("protected workspace metadata is read-only")
        return relative.as_posix()

    def read_bytes(self, target: str | Path) -> bytes:
        relative = self.relative(target)
        parent = self._parent(relative)
        try:
            info = parent.lstat()
            if info is None or not stat.S_ISREG(info.st_mode):
                raise WorkspaceBoundaryError("target is not a regular file")
            if info.st_nlink != 1:
                raise WorkspaceBoundaryError("hardlinked files are not allowed")
            content, final = parent.read_file()
            if final.st_nlink != 1:
                raise WorkspaceBoundaryError("hardlink count changed while reading")
            parent.revalidate()
            return content
        except (OSError, SafePathError) as exc:
            raise WorkspaceBoundaryError(str(exc)) from exc
        finally:
            parent.close()

    def stat(self, target: str | Path) -> os.stat_result:
        relative = self.relative(target)
        parent = self._parent(relative)
        try:
            info = parent.lstat()
            if info is None:
                raise FileNotFoundError(relative)
            if stat.S_ISLNK(info.st_mode):
                raise WorkspaceBoundaryError("symlink targets are not allowed")
            if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
                raise WorkspaceBoundaryError("hardlinked files are not allowed")
            parent.revalidate()
            return info
        finally:
            parent.close()

    def iter_files(self, target: str | Path = ".") -> list[str]:
        directory = self._open_directory(target)
        base = self._directory_relative(target)
        files: list[str] = []
        stack: list[tuple[int, tuple[str, ...]]] = [(directory, tuple(base.split("/")) if base else ())]
        try:
            while stack:
                descriptor, prefix = stack.pop()
                try:
                    names = sorted(os.listdir(descriptor), key=str.lower)
                    for name in names:
                        if not prefix and name in PROTECTED_WORKSPACE_NAMES:
                            continue
                        info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                        relative_parts = (*prefix, name)
                        if stat.S_ISDIR(info.st_mode):
                            child = os.open(
                                name,
                                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=descriptor,
                            )
                            stack.append((child, relative_parts))
                        elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                            files.append("/".join(relative_parts))
                finally:
                    os.close(descriptor)
        except Exception:
            for descriptor, _ in stack:
                os.close(descriptor)
            raise
        return sorted(files)

    def _directory_relative(self, target: str | Path) -> str:
        candidate = Path(target).expanduser()
        absolute = Path(os.path.abspath(candidate if candidate.is_absolute() else self.root / candidate))
        try:
            relative = absolute.relative_to(self.root)
        except ValueError as exc:
            raise WorkspaceBoundaryError("directory is outside task worktree") from exc
        if relative.parts and relative.parts[0] in PROTECTED_WORKSPACE_NAMES:
            raise WorkspaceBoundaryError("protected workspace metadata is read-only")
        return relative.as_posix() if relative.parts else ""

    def _open_directory(self, target: str | Path) -> int:
        relative = self._directory_relative(target)
        descriptor = os.dup(self._handle.root_fd)
        try:
            for part in Path(relative).parts if relative else ():
                child = os.open(
                    part,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=descriptor,
                )
                os.close(descriptor)
                descriptor = child
            return descriptor
        except Exception:
            os.close(descriptor)
            raise

    def write_bytes(
        self, target: str | Path, content: bytes, *, mode: int = 0o600
    ) -> None:
        relative = self.relative(target)
        parent = self._parent(relative)
        try:
            current = parent.lstat()
            if current is not None:
                if not stat.S_ISREG(current.st_mode):
                    raise WorkspaceBoundaryError("target is not a regular file")
                if current.st_nlink != 1:
                    raise WorkspaceBoundaryError("hardlinked files are not writable")
                expected_inode = current.st_ino
                selected_mode = stat.S_IMODE(current.st_mode) & 0o666
            else:
                expected_inode = None
                selected_mode = mode & 0o666
        finally:
            parent.close()
        phase: Callable[..., None] = lambda *_args, **_kwargs: None
        try:
            if expected_inode is None:
                self._handle.create(relative, content, selected_mode, phase)
            else:
                self._handle.update(
                    relative, content, selected_mode, expected_inode, phase
                )
        except (OSError, SafePathError) as exc:
            raise WorkspaceBoundaryError(str(exc)) from exc

    def transform_text(
        self, target: str | Path, transform: Callable[[str], str]
    ) -> str:
        original = self.read_bytes(target).decode("utf-8")
        updated = transform(original)
        self.write_bytes(target, updated.encode("utf-8"))
        return updated

    def copy_file(self, source: str | Path, destination: str | Path) -> int:
        content = self.read_bytes(source)
        relative = self.relative(destination)
        parent = self._parent(relative)
        try:
            if parent.lstat() is not None:
                raise WorkspaceBoundaryError("copy destination already exists")
        finally:
            parent.close()
        self.write_bytes(destination, content)
        return len(content)

    def move_file(self, source: str | Path, destination: str | Path) -> None:
        source_relative = self.relative(source)
        destination_relative = self.relative(destination)
        parent = self._parent(source_relative)
        try:
            current = parent.lstat()
            if current is None or not stat.S_ISREG(current.st_mode):
                raise WorkspaceBoundaryError("move source is not a regular file")
            if current.st_nlink != 1:
                raise WorkspaceBoundaryError("hardlinked files are not movable")
            inode = current.st_ino
        finally:
            parent.close()
        try:
            self._handle.rename_no_replace(
                source_relative, destination_relative, inode,
                lambda *_args, **_kwargs: None,
            )
        except (OSError, SafePathError) as exc:
            raise WorkspaceBoundaryError(str(exc)) from exc


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
