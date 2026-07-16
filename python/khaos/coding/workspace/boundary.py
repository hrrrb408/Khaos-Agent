"""Real-path boundary checks for Task Workspace writes."""

from __future__ import annotations

import os
import hashlib
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from khaos.coding.planning.safe_workspace_path import (
    SafePathError,
    WorkspacePathHandle,
)


class WorkspaceBoundaryError(PermissionError):
    pass


@dataclass(frozen=True)
class WorkspaceFileSnapshot:
    """Identity-bound regular-file state used for safe mutation rollback."""

    exists: bool
    mode: int = 0o600
    identity: tuple[int, int] | None = None
    size: int = 0
    digest: str = ""
    recovery_path: Path | None = field(default=None, compare=False)

    def cleanup(self) -> None:
        if self.recovery_path is not None:
            self.recovery_path.unlink(missing_ok=True)


PROTECTED_WORKSPACE_NAMES = frozenset({".git", ".agents", ".codex", ".khaos"})
DEFAULT_FILE_TOOL_BYTES = 16 * 1024 * 1024


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
        if relative.parts[0].casefold() in {
            name.casefold() for name in PROTECTED_WORKSPACE_NAMES
        }:
            raise WorkspaceBoundaryError("protected workspace metadata is read-only")
        return relative.as_posix()

    def read_bytes(
        self, target: str | Path, *, max_bytes: int = DEFAULT_FILE_TOOL_BYTES
    ) -> bytes:
        relative = self.relative(target)
        parent = self._parent(relative)
        try:
            info = parent.lstat()
            if info is None or not stat.S_ISREG(info.st_mode):
                raise WorkspaceBoundaryError("target is not a regular file")
            if info.st_nlink != 1:
                raise WorkspaceBoundaryError("hardlinked files are not allowed")
            content, final = parent.read_file(max_bytes=max_bytes)
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

    def snapshot_file(
        self,
        target: str | Path,
        *,
        recovery_root: Path | None = None,
        max_bytes: int = DEFAULT_FILE_TOOL_BYTES,
    ) -> WorkspaceFileSnapshot:
        """Capture a missing or single-link regular file through fixed dirfds."""
        relative = self.relative(target)
        parent = self._parent(relative)
        try:
            info = parent.lstat()
            if info is None:
                parent.revalidate()
                return WorkspaceFileSnapshot(False)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise WorkspaceBoundaryError(
                    "rollback target is not a single-link regular file"
                )
            if info.st_size > max_bytes:
                raise WorkspaceBoundaryError(
                    "rollback target exceeds the file-tool size limit"
                )
            descriptor = os.open(
                parent.leaf,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=parent.parent_fd,
            )
            recovery_path: Path | None = None
            recovery_descriptor: int | None = None
            try:
                if recovery_root is not None:
                    recovery_path, recovery_descriptor = self._recovery_file(
                        recovery_root
                    )
                digest = hashlib.sha256()
                total = 0
                while True:
                    chunk = os.read(descriptor, 1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_bytes:
                        raise WorkspaceBoundaryError(
                            "rollback target grew beyond the file-tool size limit"
                        )
                    digest.update(chunk)
                    if recovery_descriptor is not None:
                        self._write_all(recovery_descriptor, chunk)
                final = os.fstat(descriptor)
                if (
                    final.st_dev,
                    final.st_ino,
                    final.st_size,
                ) != (info.st_dev, info.st_ino, info.st_size):
                    raise WorkspaceBoundaryError(
                        "rollback target changed while snapshotting"
                    )
                if recovery_descriptor is not None:
                    os.fsync(recovery_descriptor)
            except Exception:
                if recovery_path is not None:
                    recovery_path.unlink(missing_ok=True)
                raise
            finally:
                os.close(descriptor)
                if recovery_descriptor is not None:
                    os.close(recovery_descriptor)
            parent.revalidate()
            return WorkspaceFileSnapshot(
                True,
                stat.S_IMODE(final.st_mode) & 0o666,
                (final.st_dev, final.st_ino),
                final.st_size,
                digest.hexdigest(),
                recovery_path,
            )
        except (OSError, SafePathError) as exc:
            raise WorkspaceBoundaryError(str(exc)) from exc
        finally:
            parent.close()

    def restore_file(
        self,
        target: str | Path,
        snapshot: WorkspaceFileSnapshot,
        *,
        expected: WorkspaceFileSnapshot,
    ) -> None:
        """Stream an authority-owned recovery file over an exact target."""
        if not snapshot.exists or snapshot.recovery_path is None:
            raise WorkspaceBoundaryError("rollback recovery file is unavailable")
        current = self.snapshot_file(target)
        if current != expected or expected.identity is None:
            raise WorkspaceBoundaryError("rollback target changed concurrently")
        recovery = snapshot.recovery_path
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(recovery, flags)
        parent = self._parent(self.relative(target))
        temporary = ""
        try:
            recovery_info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(recovery_info.st_mode)
                or recovery_info.st_nlink != 1
                or recovery_info.st_size != snapshot.size
            ):
                raise WorkspaceBoundaryError("rollback recovery identity is invalid")
            temporary_descriptor, temporary = parent.temporary(mode=snapshot.mode)
            digest = hashlib.sha256()
            total = 0
            try:
                while True:
                    chunk = os.read(descriptor, 1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > DEFAULT_FILE_TOOL_BYTES:
                        raise WorkspaceBoundaryError("rollback recovery exceeds limit")
                    digest.update(chunk)
                    self._write_all(temporary_descriptor, chunk)
                os.fsync(temporary_descriptor)
                os.fchmod(temporary_descriptor, snapshot.mode)
            finally:
                os.close(temporary_descriptor)
            if total != snapshot.size or digest.hexdigest() != snapshot.digest:
                raise WorkspaceBoundaryError("rollback recovery digest mismatch")
            parent.revalidate()
            live = parent.lstat()
            if live is None or (live.st_dev, live.st_ino) != expected.identity:
                raise WorkspaceBoundaryError("rollback target identity changed")
            self._handle._exchange(
                parent.parent_fd, temporary, parent.leaf
            )
            replaced = os.stat(
                temporary, dir_fd=parent.parent_fd, follow_symlinks=False
            )
            if (replaced.st_dev, replaced.st_ino) != expected.identity:
                self._handle._exchange(
                    parent.parent_fd, temporary, parent.leaf
                )
                raise WorkspaceBoundaryError("rollback exchange identity mismatch")
            os.unlink(temporary, dir_fd=parent.parent_fd)
            temporary = ""
            parent.fsync()
        finally:
            if temporary:
                try:
                    os.unlink(temporary, dir_fd=parent.parent_fd)
                except FileNotFoundError:
                    pass
            parent.close()
            os.close(descriptor)

    def _recovery_file(self, recovery_root: Path) -> tuple[Path, int]:
        root = recovery_root.expanduser().resolve(strict=True)
        if root == self.root or self.root in root.parents or root in self.root.parents:
            raise WorkspaceBoundaryError(
                "file-tool recovery root must be outside the TaskWorkspace"
            )
        info = os.stat(root, follow_symlinks=False)
        if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
            raise WorkspaceBoundaryError("file-tool recovery root is not private")
        for _ in range(32):
            name = f"snapshot-{os.urandom(16).hex()}"
            path = root / name
            try:
                descriptor = os.open(
                    path,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL
                    | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                )
                return path, descriptor
            except FileExistsError:
                continue
        raise WorkspaceBoundaryError("could not allocate recovery snapshot")

    @staticmethod
    def _write_all(descriptor: int, content: bytes) -> None:
        offset = 0
        while offset < len(content):
            written = os.write(descriptor, content[offset:])
            if written <= 0:
                raise OSError("short write")
            offset += written

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
                        if not prefix and name.casefold() in {
                            protected.casefold()
                            for protected in PROTECTED_WORKSPACE_NAMES
                        }:
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
        if relative.parts and relative.parts[0].casefold() in {
            name.casefold() for name in PROTECTED_WORKSPACE_NAMES
        }:
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
        source_relative = self.relative(source)
        relative = self.relative(destination)
        source_parent = self._parent(source_relative)
        parent = self._parent(relative)
        temporary = ""
        source_descriptor: int | None = None
        temporary_descriptor: int | None = None
        try:
            if parent.lstat() is not None:
                raise WorkspaceBoundaryError("copy destination already exists")
            source_info = source_parent.lstat()
            if (
                source_info is None
                or not stat.S_ISREG(source_info.st_mode)
                or source_info.st_nlink != 1
                or source_info.st_size > DEFAULT_FILE_TOOL_BYTES
            ):
                raise WorkspaceBoundaryError(
                    "copy source is not a bounded single-link regular file"
                )
            source_descriptor = os.open(
                source_parent.leaf,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=source_parent.parent_fd,
            )
            temporary_descriptor, temporary = parent.temporary(mode=0o600)
            total = 0
            try:
                while True:
                    chunk = os.read(source_descriptor, 1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > DEFAULT_FILE_TOOL_BYTES:
                        raise WorkspaceBoundaryError(
                            "copy source grew beyond the file-tool size limit"
                        )
                    self._write_all(temporary_descriptor, chunk)
                os.fsync(temporary_descriptor)
            finally:
                if temporary_descriptor is not None:
                    os.close(temporary_descriptor)
                    temporary_descriptor = None
                if source_descriptor is not None:
                    os.close(source_descriptor)
                    source_descriptor = None
            final_source = source_parent.lstat()
            if final_source is None or (
                final_source.st_dev,
                final_source.st_ino,
                final_source.st_size,
            ) != (
                source_info.st_dev,
                source_info.st_ino,
                source_info.st_size,
            ):
                raise WorkspaceBoundaryError("copy source changed while reading")
            source_parent.revalidate()
            parent.revalidate()
            os.link(
                temporary,
                parent.leaf,
                src_dir_fd=parent.parent_fd,
                dst_dir_fd=parent.parent_fd,
                follow_symlinks=False,
            )
            os.unlink(temporary, dir_fd=parent.parent_fd)
            temporary = ""
            parent.fsync()
            return total
        finally:
            if temporary_descriptor is not None:
                os.close(temporary_descriptor)
            if source_descriptor is not None:
                os.close(source_descriptor)
            if temporary:
                try:
                    os.unlink(temporary, dir_fd=parent.parent_fd)
                except FileNotFoundError:
                    pass
            source_parent.close()
            parent.close()

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

    def delete_file(
        self,
        target: str | Path,
        *,
        expected: WorkspaceFileSnapshot,
    ) -> None:
        """Delete only the exact file state installed by this mutation."""
        if not expected.exists or expected.identity is None:
            raise WorkspaceBoundaryError("delete rollback requires existing state")
        relative = self.relative(target)
        parent = self._parent(relative)
        try:
            current = parent.lstat()
            if current is None or (
                current.st_dev, current.st_ino
            ) != expected.identity:
                raise WorkspaceBoundaryError("rollback target identity changed")
            if current.st_size != expected.size:
                raise WorkspaceBoundaryError("rollback target size changed")
            digest = parent.hash_file()
            final = parent.lstat()
            if digest != expected.digest or final is None or (
                final.st_dev, final.st_ino
            ) != expected.identity:
                raise WorkspaceBoundaryError("rollback target content changed")
        finally:
            parent.close()
        try:
            self._handle.delete(
                relative,
                expected.identity[1],
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
