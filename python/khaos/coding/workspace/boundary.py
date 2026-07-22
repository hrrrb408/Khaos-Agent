"""Real-path boundary checks for Task Workspace writes."""

from __future__ import annotations

import os
import hashlib
import stat
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from khaos.coding.planning.safe_workspace_path import (
    SafePathError,
    WorkspacePathHandle,
)


class WorkspaceBoundaryError(PermissionError):
    pass


class MutationCancelled(RuntimeError):
    """Cooperative cancellation: a mutation was aborted before atomic publish.

    H2: raised by ``copy_path`` / ``copy_file`` / ``move_path`` when the
    caller-provided ``cancel_event`` is set just before the final atomic
    rename/link.  The temporary tree is cleaned up by the caller's
    ``finally`` block; the side effect never becomes visible.
    """


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


@dataclass(frozen=True)
class CreatedDirectoryIdentity:
    """Identity of a parent directory created by one mutation."""

    relative: str
    device: int
    inode: int


PROTECTED_WORKSPACE_NAMES = frozenset({".git", ".agents", ".codex", ".khaos"})
DEFAULT_FILE_TOOL_BYTES = 16 * 1024 * 1024
DEFAULT_TREE_BYTES = 64 * 1024 * 1024
DEFAULT_TREE_ENTRIES = 4096
DEFAULT_TREE_DEPTH = 32


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

    def iter_files(
        self,
        target: str | Path = ".",
        *,
        max_entries: int = DEFAULT_TREE_ENTRIES,
        max_depth: int = DEFAULT_TREE_DEPTH,
    ) -> list[str]:
        directory = self._open_directory(target)
        base = self._directory_relative(target)
        files: list[str] = []
        root_parts = tuple(base.split("/")) if base else ()
        stack: list[tuple[int, tuple[str, ...], int]] = [
            (directory, root_parts, 0)
        ]
        observed = 0
        try:
            while stack:
                descriptor, prefix, depth = stack.pop()
                try:
                    names = sorted(os.listdir(descriptor), key=str.lower)
                    for name in names:
                        observed += 1
                        if observed > max_entries:
                            raise WorkspaceBoundaryError(
                                "directory exceeds the entry limit"
                            )
                        if name.casefold() in {
                            protected.casefold()
                            for protected in PROTECTED_WORKSPACE_NAMES
                        }:
                            continue
                        info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                        relative_parts = (*prefix, name)
                        if stat.S_ISDIR(info.st_mode):
                            if depth >= max_depth:
                                raise WorkspaceBoundaryError(
                                    "directory exceeds the depth limit"
                                )
                            child = os.open(
                                name,
                                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=descriptor,
                            )
                            stack.append((child, relative_parts, depth + 1))
                        elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                            files.append("/".join(relative_parts))
                        else:
                            # Reads skip symlink/hardlink/special entries. Copy
                            # and move use the stricter validators below and
                            # reject the complete operation.
                            continue
                finally:
                    os.close(descriptor)
        except Exception:
            for descriptor, _, _ in stack:
                os.close(descriptor)
            raise
        return sorted(files)

    def iter_entries(
        self,
        target: str | Path = ".",
        *,
        max_entries: int = DEFAULT_TREE_ENTRIES,
        max_depth: int = DEFAULT_TREE_DEPTH,
    ) -> list[tuple[str, bool]]:
        """Return safe regular files and directories below ``target``."""
        directory = self._open_directory(target)
        base = self._directory_relative(target)
        root_parts = tuple(base.split("/")) if base else ()
        stack: list[tuple[int, tuple[str, ...], int]] = [
            (directory, root_parts, 0)
        ]
        entries: list[tuple[str, bool]] = []
        observed = 0
        try:
            while stack:
                descriptor, prefix, depth = stack.pop()
                try:
                    names = sorted(os.listdir(descriptor), key=str.casefold)
                    children: list[tuple[int, tuple[str, ...], int]] = []
                    for name in names:
                        if name.casefold() in {
                            protected.casefold()
                            for protected in PROTECTED_WORKSPACE_NAMES
                        }:
                            continue
                        observed += 1
                        if observed > max_entries:
                            raise WorkspaceBoundaryError(
                                "directory exceeds the entry limit"
                            )
                        info = os.stat(
                            name, dir_fd=descriptor, follow_symlinks=False
                        )
                        relative_parts = (*prefix, name)
                        relative = "/".join(relative_parts)
                        if stat.S_ISDIR(info.st_mode):
                            entries.append((relative, True))
                            if depth + 1 < max_depth:
                                child = os.open(
                                    name,
                                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                    dir_fd=descriptor,
                                )
                                children.append((child, relative_parts, depth + 1))
                        elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                            entries.append((relative, False))
                    stack.extend(reversed(children))
                finally:
                    os.close(descriptor)
        except Exception:
            for descriptor, _, _ in stack:
                os.close(descriptor)
            raise
        return entries

    def ensure_parent_directories(
        self, target: str | Path
    ) -> tuple[CreatedDirectoryIdentity, ...]:
        """Create missing parents through the fixed root without symlinks.

        Returns the created directory paths in creation order so an enclosing
        mutation authority can remove them if publish is cancelled or rolled
        back.
        """
        relative = self.relative(target)
        parts = Path(relative).parts[:-1]
        created: list[CreatedDirectoryIdentity] = []
        prefix: list[str] = []
        descriptor = os.dup(self._handle.root_fd)
        try:
            for part in parts:
                prefix.append(part)
                try:
                    child = os.open(
                        part,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=descriptor,
                    )
                except FileNotFoundError:
                    os.mkdir(part, mode=0o700, dir_fd=descriptor)
                    os.fsync(descriptor)
                    child = os.open(
                        part,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=descriptor,
                    )
                    info = os.fstat(child)
                    created.append(
                        CreatedDirectoryIdentity(
                            relative="/".join(prefix),
                            device=info.st_dev,
                            inode=info.st_ino,
                        )
                    )
                os.close(descriptor)
                descriptor = child
        finally:
            os.close(descriptor)
        return tuple(created)

    def remove_empty_directories(
        self, directories: tuple[CreatedDirectoryIdentity, ...]
    ) -> None:
        """Remove unchanged authority-created directories in reverse order."""
        for directory in reversed(directories):
            parent = self._parent(directory.relative)
            try:
                info = parent.lstat()
                if info is None:
                    continue
                if (
                    not stat.S_ISDIR(info.st_mode)
                    or info.st_dev != directory.device
                    or info.st_ino != directory.inode
                ):
                    raise WorkspaceBoundaryError(
                        "created parent directory identity changed"
                    )
                parent.revalidate()
                os.rmdir(parent.leaf, dir_fd=parent.parent_fd)
                parent.fsync()
            finally:
                parent.close()

    def copy_path(
        self,
        source: str | Path,
        destination: str | Path,
        *,
        max_bytes: int = DEFAULT_TREE_BYTES,
        max_entries: int = DEFAULT_TREE_ENTRIES,
        max_depth: int = DEFAULT_TREE_DEPTH,
        cancel_event: threading.Event | None = None,
        identity_out: list | None = None,
    ) -> int:
        """Copy a file or tree using only fixed dirfds and no-follow opens.

        H2: if ``cancel_event`` is provided and set just before the final
        atomic rename, ``MutationCancelled`` is raised and the temporary
        tree is cleaned up — the side effect never becomes visible.

        H4: if ``identity_out`` is provided, the published destination's
        ``(st_dev, st_ino, st_mode)`` is appended *inside the same dirfd
        critical section* as the atomic rename, eliminating the post-publish
        TOCTOU window that a separate ``capture_path_identity`` call would
        introduce.
        """
        source_relative = self.relative(source)
        destination_relative = self.relative(destination)
        source_parent = self._parent(source_relative)
        destination_parent = self._parent(destination_relative)
        temporary = ""
        try:
            if destination_parent.lstat() is not None:
                raise FileExistsError(destination_relative)
            source_info = source_parent.lstat()
            if source_info is None:
                raise FileNotFoundError(source_relative)
            if stat.S_ISREG(source_info.st_mode):
                return self.copy_file(
                    source, destination,
                    cancel_event=cancel_event, identity_out=identity_out,
                )
            if not stat.S_ISDIR(source_info.st_mode):
                raise WorkspaceBoundaryError("copy source type is unsafe")
            if destination_relative.startswith(f"{source_relative}/"):
                raise WorkspaceBoundaryError(
                    "copy destination cannot be inside the source tree"
                )
            source_descriptor = os.open(
                source_parent.leaf,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=source_parent.parent_fd,
            )
            try:
                for _ in range(32):
                    temporary = f".khaos-tree-{os.urandom(16).hex()}"
                    try:
                        os.mkdir(
                            temporary,
                            mode=0o700,
                            dir_fd=destination_parent.parent_fd,
                        )
                        break
                    except FileExistsError:
                        temporary = ""
                if not temporary:
                    raise WorkspaceBoundaryError(
                        "could not allocate temporary copy directory"
                    )
                destination_descriptor = os.open(
                    temporary,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=destination_parent.parent_fd,
                )
                pre_publish_identity = None
                try:
                    budget = {"bytes": 0, "entries": 0}
                    self._copy_tree_dirfd(
                        source_descriptor,
                        destination_descriptor,
                        depth=0,
                        budget=budget,
                        max_bytes=max_bytes,
                        max_entries=max_entries,
                        max_depth=max_depth,
                        cancel_event=cancel_event,
                    )
                    os.fsync(destination_descriptor)
                    # H1: capture the temp directory's identity NOW via
                    # fstat on the open fd.  ``rename`` does not change the
                    # inode, so this IS the published destination's identity.
                    # Capturing it before the rename eliminates the post-
                    # publish ``os.stat`` that could fail (and leave the
                    # published object落地 with an empty identity_out and a
                    # no-op rollback) or race with a concurrent replacement.
                    if identity_out is not None:
                        temp_stat = os.fstat(destination_descriptor)
                        pre_publish_identity = (
                            temp_stat.st_dev,
                            temp_stat.st_ino,
                            temp_stat.st_mode,
                        )
                finally:
                    os.close(destination_descriptor)
                final_source = os.fstat(source_descriptor)
                if (final_source.st_dev, final_source.st_ino) != (
                    source_info.st_dev,
                    source_info.st_ino,
                ):
                    raise WorkspaceBoundaryError(
                        "copy source directory identity changed"
                    )
            finally:
                os.close(source_descriptor)
            source_parent.revalidate()
            destination_parent.revalidate()
            # H2: cooperative cancel — check just before the atomic publish.
            # If cancelled, ``temporary`` is still set so the ``finally``
            # block below cleans up the temp tree; the destination never
            # appears.
            if cancel_event is not None and cancel_event.is_set():
                raise MutationCancelled(
                    "copy cancelled before atomic publish"
                )
            self._handle._rename_no_replace(
                destination_parent.parent_fd,
                temporary,
                destination_parent.parent_fd,
                destination_parent.leaf,
            )
            temporary = ""
            # H1: the published destination's identity was captured via
            # fstat on the temp fd BEFORE the atomic rename.  No post-
            # publish stat — eliminate the TOCTOU window and the failure
            # mode where rename succeeds but stat raises.
            if identity_out is not None and pre_publish_identity is not None:
                identity_out.append(pre_publish_identity)
            destination_parent.fsync()
            return budget["bytes"]
        finally:
            if temporary:
                self._remove_tree_at(destination_parent.parent_fd, temporary)
            source_parent.close()
            destination_parent.close()

    def move_path(
        self,
        source: str | Path,
        destination: str | Path,
        *,
        cancel_event: threading.Event | None = None,
        identity_out: list | None = None,
    ) -> None:
        """Move one validated file/tree atomically within the fixed root.

        H2: if ``cancel_event`` is provided and set just before the final
        atomic rename, ``MutationCancelled`` is raised — the source is
        untouched and no side effect lands.

        H4: if ``identity_out`` is provided, the published destination's
        ``(st_dev, st_ino, st_mode)`` is appended inside the same dirfd
        critical section as the atomic rename.
        """
        source_relative = self.relative(source)
        destination_relative = self.relative(destination)
        source_parent = self._parent(source_relative)
        destination_parent = self._parent(destination_relative)
        try:
            source_info = source_parent.lstat()
            if source_info is None:
                raise FileNotFoundError(source_relative)
            if destination_parent.lstat() is not None:
                raise FileExistsError(destination_relative)
            if stat.S_ISREG(source_info.st_mode):
                if source_info.st_nlink != 1:
                    raise WorkspaceBoundaryError("hardlinked files are not movable")
            elif stat.S_ISDIR(source_info.st_mode):
                if destination_relative.startswith(f"{source_relative}/"):
                    raise WorkspaceBoundaryError(
                        "move destination cannot be inside the source tree"
                    )
                descriptor = os.open(
                    source_parent.leaf,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=source_parent.parent_fd,
                )
                try:
                    self._validate_tree_dirfd(
                        descriptor,
                        depth=0,
                        budget={"bytes": 0, "entries": 0},
                        max_bytes=DEFAULT_TREE_BYTES,
                        max_entries=DEFAULT_TREE_ENTRIES,
                        max_depth=DEFAULT_TREE_DEPTH,
                        cancel_event=cancel_event,
                    )
                finally:
                    os.close(descriptor)
            else:
                raise WorkspaceBoundaryError("move source type is unsafe")
            source_parent.revalidate()
            destination_parent.revalidate()
            current = source_parent.lstat()
            if current is None or (current.st_dev, current.st_ino) != (
                source_info.st_dev,
                source_info.st_ino,
            ):
                raise WorkspaceBoundaryError("move source identity changed")
            # H1: the source identity is already validated above; ``rename``
            # preserves the inode, so ``current`` IS the published destina-
            # tion's identity.  Capture it now — no post-publish ``os.stat``
            # that could fail (and leave the published object with an empty
            # identity_out and a no-op rollback) or race with a concurrent
            # replacement of the destination path.
            pre_publish_identity = (
                (current.st_dev, current.st_ino, current.st_mode)
                if identity_out is not None
                else None
            )
            # H2: cooperative cancel — check just before the atomic rename.
            # The source is still in place; no side effect has landed.
            if cancel_event is not None and cancel_event.is_set():
                raise MutationCancelled(
                    "move cancelled before atomic publish"
                )
            self._handle._rename_no_replace(
                source_parent.parent_fd,
                source_parent.leaf,
                destination_parent.parent_fd,
                destination_parent.leaf,
            )
            # H1: use the pre-captured source identity — rename preserves
            # the inode, so this is the published destination's identity.
            # No post-publish stat.
            if identity_out is not None and pre_publish_identity is not None:
                identity_out.append(pre_publish_identity)
            source_parent.fsync()
            if source_parent.identity != destination_parent.identity:
                destination_parent.fsync()
        finally:
            source_parent.close()
            destination_parent.close()

    def _copy_tree_dirfd(
        self,
        source_fd: int,
        destination_fd: int,
        *,
        depth: int,
        budget: dict[str, int],
        max_bytes: int,
        max_entries: int,
        max_depth: int,
        cancel_event: threading.Event | None = None,
    ) -> None:
        if depth > max_depth:
            raise WorkspaceBoundaryError("copy source exceeds the depth limit")
        for name in sorted(os.listdir(source_fd), key=str.casefold):
            # H4: cooperative cancel — check at the top of every directory
            # entry so a slow recursive scan, a huge temp tree copy, or slow
            # filesystem I/O can be interrupted promptly rather than only
            # at the final atomic publish.  This makes the scheduler timeout
            # a real wall-clock deadline.
            if cancel_event is not None and cancel_event.is_set():
                raise MutationCancelled(
                    "copy cancelled during recursive directory traversal"
                )
            if name.casefold() in {
                protected.casefold() for protected in PROTECTED_WORKSPACE_NAMES
            }:
                raise WorkspaceBoundaryError("copy source contains protected metadata")
            budget["entries"] += 1
            if budget["entries"] > max_entries:
                raise WorkspaceBoundaryError("copy source exceeds the entry limit")
            before = os.stat(name, dir_fd=source_fd, follow_symlinks=False)
            if stat.S_ISDIR(before.st_mode):
                os.mkdir(name, mode=0o700, dir_fd=destination_fd)
                child_source = os.open(
                    name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=source_fd,
                )
                child_destination = os.open(
                    name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=destination_fd,
                )
                try:
                    self._copy_tree_dirfd(
                        child_source,
                        child_destination,
                        depth=depth + 1,
                        budget=budget,
                        max_bytes=max_bytes,
                        max_entries=max_entries,
                        max_depth=max_depth,
                        cancel_event=cancel_event,
                    )
                    os.fsync(child_destination)
                finally:
                    os.close(child_source)
                    os.close(child_destination)
                after = os.stat(name, dir_fd=source_fd, follow_symlinks=False)
                if (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino):
                    raise WorkspaceBoundaryError("copy source directory changed")
                continue
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise WorkspaceBoundaryError(
                    "copy source contains symlink, hardlink, or special file"
                )
            if before.st_size > DEFAULT_FILE_TOOL_BYTES:
                raise WorkspaceBoundaryError("copy source file exceeds the limit")
            budget["bytes"] += before.st_size
            if budget["bytes"] > max_bytes:
                raise WorkspaceBoundaryError("copy source exceeds the byte limit")
            source_file = os.open(
                name,
                os.O_RDONLY | os.O_NOFOLLOW,
                dir_fd=source_fd,
            )
            destination_file = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                stat.S_IMODE(before.st_mode) & 0o666,
                dir_fd=destination_fd,
            )
            try:
                copied = 0
                while True:
                    # H4: check before each chunk read so a large file copy
                    # can be cancelled mid-stream, not just at the final
                    # publish.
                    if cancel_event is not None and cancel_event.is_set():
                        raise MutationCancelled(
                            "copy cancelled during file copy"
                        )
                    chunk = os.read(source_file, 1024 * 1024)
                    if not chunk:
                        break
                    copied += len(chunk)
                    if copied > DEFAULT_FILE_TOOL_BYTES:
                        raise WorkspaceBoundaryError(
                            "copy source file grew beyond the limit"
                        )
                    self._write_all(destination_file, chunk)
                os.fsync(destination_file)
                final = os.fstat(source_file)
                if (final.st_dev, final.st_ino, final.st_size) != (
                    before.st_dev,
                    before.st_ino,
                    before.st_size,
                ):
                    raise WorkspaceBoundaryError("copy source file changed")
            finally:
                os.close(source_file)
                os.close(destination_file)

    def _validate_tree_dirfd(
        self,
        descriptor: int,
        *,
        depth: int,
        budget: dict[str, int],
        max_bytes: int,
        max_entries: int,
        max_depth: int,
        cancel_event: threading.Event | None = None,
    ) -> None:
        if depth > max_depth:
            raise WorkspaceBoundaryError("tree exceeds the depth limit")
        for name in sorted(os.listdir(descriptor), key=str.casefold):
            # H4: cooperative cancel — check at the top of every directory
            # entry so a slow recursive validation can be interrupted
            # promptly rather than only at the final atomic rename.
            if cancel_event is not None and cancel_event.is_set():
                raise MutationCancelled(
                    "move cancelled during recursive tree validation"
                )
            if name.casefold() in {
                protected.casefold() for protected in PROTECTED_WORKSPACE_NAMES
            }:
                raise WorkspaceBoundaryError("tree contains protected metadata")
            budget["entries"] += 1
            if budget["entries"] > max_entries:
                raise WorkspaceBoundaryError("tree exceeds the entry limit")
            info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                child = os.open(
                    name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=descriptor,
                )
                try:
                    self._validate_tree_dirfd(
                        child,
                        depth=depth + 1,
                        budget=budget,
                        max_bytes=max_bytes,
                        max_entries=max_entries,
                        max_depth=max_depth,
                        cancel_event=cancel_event,
                    )
                finally:
                    os.close(child)
            elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                if info.st_size > DEFAULT_FILE_TOOL_BYTES:
                    raise WorkspaceBoundaryError("tree file exceeds the limit")
                budget["bytes"] += info.st_size
                if budget["bytes"] > max_bytes:
                    raise WorkspaceBoundaryError("tree exceeds the byte limit")
            else:
                raise WorkspaceBoundaryError(
                    "tree contains symlink, hardlink, or special file"
                )

    @classmethod
    def _remove_tree_at(cls, parent_fd: int, name: str) -> None:
        """Remove only a no-follow temporary tree created by this authority."""
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
        try:
            for child_name in os.listdir(descriptor):
                info = os.stat(
                    child_name, dir_fd=descriptor, follow_symlinks=False
                )
                if stat.S_ISDIR(info.st_mode):
                    cls._remove_tree_at(descriptor, child_name)
                else:
                    os.unlink(child_name, dir_fd=descriptor)
        finally:
            os.close(descriptor)
        os.rmdir(name, dir_fd=parent_fd)

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
        self,
        target: str | Path,
        content: bytes,
        *,
        mode: int = 0o600,
        cancel_event: threading.Event | None = None,
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
        def phase(*_args, **_kwargs) -> None:
            return None

        def before_publish() -> None:
            if cancel_event is not None and cancel_event.is_set():
                raise MutationCancelled("mutation cancelled before publish")

        try:
            if expected_inode is None:
                self._handle.create(
                    relative,
                    content,
                    selected_mode,
                    phase,
                    before_publish,
                )
            else:
                self._handle.update(
                    relative,
                    content,
                    selected_mode,
                    expected_inode,
                    phase,
                    before_publish,
                )
        except (OSError, SafePathError) as exc:
            raise WorkspaceBoundaryError(str(exc)) from exc

    def transform_text(
        self,
        target: str | Path,
        transform: Callable[[str], str],
        *,
        cancel_event: threading.Event | None = None,
    ) -> str:
        original = self.read_bytes(target).decode("utf-8")
        updated = transform(original)
        self.write_bytes(
            target, updated.encode("utf-8"), cancel_event=cancel_event
        )
        return updated

    def copy_file(
        self,
        source: str | Path,
        destination: str | Path,
        *,
        cancel_event: threading.Event | None = None,
        identity_out: list | None = None,
    ) -> int:
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
            pre_publish_identity = None
            try:
                while True:
                    # H4: check before each chunk read so a large file copy
                    # can be cancelled mid-stream, not just at the final
                    # publish.  This makes the scheduler timeout a real
                    # wall-clock deadline.
                    if cancel_event is not None and cancel_event.is_set():
                        raise MutationCancelled(
                            "copy cancelled during file copy"
                        )
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
                # H1: capture the temp file's identity NOW via fstat on the
                # open fd.  ``os.link`` creates a hard link to the same
                # inode, so this IS the published destination's identity.
                # Capturing it before the link eliminates the post-publish
                # ``os.stat`` that could fail (and leave the published file
                # with an empty identity_out and a no-op rollback) or race
                # with a concurrent replacement of the destination path.
                if identity_out is not None:
                    temp_stat = os.fstat(temporary_descriptor)
                    pre_publish_identity = (
                        temp_stat.st_dev,
                        temp_stat.st_ino,
                        temp_stat.st_mode,
                    )
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
            # H2: cooperative cancel — check just before the atomic link.
            if cancel_event is not None and cancel_event.is_set():
                raise MutationCancelled(
                    "copy cancelled before atomic publish"
                )
            os.link(
                temporary,
                parent.leaf,
                src_dir_fd=parent.parent_fd,
                dst_dir_fd=parent.parent_fd,
                follow_symlinks=False,
            )
            os.unlink(temporary, dir_fd=parent.parent_fd)
            temporary = ""
            # H1: the published destination's identity was captured via
            # fstat on the temp fd BEFORE the atomic link.  No post-publish
            # stat — eliminate the TOCTOU window and the failure mode where
            # link succeeds but stat raises.
            if identity_out is not None and pre_publish_identity is not None:
                identity_out.append(pre_publish_identity)
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

    def capture_path_identity(
        self, target: str | Path
    ) -> tuple[int, int, int] | None:
        """Return ``(st_dev, st_ino, st_mode)`` of ``target`` via fixed dirfds.

        Used by Office rollback (M2) to capture the identity of a path
        *immediately after* the atomic publish, so the rollback closure can
        later verify the leaf has not been replaced by a concurrent
        operation before removing it.  Returns ``None`` if the path does not
        exist (e.g. the publish was rolled back by a deeper layer).
        """
        relative = self.relative(target)
        parent = self._parent(relative)
        try:
            info = parent.lstat()
            if info is None:
                return None
            # Reject symlinks outright — a published Office destination must
            # be a real directory or regular file we just created, never a
            # symlink.  This also blocks a TOCTOU where an attacker replaces
            # the leaf with a symlink between publish and capture.
            if stat.S_ISLNK(info.st_mode):
                raise WorkspaceBoundaryError(
                    "captured path is a symlink; refusing to bind identity"
                )
            parent.revalidate()
            return (info.st_dev, info.st_ino, info.st_mode)
        finally:
            parent.close()

    def remove_published(
        self,
        target: str | Path,
        expected_identity: tuple[int, int, int] | None,
    ) -> bool:
        """Identity-bound removal of a path this authority just published.

        M2: replaces the previous ``shutil.rmtree(ignore_errors=True)`` /
        ``unlink(missing_ok=True)`` rollback, which would happily remove any
        file/symlink that happened to be at the destination path — including
        one an attacker or concurrent process had swapped in after our
        publish.  This method:

        * resolves the parent directory through fixed dirfds (``O_NOFOLLOW``
          at every level, so a symlink in the path cannot redirect the
          removal);
        * ``lstat`` s the leaf *without* following it, and verifies
          ``(st_dev, st_ino)`` matches the identity captured right after the
          publish;
        * only then removes the leaf (recursively for directories via the
          ``_remove_tree_at`` dirfd primitive, or ``os.unlink`` for regular
          files), and ``fsync`` s the parent so the removal survives a
          crash.

        Returns ``True`` if the path was removed, ``False`` if it was
        already gone (no-op), and raises ``WorkspaceBoundaryError`` if the
        leaf exists but its identity does not match — the caller (storage
        authority) then quarantines the workspace rather than risking
        removal of the wrong object.
        """
        if expected_identity is None:
            return False
        relative = self.relative(target)
        parent = self._parent(relative)
        try:
            current = parent.lstat()
            if current is None:
                # Already gone — nothing to roll back.  This is the
                # "someone else already cleaned up" case; treat as success.
                return False
            expected_dev, expected_ino, _expected_mode = expected_identity
            if (current.st_dev, current.st_ino) != (expected_dev, expected_ino):
                raise WorkspaceBoundaryError(
                    "rollback target identity changed; refusing to remove a "
                    "concurrently-replaced path"
                )
            if stat.S_ISLNK(current.st_mode):
                # We never publish symlinks; a symlink here means the leaf
                # was replaced between publish and rollback.
                raise WorkspaceBoundaryError(
                    "rollback target became a symlink; refusing to follow"
                )
            parent.revalidate()
            if stat.S_ISDIR(current.st_mode):
                self._remove_tree_at(parent.parent_fd, parent.leaf)
            else:
                os.unlink(parent.leaf, dir_fd=parent.parent_fd)
            parent.revalidate()
            parent.fsync()
            return True
        finally:
            parent.close()

    def move_published_back(
        self,
        target: str | Path,
        source: str | Path,
        expected_identity: tuple[int, int, int] | None,
    ) -> bool:
        """Identity-bound move-back of a path this authority just published.

        M2: replaces the previous ``shutil.move(destination, source)``
        rollback for Office ``move_file``, which would move any object that
        happened to be at the destination path — including one an attacker
        had swapped in after our publish.  This method:

        * captures the current identity of ``target`` (the move's
          destination, which now holds the published tree);
        * verifies it matches ``expected_identity`` (captured right after
          the original move committed);
        * only then performs an identity-bound ``move_path(target, source)``
          to put the tree back where it came from.

        Returns ``True`` if the move-back happened, ``False`` if ``target``
        was already gone (no-op), and raises ``WorkspaceBoundaryError`` if
        the leaf exists but its identity does not match — the caller then
        quarantines the workspace rather than risking moving the wrong
        object back to ``source``.
        """
        if expected_identity is None:
            return False
        target_relative = self.relative(target)
        source_relative = self.relative(source)
        # Pre-verify the target's identity so we never move a
        # concurrently-replaced object back.  ``move_path`` does its own
        # identity check *during* the move, but that only guards against
        # mid-move replacement; it does not compare against the identity we
        # captured at publish time.
        parent = self._parent(target_relative)
        try:
            current = parent.lstat()
            if current is None:
                return False
            expected_dev, expected_ino, _expected_mode = expected_identity
            if (current.st_dev, current.st_ino) != (expected_dev, expected_ino):
                raise WorkspaceBoundaryError(
                    "move-back target identity changed; refusing to move a "
                    "concurrently-replaced path back to source"
                )
            if stat.S_ISLNK(current.st_mode):
                raise WorkspaceBoundaryError(
                    "move-back target became a symlink; refusing to follow"
                )
            parent.revalidate()
        finally:
            parent.close()
        # ``move_path`` re-validates the source identity during the move and
        # uses ``_rename_no_replace`` so the destination (the original
        # source) must not exist — which it cannot, since the original move
        # removed it.
        self.move_path(target_relative, source_relative)
        return True


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
