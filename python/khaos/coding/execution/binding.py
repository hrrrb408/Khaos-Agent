"""Pinned directory handles for execution-bound subprocesses.

The execution service validates a TaskWorkspace asynchronously, while the
backend still has to construct a command line before the child is spawned.
This module turns the final workspace root and cwd into directory handles at
that boundary.  The child inherits those handles, verifies their identities,
and changes directory with ``fchdir`` immediately before exec.  On Linux the
workspace handle can also be exposed through ``/proc/self/fd`` for namespace
mount construction, avoiding a second path lookup.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Self

FileIdentity = tuple[int, int]


@dataclass
class ExecutionDirectoryBinding:
    """A root/cwd pair opened below one validated workspace root."""

    root_path: Path
    cwd_path: Path
    root_fd: int
    cwd_fd: int
    root_identity: FileIdentity
    cwd_identity: FileIdentity
    _closed: bool = False

    @property
    def pass_fds(self) -> tuple[int, ...]:
        """Return the descriptors that must survive into the child."""
        if self.root_fd == self.cwd_fd:
            return (self.root_fd,)
        return (self.root_fd, self.cwd_fd)

    def proc_path(self, descriptor: int) -> str:
        """Return the Linux proc-fd spelling for an inherited descriptor."""
        if not sys_linux():
            raise PermissionError("proc-fd workspace mounts require Linux")
        return f"/proc/self/fd/{descriptor}"

    def close(self) -> None:
        """Close the parent copies, retaining no reusable authority FD."""
        if self._closed:
            return
        self._closed = True
        descriptors = {self.root_fd, self.cwd_fd}
        for descriptor in descriptors:
            try:
                os.close(descriptor)
            except OSError:
                pass

    def __enter__(self) -> Self:
        return self

    def __exit__(self, _type, _value, _traceback) -> None:
        self.close()


def sys_linux() -> bool:
    """Return whether the current process can use Linux proc-fd paths."""
    return sys_platform().startswith("linux")


def sys_platform() -> str:
    """Small indirection to keep platform checks easy to test."""
    import sys

    return sys.platform


def open_execution_directory_binding(
    root_path: Path,
    cwd_path: Path,
    *,
    expected_root_identity: FileIdentity | None = None,
    expected_cwd_identity: FileIdentity | None = None,
) -> ExecutionDirectoryBinding:
    """Open and pin a workspace root plus a cwd below it.

    Every component between the root FD and cwd is opened relative to the
    already-open parent with ``O_NOFOLLOW``.  A replacement directory is
    therefore either rejected by the expected identity check or cannot move
    the child outside the pinned root after the open succeeds.
    """
    if os.name != "posix":
        raise PermissionError("directory-bound execution requires POSIX")
    if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
        raise PermissionError("directory-bound execution lacks no-follow directory opens")

    root = _lexical_absolute(root_path)
    cwd = _lexical_absolute(cwd_path)
    try:
        relative_cwd = cwd.relative_to(root)
    except ValueError as exc:
        raise PermissionError("execution cwd is outside the pinned workspace root") from exc
    if any(part in {"", ".", ".."} for part in relative_cwd.parts):
        raise PermissionError("execution cwd contains unsafe path components")

    root_fd: int | None = None
    cwd_fd: int | None = None
    try:
        try:
            root_fd = os.open(str(root), _directory_flags())
        except OSError as exc:
            raise PermissionError("workspace root cannot be opened without following links") from exc
        root_identity = _directory_identity(root_fd, "workspace root")
        _match_expected(root_identity, expected_root_identity, "workspace root")

        if relative_cwd == Path("."):
            cwd_fd = os.dup(root_fd)
        else:
            cwd_fd = _open_relative_directory(root_fd, relative_cwd.parts)
        cwd_identity = _directory_identity(cwd_fd, "execution cwd")
        _match_expected(cwd_identity, expected_cwd_identity, "execution cwd")
        return ExecutionDirectoryBinding(
            root_path=root,
            cwd_path=cwd,
            root_fd=root_fd,
            cwd_fd=cwd_fd,
            root_identity=root_identity,
            cwd_identity=cwd_identity,
        )
    except Exception:
        for descriptor in {root_fd, cwd_fd}:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        raise


def _lexical_absolute(path: Path) -> Path:
    value = Path(path).expanduser()
    if not value.is_absolute():
        value = Path(os.path.abspath(str(value)))
    return value


def _directory_flags() -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    # O_PATH avoids requiring read permission on a directory while retaining
    # a handle that supports fstat/fchdir on Linux.  macOS has no O_PATH and
    # uses the normal read-only directory descriptor instead.
    flags |= getattr(os, "O_CLOEXEC", 0)
    if sys_linux() and hasattr(os, "O_PATH"):
        flags = os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    return flags


def _open_relative_directory(root_fd: int, parts: tuple[str, ...]) -> int:
    current_fd = os.dup(root_fd)
    try:
        for part in parts:
            if "/" in part or part in {"", ".", ".."}:
                raise PermissionError("unsafe relative workspace component")
            try:
                next_fd = os.open(part, _directory_flags(), dir_fd=current_fd)
            except OSError as exc:
                raise PermissionError(
                    "execution cwd contains an unavailable or symlinked directory"
                ) from exc
            os.close(current_fd)
            current_fd = next_fd
        return current_fd
    except Exception:
        try:
            os.close(current_fd)
        except OSError:
            pass
        raise


def _directory_identity(descriptor: int, label: str) -> FileIdentity:
    try:
        info = os.fstat(descriptor)
    except OSError as exc:
        raise PermissionError(f"{label} descriptor is unavailable") from exc
    if not stat.S_ISDIR(info.st_mode) or info.st_nlink < 1:
        raise PermissionError(f"{label} descriptor is not a directory")
    return int(info.st_dev), int(info.st_ino)


def _match_expected(
    actual: FileIdentity,
    expected: FileIdentity | None,
    label: str,
) -> None:
    if expected is not None and actual != tuple(expected):
        raise PermissionError(f"{label} identity changed while opening")
