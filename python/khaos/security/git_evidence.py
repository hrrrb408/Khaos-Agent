"""Bounded, race-safe worktree evidence for Git approval bindings.

Approval evidence is TCB input: the state that decides *what the user
approved* must satisfy the same boundedness and race-safety discipline as
the effect executor it authorizes.  This module implements two invariants:

* **Approval Evidence Is Bounded TCB Input** — no approval snapshot may read
  an unbounded amount of model-controlled workspace data.  Untracked-file
  hashing is bounded by per-file, total-byte, file-count, and wall-clock
  budgets, and a file whose declared size already exceeds a budget is
  rejected before a single byte is read (a 100 GB sparse file costs O(1)).
* **Security Evidence Must Prove Completeness** — a truncated subprocess
  result may never enter an approval digest.  Consumers of security-sensitive
  Git output must call :func:`require_complete_git_output` and fail closed.

The untracked snapshot opens files root-relative with ``O_NOFOLLOW`` on
every path component and verifies ``fstat`` regular-file mode on the same
file descriptor that is read, so the validated kernel object and the read
kernel object are identical (no check→open TOCTOU) and no path replacement
can escape the workspace root.
"""

from __future__ import annotations

import hashlib
import os
import stat
import struct
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path

# Budgets for hashing untracked worktree content.  A snapshot that would
# exceed any budget fails closed instead of silently degrading: incomplete
# evidence must never be treated as complete.
DEFAULT_MAX_FILE_BYTES = 8 * 1024 * 1024
DEFAULT_MAX_TOTAL_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_FILE_COUNT = 1024
DEFAULT_MAX_WALL_CLOCK_SECONDS = 10.0

_CHUNK_BYTES = 256 * 1024
_MANIFEST_HEADER = b"khaos-git-untracked-manifest-v1"


class GitEvidenceError(PermissionError):
    """Raised when approval evidence cannot be collected completely."""


@dataclass(frozen=True, slots=True)
class EvidenceSnapshotBudgets:
    """Hard bounds for one untracked-content evidence snapshot."""

    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES
    max_file_count: int = DEFAULT_MAX_FILE_COUNT
    max_wall_clock_seconds: float = DEFAULT_MAX_WALL_CLOCK_SECONDS

    def __post_init__(self) -> None:
        if (
            type(self.max_file_bytes) is not int
            or type(self.max_total_bytes) is not int
            or type(self.max_file_count) is not int
        ):
            raise GitEvidenceError("evidence snapshot budgets must be integers")
        if (
            self.max_file_bytes <= 0
            or self.max_total_bytes < self.max_file_bytes
            or self.max_file_count <= 0
            or not isinstance(self.max_wall_clock_seconds, (int, float))
            or self.max_wall_clock_seconds <= 0
        ):
            raise GitEvidenceError("evidence snapshot budgets are invalid")


def require_complete_git_output(result: Mapping[str, object], *, source: str) -> None:
    """Fail closed when subprocess evidence was truncated by its supervisor.

    ``ProcessSupervisor`` records ``output_truncated`` diagnostics whenever
    stdout/stderr exceed the output budget.  Ordinary display callers may
    show truncated output with a warning; security consumers must treat it
    as incomplete evidence and refuse to hash it.
    """
    diagnostics = result.get("diagnostics")
    if not isinstance(diagnostics, Mapping):
        return
    truncated = [
        key
        for key in ("output_truncated", "stdout_truncated", "stderr_truncated")
        if diagnostics.get(key)
    ]
    if truncated:
        raise GitEvidenceError(
            f"{source} output was truncated ({', '.join(sorted(truncated))}); "
            "approval evidence must be complete or fail closed"
        )


def snapshot_untracked_files(
    cwd: Path,
    entries: Iterable[str],
    *,
    budgets: EvidenceSnapshotBudgets | None = None,
) -> str:
    """Hash untracked worktree files into one canonical manifest digest.

    ``entries`` are the relative paths reported by ``git status -z`` as
    untracked.  Every entry must still exist as a regular file opened
    root-relative with ``O_NOFOLLOW``; symlinks, FIFOs, sockets, devices,
    vanished paths, and any budget breach raise :class:`GitEvidenceError`
    so the caller fails closed instead of binding partial evidence.
    """
    limits = budgets or EvidenceSnapshotBudgets()
    if os.open not in getattr(os, "supports_dir_fd", frozenset()):
        raise GitEvidenceError(
            "worktree evidence snapshot requires dir_fd support on this platform"
        )
    root = os.open(cwd, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    digest = hashlib.sha256()
    digest.update(_MANIFEST_HEADER)
    hashed = 0
    total_bytes = 0
    started = time.monotonic()
    try:
        for entry in entries:
            if hashed >= limits.max_file_count:
                raise GitEvidenceError(
                    "untracked worktree evidence exceeded the file-count budget"
                )
            path = _validate_relative_entry(entry)
            file_digest, size, read_bytes = _hash_one_file(
                root, path, limits, started
            )
            hashed += 1
            total_bytes += read_bytes
            if total_bytes > limits.max_total_bytes:
                raise GitEvidenceError(
                    "untracked worktree evidence exceeded the total-byte budget"
                )
            path_bytes = path.encode("utf-8")
            digest.update(_u64(len(path_bytes)))
            digest.update(path_bytes)
            digest.update(_u64(size))
            digest.update(file_digest)
        digest.update(_u64(hashed))
    finally:
        os.close(root)
    return digest.hexdigest()


def _open_beneath(root_fd: int, relative_path: str) -> int:
    """Open one path root-relative, rejecting symlinks on every component.

    The returned descriptor refers to exactly the kernel object that
    survived validation: each directory component is opened with
    ``O_NOFOLLOW | O_DIRECTORY`` and the final component with
    ``O_NOFOLLOW | O_NONBLOCK`` (so a FIFO cannot block the open).  The
    caller must ``fstat`` the descriptor before trusting its type.
    """
    parts = relative_path.split("/")
    dir_fd = root_fd
    try:
        for component in parts[:-1]:
            opened = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=dir_fd,
            )
            if dir_fd != root_fd:
                os.close(dir_fd)
            dir_fd = opened
        return os.open(
            parts[-1],
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
            dir_fd=dir_fd,
        )
    except OSError as exc:
        raise GitEvidenceError(
            f"untracked worktree entry {relative_path!r} could not be opened "
            f"as a regular file beneath the workspace root ({exc.strerror})"
        ) from exc
    finally:
        if dir_fd != root_fd:
            os.close(dir_fd)


def _hash_one_file(
    root_fd: int,
    relative_path: str,
    limits: EvidenceSnapshotBudgets,
    started: float,
) -> tuple[bytes, int, int]:
    """Open one file beneath ``root_fd`` and stream-hash it with bounds."""
    file_fd = _open_beneath(root_fd, relative_path)
    try:
        info = os.fstat(file_fd)
        if not stat.S_ISREG(info.st_mode):
            raise GitEvidenceError(
                f"untracked worktree entry {relative_path!r} is not a regular file"
            )
        if info.st_size > limits.max_file_bytes:
            raise GitEvidenceError(
                f"untracked worktree entry {relative_path!r} exceeds the "
                f"per-file evidence budget ({info.st_size} bytes)"
            )
        file_digest = hashlib.sha256()
        read_bytes = 0
        while True:
            chunk = os.read(file_fd, _CHUNK_BYTES)
            if not chunk:
                break
            read_bytes += len(chunk)
            if read_bytes > limits.max_file_bytes:
                raise GitEvidenceError(
                    f"untracked worktree entry {relative_path!r} grew beyond "
                    "the per-file evidence budget while being hashed"
                )
            if time.monotonic() - started > limits.max_wall_clock_seconds:
                raise GitEvidenceError(
                    "untracked worktree evidence exceeded the wall-clock budget"
                )
            file_digest.update(chunk)
        if read_bytes != info.st_size:
            raise GitEvidenceError(
                f"untracked worktree entry {relative_path!r} changed size "
                "while being hashed; evidence is incomplete"
            )
        return file_digest.digest(), int(info.st_size), read_bytes
    finally:
        os.close(file_fd)


def _validate_relative_entry(entry: str) -> str:
    """Reject structural escapes before any filesystem access happens."""
    if not entry or entry.startswith("/"):
        raise GitEvidenceError("untracked entry is not workspace-relative")
    for component in entry.split("/"):
        if component in {"", ".", ".."}:
            raise GitEvidenceError(
                "untracked entry contains a structural path escape"
            )
    return entry


def _u64(value: int) -> bytes:
    return struct.pack(">Q", value)


__all__ = [
    "DEFAULT_MAX_FILE_BYTES",
    "DEFAULT_MAX_FILE_COUNT",
    "DEFAULT_MAX_TOTAL_BYTES",
    "DEFAULT_MAX_WALL_CLOCK_SECONDS",
    "EvidenceSnapshotBudgets",
    "GitEvidenceError",
    "require_complete_git_output",
    "snapshot_untracked_files",
]
