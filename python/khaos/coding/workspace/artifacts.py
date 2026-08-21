"""Bounded ChangeSet artifact storage and verification.

The artifact owner performs only identity/digest-bound file operations.  It
does not know workspace lifecycle, approval, or quota registration; callers
must validate those state transitions before invoking these helpers.
"""
from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

from khaos.coding.workspace.errors import WorkspaceError
from khaos.coding.workspace.models import ChangeSet, TaskWorkspace

MAX_CHANGESET_BYTES = 64 * 1024 * 1024
_O_BINARY = getattr(os, "O_BINARY", 0)


def verified_artifact_path(workspace: TaskWorkspace, changeset: ChangeSet) -> Path:
    """Validate that a ChangeSet artifact is owned by its workspace root."""
    artifact = changeset.artifact
    if artifact is None:
        raise WorkspaceError("changeset has no artifact")
    expected = workspace.worktree_path.parent / f"{changeset.id}.patch"
    if artifact.path != expected or artifact.path.parent != workspace.worktree_path.parent:
        raise WorkspaceError("changeset artifact is outside its authority root")
    if artifact.path not in workspace.change_artifacts:
        raise WorkspaceError("changeset artifact is not owned by the workspace")
    try:
        info = artifact.path.lstat()
    except OSError as exc:
        raise WorkspaceError("changeset artifact is unavailable") from exc
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise WorkspaceError("changeset artifact has an unsafe file type")
    if int(info.st_size) != artifact.byte_length:
        raise WorkspaceError("changeset artifact length drifted")
    return artifact.path


def read_verified_artifact(
    path: Path,
    expected_length: int,
    expected_digest: str,
    max_bytes: int,
) -> bytes:
    """Read and verify one bounded artifact through a no-follow descriptor."""
    descriptor = os.open(
        path,
        os.O_RDONLY | _O_BINARY | getattr(os, "O_NOFOLLOW", 0),
    )
    digest = hashlib.sha256()
    data = bytearray()
    try:
        while chunk := os.read(descriptor, 1024 * 1024):
            data.extend(chunk)
            digest.update(chunk)
            if len(data) > max_bytes:
                raise WorkspaceError("changeset patch exceeds inline output bound")
    finally:
        os.close(descriptor)
    if len(data) != expected_length or digest.hexdigest() != expected_digest:
        raise WorkspaceError("changeset artifact digest or length drifted")
    return bytes(data)


def write_exclusive_artifact(path: Path, payload: bytes) -> None:
    """Publish a new artifact with exclusive creation and fsync."""
    descriptor = os.open(
        path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | _O_BINARY
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def copy_verified_artifact(
    source: Path,
    destination: Path,
    expected_length: int,
    expected_digest: str,
    *,
    max_bytes: int = MAX_CHANGESET_BYTES,
) -> None:
    """Copy an artifact with bounded streaming and digest verification."""
    source_descriptor = os.open(
        source,
        os.O_RDONLY | _O_BINARY | getattr(os, "O_NOFOLLOW", 0),
    )
    destination_descriptor: int | None = None
    digest = hashlib.sha256()
    total = 0
    try:
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        destination_descriptor = os.open(
            destination,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | _O_BINARY
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        while chunk := os.read(source_descriptor, 1024 * 1024):
            total += len(chunk)
            if total > max_bytes:
                raise WorkspaceError("changeset artifact exceeds the configured bound")
            digest.update(chunk)
            offset = 0
            while offset < len(chunk):
                offset += os.write(destination_descriptor, chunk[offset:])
        if total != expected_length or digest.hexdigest() != expected_digest:
            raise WorkspaceError("changeset artifact digest or length drifted")
        os.fsync(destination_descriptor)
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    finally:
        os.close(source_descriptor)
        if destination_descriptor is not None:
            os.close(destination_descriptor)


__all__ = [
    "MAX_CHANGESET_BYTES",
    "copy_verified_artifact",
    "read_verified_artifact",
    "verified_artifact_path",
    "write_exclusive_artifact",
]
