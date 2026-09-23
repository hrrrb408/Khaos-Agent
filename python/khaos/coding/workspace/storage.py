"""Fail-closed TaskWorkspace storage accounting and mutation authority."""

from __future__ import annotations

import os
import stat
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Generic, TypeVar

FileIdentity = tuple[int, int]
RootIdentity = tuple[int, int]
T = TypeVar("T")

DEFAULT_WORKSPACE_BYTES = 512 * 1024 * 1024
DEFAULT_WORKSPACE_ENTRIES = 100_000
_CAPTURE_ATTEMPTS = 3
_CAPTURE_RETRY_DELAY_SECONDS = 0.01


@dataclass(frozen=True)
class WorkspaceStorageLimits:
    """Aggregate storage limits assigned to one TaskWorkspace."""

    bytes: int = DEFAULT_WORKSPACE_BYTES
    entries: int = DEFAULT_WORKSPACE_ENTRIES

    def __post_init__(self) -> None:
        if self.bytes <= 0 or self.entries <= 0:
            raise ValueError("workspace storage limits must be positive")


@dataclass(frozen=True)
class WorkspaceStorageSnapshot:
    """Allocated bytes, entries, and path identities from a stable scan."""

    allocated_by_inode: dict[FileIdentity, int]
    entries: int
    complete: bool
    identity_by_path: dict[str, FileIdentity]
    root_identity: RootIdentity | None


@dataclass(frozen=True)
class WorkspaceMutation(Generic[T]):
    """A completed filesystem mutation and its identity-bound rollback."""

    value: T
    rollback: Callable[[], None]
    finalize: Callable[[], None] = lambda: None
    advances_generation: bool = True


class WorkspaceStorageViolation(PermissionError):
    """Raised when a Workspace mutation or observation violates its budget."""

    def __init__(
        self,
        diagnostic: dict[str, object],
        *,
        rollback_attempted: bool = False,
        rollback_succeeded: bool = False,
        quarantine_required: bool = True,
    ) -> None:
        self.diagnostic = diagnostic
        self.rollback_attempted = rollback_attempted
        self.rollback_succeeded = rollback_succeeded
        self.quarantine_required = quarantine_required
        super().__init__(
            f"TaskWorkspace storage violation: {diagnostic['kind']} "
            f"observed={diagnostic['observed']} limit={diagnostic['limit']}"
        )


class WorkspaceStorageAuthority:
    """Single authority shared by process and file-tool Workspace writes."""

    def __init__(
        self,
        *,
        capture: Callable[[Path], WorkspaceStorageSnapshot] | None = None,
    ) -> None:
        self._capture = capture or capture_workspace_snapshot
        self._locks: dict[str, threading.RLock] = {}
        self._locks_guard = threading.Lock()

    def assess(
        self,
        root: Path,
        baseline: WorkspaceStorageSnapshot | None,
        limits: WorkspaceStorageLimits,
        *,
        extra_allocated_bytes: int = 0,
    ) -> dict[str, object] | None:
        """Return a violation diagnostic, failing closed on any uncertainty."""
        if baseline is None or not baseline.complete:
            return _observation_violation()
        current = self._capture(root)
        if not current.complete or current.root_identity != baseline.root_identity:
            return _observation_violation()
        allocated_bytes, entries = workspace_storage_delta(baseline, current)
        allocated_bytes += max(0, extra_allocated_bytes)
        if allocated_bytes > limits.bytes:
            return {
                "kind": "workspace-bytes",
                "observed": allocated_bytes,
                "limit": limits.bytes,
            }
        if entries > limits.entries:
            return {
                "kind": "workspace-entries",
                "observed": entries,
                "limit": limits.entries,
            }
        return None

    def mutate(
        self,
        workspace_id: str,
        root: Path,
        baseline: WorkspaceStorageSnapshot | None,
        limits: WorkspaceStorageLimits,
        operation: Callable[[], WorkspaceMutation[T]],
    ) -> T:
        """Apply, account, and if needed roll back one file-tool mutation."""
        with self._lock_for(workspace_id):
            existing = self.assess(root, baseline, limits)
            if existing is not None:
                raise WorkspaceStorageViolation(existing)
            mutation = operation()
            violation = self.assess(root, baseline, limits)
            if violation is None:
                try:
                    mutation.finalize()
                except Exception as finalize_error:
                    try:
                        mutation.rollback()
                    except Exception as rollback_error:  # noqa: BLE001 - recovery failure requires quarantine
                        raise WorkspaceStorageViolation(
                            _finalization_diagnostic(
                                finalize_error,
                                rollback_error=rollback_error,
                            ),
                            rollback_attempted=True,
                            rollback_succeeded=False,
                            quarantine_required=True,
                        ) from finalize_error
                    raise WorkspaceStorageViolation(
                        _finalization_diagnostic(finalize_error),
                        rollback_attempted=True,
                        rollback_succeeded=True,
                        quarantine_required=True,
                    ) from finalize_error
                return mutation.value

            rollback_succeeded = False
            try:
                mutation.rollback()
                rollback_succeeded = True
            except Exception:  # noqa: BLE001 - rollback failure requires quarantine
                rollback_succeeded = False
            finalize_error: BaseException | None = None
            try:
                mutation.finalize()
            except Exception as error:  # noqa: BLE001 - cleanup uncertainty requires quarantine
                finalize_error = error
            remaining = self.assess(root, baseline, limits)
            quarantine_required = (
                not rollback_succeeded
                or remaining is not None
                or finalize_error is not None
            )
            diagnostic = (
                _finalization_diagnostic(
                    finalize_error,
                    original_violation=violation,
                )
                if finalize_error is not None
                else violation
            )
            raise WorkspaceStorageViolation(
                diagnostic,
                rollback_attempted=True,
                rollback_succeeded=rollback_succeeded,
                quarantine_required=quarantine_required,
            )

    def release(self, workspace_id: str) -> None:
        """Forget the in-process serialization lock after Workspace cleanup."""
        with self._locks_guard:
            self._locks.pop(workspace_id, None)

    def _lock_for(self, workspace_id: str) -> threading.RLock:
        if not workspace_id:
            raise ValueError("workspace id is required for storage authority")
        with self._locks_guard:
            return self._locks.setdefault(workspace_id, threading.RLock())


def _finalization_diagnostic(
    error: BaseException,
    *,
    rollback_error: BaseException | None = None,
    original_violation: dict[str, object] | None = None,
) -> dict[str, object]:
    """Describe an effect whose post-publish cleanup could not be proven."""
    diagnostic: dict[str, object] = {
        "kind": "workspace-finalize",
        "observed": type(error).__name__,
        "limit": "cleanup-complete",
        "error": type(error).__name__,
    }
    if rollback_error is not None:
        diagnostic["rollback_error"] = type(rollback_error).__name__
    if original_violation is not None:
        diagnostic["original_violation"] = original_violation.get("kind", "unknown")
    return diagnostic


def capture_workspace_snapshot(root: Path) -> WorkspaceStorageSnapshot:
    """Require two stable, complete scans and conservatively merge maxima.

    Git and other trusted workspace writers use atomic rename/unlink sequences.
    A scan can therefore observe a short-lived missing entry while the writer
    is still finishing.  Incomplete scans are retried within this bounded
    window; only a stable pair of complete scans proves the observation.  A
    continuous traversal error or path/inode churn remains fail-closed.
    """
    canonical = root.expanduser().resolve()
    scans: list[WorkspaceStorageSnapshot] = []
    stable = False
    for _ in range(_CAPTURE_ATTEMPTS):
        if scans:
            time.sleep(_CAPTURE_RETRY_DELAY_SECONDS)
        scans.append(_capture_once(canonical))
        if len(scans) >= 2 and _same_identity_view(scans[-2], scans[-1]):
            stable = True
            break

    allocated: dict[FileIdentity, int] = {}
    usable_scans = [snapshot for snapshot in scans if snapshot.complete]
    for snapshot in usable_scans:
        for identity, size in snapshot.allocated_by_inode.items():
            allocated[identity] = max(size, allocated.get(identity, 0))
    final = usable_scans[-1] if usable_scans else scans[-1]
    return WorkspaceStorageSnapshot(
        allocated_by_inode=allocated,
        entries=max(snapshot.entries for snapshot in usable_scans)
        if usable_scans
        else 0,
        complete=stable,
        identity_by_path=dict(final.identity_by_path),
        root_identity=final.root_identity,
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
    allocated: dict[FileIdentity, int] = {}
    identities: dict[str, FileIdentity] = {}
    entries = 0
    complete = True
    try:
        root_info = os.stat(root, follow_symlinks=False)
    except OSError:
        return WorkspaceStorageSnapshot({}, 0, False, {}, None)
    if not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode):
        return WorkspaceStorageSnapshot({}, 0, False, {}, None)
    root_identity = (root_info.st_dev, root_info.st_ino)

    def onerror(_error: OSError) -> None:
        nonlocal complete
        complete = False

    try:
        iterator = os.walk(root, followlinks=False, onerror=onerror)
        for directory, subdirectories, files in iterator:
            try:
                directory_info = os.stat(directory, follow_symlinks=False)
            except OSError:
                complete = False
                continue
            if not stat.S_ISDIR(directory_info.st_mode):
                complete = False
                continue
            names = [*subdirectories, *files]
            entries += len(names)
            for name in names:
                path = Path(directory) / name
                try:
                    value = os.stat(path, follow_symlinks=False)
                    relative = path.relative_to(root).as_posix()
                except (OSError, ValueError):
                    complete = False
                    continue
                identity = (value.st_dev, value.st_ino)
                identities[relative] = identity
                if not stat.S_ISREG(value.st_mode):
                    continue
                allocated_bytes = int(getattr(value, "st_blocks", 0)) * 512
                if allocated_bytes <= 0 and value.st_size > 0:
                    allocated_bytes = value.st_size
                allocated[identity] = max(
                    allocated_bytes, allocated.get(identity, 0)
                )
    except OSError:
        complete = False
    try:
        final_root = os.stat(root, follow_symlinks=False)
        if (final_root.st_dev, final_root.st_ino) != root_identity:
            complete = False
    except OSError:
        complete = False
    return WorkspaceStorageSnapshot(
        allocated, entries, complete, identities, root_identity
    )


def _same_identity_view(
    left: WorkspaceStorageSnapshot,
    right: WorkspaceStorageSnapshot,
) -> bool:
    return (
        left.complete
        and right.complete
        and left.root_identity == right.root_identity
        and left.identity_by_path == right.identity_by_path
    )


def _observation_violation() -> dict[str, object]:
    return {
        "kind": "workspace-observation",
        "observed": "incomplete",
        "limit": "complete-and-stable",
    }
