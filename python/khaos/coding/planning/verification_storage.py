"""Boot-scoped runtime registry for trusted verification storage roots."""
from __future__ import annotations

import os
import secrets
import stat
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from khaos.coding.planning.trusted_verification import (
    ArtifactRootCapability, ArtifactRootIdentity,
    DisposableStorageRootCapability, DisposableStorageRootIdentity,
)


def _overlaps(left: Path, right: Path) -> bool:
    return left == right or left in right.parents or right in left.parents


def _open_directory_nofollow(path: Path) -> tuple[int, Path]:
    """Open/create only the final directory while pinning every ancestor FD."""
    absolute = Path(os.path.abspath(os.fspath(path.expanduser())))
    if not absolute.is_absolute() or absolute.name in {"", ".", ".."}:
        raise PermissionError("verification storage root must be absolute")
    parts = absolute.parts
    current_fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in parts[1:-1]:
            next_fd = os.open(
                component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=current_fd,
            )
            os.close(current_fd)
            current_fd = next_fd
        try:
            os.mkdir(absolute.name, 0o700, dir_fd=current_fd)
        except FileExistsError:
            pass
        root_fd = os.open(
            absolute.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=current_fd,
        )
        os.fsync(current_fd)
        return root_fd, absolute
    finally:
        os.close(current_fd)


@dataclass(frozen=True)
class _StorageRecord:
    runtime_id: str
    boot_id: str
    kind: str
    capability: Any


class RuntimeVerificationStorageRegistry:
    """Issues opaque capability IDs scoped to one Runtime boot."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: dict[str, _StorageRecord] = {}

    def issue_pair(
        self, *, runtime_id: str, boot_id: str, artifact_root: Path,
        snapshot_root: Path, forbidden_roots: Iterable[Path],
    ) -> tuple[str, str]:
        artifact_path = Path(os.path.abspath(os.fspath(artifact_root.expanduser())))
        snapshot_path = Path(os.path.abspath(os.fspath(snapshot_root.expanduser())))
        forbidden = tuple(
            Path(os.path.abspath(os.fspath(path.expanduser())))
            for path in forbidden_roots
        )
        if _overlaps(artifact_path, snapshot_path):
            raise PermissionError("verification storage roots overlap each other")
        for root in (artifact_path, snapshot_path):
            for protected in forbidden:
                if _overlaps(root, protected):
                    raise PermissionError(
                        "verification storage root overlaps a protected root"
                    )
        artifact_fd, artifact_path = _open_directory_nofollow(artifact_path)
        try:
            artifact_stat = os.fstat(artifact_fd)
            self._validate_storage_identity(artifact_stat)
            artifact_capability = ArtifactRootCapability(
                artifact_fd, artifact_path,
                ArtifactRootIdentity(
                    artifact_stat.st_dev, artifact_stat.st_ino,
                    artifact_stat.st_uid, artifact_stat.st_gid,
                    stat.S_IMODE(artifact_stat.st_mode),
                ),
            )
            snapshot_fd, snapshot_path = _open_directory_nofollow(snapshot_path)
        except Exception:
            os.close(artifact_fd)
            raise
        snapshot_stat = os.fstat(snapshot_fd)
        try:
            self._validate_storage_identity(snapshot_stat)
        except Exception:
            os.close(artifact_fd)
            os.close(snapshot_fd)
            raise
        snapshot_capability_id = f"vsc_{secrets.token_hex(32)}"
        snapshot_capability = DisposableStorageRootCapability(
            snapshot_fd, snapshot_path,
            DisposableStorageRootIdentity(
                snapshot_stat.st_dev, snapshot_stat.st_ino,
                snapshot_stat.st_uid, snapshot_stat.st_gid,
                stat.S_IMODE(snapshot_stat.st_mode),
            ),
            snapshot_capability_id,
        )
        artifact_id = f"vac_{secrets.token_hex(32)}"
        with self._lock:
            self._records[artifact_id] = _StorageRecord(
                runtime_id, boot_id, "artifact", artifact_capability,
            )
            self._records[snapshot_capability_id] = _StorageRecord(
                runtime_id, boot_id, "snapshot", snapshot_capability,
            )
        return artifact_id, snapshot_capability_id

    @staticmethod
    def _validate_storage_identity(value: os.stat_result) -> None:
        mode = stat.S_IMODE(value.st_mode)
        if (not stat.S_ISDIR(value.st_mode) or value.st_uid != os.getuid()
                or mode & 0o077 or mode & 0o7000):
            raise PermissionError(
                "verification storage root owner or mode is outside policy"
            )

    def resolve(
        self, capability_id: str, *, runtime_id: str, boot_id: str, kind: str,
    ) -> Any:
        with self._lock:
            record = self._records.get(capability_id)
        if (record is None or record.runtime_id != runtime_id
                or record.boot_id != boot_id or record.kind != kind):
            raise PermissionError("verification storage capability is invalid or stale")
        record.capability.verify_identity()
        return record.capability

    def revoke_runtime(self, runtime_id: str | None) -> None:
        if runtime_id is None:
            return
        with self._lock:
            selected = [
                (key, value) for key, value in self._records.items()
                if value.runtime_id == runtime_id
            ]
            for key, _ in selected:
                self._records.pop(key, None)
        for _, record in selected:
            record.capability.close()


VERIFICATION_STORAGE_REGISTRY = RuntimeVerificationStorageRegistry()
