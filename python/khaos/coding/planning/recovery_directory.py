"""Dirfd-scoped private recovery artifacts for planned workspace mutation."""
from __future__ import annotations

import hashlib
import json
import os
import stat
import uuid
from pathlib import Path
from khaos.coding.planning.safe_identifiers import (
    SafeRecoveryArtifactName, SafeRecoveryRunId, SafeSealTombstoneName,
    UnsafePersistedIdentifier,
)


class RecoveryDirectoryError(RuntimeError):
    """Recovery storage cannot satisfy its fail-closed boundary."""


class RecoveryDirectory:
    """Capability bound to one configured container and execution run."""

    def __init__(
        self, container: Path, run_id: str, *, create: bool,
        allowed_artifacts: frozenset[str] = frozenset(),
        allow_missing_run: bool = False,
    ) -> None:
        self.container_path = container
        try:
            self.run_id = SafeRecoveryRunId.parse(run_id).value
            self._allowed = {
                SafeRecoveryArtifactName.parse(name).value for name in allowed_artifacts
            }
        except UnsafePersistedIdentifier as exc:
            raise RecoveryDirectoryError(str(exc)) from exc
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        parent = container.parent
        self._parent_fd = os.open(parent, flags)
        try:
            parent_info = os.fstat(self._parent_fd)
            if (not stat.S_ISDIR(parent_info.st_mode)
                    or parent_info.st_uid != os.getuid()
                    or stat.S_IMODE(parent_info.st_mode) & 0o022):
                raise RecoveryDirectoryError("recovery parent permissions invalid")
            try:
                os.mkdir(container.name, 0o700, dir_fd=self._parent_fd)
                os.fsync(self._parent_fd)
            except FileExistsError:
                pass
            self._container_fd = os.open(container.name, flags, dir_fd=self._parent_fd)
            self._validate_fd(self._container_fd)
            container_info = os.fstat(self._container_fd)
            self.container_identity = f"{container_info.st_dev}:{container_info.st_ino}"
            if create:
                os.mkdir(run_id, 0o700, dir_fd=self._container_fd)
                os.fsync(self._container_fd)
            try:
                self._run_fd = os.open(run_id, flags, dir_fd=self._container_fd)
            except FileNotFoundError:
                if not allow_missing_run:
                    raise
                self._run_fd = -1
                self._identity = (-1, -1)
            else:
                self._validate_fd(self._run_fd)
                self._identity = self._identity_of(self._run_fd)
        except Exception:
            os.close(self._parent_fd)
            raise

    @staticmethod
    def _identity_of(fd: int) -> tuple[int, int]:
        info = os.fstat(fd)
        return info.st_dev, info.st_ino

    @staticmethod
    def _validate_fd(fd: int) -> None:
        info = os.fstat(fd)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
            raise RecoveryDirectoryError("recovery directory identity invalid")
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise RecoveryDirectoryError("recovery directory permissions invalid")

    @property
    def path(self) -> Path:
        return self.container_path / self.run_id

    @property
    def run_exists(self) -> bool:
        return self._run_fd >= 0

    def _assert_identity(self) -> None:
        if self._run_fd < 0:
            raise RecoveryDirectoryError("recovery run directory is absent")
        if self._identity_of(self._run_fd) != self._identity:
            raise RecoveryDirectoryError("recovery directory identity drifted")

    def create_backup(self, content: bytes, mode: int) -> tuple[str, str]:
        self._assert_identity()
        name = f"artifact-{uuid.uuid4().hex}.bak"
        fd = os.open(
            name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600, dir_fd=self._run_fd,
        )
        try:
            with os.fdopen(fd, "wb") as writer:
                writer.write(content)
                writer.flush()
                os.fsync(writer.fileno())
            os.chmod(name, mode & 0o777, dir_fd=self._run_fd, follow_symlinks=False)
            os.fsync(self._run_fd)
        except Exception:
            try:
                os.unlink(name, dir_fd=self._run_fd)
            except OSError:
                pass
            raise
        self._allowed.add(name)
        return name, hashlib.sha256(content).hexdigest()

    def write_tombstone(self, name: str, payload: dict[str, object]) -> str:
        safe = SafeSealTombstoneName.parse(name).value
        data = json.dumps(
            payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
        fd = os.open(
            safe, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600, dir_fd=self._container_fd,
        )
        try:
            with os.fdopen(fd, "wb") as writer:
                writer.write(data)
                writer.flush()
                os.fsync(writer.fileno())
            os.fsync(self._container_fd)
        except Exception:
            try:
                os.unlink(safe, dir_fd=self._container_fd)
            except OSError:
                pass
            raise
        return hashlib.sha256(data).hexdigest()

    def read_tombstone(self, name: str) -> dict[str, object]:
        safe = SafeSealTombstoneName.parse(name).value
        fd = os.open(safe, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self._container_fd)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise RecoveryDirectoryError("seal tombstone is not a regular file")
            data = b""
            while True:
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                data += chunk
            return json.loads(data.decode("utf-8"))
        finally:
            os.close(fd)

    def delete_tombstone(self, name: str) -> None:
        safe = SafeSealTombstoneName.parse(name).value
        os.unlink(safe, dir_fd=self._container_fd)
        os.fsync(self._container_fd)

    def discard_unreferenced(self, name: str) -> None:
        self._assert_identity()
        os.unlink(name, dir_fd=self._run_fd)
        os.fsync(self._run_fd)
        self._allowed.discard(name)

    def read(self, name: str) -> bytes:
        self._assert_identity()
        if name not in self._allowed:
            raise RecoveryDirectoryError("artifact is not journal-authorized")
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self._run_fd)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise RecoveryDirectoryError("artifact is not a regular file")
            chunks: list[bytes] = []
            while True:
                chunk = os.read(fd, 65536)
                if not chunk:
                    return b"".join(chunks)
                chunks.append(chunk)
        finally:
            os.close(fd)

    def seal(self) -> None:
        """Remove only journal-authorized artifacts and the empty run directory."""
        self._assert_identity()
        names = set(os.listdir(self._run_fd))
        unknown = names - self._allowed
        if unknown:
            raise RecoveryDirectoryError("unknown recovery artifact present")
        for name in sorted(names):
            info = os.stat(name, dir_fd=self._run_fd, follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode):
                raise RecoveryDirectoryError("recovery artifact type invalid")
            os.unlink(name, dir_fd=self._run_fd)
        os.fsync(self._run_fd)
        os.close(self._run_fd)
        self._run_fd = -1
        os.rmdir(self.run_id, dir_fd=self._container_fd)
        os.fsync(self._container_fd)

    def seal_with_retention(self) -> str:
        """Seal the run while retaining a private failure-only evidence copy."""
        self._assert_identity()
        names = set(os.listdir(self._run_fd))
        if names - self._allowed:
            raise RecoveryDirectoryError("unknown recovery artifact present")
        retained = f".rollback-retained-{uuid.uuid4().hex}"
        os.mkdir(retained, 0o700, dir_fd=self._container_fd)
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        retained_fd = os.open(retained, flags, dir_fd=self._container_fd)
        try:
            for name in sorted(names):
                info = os.stat(name, dir_fd=self._run_fd, follow_symlinks=False)
                if not stat.S_ISREG(info.st_mode):
                    raise RecoveryDirectoryError("recovery artifact type invalid")
                os.link(
                    name, name, src_dir_fd=self._run_fd,
                    dst_dir_fd=retained_fd, follow_symlinks=False,
                )
            os.fsync(retained_fd)
            os.fsync(self._container_fd)
        finally:
            os.close(retained_fd)
        self.seal()
        return retained

    def discard_retention(self, retained: str) -> None:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        fd = os.open(retained, flags, dir_fd=self._container_fd)
        try:
            for name in sorted(os.listdir(fd)):
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if not stat.S_ISREG(info.st_mode):
                    raise RecoveryDirectoryError("retained artifact type invalid")
                os.unlink(name, dir_fd=fd)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.rmdir(retained, dir_fd=self._container_fd)
        os.fsync(self._container_fd)

    def close(self) -> None:
        for name in ("_run_fd", "_container_fd", "_parent_fd"):
            fd = getattr(self, name, -1)
            if fd >= 0:
                os.close(fd)
                setattr(self, name, -1)

    def __enter__(self) -> "RecoveryDirectory":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()
