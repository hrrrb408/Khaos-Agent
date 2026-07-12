"""Dirfd-anchored, no-follow workspace mutation primitives."""
from __future__ import annotations

import errno
import ctypes
import hashlib
import os
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Callable
from khaos.coding.planning.safe_identifiers import (
    SafeWorkspaceRelativePath, UnsafePersistedIdentifier,
)


class SafePathError(RuntimeError):
    pass


@dataclass
class SafeParentDirectory:
    root_fd: int
    parent_fd: int
    parts: tuple[str, ...]
    leaf: str
    identity: tuple[int, int]

    def close(self) -> None:
        os.close(self.parent_fd)

    def revalidate(self) -> None:
        descriptor = os.dup(self.root_fd)
        try:
            for part in self.parts:
                child = os.open(
                    part,
                    os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=descriptor,
                )
                os.close(descriptor)
                descriptor = child
            current = os.fstat(descriptor)
            if (current.st_dev, current.st_ino) != self.identity:
                raise SafePathError("parent directory identity changed")
        finally:
            os.close(descriptor)

    def lstat(self) -> os.stat_result | None:
        try:
            return os.stat(self.leaf, dir_fd=self.parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return None

    def hash_file(self) -> str | None:
        info = self.lstat()
        if info is None:
            return None
        if not stat.S_ISREG(info.st_mode):
            raise SafePathError("target is not a regular file")
        descriptor = os.open(
            self.leaf, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=self.parent_fd,
        )
        try:
            digest = hashlib.sha256()
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
            return digest.hexdigest()
        finally:
            os.close(descriptor)

    def read_file(self) -> tuple[bytes, os.stat_result]:
        info = self.lstat()
        if info is None or not stat.S_ISREG(info.st_mode):
            raise SafePathError("target is not a regular file")
        descriptor = os.open(
            self.leaf, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self.parent_fd
        )
        try:
            chunks: list[bytes] = []
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            final = os.fstat(descriptor)
            if (final.st_dev, final.st_ino, final.st_size) != (
                info.st_dev, info.st_ino, info.st_size
            ):
                raise SafePathError("target changed while reading")
            return b"".join(chunks), final
        finally:
            os.close(descriptor)

    def fsync(self) -> None:
        os.fsync(self.parent_fd)

    def temporary(self, *, mode: int) -> tuple[int, str]:
        for _ in range(32):
            name = f".khaos-{secrets.token_hex(16)}"
            try:
                descriptor = os.open(
                    name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                    mode, dir_fd=self.parent_fd,
                )
                return descriptor, name
            except FileExistsError:
                continue
        raise SafePathError("could not allocate safe temporary file")


class WorkspacePathHandle:
    """Fixed root directory capability for one mutation session."""

    def __init__(self, root: Path) -> None:
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        if not nofollow or not hasattr(os, "supports_dir_fd"):
            raise SafePathError("platform lacks O_NOFOLLOW/dir_fd safety")
        self.root = root.resolve(strict=True)
        self.root_fd = os.open(
            self.root, os.O_RDONLY | os.O_DIRECTORY | nofollow
        )
        root_stat = os.fstat(self.root_fd)
        self.root_identity = (root_stat.st_dev, root_stat.st_ino)

    def close(self) -> None:
        os.close(self.root_fd)

    def parent(self, relative: str) -> SafeParentDirectory:
        try:
            validated = SafeWorkspaceRelativePath.parse(relative)
        except UnsafePersistedIdentifier as exc:
            raise SafePathError(str(exc)) from exc
        pure = PurePosixPath(validated.value)
        parts = tuple(pure.parts[:-1])
        descriptor = os.dup(self.root_fd)
        try:
            for part in parts:
                child = os.open(
                    part,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=descriptor,
                )
                os.close(descriptor)
                descriptor = child
            info = os.fstat(descriptor)
            return SafeParentDirectory(
                self.root_fd, descriptor, parts, pure.name,
                (info.st_dev, info.st_ino),
            )
        except Exception:
            os.close(descriptor)
            raise

    @staticmethod
    def _write_temp(parent: SafeParentDirectory, content: bytes, mode: int) -> str:
        descriptor, name = parent.temporary(mode=mode)
        try:
            offset = 0
            while offset < len(content):
                offset += os.write(descriptor, content[offset:])
            os.fsync(descriptor)
            os.fchmod(descriptor, mode)
        finally:
            os.close(descriptor)
        return name

    @staticmethod
    def _exchange(parent_fd: int, left: str, right: str) -> None:
        """Atomically exchange two names, or fail closed if unavailable."""
        libc = ctypes.CDLL(None, use_errno=True)
        if hasattr(libc, "renameatx_np"):
            result = libc.renameatx_np(
                parent_fd, left.encode(), parent_fd, right.encode(), 0x00000002
            )
        elif hasattr(libc, "renameat2"):
            result = libc.renameat2(
                parent_fd, left.encode(), parent_fd, right.encode(), 0x2
            )
        else:
            raise SafePathError("platform lacks atomic rename exchange")
        if result != 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))

    def create(
        self, relative: str, content: bytes, mode: int,
        phase: Callable[[str], None],
    ) -> None:
        parent = self.parent(relative)
        temp = ""
        try:
            if parent.lstat() is not None:
                raise FileExistsError(relative)
            temp = self._write_temp(parent, content, mode)
            parent.revalidate()
            os.link(
                temp, parent.leaf,
                src_dir_fd=parent.parent_fd, dst_dir_fd=parent.parent_fd,
                follow_symlinks=False,
            )
            os.unlink(temp, dir_fd=parent.parent_fd)
            temp = ""
            phase("filesystem-applied")
            parent.revalidate()
            parent.fsync()
            phase("directory-synced")
        finally:
            if temp:
                try:
                    os.unlink(temp, dir_fd=parent.parent_fd)
                except FileNotFoundError:
                    pass
            parent.close()

    def update(
        self, relative: str, content: bytes, mode: int, expected_inode: int,
        phase: Callable[[str], None],
    ) -> None:
        parent = self.parent(relative)
        temp = ""
        try:
            current = parent.lstat()
            if current is None or current.st_ino != expected_inode or not stat.S_ISREG(current.st_mode):
                raise SafePathError("update target identity changed")
            temp = self._write_temp(parent, content, mode)
            parent.revalidate()
            current = parent.lstat()
            if current is None or current.st_ino != expected_inode:
                raise SafePathError("update target identity changed")
            self._exchange(parent.parent_fd, temp, parent.leaf)
            replaced = os.stat(
                temp, dir_fd=parent.parent_fd, follow_symlinks=False
            )
            if replaced.st_ino != expected_inode or not stat.S_ISREG(replaced.st_mode):
                self._exchange(parent.parent_fd, temp, parent.leaf)
                raise SafePathError("update target was replaced by another actor")
            os.unlink(temp, dir_fd=parent.parent_fd)
            temp = ""
            phase("filesystem-applied")
            parent.revalidate()
            parent.fsync()
            phase("directory-synced")
        finally:
            if temp:
                try:
                    os.unlink(temp, dir_fd=parent.parent_fd)
                except FileNotFoundError:
                    pass
            parent.close()

    def delete(self, relative: str, expected_inode: int, phase: Callable[[str], None]) -> None:
        parent = self.parent(relative)
        try:
            current = parent.lstat()
            if current is None or current.st_ino != expected_inode or not stat.S_ISREG(current.st_mode):
                raise SafePathError("delete target identity changed")
            parent.revalidate()
            os.unlink(parent.leaf, dir_fd=parent.parent_fd)
            phase("filesystem-applied")
            parent.revalidate()
            parent.fsync()
            phase("directory-synced")
        finally:
            parent.close()

    def rename_no_replace(
        self, source: str, destination: str, expected_inode: int,
        phase: Callable[[str], None],
    ) -> None:
        source_parent = self.parent(source)
        destination_parent = self.parent(destination)
        try:
            current = source_parent.lstat()
            if current is None or current.st_ino != expected_inode or not stat.S_ISREG(current.st_mode):
                raise SafePathError("rename source identity changed")
            if destination_parent.lstat() is not None:
                raise FileExistsError(destination)
            source_parent.revalidate()
            destination_parent.revalidate()
            try:
                os.link(
                    source_parent.leaf, destination_parent.leaf,
                    src_dir_fd=source_parent.parent_fd,
                    dst_dir_fd=destination_parent.parent_fd,
                    follow_symlinks=False,
                )
            except OSError as exc:
                if exc.errno in {errno.EXDEV, errno.EPERM, errno.EOPNOTSUPP}:
                    raise SafePathError("platform cannot provide rename no-replace") from exc
                raise
            try:
                os.unlink(source_parent.leaf, dir_fd=source_parent.parent_fd)
            except Exception:
                os.unlink(destination_parent.leaf, dir_fd=destination_parent.parent_fd)
                raise
            phase("filesystem-applied")
            source_parent.revalidate()
            destination_parent.revalidate()
            source_parent.fsync()
            if destination_parent.identity != source_parent.identity:
                destination_parent.fsync()
            phase("directory-synced")
        finally:
            source_parent.close()
            destination_parent.close()
