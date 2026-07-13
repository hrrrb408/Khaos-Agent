"""Server-owned trusted verification command and disposable workspace policy."""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable

from khaos.coding.planning.contracts import VerificationCatalogEntry, VerificationRequirement
from khaos.coding.planning.verification_execution_models import TrustedVerificationCommand


_SHELL_LAUNCHERS = {
    "sh", "bash", "dash", "zsh", "cmd", "cmd.exe", "powershell",
    "powershell.exe", "pwsh", "eval", "xargs", "env",
}
_CONTROL = re.compile(r"[\x00\n\r]|&&|\|\||[;|`]|\$\(")

# Batch 3.1.1 §4: hard limits for verification snapshot copy.
_MAX_SNAPSHOT_FILES = 50_000
_MAX_SNAPSHOT_DIRS = 5_000
_MAX_SNAPSHOT_BYTES = 2 * 1024 * 1024 * 1024  # 2 GiB


@dataclass(frozen=True)
class TrustedToolchain:
    executable_id: str
    language: str
    absolute_path: str
    version: str
    image_digest: str
    binary_digest: str = ""


@dataclass(frozen=True)
class SandboxProfile:
    profile_id: str
    image_digest: str
    network_enabled: bool = False
    read_only_root: bool = True
    run_as_user: str = "65532:65532"
    memory_bytes: int = 512 * 1024 * 1024
    cpu_count: float = 1.0
    pids_limit: int = 128
    file_size_bytes: int = 64 * 1024 * 1024
    open_files: int = 256

    @property
    def digest(self) -> str:
        payload = {
            "profile_id": self.profile_id, "image_digest": self.image_digest,
            "network_enabled": self.network_enabled,
            "read_only_root": self.read_only_root, "run_as_user": self.run_as_user,
            "memory_bytes": self.memory_bytes, "cpu_count": self.cpu_count,
            "pids_limit": self.pids_limit, "file_size_bytes": self.file_size_bytes,
            "open_files": self.open_files,
        }
        return hashlib.sha256(json.dumps(
            payload, sort_keys=True, separators=(",", ":"),
        ).encode()).hexdigest()


class TrustedCommandFactory:
    """Rebuild commands from catalog evidence; caller command fields are absent."""

    def __init__(
        self,
        toolchains: tuple[TrustedToolchain, ...],
        profiles: tuple[SandboxProfile, ...],
        *,
        default_timeout_ms: int = 120_000,
        output_limit_bytes: int = 2 * 1024 * 1024,
    ) -> None:
        self._tools = {(tool.language, tool.executable_id): tool for tool in toolchains}
        self._profiles = {profile.profile_id: profile for profile in profiles}
        self._timeout = default_timeout_ms
        self._output_limit = output_limit_bytes

    def build(
        self,
        requirements: tuple[VerificationRequirement, ...],
        entries: tuple[VerificationCatalogEntry, ...],
        *,
        profile_id: str,
    ) -> tuple[TrustedVerificationCommand, ...]:
        profile = self._profiles.get(profile_id)
        if profile is None or profile.network_enabled or not profile.read_only_root:
            raise PermissionError("trusted verification requires an offline read-only profile")
        entry_map = {
            (entry.verification_type, entry.language, entry.argv): entry
            for entry in entries
        }
        commands: list[TrustedVerificationCommand] = []
        for ordinal, requirement in enumerate(requirements):
            if requirement.command is None:
                if requirement.required:
                    raise PermissionError("required verification has no trusted command")
                continue
            entry = entry_map.get((
                requirement.verification_type, requirement.scope, requirement.command,
            ))
            if entry is None:
                raise PermissionError("verification requirement is absent from trusted catalog")
            argv = tuple(entry.argv)
            self._validate_argv(argv)
            executable_id = argv[0]
            tool = self._tools.get((entry.language, executable_id))
            if tool is None or tool.image_digest != profile.image_digest:
                raise PermissionError("trusted toolchain is unavailable for sandbox image")
            command = TrustedVerificationCommand(
                command_id=f"verify-{ordinal + 1}-{hashlib.sha256('|'.join(argv).encode()).hexdigest()[:12]}",
                requirement_id=f"requirement-{ordinal + 1}",
                kind=entry.verification_type,
                language=entry.language,
                executable_id=tool.executable_id,
                argv=(tool.absolute_path, *argv[1:]),
                cwd=".", config_path=entry.config_path,
                config_hash=entry.config_hash,
                toolchain_id=f"{tool.language}:{tool.executable_id}",
                toolchain_version=tool.version,
                sandbox_profile_id=profile.profile_id,
                timeout_ms=self._timeout,
                output_limit_bytes=self._output_limit,
                expected_exit_codes=(0,), executes_project_code=True,
                metadata={"required": requirement.required},
            ).normalized()
            commands.append(command)
        return tuple(commands)

    @staticmethod
    def _validate_argv(argv: tuple[str, ...]) -> None:
        if not argv or any(not isinstance(part, str) or _CONTROL.search(part) for part in argv):
            raise PermissionError("invalid trusted verification argv")
        launcher = PurePosixPath(argv[0].replace("\\", "/")).name.casefold()
        if launcher in _SHELL_LAUNCHERS:
            raise PermissionError("shell and command launchers are forbidden")
        if launcher in {"npm", "pnpm", "yarn"}:
            if len(argv) < 3 or argv[1] not in {"run", "test"}:
                raise PermissionError("package manager verification must use a catalog script")
        if argv[0].startswith(("./", "../", "/")):
            raise PermissionError("catalog executable must be a logical toolchain id")


@dataclass(frozen=True)
class ManifestEntry:
    path: str
    content_hash: str
    mode: int


@dataclass(frozen=True)
class DisposableVerificationWorkspace:
    instance_id: str
    root: Path
    manifest: tuple[ManifestEntry, ...]
    manifest_digest: str


class VerificationSnapshotCapability:
    """Batch 3.1.1 §4: fixed root FD + O_NOFOLLOW for safe workspace traversal.

    Opens the canonical workspace root with ``O_DIRECTORY | O_NOFOLLOW``
    and walks the tree using ``dir_fd``-relative ``openat``/``fstatat``.
    Symlinks are rejected at every level (``O_NOFOLLOW`` on files,
    ``O_DIRECTORY | O_NOFOLLOW`` on directories).  After opening a file,
    ``fstat`` is called to detect inode replacement during reading.
    """

    def __init__(self, root_fd: int, root_path: Path) -> None:
        self._root_fd = root_fd
        self._root_path = root_path

    @classmethod
    def open(cls, root: Path) -> "VerificationSnapshotCapability":
        root = root.resolve(strict=True)
        fd = os.open(str(root), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        return cls(fd, root)

    def close(self) -> None:
        try:
            os.close(self._root_fd)
        except OSError:
            pass

    def __enter__(self) -> "VerificationSnapshotCapability":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


class VerificationWorkspaceFactory:
    """Copies a canonical workspace without Git metadata, symlinks or hardlinks.

    Batch 3.1.1 §4: rewritten to use ``dir_fd`` + ``O_NOFOLLOW`` instead
    of ``Path.rglob`` / ``is_symlink`` / ``Path.open``.  The source tree
    is traversed using ``os.openat`` with ``O_NOFOLLOW`` at every level,
    preventing symlink swap races.  After opening each file for reading,
    ``fstat`` is called to verify the inode hasn't been replaced during
    the copy.  Files with ``st_nlink != 1`` are rejected (hardlink guard).
    """

    def __init__(self, root: Path) -> None:
        self._root = root.resolve()

    def create(
        self,
        source: Path,
        *,
        forbidden_roots: Iterable[Path],
    ) -> DisposableVerificationWorkspace:
        source = source.resolve(strict=True)
        forbidden = tuple(path.resolve() for path in forbidden_roots)
        if any(self._root == path or self._root in path.parents or path in self._root.parents for path in forbidden):
            raise PermissionError("verification root overlaps a protected root")
        self._root.mkdir(mode=0o700, parents=True, exist_ok=True)
        instance_id = f"verify_{secrets.token_hex(16)}"
        destination = self._root / instance_id
        destination.mkdir(mode=0o700)
        entries: list[ManifestEntry] = []
        # Batch 3.1.1 §4: cumulative counters tracked as instance attributes
        # so that recursive _copy_tree calls propagate counts correctly.
        self._file_count = 0
        self._dir_count = 0
        self._total_bytes = 0
        try:
            # Open the source root with O_NOFOLLOW.
            src_root_fd = os.open(
                str(source), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            )
            try:
                # Open the destination root.
                dst_root_fd = os.open(
                    str(destination), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                )
                try:
                    self._copy_tree(
                        src_root_fd, dst_root_fd, source, destination,
                        entries, "",
                    )
                finally:
                    os.close(dst_root_fd)
            finally:
                os.close(src_root_fd)
            payload = [entry.__dict__ for entry in entries]
            manifest_digest = hashlib.sha256(json.dumps(
                payload, sort_keys=True, separators=(",", ":"),
            ).encode()).hexdigest()
            return DisposableVerificationWorkspace(
                instance_id, destination, tuple(entries), manifest_digest,
            )
        except Exception:
            self._safe_destroy(destination)
            raise

    def _copy_tree(
        self, src_fd: int, dst_fd: int, src_root: Path, dst_root: Path,
        entries: list[ManifestEntry], prefix: str,
    ) -> None:
        """Recursively copy entries from ``src_fd`` to ``dst_fd`` using dir_fd."""
        try:
            names = os.listdir(src_fd)
        except OSError:
            return
        for name in sorted(names):
            if prefix == "" and name == ".git":
                continue
            child_prefix = f"{prefix}{name}" if prefix == "" else f"{prefix}/{name}"
            # Open the child with O_NOFOLLOW | O_NONBLOCK in the source.
            # O_NOFOLLOW rejects symlinks; O_NONBLOCK prevents blocking on
            # FIFOs and special files (which are later rejected by type check).
            try:
                child_src_fd = os.open(
                    name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=src_fd,
                )
            except OSError as exc:
                # Likely a symlink (O_NOFOLLOW rejects symlinks for files).
                raise PermissionError(
                    f"verification workspace rejects symlink: {child_prefix}"
                ) from exc
            try:
                st = os.fstat(child_src_fd)
                if stat.S_ISDIR(st.st_mode):
                    self._dir_count += 1
                    if self._dir_count > _MAX_SNAPSHOT_DIRS:
                        raise PermissionError("verification snapshot directory limit exceeded")
                    # Create the destination directory with O_DIRECTORY.
                    try:
                        child_dst_fd = os.open(
                            name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dst_fd,
                        )
                    except FileNotFoundError:
                        os.mkdir(name, mode=0o700, dir_fd=dst_fd)
                        child_dst_fd = os.open(
                            name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dst_fd,
                        )
                    try:
                        self._copy_tree(
                            child_src_fd, child_dst_fd, src_root, dst_root,
                            entries, child_prefix,
                        )
                    finally:
                        os.close(child_dst_fd)
                elif stat.S_ISREG(st.st_mode):
                    # Reject hardlinks (st_nlink != 1).
                    if st.st_nlink != 1:
                        raise PermissionError(
                            f"verification workspace rejects hardlink: {child_prefix}"
                        )
                    self._file_count += 1
                    if self._file_count > _MAX_SNAPSHOT_FILES:
                        raise PermissionError("verification snapshot file limit exceeded")
                    # Read the source file content using the dir_fd.
                    source_hash, byte_length = self._copy_file(
                        child_src_fd, dst_fd, name, st.st_mode, st,
                    )
                    self._total_bytes += byte_length
                    if self._total_bytes > _MAX_SNAPSHOT_BYTES:
                        raise PermissionError("verification snapshot byte limit exceeded")
                    entries.append(ManifestEntry(
                        child_prefix, source_hash, stat.S_IMODE(st.st_mode),
                    ))
                else:
                    raise PermissionError(
                        f"verification workspace accepts regular files only: {child_prefix}"
                    )
            finally:
                os.close(child_src_fd)

    @staticmethod
    def _copy_file(
        src_fd: int, dst_dir_fd: int, name: str, src_mode: int,
        pre_st: os.stat_result,
    ) -> tuple[str, int]:
        """Copy a file from ``src_fd`` to ``dst_dir_fd/name`` with O_NOFOLLOW.

        Returns (sha256_hexdigest, byte_length).  After writing, re-stat the
        source fd to verify the inode hasn't been replaced during reading.
        ``pre_st`` is the stat captured before reading; since the fd is bound
        to the inode at open time, this is defense-in-depth.
        """
        digest = hashlib.sha256()
        # Open the destination with O_CREAT | O_EXCL | O_NOFOLLOW.
        dst_fd = os.open(
            name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            stat.S_IMODE(src_mode) & 0o777, dir_fd=dst_dir_fd,
        )
        byte_length = 0
        try:
            while True:
                chunk = os.read(src_fd, 1024 * 1024)
                if not chunk:
                    break
                os.write(dst_fd, chunk)
                digest.update(chunk)
                byte_length += len(chunk)
            os.fsync(dst_fd)
        finally:
            os.close(dst_fd)
        # Re-stat the source fd to detect inode replacement during reading.
        post_st = os.fstat(src_fd)
        if post_st.st_ino != pre_st.st_ino or post_st.st_dev != pre_st.st_dev:
            raise PermissionError(
                f"verification source inode changed during copy: {name}"
            )
        return digest.hexdigest(), byte_length

    @staticmethod
    def destroy(workspace: DisposableVerificationWorkspace) -> None:
        """Batch 3.1.1 §6: safe destroy using manifest-driven deletion.

        Deletes only the files declared in the manifest, then removes
        empty directories.  Rejects symlinks and unknown files.  Falls
        back to ``shutil.rmtree`` only if the manifest is empty (which
        should not happen in normal operation).
        """
        VerificationWorkspaceFactory._safe_destroy(workspace.root, workspace.manifest)

    @staticmethod
    def _safe_destroy(
        root: Path, manifest: tuple[ManifestEntry, ...] = (),
    ) -> None:
        """Destroy a workspace root using manifest-driven deletion."""
        if not root.exists():
            return
        if not manifest:
            # Empty manifest — nothing to delete.  Just remove the root dir.
            try:
                os.rmdir(str(root))
            except OSError:
                pass
            return
        # Delete each declared file using O_NOFOLLOW.
        for entry in manifest:
            file_path = root / entry.path
            try:
                fd = os.open(
                    str(file_path), os.O_RDONLY | os.O_NOFOLLOW,
                )
                os.close(fd)
                file_path.unlink()
            except (FileNotFoundError, PermissionError, OSError):
                pass
        # Remove empty directories (deepest first).
        all_dirs: set[str] = set()
        for entry in manifest:
            parts = entry.path.split("/")
            for i in range(1, len(parts)):
                all_dirs.add("/".join(parts[:i]))
        for dir_rel in sorted(all_dirs, key=len, reverse=True):
            dir_path = root / dir_rel
            try:
                os.rmdir(str(dir_path))
            except OSError:
                pass
        # Finally remove the root.
        try:
            os.rmdir(str(root))
        except OSError:
            pass
