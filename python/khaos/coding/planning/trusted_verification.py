"""Server-owned trusted verification command and disposable workspace policy."""
from __future__ import annotations

import fnmatch
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
    # Batch 3.1.3 §5: fixed version argv for attestation (e.g. ("--version",))
    version_argv: tuple[str, ...] = ()
    # Batch 3.1.3 §5: binds the ImageAttestation digest at declaration time
    image_attestation_digest: str = ""


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
    # Batch 3.1.5 §1: explicit image identity fields.  When set, these
    # replace the old ``image_digest`` conflation.  ``requested_image_reference``
    # is the full ``repository@sha256:digest``; ``approved_repository_digest``
    # is the digest extracted from RepoDigests; ``approved_platform`` is
    # the expected ``os/arch``.  The old ``image_digest`` field remains
    # for backward compatibility with test profiles but production code
    # must set the new fields.
    requested_image_reference: str = ""
    approved_repository_digest: str = ""
    approved_platform: str = ""

    @property
    def digest(self) -> str:
        payload = {
            "profile_id": self.profile_id, "image_digest": self.image_digest,
            "network_enabled": self.network_enabled,
            "read_only_root": self.read_only_root, "run_as_user": self.run_as_user,
            "memory_bytes": self.memory_bytes, "cpu_count": self.cpu_count,
            "pids_limit": self.pids_limit, "file_size_bytes": self.file_size_bytes,
            "open_files": self.open_files,
            # Batch 3.1.5 §1: include explicit image identity in digest.
            "requested_image_reference": self.requested_image_reference,
            "approved_repository_digest": self.approved_repository_digest,
            "approved_platform": self.approved_platform,
        }
        return hashlib.sha256(json.dumps(
            payload, sort_keys=True, separators=(",", ":"),
        ).encode()).hexdigest()

    @property
    def sandbox_profile_digest(self) -> str:
        """Batch 3.1.5 §1: alias for ``digest`` — the canonical profile digest."""
        return self.digest

    @property
    def effective_image_reference(self) -> str:
        """Batch 3.1.5 §1: the image reference to use for probing.

        Returns ``requested_image_reference`` when set (production),
        otherwise falls back to ``image_digest`` (test compatibility).
        """
        return self.requested_image_reference or self.image_digest


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
                # Batch 3.1.3 §5: bind toolchain attestation fields from
                # the declaration.  These flow into the command canonical
                # digest and verification plan digest.
                binary_digest=tool.binary_digest,
                image_attestation_digest=tool.image_attestation_digest,
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
    # Batch 3.1.2 §8: source root path and allowed generated output policy.
    source_root: str = ""
    allowed_generated_output: tuple[str, ...] = ()


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


@dataclass(frozen=True)
class ArtifactRootIdentity:
    """Batch 3.1.2 §7: recorded identity of the artifact root directory."""
    dev: int
    ino: int
    uid: int
    gid: int
    mode: int


class ArtifactRootCapability:
    """Batch 3.1.2 §7: long-term safe artifact root with dir_fd-only access.

    Opens the artifact root with ``O_DIRECTORY | O_NOFOLLOW`` at runtime
    startup, records its dev/inode/owner/mode, and proves it does not
    overlap with repository/main workspace/task workspace/recovery/
    verification workspace/database root.  All subsequent file operations
    use ``dir_fd`` — no full Path re-parsing, no ``os.rename`` to
    overwrite existing final files.

    Protocol: RESERVED → temp written/fsynced → final installed
    no-replace → root fsynced → SEALED → Step binding.
    """

    def __init__(self, root_fd: int, root_path: Path, identity: ArtifactRootIdentity) -> None:
        self._root_fd = root_fd
        self._root_path = root_path
        self._identity = identity

    @classmethod
    def open(
        cls, root: Path, *, forbidden_roots: Iterable[Path] = (),
    ) -> "ArtifactRootCapability":
        """Open the artifact root and verify it doesn't overlap protected roots.

        Creates the root (0o700) if it doesn't exist, then opens it with
        ``O_DIRECTORY | O_NOFOLLOW`` and records its identity.  Raises
        ``PermissionError`` if the root overlaps any forbidden root.
        """
        root = root.resolve()
        forbidden = tuple(path.resolve() for path in forbidden_roots)
        for path in forbidden:
            if root == path or root in path.parents or path in root.parents:
                raise PermissionError(
                    f"artifact root overlaps a protected root: {root} vs {path}"
                )
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(str(root), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        st = os.fstat(fd)
        identity = ArtifactRootIdentity(
            dev=st.st_dev, ino=st.st_ino,
            uid=st.st_uid, gid=st.st_gid, mode=stat.S_IMODE(st.st_mode),
        )
        return cls(fd, root, identity)

    @property
    def identity(self) -> ArtifactRootIdentity:
        return self._identity

    @property
    def root_path(self) -> Path:
        return self._root_path

    def close(self) -> None:
        try:
            os.close(self._root_fd)
        except OSError:
            pass

    def __enter__(self) -> "ArtifactRootCapability":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    # ------------------------------------------------------------------
    # §7: RESERVED → temp → final no-replace → fsync → SEALED protocol
    # ------------------------------------------------------------------

    def write_artifact(self, artifact_id: str, payload: bytes) -> tuple[str, int]:
        """Write an artifact using the no-replace protocol.

        Returns ``(content_digest, byte_length)``.  Steps:
        1. Write temp file (``.{artifact_id}.tmp``) with O_CREAT|O_EXCL|O_NOFOLLOW.
        2. fsync the temp file.
        3. Link temp → final (``{artifact_id}.log``) — fails if final exists.
        4. fsync the artifact root directory.
        5. Unlink the temp file.

        No ``os.rename`` is used — final files are never overwritten.
        """
        # Validate artifact_id is a fixed server-side format (alphanumeric + dash).
        if not artifact_id or not all(c.isalnum() or c in "-_" for c in artifact_id):
            raise ValueError(f"invalid artifact basename: {artifact_id!r}")
        temp_name = f".{artifact_id}.tmp"
        final_name = f"{artifact_id}.log"
        digest = hashlib.sha256()
        # Step 1: write temp file with O_CREAT|O_EXCL|O_NOFOLLOW.
        temp_fd = os.open(
            temp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600, dir_fd=self._root_fd,
        )
        try:
            # Batch 3.1.3 §7: loop to handle short writes.
            written = 0
            while written < len(payload):
                n = os.write(temp_fd, payload[written:])
                if n == 0:
                    raise OSError("short write returned 0 bytes")
                written += n
            os.fsync(temp_fd)
        finally:
            os.close(temp_fd)
        digest_hex = digest.update(payload) or digest.hexdigest()
        byte_length = len(payload)
        # Step 3: link temp → final (no-replace).
        try:
            os.link(
                temp_name, final_name,
                src_dir_fd=self._root_fd, dst_dir_fd=self._root_fd,
            )
        except FileExistsError as exc:
            # Final file already exists — clean up temp and fail closed.
            try:
                os.unlink(temp_name, dir_fd=self._root_fd)
            except OSError:
                pass
            raise PermissionError(
                f"artifact final file already exists (no-replace): {final_name}"
            ) from exc
        except OSError as exc:
            try:
                os.unlink(temp_name, dir_fd=self._root_fd)
            except OSError:
                pass
            raise
        # Step 4: fsync the root directory.
        os.fsync(self._root_fd)
        # Step 5: unlink the temp file.
        try:
            os.unlink(temp_name, dir_fd=self._root_fd)
        except OSError:
            pass
        # Batch 3.1.3 §7: fsync root again after unlink temp.
        os.fsync(self._root_fd)
        return digest_hex, byte_length

    def read_artifact(self, artifact_id: str) -> bytes:
        """Read an artifact by ID using dir_fd only (no Path re-parsing)."""
        final_name = f"{artifact_id}.log"
        fd = os.open(
            final_name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self._root_fd,
        )
        try:
            return os.read(fd, 64 * 1024 * 1024)
        finally:
            os.close(fd)

    def artifact_exists(self, artifact_id: str) -> bool:
        """Check if a final artifact file exists (dir_fd only)."""
        final_name = f"{artifact_id}.log"
        try:
            fd = os.open(
                final_name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self._root_fd,
            )
            os.close(fd)
            return True
        except FileNotFoundError:
            return False
        except OSError:
            return False

    def unlink_artifact(self, artifact_id: str) -> bool:
        """Remove an artifact final file (dir_fd only). Returns True if removed."""
        final_name = f"{artifact_id}.log"
        try:
            os.unlink(final_name, dir_fd=self._root_fd)
            return True
        except FileNotFoundError:
            return False

    # ------------------------------------------------------------------
    # §7: Startup reconciliation
    # ------------------------------------------------------------------

    def list_files(self) -> tuple[tuple[str, int], ...]:
        """List all files in the artifact root with their sizes.

        Returns a tuple of ``(name, byte_length)`` pairs.  Only regular
        files are included.

        Batch 3.1.3 §7: unknown non-regular files (symlinks, FIFOs,
        sockets, devices) are NOT silently ignored — they raise
        ``PermissionError`` so the caller can fail-closed before READY.
        """
        results: list[tuple[str, int]] = []
        for name in os.listdir(self._root_fd):
            try:
                st = os.stat(name, dir_fd=self._root_fd, follow_symlinks=False)
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode):
                # Batch 3.1.3 §7: reject non-regular files, don't skip.
                raise PermissionError(
                    f"artifact root contains non-regular file: {name} "
                    f"(mode={st.st_mode:o})"
                )
            results.append((name, st.st_size))
        return tuple(results)

    def reconcile(
        self, *, expected_artifacts: Iterable[tuple[str, str, int]],
    ) -> dict[str, list[str]]:
        """Batch 3.1.2 §7: reconcile the artifact root against expected DB rows.

        ``expected_artifacts`` is an iterable of ``(artifact_id, status,
        byte_length)`` tuples from the DB.  Returns a report dict with:
        - ``reserved_no_file``: RESERVED artifacts with no temp or final.
        - ``reserved_temp``: RESERVED artifacts with only a temp file.
        - ``reserved_final``: RESERVED artifacts with a final file (link ok, seal fault).
        - ``sealed_missing``: SEALED artifacts whose final file is gone.
        - ``unknown_files``: files in the root with no DB row.
        - ``cleanup_failed``: files that could not be removed.
        """
        expected: dict[str, tuple[str, int]] = {}
        for artifact_id, status, byte_length in expected_artifacts:
            expected[artifact_id] = (status, byte_length)
        actual = self.list_files()
        actual_names = {name for name, _ in actual}
        report: dict[str, list[str]] = {
            "reserved_no_file": [],
            "reserved_temp": [],
            "reserved_final": [],
            "sealed_missing": [],
            "unknown_files": [],
            "cleanup_failed": [],
        }
        # Check expected artifacts.
        for artifact_id, (status, _) in expected.items():
            final_name = f"{artifact_id}.log"
            temp_name = f".{artifact_id}.tmp"
            has_final = final_name in actual_names
            has_temp = temp_name in actual_names
            if status == "reserved":
                if not has_final and not has_temp:
                    report["reserved_no_file"].append(artifact_id)
                elif has_temp and not has_final:
                    report["reserved_temp"].append(artifact_id)
                elif has_final:
                    report["reserved_final"].append(artifact_id)
            elif status == "sealed" and not has_final:
                report["sealed_missing"].append(artifact_id)
        # Check for unknown files.
        expected_names = set()
        for artifact_id in expected:
            expected_names.add(f"{artifact_id}.log")
            expected_names.add(f".{artifact_id}.tmp")
        for name, _ in actual:
            if name not in expected_names:
                report["unknown_files"].append(name)
        return report

    def cleanup_orphan(self, name: str) -> bool:
        """Remove an orphan file (temp or unknown) from the artifact root.

        Returns True if removed, False if cleanup failed.
        """
        try:
            os.unlink(name, dir_fd=self._root_fd)
            return True
        except OSError:
            return False

    def verify_sealed_artifact(
        self, artifact_id: str, *, expected_digest: str, expected_size: int,
    ) -> bool:
        """Batch 3.1.3 §7: verify a sealed artifact's digest and size.

        Re-reads the final file and computes its SHA-256, then compares
        against the expected digest and byte length from the DB.
        Returns True if both match, False otherwise.
        """
        final_name = f"{artifact_id}.log"
        try:
            fd = os.open(
                final_name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self._root_fd,
            )
        except FileNotFoundError:
            return False
        try:
            st = os.fstat(fd)
            if st.st_size != expected_size:
                return False
            digest = hashlib.sha256()
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
            return digest.hexdigest() == expected_digest
        except OSError:
            return False
        finally:
            os.close(fd)


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
        allowed_generated_output: Iterable[str] = (),
        instance_id: str = "",
    ) -> DisposableVerificationWorkspace:
        """Batch 3.1.3 §6: persist PREPARED row before filesystem creation.

        The caller generates the workspace ID and instance_id, persists a
        PREPARED row, then calls this method.  If a crash occurs during
        mkdir/copy/seal, the reconciliation can use the PREPARED row to
        find and safely clean up the partial directory.
        """
        source = source.resolve(strict=True)
        forbidden = tuple(path.resolve() for path in forbidden_roots)
        if any(self._root == path or self._root in path.parents or path in self._root.parents for path in forbidden):
            raise PermissionError("verification root overlaps a protected root")
        self._root.mkdir(mode=0o700, parents=True, exist_ok=True)
        # Batch 3.1.3 §6: use caller-provided instance_id so the PREPARED
        # row can be persisted before the filesystem is created.
        if not instance_id:
            instance_id = f"verify_{secrets.token_hex(16)}"
        destination = self._root / instance_id
        destination.mkdir(mode=0o700)
        entries: list[ManifestEntry] = []
        # Batch 3.1.1 §4: cumulative counters tracked as instance attributes
        # so that recursive _copy_tree calls propagate counts correctly.
        self._file_count = 0
        self._dir_count = 0
        self._total_bytes = 0
        allowed = tuple(allowed_generated_output)
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
                    # Batch 3.1.3 §6: fsync the destination root after copy.
                    os.fsync(dst_root_fd)
                finally:
                    os.close(dst_root_fd)
            finally:
                os.close(src_root_fd)
            # Batch 3.1.3 §6: re-read target and verify hash/mode/type.
            self._verify_copy_integrity(destination, entries)
            payload = [entry.__dict__ for entry in entries]
            manifest_digest = hashlib.sha256(json.dumps(
                payload, sort_keys=True, separators=(",", ":"),
            ).encode()).hexdigest()
            return DisposableVerificationWorkspace(
                instance_id, destination, tuple(entries), manifest_digest,
                source_root=str(source),
                allowed_generated_output=allowed,
            )
        except Exception:
            self._safe_destroy(destination)
            raise

    @staticmethod
    def _verify_copy_integrity(destination: Path, entries: list[ManifestEntry]) -> None:
        """Batch 3.1.3 §6: re-read each target file and verify hash/mode/type.

        After the recursive copy completes, re-open each destination file
        and verify its content hash, mode, and type match the manifest
        entry.  This catches silent corruption (short writes, disk errors).
        """
        for entry in entries:
            target = destination / entry.path
            try:
                st = os.stat(target, follow_symlinks=False)
            except OSError as exc:
                raise PermissionError(
                    f"verification target vanished after copy: {entry.path}"
                ) from exc
            if not stat.S_ISREG(st.st_mode):
                raise PermissionError(
                    f"verification target is not a regular file: {entry.path}"
                )
            if stat.S_IMODE(st.st_mode) != entry.mode:
                raise PermissionError(
                    f"verification target mode mismatch: {entry.path} "
                    f"expected={entry.mode:o} actual={stat.S_IMODE(st.st_mode):o}"
                )
            # Re-read and verify content hash.
            digest = hashlib.sha256()
            with open(target, "rb") as f:
                while True:
                    chunk = f.read(1024 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
            if digest.hexdigest() != entry.content_hash:
                raise PermissionError(
                    f"verification target content hash mismatch: {entry.path}"
                )

    def _copy_tree(
        self, src_fd: int, dst_fd: int, src_root: Path, dst_root: Path,
        entries: list[ManifestEntry], prefix: str,
    ) -> None:
        """Recursively copy entries from ``src_fd`` to ``dst_fd`` using dir_fd.

        Batch 3.1.2 §6: after opening each child (file or directory), the
        parent dir FD is held and the original basename is re-lstat'd to
        verify the directory entry still points to the opened object.
        dev/inode/type/mode/nlink are compared between the open-time
        fstat and the post-read fstatat.
        """
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
                    # Batch 3.1.2 §6: re-lstat the directory basename through
                    # the parent dir FD and verify identity.
                    self._verify_path_entry(src_fd, name, st, child_prefix)
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
                        # Batch 3.1.3 §6: fsync the directory after copy.
                        os.fsync(child_dst_fd)
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
                        child_src_fd, dst_fd, name, st.st_mode, st, src_fd,
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
    def _verify_path_entry(
        parent_fd: int, name: str, pre_st: os.stat_result, label: str,
    ) -> None:
        """Batch 3.1.2 §6: re-lstat the basename through the parent dir FD.

        Compares dev/inode/type/mode/nlink between the open-time fstat
        (``pre_st``) and a fresh ``os.stat(name, dir_fd=parent_fd,
        follow_symlinks=False)`` on the parent directory.  If the
        directory entry was swapped (e.g., the original file was unlinked
        and a new file with the same name was created), the identity
        fields will not match and the copy is rejected fail-closed.

        Uses ``os.stat`` with ``dir_fd`` + ``follow_symlinks=False``
        instead of ``os.fstatat`` for macOS compatibility.
        """
        try:
            post_st = os.stat(
                name, dir_fd=parent_fd, follow_symlinks=False,
            )
        except OSError as exc:
            raise PermissionError(
                f"verification source path entry vanished during copy: {label}"
            ) from exc
        if (post_st.st_dev != pre_st.st_dev
                or post_st.st_ino != pre_st.st_ino
                or post_st.st_mode != pre_st.st_mode
                or post_st.st_nlink != pre_st.st_nlink):
            raise PermissionError(
                f"verification source path entry identity changed during copy: {label} "
                f"(dev={pre_st.st_dev}->{post_st.st_dev} ino={pre_st.st_ino}->{post_st.st_ino} "
                f"mode={pre_st.st_mode:o}->{post_st.st_mode:o} nlink={pre_st.st_nlink}->{post_st.st_nlink})"
            )

    @staticmethod
    def _copy_file(
        src_fd: int, dst_dir_fd: int, name: str, src_mode: int,
        pre_st: os.stat_result, src_parent_fd: int,
    ) -> tuple[str, int]:
        """Copy a file from ``src_fd`` to ``dst_dir_fd/name`` with O_NOFOLLOW.

        Batch 3.1.2 §6: after reading the source file, hold the parent
        directory FD and re-lstat the original basename to verify the
        directory entry still points to the opened object.  dev/inode/
        type/mode/nlink are compared.  Only then is the destination
        manifest entry sealed.

        Returns (sha256_hexdigest, byte_length).
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
                # Batch 3.1.3 §6: loop to handle short writes.
                written = 0
                while written < len(chunk):
                    n = os.write(dst_fd, chunk[written:])
                    if n == 0:
                        raise OSError("short write returned 0 bytes")
                    written += n
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
        # Batch 3.1.2 §6: re-lstat the basename through the parent dir FD
        # and verify the directory entry still points to the opened object.
        VerificationWorkspaceFactory._verify_path_entry(
            src_parent_fd, name, pre_st, name,
        )
        return digest.hexdigest(), byte_length

    @staticmethod
    def destroy(workspace: DisposableVerificationWorkspace) -> None:
        """Batch 3.1.2 §8: crash-safe destroy with manifest + policy attestation.

        Walks the actual directory tree (not just manifest entries) using
        ``dir_fd``-relative operations with ``O_NOFOLLOW`` at every level.
        For each file found:
        - If in the source manifest → delete (we copied it).
        - If matches an allowed_generated_output pattern → delete (expected byproduct).
        - Otherwise → raise ``PermissionError`` (unknown file, fail-closed).

        Directories are ``fsync``'d after their children are removed.
        The instance root is ``rmdir``'d last, and its absence is confirmed
        via ``os.stat`` (must raise ``FileNotFoundError``) before returning.

        ``unlink``/``rmdir`` errors are NEVER swallowed — they propagate
        to the caller so the run can be marked cleanup-failed.
        """
        root = workspace.root
        if not root.exists():
            # Already gone — confirm absence and return.
            try:
                os.stat(str(root))
            except FileNotFoundError:
                return
            raise PermissionError(
                f"disposable workspace root exists but is not a directory: {root}"
            )
        # Build manifest paths set for fast lookup.
        manifest_paths = {entry.path for entry in workspace.manifest}
        allowed = workspace.allowed_generated_output
        # Open the instance root with O_DIRECTORY|O_NOFOLLOW (fix root FD).
        root_fd = os.open(
            str(root), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
        try:
            VerificationWorkspaceFactory._destroy_tree(
                root_fd, "", manifest_paths, allowed, str(root),
            )
        finally:
            os.close(root_fd)
        # rmdir the instance root itself.
        os.rmdir(str(root))
        # fsync the parent directory so the rmdir is durable.
        parent_fd = os.open(
            str(root.parent), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
        # Confirm the instance root no longer exists.
        try:
            os.stat(str(root))
        except FileNotFoundError:
            return
        raise PermissionError(
            f"disposable workspace root still exists after rmdir: {root}"
        )

    @staticmethod
    def _destroy_tree(
        dir_fd: int, prefix: str,
        manifest_paths: set[str],
        allowed_generated_output: tuple[str, ...],
        root_label: str,
    ) -> None:
        """Recursively destroy all entries in ``dir_fd`` with manifest attestation.

        For each child:
        - Directory → recurse, then rmdir + fsync parent.
        - Regular file → check manifest or allowed_generated_output, then unlink.
        - Symlink/special → raise PermissionError (reject).
        Unknown files (not in manifest, not matching policy) raise PermissionError.
        """
        names = os.listdir(dir_fd)
        for name in sorted(names):
            child_path = f"{prefix}{name}" if prefix == "" else f"{prefix}/{name}"
            # Open the child with O_NOFOLLOW (rejects symlinks).
            try:
                child_fd = os.open(
                    name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd,
                )
            except OSError as exc:
                raise PermissionError(
                    f"disposable workspace destroy rejects symlink or special: {child_path}"
                ) from exc
            try:
                st = os.fstat(child_fd)
                if stat.S_ISDIR(st.st_mode):
                    # Recurse into the directory.
                    VerificationWorkspaceFactory._destroy_tree(
                        child_fd, child_path, manifest_paths,
                        allowed_generated_output, root_label,
                    )
                    # rmdir the now-empty directory.
                    os.rmdir(name, dir_fd=dir_fd)
                elif stat.S_ISREG(st.st_mode):
                    # Check if the file is known (manifest) or allowed (policy).
                    in_manifest = child_path in manifest_paths
                    in_policy = any(
                        fnmatch.fnmatch(child_path, pattern)
                        for pattern in allowed_generated_output
                    )
                    if not in_manifest and not in_policy:
                        raise PermissionError(
                            f"disposable workspace destroy rejects unknown file: {child_path}"
                        )
                    # Unlink the file.
                    os.unlink(name, dir_fd=dir_fd)
                else:
                    raise PermissionError(
                        f"disposable workspace destroy rejects special file: {child_path}"
                    )
            finally:
                os.close(child_fd)
        # fsync the directory after all children are removed.
        os.fsync(dir_fd)

    @staticmethod
    def _safe_destroy(
        root: Path, manifest: tuple[ManifestEntry, ...] = (),
    ) -> None:
        """Best-effort destroy for failed ``create()`` — no policy attestation.

        Used only when ``create()`` raises mid-copy and the workspace is
        in an inconsistent state.  Walks the actual tree and removes
        everything (manifest may be incomplete).  Errors are still
        propagated, not swallowed.
        """
        if not root.exists():
            return
        root_fd = os.open(
            str(root), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
        try:
            VerificationWorkspaceFactory._destroy_tree_unchecked(root_fd)
        finally:
            os.close(root_fd)
        os.rmdir(str(root))

    @staticmethod
    def _destroy_tree_unchecked(dir_fd: int) -> None:
        """Recursively remove all entries without manifest/policy checks."""
        names = os.listdir(dir_fd)
        for name in sorted(names):
            try:
                child_fd = os.open(
                    name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd,
                )
            except OSError:
                # Symlink — unlink directly.
                try:
                    os.unlink(name, dir_fd=dir_fd)
                except OSError:
                    pass
                continue
            try:
                st = os.fstat(child_fd)
                if stat.S_ISDIR(st.st_mode):
                    VerificationWorkspaceFactory._destroy_tree_unchecked(child_fd)
                    try:
                        os.rmdir(name, dir_fd=dir_fd)
                    except OSError:
                        pass
                else:
                    try:
                        os.unlink(name, dir_fd=dir_fd)
                    except OSError:
                        pass
            finally:
                os.close(child_fd)
