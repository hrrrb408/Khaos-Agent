"""Fail-closed Git runner for host-side workspace control-plane effects.

Repository-local Git configuration is untrusted input.  This runner pins the
Git executable, scrubs ambient configuration, disables extension points that
can spawn programs, and refuses the checkout path entirely.  Worktree
creation therefore uses ``--no-checkout``; tracked content is materialized
from raw tree/blob objects with a no-follow, traversal-checked extractor.
"""

# KHAOS-PRIVILEGED-SPAWN owner=TrustedGitRunner threat-model=untrusted-repository-config boundary=workspace-control-plane

from __future__ import annotations

import asyncio
import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from khaos.coding.execution.environment import scrub_spawn_environment
from khaos.security.authority import AuthorityEnvelope

FileIdentity = tuple[int, int, int, int]
_PROTECTED_GIT_NAME = ".git"


class TrustedGitError(RuntimeError):
    """Raised when a host-side Git authority or invocation is not trusted."""


def _identity(info: os.stat_result) -> FileIdentity:
    return (int(info.st_dev), int(info.st_ino), int(info.st_uid), int(info.st_mode))


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise TrustedGitError(f"Git executable is unavailable: {path}") from exc
    try:
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def resolve_trusted_git() -> tuple[Path, FileIdentity, str]:
    """Resolve and fingerprint the platform Git without consulting ``PATH``."""
    system_git = (
        Path("C:/Program Files/Git/cmd/git.exe")
        if os.name == "nt"
        else Path("/usr/bin/git")
    )
    try:
        executable = system_git.resolve(strict=True)
        info = executable.stat()
    except OSError as exc:
        raise TrustedGitError("trusted system Git executable is unavailable") from exc
    if (
        not executable.is_absolute()
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or info.st_mode & 0o022
    ):
        raise TrustedGitError(
            "Git executable must be absolute, root-owned, regular, and immutable"
        )
    for parent in executable.parents:
        try:
            parent_info = parent.stat()
        except OSError as exc:
            raise TrustedGitError("Git executable parent chain is unavailable") from exc
        if parent_info.st_uid != 0 or parent_info.st_mode & 0o022:
            raise TrustedGitError("Git executable parent chain is not trusted")
    return executable, _identity(info), _file_digest(executable)


def _verify_identity(
    path: Path,
    expected: FileIdentity,
    *,
    require_root_owner: bool,
    label: str,
    expected_digest: str | None = None,
) -> None:
    """Open an authority object with no-follow and compare its live identity."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            current = os.fstat(descriptor)
            if expected_digest is not None:
                digest = hashlib.sha256()
                while chunk := os.read(descriptor, 1024 * 1024):
                    digest.update(chunk)
                if digest.hexdigest() != expected_digest:
                    raise TrustedGitError(f"{label} content digest drifted")
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise TrustedGitError(f"{label} is unavailable") from exc
    if _identity(current) != expected:
        raise TrustedGitError(f"{label} identity drifted")
    required_uid = 0 if require_root_owner else os.getuid()
    if current.st_uid != required_uid or current.st_mode & 0o022:
        raise TrustedGitError(f"{label} trust policy failed")


@dataclass(frozen=True)
class TrustedGitRunner:
    """Run a bounded set of Git operations under one authority envelope."""

    executable: Path
    git_identity: FileIdentity
    git_digest: str
    authority_root: Path
    authority_root_identity: FileIdentity

    @classmethod
    def for_authority_root(cls, root: Path, root_identity: FileIdentity) -> "TrustedGitRunner":
        executable, identity, digest = resolve_trusted_git()
        return cls(executable, identity, digest, root, root_identity)

    def _verify(self) -> None:
        _verify_identity(
            self.executable,
            self.git_identity,
            require_root_owner=True,
            label="Git executable",
            expected_digest=self.git_digest,
        )
        _verify_identity(
            self.authority_root,
            self.authority_root_identity,
            require_root_owner=False,
            label="workspace authority root",
        )

    @staticmethod
    def _validate_args(args: tuple[str, ...]) -> tuple[str, ...]:
        """Reject caller-supplied config/cwd switches and disable checkout."""
        if any(
            arg in {"-c", "--config-env"}
            or arg.startswith("--config=")
            or arg.startswith("--config-env=")
            for arg in args
        ):
            raise TrustedGitError("TrustedGitRunner rejects caller Git configuration switches")
        values = list(args)
        if values[:2] == ["worktree", "add"] and "--no-checkout" not in values:
            values.insert(2, "--no-checkout")
        return tuple(values)

    def _environment(self) -> dict[str, str]:
        # These values are pinned and preserved explicitly.  The runner does
        # not inherit PATH, credentials, proxy variables, Git aliases, or
        # caller-provided GIT_CONFIG_* injection variables.
        return scrub_spawn_environment(
            {
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_SYSTEM": os.devnull,
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_ASKPASS": os.devnull,
                "SSH_ASKPASS": os.devnull,
                "GIT_PAGER": "cat",
                "PAGER": "cat",
                "GIT_EDITOR": ":",
                "GIT_SEQUENCE_EDITOR": ":",
                "GIT_OPTIONAL_LOCKS": "0",
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "HOME": str(self.authority_root),
            },
            preserve={
                "GIT_CONFIG_GLOBAL",
                "GIT_CONFIG_SYSTEM",
                "GIT_TERMINAL_PROMPT",
                "GIT_ASKPASS",
                "SSH_ASKPASS",
            },
        )

    def _argv(self, args: tuple[str, ...]) -> tuple[str, ...]:
        # Command-line configuration has higher precedence than repository
        # local config.  The checkout itself is separately forbidden by
        # --no-checkout; this closes hooks, fsmonitor and untracked-cache
        # process-extension surfaces for status/worktree/admin operations.
        safe_config = (
            "-c",
            f"core.hooksPath={os.devnull}",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.untrackedCache=false",
        )
        return ("--no-optional-locks", *safe_config, *self._validate_args(args))

    @staticmethod
    def _authority_or_fail(authority: AuthorityEnvelope | None) -> AuthorityEnvelope:
        if not isinstance(authority, AuthorityEnvelope):
            raise TrustedGitError("TrustedGitRunner requires an immutable authority envelope")
        if not authority.operation_class.startswith("git."):
            raise TrustedGitError("Git operation authority class is invalid")
        return authority

    async def run(
        self,
        repository: Path,
        *args: str,
        authority: AuthorityEnvelope,
        preserve_output: bool = False,
    ) -> str:
        """Run one text-producing Git command with fail-closed authority."""
        if args and args[0] == "status":
            dirty = await self.is_dirty(repository, authority=authority)
            return "dirty" if dirty else ""
        self._verify()
        self._authority_or_fail(authority)
        try:
            process = await asyncio.create_subprocess_exec(
                str(self.executable),
                *self._argv(tuple(args)),
                cwd=str(repository),
                env=self._environment(),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()
        except OSError as exc:
            raise TrustedGitError("trusted Git process could not start") from exc
        if process.returncode != 0:
            message = stderr.decode("utf-8", errors="replace").strip()
            raise TrustedGitError(message or "trusted Git command failed")
        output = stdout.decode("utf-8", errors="replace")
        return output if preserve_output else output.strip()

    async def run_bytes(
        self,
        repository: Path,
        *args: str,
        authority: AuthorityEnvelope,
    ) -> bytes:
        """Run one binary-producing Git command with the same authority gate."""
        self._verify()
        self._authority_or_fail(authority)
        try:
            process = await asyncio.create_subprocess_exec(
                str(self.executable),
                *self._argv(tuple(args)),
                cwd=str(repository),
                env=self._environment(),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()
        except OSError as exc:
            raise TrustedGitError("trusted Git process could not start") from exc
        if process.returncode != 0:
            message = stderr.decode("utf-8", errors="replace").strip()
            raise TrustedGitError(message or "trusted Git command failed")
        return stdout

    async def materialize_tree(
        self,
        repository: Path,
        treeish: str,
        worktree: Path,
        *,
        authority: AuthorityEnvelope,
    ) -> None:
        """Materialize a commit's blobs without checkout filters or archives.

        ``git archive`` consults tracked ``.gitattributes`` and can therefore
        activate a repository-local filter process.  The trusted path only
        asks Git for tree metadata and raw blob bytes, then validates every
        pathname and symlink before creating the worktree entry itself.
        """
        listing = await self.run_bytes(
            repository,
            "ls-tree",
            "-r",
            "-z",
            "--full-tree",
            treeish,
            authority=authority.derive(operation_class="git.tree"),
        )
        entries = _parse_tree_listing(listing)
        await self._materialize_blobs(
            repository,
            entries,
            worktree,
            authority=authority.derive(operation_class="git.blob"),
        )

    async def _materialize_blobs(
        self,
        repository: Path,
        entries: list[tuple[str, str, str]],
        worktree: Path,
        *,
        authority: AuthorityEnvelope,
    ) -> None:
        self._verify()
        self._authority_or_fail(authority)
        process: asyncio.subprocess.Process | None = None
        try:
            process = await asyncio.create_subprocess_exec(
                str(self.executable),
                *self._argv(("cat-file", "--batch")),
                cwd=str(repository),
                env=self._environment(),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            if process.stdin is None or process.stdout is None:
                raise TrustedGitError("trusted Git blob process has no usable pipes")
            for _, object_id, _ in entries:
                process.stdin.write(f"{object_id}\n".encode("ascii"))
            await process.stdin.drain()
            process.stdin.close()

            seen: set[str] = set()
            for mode, object_id, path in entries:
                if path in seen:
                    raise TrustedGitError(f"Git tree contains duplicate path: {path}")
                seen.add(path)
                header = await process.stdout.readline()
                fields = header.rstrip(b"\n").split()
                if len(fields) != 3 or fields[0].decode("ascii", errors="replace") != object_id:
                    raise TrustedGitError("Git blob response did not match requested object")
                if fields[1] != b"blob":
                    raise TrustedGitError(f"Git tree entry is not a blob: {path}")
                try:
                    size = int(fields[2])
                except ValueError as exc:
                    raise TrustedGitError("Git blob response has an invalid size") from exc
                parts = _safe_member_parts(path)
                parent = _ensure_directory(worktree, parts[:-1])
                target = parent / parts[-1]
                if target.exists() or target.is_symlink():
                    raise TrustedGitError(
                        f"Git tree would overwrite an existing worktree entry: {path}"
                    )
                if mode == "120000":
                    if size > 4096:
                        raise TrustedGitError("Git symlink target is unreasonably large")
                    link_target = await process.stdout.readexactly(size)
                    await _read_blob_separator(process.stdout)
                    os.symlink(_safe_symlink_target(parts, link_target), target)
                    continue
                if mode not in {"100644", "100755"}:
                    raise TrustedGitError(f"Git tree entry has an unsupported mode: {path}")
                descriptor = os.open(
                    target,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_NOFOLLOW", 0),
                    0o755 if mode == "100755" else 0o644,
                )
                try:
                    remaining = size
                    with os.fdopen(descriptor, "wb") as output:
                        while remaining:
                            chunk = await process.stdout.read(min(1024 * 1024, remaining))
                            if not chunk:
                                raise TrustedGitError("Git blob ended before its declared size")
                            output.write(chunk)
                            remaining -= len(chunk)
                except Exception:
                    target.unlink(missing_ok=True)
                    raise
                await _read_blob_separator(process.stdout)
            stderr = await process.stderr.read() if process.stderr is not None else b""
            await process.wait()
            if process.returncode != 0:
                message = stderr.decode("utf-8", errors="replace").strip()
                raise TrustedGitError(message or "trusted Git blob process failed")
        except TrustedGitError:
            if process is not None and process.returncode is None:
                process.kill()
                await process.wait()
            raise
        except (OSError, asyncio.IncompleteReadError) as exc:
            if process is not None and process.returncode is None:
                process.kill()
                await process.wait()
            raise TrustedGitError("trusted Git blob materialization failed") from exc

    async def is_dirty(
        self,
        repository: Path,
        *,
        authority: AuthorityEnvelope,
    ) -> bool:
        """Detect changes without invoking status/filter extensions."""
        staged = await self.run(
            repository,
            "diff-index",
            "--cached",
            "--no-ext-diff",
            "--name-only",
            "HEAD",
            authority=authority.derive(operation_class="git.status"),
        )
        if staged:
            return True
        untracked = await self.run(
            repository,
            "ls-files",
            "--others",
            "--exclude-standard",
            authority=authority.derive(operation_class="git.status"),
        )
        if untracked:
            return True
        listing = await self.run_bytes(
            repository,
            "ls-files",
            "--stage",
            "-z",
            authority=authority.derive(operation_class="git.status"),
        )
        return not _working_tree_matches_index(listing, repository)

    def run_sync(
        self,
        repository: Path,
        *args: str,
        authority: AuthorityEnvelope,
    ) -> str:
        """Synchronous variant used only by startup/recovery discovery."""
        if args and args[0] == "status":
            return "dirty" if self.is_dirty_sync(repository, authority=authority) else ""
        self._verify()
        self._authority_or_fail(authority)
        try:
            import subprocess

            completed = subprocess.run(
                [str(self.executable), *self._argv(tuple(args))],
                cwd=repository,
                env=self._environment(),
                capture_output=True,
                text=True,
                check=False,
            )
        except OSError as exc:
            raise TrustedGitError("trusted Git process could not start") from exc
        if completed.returncode != 0:
            message = completed.stderr.strip()
            raise TrustedGitError(message or "trusted Git command failed")
        return completed.stdout.strip()

    def is_dirty_sync(
        self,
        repository: Path,
        *,
        authority: AuthorityEnvelope,
    ) -> bool:
        """Synchronous filter-free dirty-state check for recovery."""
        staged = self.run_sync(
            repository,
            "diff-index",
            "--cached",
            "--no-ext-diff",
            "--name-only",
            "HEAD",
            authority=authority.derive(operation_class="git.status"),
        )
        if staged:
            return True
        untracked = self.run_sync(
            repository,
            "ls-files",
            "--others",
            "--exclude-standard",
            authority=authority.derive(operation_class="git.status"),
        )
        if untracked:
            return True
        listing = self.run_sync_bytes(
            repository,
            "ls-files",
            "--stage",
            "-z",
            authority=authority.derive(operation_class="git.status"),
        )
        return not _working_tree_matches_index(listing, repository)

    def run_sync_bytes(
        self,
        repository: Path,
        *args: str,
        authority: AuthorityEnvelope,
    ) -> bytes:
        """Synchronous binary variant used by recovery dirty checks."""
        self._verify()
        self._authority_or_fail(authority)
        try:
            import subprocess

            completed = subprocess.run(
                [str(self.executable), *self._argv(tuple(args))],
                cwd=repository,
                env=self._environment(),
                capture_output=True,
                check=False,
            )
        except OSError as exc:
            raise TrustedGitError("trusted Git process could not start") from exc
        if completed.returncode != 0:
            message = completed.stderr.decode("utf-8", errors="replace").strip()
            raise TrustedGitError(message or "trusted Git command failed")
        return completed.stdout


def _safe_member_parts(name: str) -> tuple[str, ...]:
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise TrustedGitError(f"Git archive contains an unsafe path: {name!r}")
    if _PROTECTED_GIT_NAME in {part.casefold() for part in path.parts}:
        raise TrustedGitError("Git archive attempted to materialize .git metadata")
    return tuple(path.parts)


def _ensure_directory(root: Path, parts: tuple[str, ...]) -> Path:
    current = root
    for part in parts:
        current /= part
        try:
            info = current.lstat()
        except FileNotFoundError:
            current.mkdir(mode=0o700)
            info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise TrustedGitError("Git archive parent traverses a non-directory")
    return current


def _parse_tree_listing(listing: bytes) -> list[tuple[str, str, str]]:
    """Parse NUL-delimited ``ls-tree`` records without pathname quoting."""
    entries: list[tuple[str, str, str]] = []
    for record in listing.split(b"\0"):
        if not record:
            continue
        metadata, separator, raw_path = record.partition(b"\t")
        fields = metadata.split()
        if not separator or len(fields) != 3:
            raise TrustedGitError("Git tree listing has an invalid record")
        try:
            mode = fields[0].decode("ascii")
            object_type = fields[1].decode("ascii")
            object_id = fields[2].decode("ascii")
            path = os.fsdecode(raw_path)
        except UnicodeDecodeError as exc:
            raise TrustedGitError("Git tree listing is not valid text metadata") from exc
        if object_type != "blob" or len(object_id) != 40:
            raise TrustedGitError("Git tree contains an unsupported object")
        if any(character not in "0123456789abcdef" for character in object_id):
            raise TrustedGitError("Git tree contains an invalid object id")
        if mode not in {"100644", "100755", "120000"}:
            raise TrustedGitError(f"Git tree contains an unsupported mode: {path}")
        entries.append((mode, object_id, path))
    return entries


def _parse_index_listing(listing: bytes) -> list[tuple[str, str, str]]:
    """Parse NUL-delimited ``ls-files --stage`` records."""
    entries: list[tuple[str, str, str]] = []
    for record in listing.split(b"\0"):
        if not record:
            continue
        metadata, separator, raw_path = record.partition(b"\t")
        fields = metadata.split()
        if not separator or len(fields) != 3:
            raise TrustedGitError("Git index listing has an invalid record")
        try:
            mode = fields[0].decode("ascii")
            object_id = fields[1].decode("ascii")
            stage = fields[2].decode("ascii")
            path = os.fsdecode(raw_path)
        except UnicodeDecodeError as exc:
            raise TrustedGitError("Git index listing is not valid metadata") from exc
        if stage != "0" or len(object_id) not in {40, 64}:
            raise TrustedGitError("Git index contains a conflicted or invalid entry")
        if any(character not in "0123456789abcdef" for character in object_id):
            raise TrustedGitError("Git index contains an invalid object id")
        if mode not in {"100644", "100755", "120000"}:
            raise TrustedGitError(f"Git index contains an unsupported mode: {path}")
        entries.append((mode, object_id, path))
    return entries


def _blob_hasher(object_id: str, size: int) -> "hashlib._Hash":
    algorithm = "sha256" if len(object_id) == 64 else "sha1"
    digest = hashlib.new(algorithm)
    digest.update(f"blob {size}\0".encode("ascii"))
    return digest


def _working_tree_matches_index(listing: bytes, repository: Path) -> bool:
    """Compare raw worktree bytes to the index without clean/smudge filters."""
    for mode, object_id, path in _parse_index_listing(listing):
        parts = _safe_member_parts(path)
        target = repository.joinpath(*parts)
        try:
            info = target.lstat()
        except FileNotFoundError:
            return False
        if mode == "120000":
            if not stat.S_ISLNK(info.st_mode):
                return False
            content = os.fsencode(os.readlink(target))
            digest = _blob_hasher(object_id, len(content))
            digest.update(content)
        else:
            if not stat.S_ISREG(info.st_mode):
                return False
            executable = bool(info.st_mode & 0o111)
            if executable != (mode == "100755"):
                return False
            digest = _blob_hasher(object_id, int(info.st_size))
            descriptor = os.open(
                target,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            )
            try:
                while chunk := os.read(descriptor, 1024 * 1024):
                    digest.update(chunk)
            finally:
                os.close(descriptor)
        if digest.hexdigest() != object_id:
            return False
    return True


async def _read_blob_separator(stdout: asyncio.StreamReader) -> None:
    separator = await stdout.readexactly(1)
    if separator != b"\n":
        raise TrustedGitError("Git blob response is missing its separator")


def _safe_symlink_target(parts: tuple[str, ...], raw_target: bytes) -> str:
    """Reject symlinks that escape the disposable worktree or target metadata."""
    if b"\0" in raw_target:
        raise TrustedGitError("Git symlink target contains NUL")
    target = os.fsdecode(raw_target)
    path = PurePosixPath(target)
    if path.is_absolute():
        raise TrustedGitError("Git symlink target is absolute")
    resolved = list(parts[:-1])
    for part in path.parts:
        if part in {"", "."}:
            continue
        if part == "..":
            if not resolved:
                raise TrustedGitError("Git symlink target escapes the worktree")
            resolved.pop()
            continue
        resolved.append(part)
    if _PROTECTED_GIT_NAME in {part.casefold() for part in resolved}:
        raise TrustedGitError("Git symlink target reaches protected metadata")
    return target


__all__ = [
    "FileIdentity",
    "TrustedGitError",
    "TrustedGitRunner",
    "resolve_trusted_git",
]
