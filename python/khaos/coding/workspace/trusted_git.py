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
import signal
import stat
import subprocess
from dataclasses import dataclass
from enum import Enum
from pathlib import Path, PurePosixPath

from khaos.coding.execution.environment import scrub_spawn_environment
from khaos.security.authority_broker import (
    AuthorityBroker,
    AuthorityBrokerError,
    EffectCapability,
)

FileIdentity = tuple[int, int, int, int]
_PROTECTED_GIT_NAME = ".git"
_MAX_GIT_ERROR_BYTES = 64 * 1024
_MAX_GIT_CHUNK_BYTES = 1024 * 1024
_ALLOWED_COMMANDS = frozenset(
    {
        "apply",
        "cat-file",
        "commit-tree",
        "diff",
        "diff-files",
        "diff-index",
        "diff-tree",
        "hash-object",
        "ls-files",
        "ls-tree",
        "read-tree",
        "rev-parse",
        "update-index",
        "update-ref",
        "worktree",
        "write-tree",
    }
)
_ALLOWED_WORKTREE_COMMANDS = frozenset({"add", "move", "remove"})
_DIFF_COMMANDS = frozenset({"diff", "diff-files", "diff-index", "diff-tree"})


@dataclass(frozen=True)
class WorkspaceBootstrapLimits:
    """Independent resource limits for untrusted Git tree materialization.

    These limits are deliberately separate from the post-bootstrap workspace
    growth budget.  A tracked repository must not become the storage baseline
    merely because it was materialized before the baseline was captured.
    """

    max_materialized_bytes: int = 512 * 1024 * 1024
    max_single_blob_bytes: int = 128 * 1024 * 1024
    max_tree_entries: int = 100_000
    max_path_depth: int = 64
    max_symlinks: int = 1_024
    max_tree_listing_bytes: int = 64 * 1024 * 1024
    max_duration_seconds: float = 120.0

    def __post_init__(self) -> None:
        if (
            self.max_materialized_bytes <= 0
            or self.max_single_blob_bytes <= 0
            or self.max_tree_entries <= 0
            or self.max_path_depth <= 0
            or self.max_symlinks < 0
            or self.max_tree_listing_bytes <= 0
            or self.max_duration_seconds <= 0
        ):
            raise ValueError("workspace bootstrap limits must be positive")
        if self.max_single_blob_bytes > self.max_materialized_bytes:
            raise ValueError("single blob limit cannot exceed materialized byte limit")


@dataclass(frozen=True)
class GitStreamResult:
    """Bounded digest/preview metadata for a streamed Git stdout."""

    byte_length: int
    sha256: str
    preview: str


class TrustedGitError(RuntimeError):
    """Raised when a host-side Git authority or invocation is not trusted."""


class TrustedGitProcessState(str, Enum):
    """Terminal ownership state for one host-side Git process."""

    NEW = "new"
    SPAWNED = "spawned"
    RUNNING = "running"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"
    QUARANTINED = "quarantined"


class TrustedGitProcessOwner:
    """Own a Git subprocess from spawn through a proved terminal state.

    ``asyncio.create_subprocess_exec`` is launched in a task and shielded so a
    caller cancellation cannot abandon the process between kernel spawn and
    assignment to the owner.  Once a process exists, cancellation and error
    cleanup are themselves shielded and operate on the whole POSIX process
    group.  If exit cannot be proved, the owner remains quarantined and the
    caller receives a hard failure instead of a false success.
    """

    def __init__(
        self,
        label: str,
        *,
        terminate_grace_seconds: float = 0.75,
        spawn_adoption_seconds: float = 5.0,
    ) -> None:
        if not label or terminate_grace_seconds <= 0 or spawn_adoption_seconds <= 0:
            raise ValueError("invalid TrustedGitProcessOwner limits")
        self.label = label
        self.terminate_grace_seconds = terminate_grace_seconds
        self.spawn_adoption_seconds = spawn_adoption_seconds
        self.state = TrustedGitProcessState.NEW
        self.process: asyncio.subprocess.Process | None = None
        self.quarantine_reason: str | None = None

    @property
    def terminal(self) -> bool:
        return self.state in {
            TrustedGitProcessState.COMPLETED,
            TrustedGitProcessState.CANCELLED,
            TrustedGitProcessState.FAILED,
            TrustedGitProcessState.QUARANTINED,
        }

    @staticmethod
    def _spawn_options() -> dict[str, object]:
        if os.name == "nt":
            return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
        return {"start_new_session": True}

    async def spawn(self, *argv: str, **kwargs: object) -> asyncio.subprocess.Process:
        """Spawn and publish the child, adopting it if the caller is cancelled."""
        if self.state is not TrustedGitProcessState.NEW:
            raise TrustedGitError(f"Git process owner {self.label} was reused")
        spawn_task = asyncio.create_task(
            asyncio.create_subprocess_exec(*argv, **self._spawn_options(), **kwargs)
        )
        try:
            process = await asyncio.shield(spawn_task)
        except asyncio.CancelledError:
            try:
                process = await asyncio.shield(
                    asyncio.wait_for(
                        asyncio.shield(spawn_task), self.spawn_adoption_seconds
                    )
                )
            except TimeoutError as exc:
                self.state = TrustedGitProcessState.QUARANTINED
                self.quarantine_reason = "spawn could not be adopted after cancellation"
                # ``wait_for(spawn_task)`` would cancel the spawn coroutine,
                # but cancellation of subprocess creation does not prove
                # that a kernel child was not created. Keep the original task
                # alive and attach an owner-side reaper that adopts and
                # terminates a child if it appears later.
                asyncio.create_task(
                    self._adopt_late_spawn(spawn_task),
                    name=f"khaos-git-reaper:{self.label}",
                )
                raise TrustedGitError(
                    f"Git process {self.label} could not be adopted after cancellation"
                ) from exc
            self.process = process
            self.state = TrustedGitProcessState.SPAWNED
            await asyncio.shield(self.abort(cancelled=True))
            raise
        except Exception:
            if not spawn_task.done():
                spawn_task.cancel()
                try:
                    await spawn_task
                except asyncio.CancelledError:
                    pass
            self.state = TrustedGitProcessState.FAILED
            raise
        self.process = process
        self.state = TrustedGitProcessState.RUNNING
        return process

    async def _adopt_late_spawn(
        self, spawn_task: asyncio.Task[asyncio.subprocess.Process]
    ) -> None:
        """Reap a spawn that outlived the caller's bounded adoption window."""
        try:
            process = await spawn_task
        except BaseException:  # noqa: BLE001 - reaper must consume late spawn failures
            # A failed/cancelled spawn proves that no process was published.
            return
        self.process = process
        self.state = TrustedGitProcessState.SPAWNED
        try:
            await self.abort(cancelled=True)
        except TrustedGitError as exc:
            self.state = TrustedGitProcessState.QUARANTINED
            self.quarantine_reason = str(exc) or "late Git process cleanup failed"

    async def communicate_after_spawn(
        self,
        *argv: str,
        input_bytes: bytes | None = None,
        **kwargs: object,
    ) -> tuple[bytes, bytes]:
        """Spawn one command and communicate under the same owner."""
        await self.spawn(*argv, **kwargs)
        return await self.communicate(input_bytes)

    async def communicate(
        self, input_bytes: bytes | None = None
    ) -> tuple[bytes, bytes]:
        """Communicate with cancellation-safe ownership transfer."""
        process = self._require_process()
        try:
            stdout, stderr = await process.communicate(input=input_bytes)
        except asyncio.CancelledError:
            await asyncio.shield(self.abort(cancelled=True))
            raise
        except Exception:
            await asyncio.shield(self.abort(cancelled=False))
            raise
        self.state = (
            TrustedGitProcessState.COMPLETED
            if process.returncode == 0
            else TrustedGitProcessState.FAILED
        )
        return stdout, stderr

    async def wait(self) -> int:
        """Wait for a process that has already had its pipes drained."""
        process = self._require_process()
        try:
            returncode = await process.wait()
        except asyncio.CancelledError:
            await asyncio.shield(self.abort(cancelled=True))
            raise
        except Exception:
            await asyncio.shield(self.abort(cancelled=False))
            raise
        self.state = (
            TrustedGitProcessState.COMPLETED
            if returncode == 0
            else TrustedGitProcessState.FAILED
        )
        return returncode

    async def abort(self, *, cancelled: bool) -> None:
        """Terminate the child and prove that it is no longer running."""
        process = self.process
        target_state = (
            TrustedGitProcessState.CANCELLED
            if cancelled
            else TrustedGitProcessState.FAILED
        )
        if process is None:
            self.state = target_state
            return
        try:
            if process.returncode is None:
                self._signal(process, force=False)
                try:
                    await asyncio.wait_for(
                        process.wait(), self.terminate_grace_seconds
                    )
                except TimeoutError:
                    self._signal(process, force=True)
                    await asyncio.wait_for(
                        process.wait(), self.terminate_grace_seconds
                    )
            if process.returncode is None:
                raise TrustedGitError("Git process exit could not be proved")
        except Exception as exc:
            self.state = TrustedGitProcessState.QUARANTINED
            self.quarantine_reason = str(exc) or "Git process cleanup failed"
            raise TrustedGitError(
                f"Git process {self.label} is quarantined: {self.quarantine_reason}"
            ) from exc
        self.state = target_state

    def _require_process(self) -> asyncio.subprocess.Process:
        if self.process is None:
            raise TrustedGitError(f"Git process {self.label} was not spawned")
        return self.process

    @staticmethod
    def _signal(process: asyncio.subprocess.Process, *, force: bool) -> None:
        if process.returncode is not None:
            return
        if os.name == "nt":
            process.kill() if force else process.terminate()
            return
        signum = signal.SIGKILL if force else signal.SIGTERM
        try:
            os.killpg(process.pid, signum)
        except ProcessLookupError:
            return
        except OSError:
            if force:
                process.kill()
            else:
                process.terminate()


def _identity(info: os.stat_result) -> FileIdentity:
    return (int(info.st_dev), int(info.st_ino), int(info.st_uid), int(info.st_mode))


def _verify_same_file_snapshot(
    current: os.stat_result, expected: os.stat_result
) -> None:
    """Reject descriptor content drift that a pathname check cannot see."""
    if (
        current.st_dev,
        current.st_ino,
        current.st_mode,
        current.st_nlink,
        current.st_size,
        current.st_mtime_ns,
        current.st_ctime_ns,
    ) != (
        expected.st_dev,
        expected.st_ino,
        expected.st_mode,
        expected.st_nlink,
        expected.st_size,
        expected.st_mtime_ns,
        expected.st_ctime_ns,
    ):
        raise TrustedGitError("Git hash input changed while being consumed")


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
    """Run bounded Git operations under a broker-issued capability."""

    executable: Path
    git_identity: FileIdentity
    git_digest: str
    authority_root: Path
    authority_root_identity: FileIdentity
    authority_broker: AuthorityBroker | None = None

    @classmethod
    def for_authority_root(
        cls,
        root: Path,
        root_identity: FileIdentity,
        *,
        authority_broker: AuthorityBroker | None = None,
    ) -> TrustedGitRunner:
        executable, identity, digest = resolve_trusted_git()
        return cls(
            executable,
            identity,
            digest,
            root,
            root_identity,
            authority_broker or AuthorityBroker.default(),
        )

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
        """Allow only audited plumbing operations and safe diff modes."""
        if any(
            arg in {"-c", "--config-env"}
            or arg.startswith(("--config=", "--config-env="))
            for arg in args
        ):
            raise TrustedGitError("TrustedGitRunner rejects caller Git configuration switches")
        values = list(args)
        for arg in values:
            if (
                arg in {"--ext-diff", "--textconv", "--paginate", "--exec-path"}
                or arg.startswith(
                    (
                        "--upload-pack",
                        "--receive-pack",
                        "--ssh-command",
                        "--exec-path=",
                        "--output=",
                    )
                )
            ):
                raise TrustedGitError("TrustedGitRunner rejects Git extension or output switches")
        command_index = next(
            (
                index
                for index, arg in enumerate(values)
                if not arg.startswith("-")
                and not arg.startswith("--git-dir=")
                and not arg.startswith("--work-tree=")
            ),
            None,
        )
        if command_index is None or values[command_index] not in _ALLOWED_COMMANDS:
            raise TrustedGitError("TrustedGitRunner operation is outside the audited allowlist")
        command = values[command_index]
        if command == "worktree" and (
            len(values) <= command_index + 1
            or values[command_index + 1] not in _ALLOWED_WORKTREE_COMMANDS
        ):
            raise TrustedGitError("TrustedGitRunner worktree operation is not allowed")
        if command == "worktree" and "--checkout" in values:
            raise TrustedGitError("TrustedGitRunner refuses checkout-enabled worktrees")
        if command == "read-tree" and ("-u" in values or "--update-worktree" in values):
            raise TrustedGitError("TrustedGitRunner refuses checkout-enabled read-tree")
        if command == "hash-object" and "--no-filters" not in values:
            raise TrustedGitError("TrustedGitRunner hash-object requires --no-filters")
        if values[:2] == ["worktree", "add"] and "--no-checkout" not in values:
            values.insert(2, "--no-checkout")
        if command in _DIFF_COMMANDS:
            insertion = command_index + 1
            for flag in ("--no-ext-diff", "--no-textconv"):
                if flag not in values:
                    values.insert(insertion, flag)
                    insertion += 1
        return tuple(values)

    def _environment(self, *, index_file: Path | None = None) -> dict[str, str]:
        # These values are pinned and preserved explicitly.  The runner does
        # not inherit PATH, credentials, proxy variables, Git aliases, or
        # caller-provided GIT_CONFIG_* injection variables.
        environment = {
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
            }
        if index_file is not None:
            environment["GIT_INDEX_FILE"] = str(index_file)
        return scrub_spawn_environment(
            environment,
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
            "-c",
            "commit.gpgSign=false",
        )
        return ("--no-optional-locks", *safe_config, *self._validate_args(args))

    def _authority_or_fail(
        self, authority: EffectCapability | None
    ) -> EffectCapability:
        if not isinstance(authority, EffectCapability):
            raise TrustedGitError(
                "TrustedGitRunner requires a broker-issued effect capability"
            )
        if not authority.authority.operation_class.startswith("git."):
            raise TrustedGitError("Git operation authority class is invalid")
        broker = self.authority_broker
        if broker is None:
            raise TrustedGitError("TrustedGitRunner has no authority broker")
        try:
            broker.validate(
                authority,
                expected_operation=authority.authority.operation_class,
                expected_resource_digest=authority.resource_digest,
            )
        except AuthorityBrokerError as exc:
            raise TrustedGitError(f"Git effect capability rejected: {exc}") from exc
        return authority

    async def run(
        self,
        repository: Path,
        *args: str,
        authority: EffectCapability,
        preserve_output: bool = False,
        index_file: Path | None = None,
    ) -> str:
        """Run one text-producing Git command with fail-closed authority."""
        if args and args[0] == "status":
            dirty = await self.is_dirty(repository, authority=authority)
            return "dirty" if dirty else ""
        self._verify()
        self._authority_or_fail(authority)
        owner = TrustedGitProcessOwner("git.run")
        try:
            stdout, stderr = await owner.communicate_after_spawn(
                str(self.executable),
                *self._argv(tuple(args)),
                cwd=str(repository),
                env=self._environment(index_file=index_file),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except OSError as exc:
            raise TrustedGitError("trusted Git process could not start") from exc
        if owner.process is None or owner.process.returncode != 0:
            message = stderr.decode("utf-8", errors="replace").strip()
            raise TrustedGitError(message or "trusted Git command failed")
        output = stdout.decode("utf-8", errors="replace")
        return output if preserve_output else output.strip()

    async def run_bytes(
        self,
        repository: Path,
        *args: str,
        authority: EffectCapability,
        index_file: Path | None = None,
    ) -> bytes:
        """Run one binary-producing Git command with the same authority gate."""
        self._verify()
        self._authority_or_fail(authority)
        owner = TrustedGitProcessOwner("git.run-bytes")
        try:
            stdout, stderr = await owner.communicate_after_spawn(
                str(self.executable),
                *self._argv(tuple(args)),
                cwd=str(repository),
                env=self._environment(index_file=index_file),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except OSError as exc:
            raise TrustedGitError("trusted Git process could not start") from exc
        if owner.process is None or owner.process.returncode != 0:
            message = stderr.decode("utf-8", errors="replace").strip()
            raise TrustedGitError(message or "trusted Git command failed")
        return stdout

    async def run_with_input(
        self,
        repository: Path,
        *args: str,
        input_bytes: bytes,
        authority: EffectCapability,
        max_input_bytes: int = 64 * 1024,
        max_output_bytes: int = 64 * 1024,
        index_file: Path | None = None,
    ) -> str:
        """Run a plumbing command with bounded, caller-owned stdin only."""
        if len(input_bytes) > max_input_bytes:
            raise TrustedGitError("trusted Git input exceeds the configured bound")
        self._verify()
        self._authority_or_fail(authority)
        owner = TrustedGitProcessOwner("git.run-with-input")
        try:
            stdout, stderr = await owner.communicate_after_spawn(
                str(self.executable),
                *self._argv(tuple(args)),
                cwd=str(repository),
                env=self._environment(index_file=index_file),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                input_bytes=input_bytes,
            )
        except OSError as exc:
            raise TrustedGitError("trusted Git process could not start") from exc
        if len(stdout) > max_output_bytes or len(stderr) > _MAX_GIT_ERROR_BYTES:
            raise TrustedGitError("trusted Git output exceeds the configured bound")
        if owner.process is None or owner.process.returncode != 0:
            message = stderr.decode("utf-8", errors="replace").strip()
            raise TrustedGitError(message or "trusted Git command failed")
        return stdout.decode("utf-8", errors="replace").strip()

    async def hash_fd(
        self,
        repository: Path,
        descriptor: int,
        expected: os.stat_result,
        *,
        authority: EffectCapability,
        max_bytes: int,
        index_file: Path | None = None,
    ) -> str:
        """Hash a pinned regular-file descriptor without handing Git a path.

        ``git hash-object <pathname>`` is deliberately not used for mutable
        workspace entries.  The descriptor is opened by ``SafeWorkspaceFS``
        with no-follow parent traversal, streamed in bounded chunks, and
        revalidated after the stream.  A replacement of the leaf or a parent
        directory therefore cannot turn Git into a host-file confused deputy.
        """
        if max_bytes <= 0:
            raise ValueError("max_bytes must be positive")
        if not stat.S_ISREG(expected.st_mode) or expected.st_nlink != 1:
            raise TrustedGitError("Git hash input is not a single-link regular file")
        self._verify()
        self._authority_or_fail(authority)
        try:
            opened = os.fstat(descriptor)
            _verify_same_file_snapshot(opened, expected)
            os.lseek(descriptor, 0, os.SEEK_SET)
        except OSError as exc:
            raise TrustedGitError("Git hash input descriptor is unavailable") from exc

        owner = TrustedGitProcessOwner("git.hash-fd")
        stderr_task: asyncio.Task[tuple[bytes, bool]] | None = None
        stdout_task: asyncio.Task[tuple[bytes, bool]] | None = None
        try:
            process = await owner.spawn(
                str(self.executable),
                *self._argv(("hash-object", "--stdin", "--no-filters", "-w")),
                cwd=str(repository),
                env=self._environment(index_file=index_file),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            if process.stdin is None or process.stdout is None or process.stderr is None:
                raise TrustedGitError("trusted Git hash process has unusable pipes")
            stdout_task = asyncio.create_task(
                _drain_stream_limited(process.stdout, 4096)
            )
            stderr_task = asyncio.create_task(
                _drain_stream_limited(process.stderr, _MAX_GIT_ERROR_BYTES)
            )
            total = 0
            while True:
                chunk = await asyncio.to_thread(os.read, descriptor, _MAX_GIT_CHUNK_BYTES)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise TrustedGitError("Git hash input exceeds its configured bound")
                process.stdin.write(chunk)
                await process.stdin.drain()
            process.stdin.close()
            await process.stdin.wait_closed()
            stdout, stdout_overflow = await stdout_task
            stdout_task = None
            stderr, stderr_overflow = await stderr_task
            stderr_task = None
            await owner.wait()
            if stdout_overflow or stderr_overflow:
                raise TrustedGitError("trusted Git hash output exceeds its bound")
            if process.returncode != 0:
                message = stderr.decode("utf-8", errors="replace").strip()
                raise TrustedGitError(message or "trusted Git hash command failed")
            try:
                final = os.fstat(descriptor)
                _verify_same_file_snapshot(final, expected)
            except OSError as exc:
                raise TrustedGitError("Git hash input changed during hashing") from exc
            object_id = stdout.decode("ascii", errors="strict").strip()
            if not object_id or len(object_id) not in {40, 64}:
                raise TrustedGitError("Git hash command returned an invalid object id")
            return object_id
        except asyncio.CancelledError:
            await asyncio.shield(owner.abort(cancelled=True))
            raise
        except (OSError, UnicodeError, TrustedGitError) as exc:
            if not owner.terminal:
                await asyncio.shield(owner.abort(cancelled=False))
            if isinstance(exc, TrustedGitError):
                raise
            raise TrustedGitError("trusted Git hash input failed") from exc
        finally:
            for task in (stdout_task, stderr_task):
                if task is not None:
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass
            if not owner.terminal:
                await asyncio.shield(owner.abort(cancelled=False))

    async def stream_to_file(
        self,
        repository: Path,
        *args: str,
        destination: Path,
        authority: EffectCapability,
        max_bytes: int,
        preview_bytes: int = 64 * 1024,
        index_file: Path | None = None,
    ) -> GitStreamResult:
        """Stream Git stdout into an exclusive artifact with hard bounds."""
        if max_bytes <= 0 or preview_bytes <= 0 or preview_bytes > max_bytes:
            raise ValueError("invalid Git stream limits")
        self._verify()
        self._authority_or_fail(authority)
        process: asyncio.subprocess.Process | None = None
        owner = TrustedGitProcessOwner("git.stream-to-file")
        stderr_task: asyncio.Task[bytes] | None = None
        descriptor: int | None = None
        completed = False
        try:
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            descriptor = os.open(
                destination,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            process = await owner.spawn(
                str(self.executable),
                *self._argv(tuple(args)),
                cwd=str(repository),
                env=self._environment(index_file=index_file),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            if process.stdout is None or process.stderr is None:
                raise TrustedGitError("trusted Git process has no usable output pipes")
            stderr_task = asyncio.create_task(
                _drain_stream_limited(process.stderr, _MAX_GIT_ERROR_BYTES)
            )
            digest = hashlib.sha256()
            preview = bytearray()
            byte_length = 0
            while chunk := await process.stdout.read(_MAX_GIT_CHUNK_BYTES):
                byte_length += len(chunk)
                if byte_length > max_bytes:
                    raise TrustedGitError("trusted Git artifact exceeds the configured bound")
                offset = 0
                while offset < len(chunk):
                    offset += os.write(descriptor, chunk[offset:])
                digest.update(chunk)
                if len(preview) < preview_bytes:
                    preview.extend(chunk[: preview_bytes - len(preview)])
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = None
            stderr, stderr_overflow = await stderr_task
            stderr_task = None
            await owner.wait()
            if stderr_overflow:
                raise TrustedGitError(
                    "trusted Git diagnostic output exceeds its bound"
                )
            if process.returncode != 0:
                message = stderr.decode("utf-8", errors="replace").strip()
                raise TrustedGitError(message or "trusted Git command failed")
            completed = True
            return GitStreamResult(
                byte_length=byte_length,
                sha256=digest.hexdigest(),
                preview=preview.decode("utf-8", errors="replace"),
            )
        except asyncio.CancelledError:
            await asyncio.shield(owner.abort(cancelled=True))
            raise
        except TrustedGitError:
            if not owner.terminal:
                await asyncio.shield(owner.abort(cancelled=False))
            raise
        except OSError as exc:
            if not owner.terminal:
                await asyncio.shield(owner.abort(cancelled=False))
            raise TrustedGitError("trusted Git artifact stream failed") from exc
        finally:
            if stderr_task is not None:
                stderr_task.cancel()
                try:
                    await stderr_task
                except asyncio.CancelledError:
                    pass
            if not completed and not owner.terminal:
                await asyncio.shield(owner.abort(cancelled=False))
            if descriptor is not None:
                os.close(descriptor)
            if not completed:
                destination.unlink(missing_ok=True)

    async def run_bytes_limited(
        self,
        repository: Path,
        *args: str,
        authority: EffectCapability,
        max_bytes: int,
        index_file: Path | None = None,
    ) -> bytes:
        """Run a binary Git operation with a hard stdout bound."""
        if max_bytes <= 0:
            raise ValueError("max_bytes must be positive")
        self._verify()
        self._authority_or_fail(authority)
        process: asyncio.subprocess.Process | None = None
        owner = TrustedGitProcessOwner("git.run-bytes-limited")
        stderr_task: asyncio.Task[bytes] | None = None
        try:
            process = await owner.spawn(
                str(self.executable),
                *self._argv(tuple(args)),
                cwd=str(repository),
                env=self._environment(index_file=index_file),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            if process.stdout is None or process.stderr is None:
                raise TrustedGitError("trusted Git process has no usable output pipes")
            stderr_task = asyncio.create_task(
                _drain_stream_limited(process.stderr, _MAX_GIT_ERROR_BYTES)
            )
            output = bytearray()
            while chunk := await process.stdout.read(
                min(_MAX_GIT_CHUNK_BYTES, max_bytes + 1 - len(output))
            ):
                output.extend(chunk)
                if len(output) > max_bytes:
                    raise TrustedGitError("trusted Git output exceeds the configured bound")
            stderr, stderr_overflow = await stderr_task
            stderr_task = None
            await owner.wait()
            if stderr_overflow:
                raise TrustedGitError(
                    "trusted Git diagnostic output exceeds its bound"
                )
            if process.returncode != 0:
                message = stderr.decode("utf-8", errors="replace").strip()
                raise TrustedGitError(message or "trusted Git command failed")
            return bytes(output)
        except asyncio.CancelledError:
            await asyncio.shield(owner.abort(cancelled=True))
            raise
        except TrustedGitError:
            if not owner.terminal:
                await asyncio.shield(owner.abort(cancelled=False))
            raise
        except (OSError, asyncio.IncompleteReadError) as exc:
            if not owner.terminal:
                await asyncio.shield(owner.abort(cancelled=False))
            raise TrustedGitError("trusted Git process could not be read") from exc
        finally:
            if stderr_task is not None:
                stderr_task.cancel()
                try:
                    await stderr_task
                except asyncio.CancelledError:
                    pass
            if not owner.terminal:
                await asyncio.shield(owner.abort(cancelled=False))

    async def materialize_tree(
        self,
        repository: Path,
        treeish: str,
        worktree: Path,
        *,
        authority: EffectCapability,
        limits: WorkspaceBootstrapLimits | None = None,
    ) -> None:
        """Materialize a commit's blobs without checkout filters or archives.

        ``git archive`` consults tracked ``.gitattributes`` and can therefore
        activate a repository-local filter process.  The trusted path only
        asks Git for tree metadata and raw blob bytes, then validates every
        pathname and symlink before creating the worktree entry itself.
        """
        bootstrap_limits = limits or WorkspaceBootstrapLimits()
        try:
            async with asyncio.timeout(bootstrap_limits.max_duration_seconds):
                object_id_length = await self._object_id_length(
                    repository, authority=authority
                )
                listing = await self.run_bytes_limited(
                    repository,
                    "ls-tree",
                    "-r",
                    "-z",
                    "--full-tree",
                    treeish,
                    authority=authority.derive(operation_class="git.tree"),
                    max_bytes=bootstrap_limits.max_tree_listing_bytes,
                )
                entries = _parse_tree_listing(
                    listing,
                    object_id_length=object_id_length,
                    max_entries=bootstrap_limits.max_tree_entries,
                )
                await self._materialize_blobs(
                    repository,
                    entries,
                    worktree,
                    authority=authority.derive(operation_class="git.blob"),
                    limits=bootstrap_limits,
                    object_id_length=object_id_length,
                )
        except TimeoutError as exc:
            raise TrustedGitError("Git workspace bootstrap exceeded its time limit") from exc

    async def _materialize_blobs(
        self,
        repository: Path,
        entries: list[tuple[str, str, str]],
        worktree: Path,
        *,
        authority: EffectCapability,
        limits: WorkspaceBootstrapLimits,
        object_id_length: int,
    ) -> None:
        self._verify()
        self._authority_or_fail(authority)
        process: asyncio.subprocess.Process | None = None
        owner = TrustedGitProcessOwner("git.materialize-blobs")
        try:
            process = await owner.spawn(
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
            seen: set[str] = set()
            materialized_bytes = 0
            symlink_count = 0
            for mode, object_id, path in entries:
                if len(seen) >= limits.max_tree_entries:
                    raise TrustedGitError("Git tree exceeds the entry limit")
                if path in seen:
                    raise TrustedGitError(f"Git tree contains duplicate path: {path}")
                seen.add(path)
                parts = _safe_member_parts(path)
                if len(parts) > limits.max_path_depth:
                    raise TrustedGitError("Git tree path exceeds the depth limit")
                process.stdin.write(f"{object_id}\n".encode("ascii"))
                await process.stdin.drain()
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
                if size < 0 or size > limits.max_single_blob_bytes:
                    raise TrustedGitError("Git blob exceeds the single-blob limit")
                materialized_bytes += size
                if materialized_bytes > limits.max_materialized_bytes:
                    raise TrustedGitError("Git tree exceeds the materialized-byte limit")
                parent = _ensure_directory(worktree, parts[:-1])
                target = parent / parts[-1]
                if target.exists() or target.is_symlink():
                    raise TrustedGitError(
                        f"Git tree would overwrite an existing worktree entry: {path}"
                    )
                if mode == "120000":
                    symlink_count += 1
                    if symlink_count > limits.max_symlinks or size > 4096:
                        raise TrustedGitError("Git symlink target is unreasonably large")
                    link_target = await process.stdout.readexactly(size)
                    await _read_blob_separator(process.stdout)
                    _verify_blob_digest(object_id, link_target)
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
                    digest = _blob_hasher(object_id, size)
                    with os.fdopen(descriptor, "wb") as output:
                        while remaining:
                            chunk = await process.stdout.read(min(_MAX_GIT_CHUNK_BYTES, remaining))
                            if not chunk:
                                raise TrustedGitError("Git blob ended before its declared size")
                            output.write(chunk)
                            digest.update(chunk)
                            remaining -= len(chunk)
                        output.flush()
                        os.fsync(output.fileno())
                except Exception:
                    target.unlink(missing_ok=True)
                    raise
                await _read_blob_separator(process.stdout)
                if digest.hexdigest() != object_id:
                    target.unlink(missing_ok=True)
                    raise TrustedGitError("Git blob content hash did not match its object id")
            if process.stdin is not None:
                process.stdin.close()
                await process.stdin.wait_closed()
            if await process.stdout.read(1):
                raise TrustedGitError("Git blob process returned unexpected trailing data")
            stderr, stderr_overflow = (
                await _drain_stream_limited(process.stderr, _MAX_GIT_ERROR_BYTES)
                if process.stderr is not None
                else (b"", False)
            )
            await owner.wait()
            if stderr_overflow:
                raise TrustedGitError(
                    "trusted Git diagnostic output exceeds its bound"
                )
            if process.returncode != 0:
                message = stderr.decode("utf-8", errors="replace").strip()
                raise TrustedGitError(message or "trusted Git blob process failed")
        except asyncio.CancelledError:
            await asyncio.shield(owner.abort(cancelled=True))
            raise
        except TrustedGitError:
            if not owner.terminal:
                await asyncio.shield(owner.abort(cancelled=False))
            raise
        except (OSError, asyncio.IncompleteReadError, ValueError) as exc:
            if not owner.terminal:
                await asyncio.shield(owner.abort(cancelled=False))
            raise TrustedGitError("trusted Git blob materialization failed") from exc
        finally:
            if not owner.terminal:
                await asyncio.shield(owner.abort(cancelled=False))

    async def _object_id_length(
        self, repository: Path, *, authority: EffectCapability
    ) -> int:
        object_format = await self.run(
            repository,
            "rev-parse",
            "--show-object-format",
            authority=authority.derive(operation_class="git.object-format"),
        )
        return _object_id_length(object_format)

    async def is_dirty(
        self,
        repository: Path,
        *,
        authority: EffectCapability,
    ) -> bool:
        """Detect changes without invoking status/filter extensions."""
        object_id_length = await self._object_id_length(repository, authority=authority)
        staged = await self.run(
            repository,
            "diff-index",
            "--cached",
            "--no-ext-diff",
            "--no-textconv",
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
        return not _working_tree_matches_index(listing, repository, object_id_length)

    def run_sync(
        self,
        repository: Path,
        *args: str,
        authority: EffectCapability,
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
        authority: EffectCapability,
    ) -> bool:
        """Synchronous filter-free dirty-state check for recovery."""
        object_id_length = self._object_id_length_sync(repository, authority=authority)
        staged = self.run_sync(
            repository,
            "diff-index",
            "--cached",
            "--no-ext-diff",
            "--no-textconv",
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
        return not _working_tree_matches_index(listing, repository, object_id_length)

    def _object_id_length_sync(
        self, repository: Path, *, authority: EffectCapability
    ) -> int:
        object_format = self.run_sync(
            repository,
            "rev-parse",
            "--show-object-format",
            authority=authority.derive(operation_class="git.object-format"),
        )
        return _object_id_length(object_format)

    def run_sync_bytes(
        self,
        repository: Path,
        *args: str,
        authority: EffectCapability,
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


def _parse_tree_listing(
    listing: bytes,
    *,
    object_id_length: int = 40,
    max_entries: int | None = None,
) -> list[tuple[str, str, str]]:
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
        if mode == "160000":
            raise TrustedGitError(
                "Git submodules/gitlinks are unsupported by Khaos sandboxed workspace bootstrap"
            )
        if object_type != "blob" or len(object_id) != object_id_length:
            raise TrustedGitError("Git tree contains an unsupported object")
        if any(character not in "0123456789abcdef" for character in object_id):
            raise TrustedGitError("Git tree contains an invalid object id")
        if mode not in {"100644", "100755", "120000"}:
            raise TrustedGitError(f"Git tree contains an unsupported mode: {path}")
        entries.append((mode, object_id, path))
        if max_entries is not None and len(entries) > max_entries:
            raise TrustedGitError("Git tree exceeds the entry limit")
    return entries


def _parse_index_listing(
    listing: bytes, *, object_id_length: int | None = None
) -> list[tuple[str, str, str]]:
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
        if stage != "0" or (
            len(object_id) not in {40, 64}
            if object_id_length is None
            else len(object_id) != object_id_length
        ):
            raise TrustedGitError("Git index contains a conflicted or invalid entry")
        if any(character not in "0123456789abcdef" for character in object_id):
            raise TrustedGitError("Git index contains an invalid object id")
        if mode == "160000":
            raise TrustedGitError(
                "Git submodules/gitlinks are unsupported by Khaos sandboxed workspace bootstrap"
            )
        if mode not in {"100644", "100755", "120000"}:
            raise TrustedGitError(f"Git index contains an unsupported mode: {path}")
        entries.append((mode, object_id, path))
    return entries


def _blob_hasher(object_id: str, size: int) -> hashlib._Hash:
    algorithm = "sha256" if len(object_id) == 64 else "sha1"
    digest = hashlib.new(algorithm)
    digest.update(f"blob {size}\0".encode("ascii"))
    return digest


def _working_tree_matches_index(
    listing: bytes, repository: Path, object_id_length: int | None = None
) -> bool:
    """Compare raw worktree bytes to the index without clean/smudge filters."""
    for mode, object_id, path in _parse_index_listing(
        listing, object_id_length=object_id_length
    ):
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


async def _drain_stream_limited(
    stream: asyncio.StreamReader, max_bytes: int
) -> tuple[bytes, bool]:
    """Drain diagnostics without allowing output or pipe backpressure to grow."""
    output = bytearray()
    overflow = False
    while chunk := await stream.read(_MAX_GIT_CHUNK_BYTES):
        remaining = max_bytes - len(output)
        if remaining > 0:
            output.extend(chunk[:remaining])
        if len(chunk) > max(remaining, 0):
            overflow = True
        # Once the preview is full, continue reading and discard diagnostics
        # so the child cannot block on a full stderr pipe.
    return bytes(output), overflow


def _object_id_length(object_format: str) -> int:
    if object_format == "sha1":
        return 40
    if object_format == "sha256":
        return 64
    raise TrustedGitError(f"unsupported Git object format: {object_format}")


def _verify_blob_digest(object_id: str, content: bytes) -> None:
    digest = _blob_hasher(object_id, len(content))
    digest.update(content)
    if digest.hexdigest() != object_id:
        raise TrustedGitError("Git blob content hash did not match its object id")


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
    "GitStreamResult",
    "TrustedGitError",
    "TrustedGitRunner",
    "WorkspaceBootstrapLimits",
    "resolve_trusted_git",
]
