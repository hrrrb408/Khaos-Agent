"""Async Git Worktree lifecycle manager."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import stat
import tempfile
import uuid
from collections.abc import Callable
from contextlib import asynccontextmanager
from pathlib import Path, PurePosixPath
from typing import Any, TypeVar

from khaos.coding.workspace.boundary import (
    PROTECTED_WORKSPACE_NAMES,
    SafePathError,
    SafeWorkspaceFS,
    WorkspaceBoundaryError,
)
from khaos.coding.workspace.git_identity import (
    GitIdentityError,
    capture_git_worktree_identity,
    restore_git_pointer_for_cleanup,
    verify_git_worktree_identity,
)
from khaos.coding.workspace.models import (
    MAX_CHANGESET_INLINE_BYTES,
    ChangeSet,
    ChangeSetArtifact,
    TaskWorkspace,
    WorkspaceState,
    WorkspaceTransition,
)
from khaos.coding.workspace.storage import (
    WorkspaceMutation,
    WorkspaceStorageAuthority,
    WorkspaceStorageLimits,
    WorkspaceStorageViolation,
    capture_workspace_snapshot,
)
from khaos.coding.workspace.trusted_git import (
    TrustedGitError,
    TrustedGitRunner,
    WorkspaceBootstrapLimits,
    _parse_index_listing,
)
from khaos.security.authority import AuthorityEnvelope
from khaos.security.authority_broker import (
    AuthorityBroker,
    EffectCapability,
)

logger = logging.getLogger(__name__)
T = TypeVar("T")
FileIdentity = tuple[int, int, int, int]
MAX_CHANGESET_BYTES = 64 * 1024 * 1024
MAX_CHANGESET_PREVIEW_BYTES = 64 * 1024
MAX_CHANGESET_FILES = 10_000
MAX_CHANGESET_NAMES_BYTES = 8 * 1024 * 1024
MAX_CHANGESET_STAT_BYTES = 1024 * 1024
MAX_CHANGESET_ARTIFACTS = 64
MAX_CHANGESET_ARTIFACT_BYTES = 256 * 1024 * 1024


class WorkspaceError(RuntimeError):
    """Raised when a worktree operation cannot be completed safely."""


def _install_protected_metadata_guards(worktree: Path) -> None:
    """Ensure every protected name has a non-symlink mount target.

    Linux namespace and Docker backends can only apply a child read-only bind
    when the mountpoint exists.  Missing protected names are therefore
    represented by empty directories inside the disposable worktree.  They
    are part of the storage baseline and are removed with the worktree.
    """
    entries = {entry.name.casefold(): entry for entry in worktree.iterdir()}
    for name in sorted(PROTECTED_WORKSPACE_NAMES):
        path = entries.get(name.casefold(), worktree / name)
        if not path.exists() and not path.is_symlink():
            path.mkdir(mode=0o500)
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise WorkspaceError(f"protected workspace metadata is a symlink: {name}")
        if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
            raise WorkspaceError(f"protected workspace metadata has unsafe type: {name}")
        if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
            raise WorkspaceError(f"protected workspace metadata is hardlinked: {name}")


def _identity(info: os.stat_result) -> FileIdentity:
    return (int(info.st_dev), int(info.st_ino), int(info.st_uid), int(info.st_mode))


def _safe_workspace_target(
    workspace: TaskWorkspace, relative: str
) -> tuple[Path, str]:
    """Resolve a Git pathname without following attacker-controlled parents."""
    if not isinstance(relative, str) or "\0" in relative:
        raise WorkspaceError("workspace path is invalid")
    path = PurePosixPath(relative)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise WorkspaceError("workspace path is not relative and normalized")
    if any(part.casefold() in PROTECTED_WORKSPACE_NAMES for part in path.parts):
        raise WorkspaceError("workspace path reaches protected metadata")
    root = workspace.worktree_path.resolve(strict=True)
    target = workspace.worktree_path.joinpath(*path.parts)
    try:
        parent = target.parent.resolve(strict=True)
        parent.relative_to(root)
    except (OSError, ValueError) as exc:
        raise WorkspaceError("workspace path parent escapes the worktree") from exc
    return target, path.as_posix()


def _safe_branch_ref(branch_name: str) -> str:
    """Return a validated local ref name for CAS branch publication."""
    forbidden = set("~^:?*[\\")
    if (
        not branch_name
        or branch_name.startswith("/")
        or branch_name.endswith("/")
        or ".." in branch_name
        or "@{" in branch_name
        or any(ord(char) < 32 or char in forbidden for char in branch_name)
    ):
        raise WorkspaceError("workspace branch ref is invalid")
    return f"refs/heads/{branch_name}"


def _verified_changeset_artifact_path(
    workspace: TaskWorkspace, changeset: ChangeSet
) -> Path:
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


def _read_verified_artifact(
    path: Path,
    expected_length: int,
    expected_digest: str,
    max_bytes: int,
) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
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


def _write_exclusive_artifact(path: Path, payload: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
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


def _copy_verified_artifact(
    source: Path,
    destination: Path,
    expected_length: int,
    expected_digest: str,
) -> None:
    source_descriptor = os.open(
        source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
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
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        while chunk := os.read(source_descriptor, 1024 * 1024):
            total += len(chunk)
            if total > MAX_CHANGESET_BYTES:
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


def _open_private_authority_root(configured: Path) -> tuple[Path, FileIdentity]:
    """Create a private root without following attacker-controlled components."""
    if (
        os.name != "posix"
        or not hasattr(os, "O_DIRECTORY")
        or not hasattr(os, "O_NOFOLLOW")
    ):
        raise PermissionError(
            "private workspace authority roots require POSIX dirfd/no-follow support"
        )
    missing: list[str] = []
    ancestor = configured
    while not ancestor.exists():
        missing.append(ancestor.name)
        ancestor = ancestor.parent
    canonical_ancestor = ancestor.resolve(strict=True)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory_fd = os.open(canonical_ancestor, flags | nofollow)
    canonical = canonical_ancestor
    try:
        for component in reversed(missing):
            if component in {"", ".", ".."} or "/" in component:
                raise WorkspaceError("workspace authority root is invalid")
            try:
                os.mkdir(component, mode=0o700, dir_fd=directory_fd)
            except FileExistsError:
                pass
            next_fd = os.open(component, flags | nofollow, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
            canonical /= component
        info = os.fstat(directory_fd)
    except Exception:
        os.close(directory_fd)
        raise
    os.close(directory_fd)
    if not stat.S_ISDIR(info.st_mode):
        raise WorkspaceError("workspace authority root is not a directory")
    if info.st_uid != os.getuid() or info.st_mode & 0o022:
        raise WorkspaceError(
            "workspace authority root must be user-owned and not group/other writable"
        )
    return canonical, _identity(info)


ALLOWED: dict[WorkspaceState, frozenset[WorkspaceState]] = {
    WorkspaceState.CREATING: frozenset({WorkspaceState.READY, WorkspaceState.FAILED}),
    WorkspaceState.READY: frozenset({WorkspaceState.INDEXING, WorkspaceState.RUNNING, WorkspaceState.FAILED, WorkspaceState.CANCELLED}),
    WorkspaceState.INDEXING: frozenset({WorkspaceState.RUNNING, WorkspaceState.FAILED, WorkspaceState.CANCELLED}),
    WorkspaceState.RUNNING: frozenset({WorkspaceState.VERIFYING, WorkspaceState.FAILED, WorkspaceState.CANCELLED}),
    WorkspaceState.VERIFYING: frozenset({WorkspaceState.RUNNING, WorkspaceState.REVIEWING, WorkspaceState.FAILED, WorkspaceState.CANCELLED}),
    WorkspaceState.REVIEWING: frozenset({WorkspaceState.AWAITING_APPROVAL, WorkspaceState.RUNNING, WorkspaceState.FAILED}),
    WorkspaceState.AWAITING_APPROVAL: frozenset({WorkspaceState.APPLYING, WorkspaceState.CANCELLED}),
    WorkspaceState.APPLYING: frozenset({WorkspaceState.APPLIED, WorkspaceState.FAILED}),
    WorkspaceState.APPLIED: frozenset({WorkspaceState.CLEANING}),
    WorkspaceState.FAILED: frozenset({WorkspaceState.CLEANING}),
    WorkspaceState.CANCELLED: frozenset({WorkspaceState.CLEANING}),
    WorkspaceState.CLEANING: frozenset({WorkspaceState.CLEANED}),
    WorkspaceState.CLEANED: frozenset(),
}


class WorkspaceManager:
    """Create isolated worktrees and immutable ChangeSets."""

    def __init__(
        self,
        root: Path | None = None,
        *,
        storage_limits: WorkspaceStorageLimits | None = None,
        storage_authority: WorkspaceStorageAuthority | None = None,
        bootstrap_limits: WorkspaceBootstrapLimits | None = None,
        policy_digest: str = "legacy-unbound",
    ) -> None:
        configured_root = (
            root or Path(tempfile.gettempdir()) / "khaos" / "worktrees"
        ).expanduser().absolute()
        self.root, self._root_identity = _open_private_authority_root(
            configured_root
        )
        self._authority_broker = AuthorityBroker.default()
        try:
            self._git_runner = TrustedGitRunner.for_authority_root(
                self.root,
                self._root_identity,
                authority_broker=self._authority_broker,
            )
        except TrustedGitError as exc:
            raise WorkspaceError(str(exc)) from exc
        self._git_executable = self._git_runner.executable
        self._git_identity = self._git_runner.git_identity
        self._git_digest = self._git_runner.git_digest
        self.policy_digest = policy_digest
        self.storage_limits = storage_limits or WorkspaceStorageLimits()
        self.storage_authority = storage_authority or WorkspaceStorageAuthority()
        self.bootstrap_limits = bootstrap_limits or WorkspaceBootstrapLimits()
        self._workspaces: dict[str, TaskWorkspace] = {}
        self._task_ids: set[str] = set()
        self._lock = asyncio.Lock()
        self._storage_mutation_locks: dict[str, asyncio.Lock] = {}
        # Batch 2.5 §4: optional lease invalidation hook. When set
        # (by ApprovalRuntime / WorkspaceExecutionLeaseCoordinator),
        # cleanup() calls it BEFORE removing the worktree so the ACTIVE
        # execution lease is released.
        self._lease_invalidation_hook: Any = None
        # Batch 2.6 §5: optional per-workspace mutation fence. When set,
        # cleanup() acquires the fence BEFORE lease invalidation so that
        # cleanup is serialized with active lease acquisition / Batch 3
        # execution / RepositoryIndexer generation updates.
        self._mutation_fence: Any = None

    def set_lease_invalidation_hook(self, hook: Any) -> None:
        """Register a callable invoked during cleanup to release execution leases."""
        self._lease_invalidation_hook = hook

    def set_mutation_fence(self, fence: Any) -> None:
        """Batch 2.6 §5: register the shared per-workspace mutation fence."""
        self._mutation_fence = fence

    @asynccontextmanager
    async def _changeset_mutation_scope(
        self, workspace_id: str, owner: str
    ):
        """Serialize ChangeSet capture with every workspace mutation."""
        if self._mutation_fence is None:
            yield
            return
        async with self._mutation_fence.use(workspace_id, owner=owner):
            yield

    async def _discard_changeset_artifact(
        self,
        workspace: TaskWorkspace,
        artifact_path: Path | None,
        artifact_length: int,
        artifact_registered: bool,
    ) -> None:
        """Rollback a partially built ChangeSet while the mutation fence is held."""
        if artifact_path is not None and artifact_registered:
            async with self._lock:
                workspace.change_artifacts.discard(artifact_path)
                workspace.change_artifact_bytes = max(
                    0, workspace.change_artifact_bytes - artifact_length
                )
        if artifact_path is not None:
            artifact_path.unlink(missing_ok=True)

    async def _finish_changeset_build(
        self, workspace: TaskWorkspace, index_file: Path
    ) -> None:
        """Release reservations and temporary index files after any outcome."""
        async with self._lock:
            workspace.change_artifact_reservations = max(
                0, workspace.change_artifact_reservations - 1
            )
        index_file.unlink(missing_ok=True)
        index_file.with_name(f"{index_file.name}.lock").unlink(missing_ok=True)

    async def _assert_changeset_snapshot(
        self,
        workspace: TaskWorkspace,
        authority_generation: int,
        git_identity: object,
    ) -> None:
        """Reject authority or Git-admin drift during a ChangeSet capture."""
        if workspace.authority_generation != authority_generation:
            raise WorkspaceError("workspace authority generation changed during ChangeSet capture")
        if workspace.git_identity is not git_identity:
            raise WorkspaceError("workspace Git identity changed during ChangeSet capture")
        if workspace.state in {
            WorkspaceState.CLEANING,
            WorkspaceState.CLEANED,
            WorkspaceState.CANCELLED,
        }:
            raise WorkspaceError("workspace changed state during ChangeSet capture")
        try:
            await asyncio.to_thread(verify_git_worktree_identity, workspace.git_identity)
        except GitIdentityError as exc:
            raise WorkspaceError(str(exc)) from exc

    def _default_git_authority(self, repository: Path) -> AuthorityEnvelope:
        return self._authority_broker.envelope(
            principal_id="legacy",
            project_id="local",
            runtime_id="workspace-manager",
            task_id="host-git",
            workspace_id=repository.name or "repository",
            workspace_generation=1,
            policy_digest=self.policy_digest,
            operation_class="git.host",
            resource_digest=hashlib.sha256(
                str(repository.resolve()).encode("utf-8")
            ).hexdigest(),
        )

    async def _git(
        self,
        repository: Path,
        *args: str,
        authority: EffectCapability | None = None,
        preserve_output: bool = False,
    ) -> str:
        try:
            # Reconstruct from the manager-owned identity on every call.  The
            # explicit fields are intentionally mutable only through the
            # manager's startup/revalidation contract; this preserves the
            # digest-drift test and prevents a stale cached runner from
            # becoming an authority bypass.
            runner = TrustedGitRunner(
                self._git_executable,
                self._git_identity,
                self._git_digest,
                self.root,
                self._root_identity,
                self._authority_broker,
            )
            if authority is None:
                context = self._default_git_authority(repository)
                capability = self._authority_broker.issue(
                    context,
                    allowed_operation="git.*",
                )
            elif isinstance(authority, EffectCapability):
                capability = authority
            else:
                raise WorkspaceError(
                    "trusted Git requires a broker-issued capability; "
                    "AuthorityEnvelope is context only"
                )
            return await runner.run(
                repository,
                *args,
                authority=capability,
                preserve_output=preserve_output,
            )
        except TrustedGitError as exc:
            raise WorkspaceError(str(exc)) from exc

    async def _materialize_git_tree(
        self,
        repository: Path,
        base_sha: str,
        worktree: Path,
        *,
        authority: EffectCapability,
    ) -> None:
        try:
            runner = TrustedGitRunner(
                self._git_executable,
                self._git_identity,
                self._git_digest,
                self.root,
                self._root_identity,
                self._authority_broker,
            )
            if not isinstance(authority, EffectCapability):
                raise WorkspaceError(
                    "trusted Git materialization requires a broker capability"
                )
            await runner.materialize_tree(
                repository,
                base_sha,
                worktree,
                authority=authority.derive(operation_class="git.materialize"),
                limits=self.bootstrap_limits,
            )
        except TrustedGitError as exc:
            raise WorkspaceError(str(exc)) from exc

    async def _workspace_git(
        self,
        workspace: TaskWorkspace,
        *args: str,
        preserve_output: bool = False,
        index_file: Path | None = None,
    ) -> str:
        """Run Git only against the pinned admin dir and worktree."""
        identity = workspace.git_identity
        if identity is None:
            raise WorkspaceError("TaskWorkspace Git identity is missing")
        try:
            await asyncio.to_thread(verify_git_worktree_identity, identity)
        except GitIdentityError as exc:
            raise WorkspaceError(str(exc)) from exc
        authority = workspace.authority_capability
        if authority is None:
            raise WorkspaceError("TaskWorkspace authority capability is missing")
        try:
            return await self._git_runner.run(
                workspace.worktree_path,
                f"--git-dir={identity.admin_dir}",
                f"--work-tree={workspace.worktree_path}",
                *args,
                authority=authority.derive(operation_class="git.workspace"),
                preserve_output=preserve_output,
                index_file=index_file,
            )
        except TrustedGitError as exc:
            raise WorkspaceError(str(exc)) from exc

    async def _workspace_git_input(
        self,
        workspace: TaskWorkspace,
        *args: str,
        input_bytes: bytes,
        max_input_bytes: int = 64 * 1024,
        index_file: Path | None = None,
    ) -> str:
        """Run one audited Git plumbing operation with bounded stdin."""
        identity = workspace.git_identity
        authority = workspace.authority_capability
        if identity is None or authority is None:
            raise WorkspaceError("TaskWorkspace Git capability is missing")
        try:
            await asyncio.to_thread(verify_git_worktree_identity, identity)
            return await self._git_runner.run_with_input(
                workspace.worktree_path,
                f"--git-dir={identity.admin_dir}",
                f"--work-tree={workspace.worktree_path}",
                *args,
                input_bytes=input_bytes,
                max_input_bytes=max_input_bytes,
                authority=authority.derive(operation_class="git.workspace"),
                index_file=index_file,
            )
        except (GitIdentityError, TrustedGitError) as exc:
            raise WorkspaceError(str(exc)) from exc

    async def _workspace_git_hash_fd(
        self,
        workspace: TaskWorkspace,
        descriptor: int,
        expected: os.stat_result,
        *,
        max_bytes: int,
    ) -> str:
        """Hash a fixed workspace descriptor through trusted Git stdin."""
        identity = workspace.git_identity
        authority = workspace.authority_capability
        if identity is None or authority is None:
            raise WorkspaceError("TaskWorkspace Git capability is missing")
        try:
            await asyncio.to_thread(verify_git_worktree_identity, identity)
            return await self._git_runner.hash_fd(
                workspace.worktree_path,
                descriptor,
                expected,
                authority=authority.derive(operation_class="git.workspace"),
                max_bytes=max_bytes,
            )
        except (GitIdentityError, TrustedGitError) as exc:
            raise WorkspaceError(str(exc)) from exc

    async def _workspace_git_bytes_limited(
        self,
        workspace: TaskWorkspace,
        *args: str,
        max_bytes: int,
        index_file: Path | None = None,
    ) -> bytes:
        """Run one workspace Git read with an explicit output cap."""
        identity = workspace.git_identity
        authority = workspace.authority_capability
        if identity is None or authority is None:
            raise WorkspaceError("TaskWorkspace Git capability is missing")
        try:
            await asyncio.to_thread(verify_git_worktree_identity, identity)
            return await self._git_runner.run_bytes_limited(
                workspace.worktree_path,
                f"--git-dir={identity.admin_dir}",
                f"--work-tree={workspace.worktree_path}",
                *args,
                authority=authority.derive(operation_class="git.workspace"),
                max_bytes=max_bytes,
                index_file=index_file,
            )
        except (GitIdentityError, TrustedGitError) as exc:
            raise WorkspaceError(str(exc)) from exc

    async def _workspace_git_stream(
        self,
        workspace: TaskWorkspace,
        *args: str,
        destination: Path,
        max_bytes: int,
        index_file: Path | None = None,
    ):
        """Stream workspace Git output into a private artifact."""
        identity = workspace.git_identity
        authority = workspace.authority_capability
        if identity is None or authority is None:
            raise WorkspaceError("TaskWorkspace Git capability is missing")
        try:
            await asyncio.to_thread(verify_git_worktree_identity, identity)
            return await self._git_runner.stream_to_file(
                workspace.worktree_path,
                f"--git-dir={identity.admin_dir}",
                f"--work-tree={workspace.worktree_path}",
                *args,
                destination=destination,
                authority=authority.derive(operation_class="git.workspace"),
                max_bytes=max_bytes,
                preview_bytes=MAX_CHANGESET_PREVIEW_BYTES,
                index_file=index_file,
            )
        except (GitIdentityError, TrustedGitError) as exc:
            raise WorkspaceError(str(exc)) from exc

    async def _workspace_diff_digest(self, workspace: TaskWorkspace) -> str:
        """Hash the current raw diff without materializing it in Python memory."""
        index_file = workspace.worktree_path.parent / f".binding-index-{uuid.uuid4().hex}"
        temporary = workspace.worktree_path.parent / f".binding-{uuid.uuid4().hex}.patch"
        try:
            await self._prepare_raw_changeset_index(workspace, index_file)
            result = await self._workspace_git_stream(
                workspace,
                "diff",
                "--cached",
                "--no-ext-diff",
                "--no-textconv",
                "--binary",
                workspace.base_sha,
                destination=temporary,
                max_bytes=MAX_CHANGESET_BYTES,
                index_file=index_file,
            )
            return result.sha256
        finally:
            temporary.unlink(missing_ok=True)
            index_file.unlink(missing_ok=True)
            index_file.with_name(f"{index_file.name}.lock").unlink(missing_ok=True)

    async def _hash_workspace_entry(
        self,
        workspace: TaskWorkspace,
        safe_relative: str,
        info: os.stat_result,
    ) -> tuple[str, str]:
        """Hash one raw worktree entry without a pathname TOCTOU."""
        try:
            filesystem = SafeWorkspaceFS(workspace.worktree_path)
        except (OSError, SafePathError, WorkspaceBoundaryError) as exc:
            raise WorkspaceError(str(exc)) from exc
        try:
            if stat.S_ISLNK(info.st_mode):
                raw_target, opened = filesystem.read_symlink_bytes(safe_relative)
                if (
                    opened.st_dev,
                    opened.st_ino,
                    opened.st_mode,
                    opened.st_nlink,
                ) != (
                    info.st_dev,
                    info.st_ino,
                    info.st_mode,
                    info.st_nlink,
                ):
                    raise WorkspaceError("workspace symlink identity changed")
                object_id = await self._workspace_git_input(
                    workspace,
                    "hash-object",
                    "--stdin",
                    "--no-filters",
                    "-w",
                    input_bytes=raw_target,
                    max_input_bytes=4096,
                )
                return object_id, "120000"
            if stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                descriptor, opened = filesystem.open_regular_file(safe_relative)
                try:
                    if (
                        opened.st_dev,
                        opened.st_ino,
                        opened.st_mode,
                        opened.st_nlink,
                        opened.st_size,
                    ) != (
                        info.st_dev,
                        info.st_ino,
                        info.st_mode,
                        info.st_nlink,
                        info.st_size,
                    ):
                        raise WorkspaceError("workspace file identity changed")
                    object_id = await self._workspace_git_hash_fd(
                        workspace,
                        descriptor,
                        opened,
                        max_bytes=MAX_CHANGESET_BYTES,
                    )
                finally:
                    os.close(descriptor)
                return object_id, "100755" if opened.st_mode & 0o111 else "100644"
        except (OSError, SafePathError, WorkspaceBoundaryError) as exc:
            raise WorkspaceError(str(exc)) from exc
        finally:
            filesystem.close()
        raise WorkspaceError(f"workspace change has an unsupported file type: {safe_relative}")

    async def _prepare_raw_changeset_index(
        self, workspace: TaskWorkspace, index_file: Path
    ) -> None:
        """Build a temporary raw-byte index, bypassing all clean filters."""
        tracked_listing = await self._workspace_git_bytes_limited(
            workspace, "ls-files", "--stage", "-z", max_bytes=MAX_CHANGESET_NAMES_BYTES
        )
        tracked = _parse_index_listing(
            tracked_listing, object_id_length=len(workspace.base_sha)
        )
        untracked_listing = await self._workspace_git_bytes_limited(
            workspace,
            "ls-files",
            "--others",
            "--exclude-standard",
            "-z",
            max_bytes=MAX_CHANGESET_NAMES_BYTES,
        )
        untracked = tuple(
            os.fsdecode(raw) for raw in untracked_listing.split(b"\0") if raw
        )
        if len(tracked) + len(untracked) > MAX_CHANGESET_FILES:
            raise WorkspaceError("changeset contains too many files")
        index_file.unlink(missing_ok=True)
        await self._workspace_git(
            workspace,
            "read-tree",
            workspace.base_sha,
            index_file=index_file,
        )
        paths = {path for _, _, path in tracked}
        paths.update(untracked)
        for relative in sorted(paths):
            _target, safe_relative = _safe_workspace_target(workspace, relative)
            try:
                filesystem = SafeWorkspaceFS(workspace.worktree_path)
                try:
                    info = filesystem.lstat(safe_relative)
                finally:
                    filesystem.close()
            except FileNotFoundError:
                await self._workspace_git(
                    workspace,
                    "update-index",
                    "--remove",
                    "--",
                    safe_relative,
                    index_file=index_file,
                )
                continue
            except (OSError, SafePathError, WorkspaceBoundaryError) as exc:
                raise WorkspaceError(str(exc)) from exc
            if info is None:
                await self._workspace_git(
                    workspace,
                    "update-index",
                    "--remove",
                    "--",
                    safe_relative,
                    index_file=index_file,
                )
                continue
            object_id, mode = await self._hash_workspace_entry(
                workspace, safe_relative, info
            )
            if len(object_id) != len(workspace.base_sha) or any(
                character not in "0123456789abcdef" for character in object_id
            ):
                raise WorkspaceError("Git returned an object id for the wrong repository format")
            await self._workspace_git(
                workspace,
                "update-index",
                "--add",
                "--cacheinfo",
                f"{mode},{object_id},{safe_relative}",
                index_file=index_file,
            )

    async def create(
        self,
        repository_root: Path,
        task_id: str,
        *,
        base_ref: str = "HEAD",
        principal_id: str = "legacy",
        project_id: str = "",
        creator_runtime_id: str = "",
    ) -> TaskWorkspace:
        repository = repository_root.resolve()
        async with self._lock:
            if task_id in self._task_ids:
                raise WorkspaceError(f"task already has an active workspace: {task_id}")
            if not (repository / ".git").exists():
                raise WorkspaceError(f"not a git repository: {repository}")
            workspace_id = uuid.uuid4().hex[:12]
            authority_context = self._authority_broker.envelope(
                principal_id=principal_id or "legacy",
                project_id=project_id or "local",
                runtime_id=creator_runtime_id or "legacy-runtime",
                task_id=task_id,
                workspace_id=workspace_id,
                workspace_generation=1,
                policy_digest=self.policy_digest,
                operation_class="git.bootstrap",
                resource_digest=hashlib.sha256(
                    str(repository).encode("utf-8")
                ).hexdigest(),
            )
            authority_capability = self._authority_broker.issue(
                authority_context,
                allowed_operation="git.*",
            )
            dirty = await self._git(
                repository,
                "status",
                "--porcelain",
                authority=authority_capability,
            )
            if dirty:
                raise WorkspaceError("主工作树存在未提交修改，拒绝创建可写 Worktree")
            base_sha = await self._git(
                repository,
                "rev-parse",
                base_ref,
                authority=authority_capability,
            )
            branch = f"khaos/task/{task_id}"
            path = (self.root / workspace_id).resolve()
            pending_path = (self.root / f".pending-{workspace_id}").resolve()
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.exists() or path.is_symlink() or pending_path.exists() or pending_path.is_symlink():
                raise WorkspaceError("workspace bootstrap path already exists")
            active_path: Path | None = pending_path
            try:
                await self._git(
                    repository,
                    "worktree",
                    "add",
                    "--no-checkout",
                    "-b",
                    branch,
                    str(pending_path),
                    base_sha,
                    authority=authority_capability,
                )
                git_identity = await asyncio.to_thread(
                    capture_git_worktree_identity, repository, pending_path
                )
                # ``--no-checkout`` deliberately leaves the worktree empty.
                # Set the linked index to the approved tree without ``-u`` so
                # Git does not invoke any smudge/filter driver; tracked bytes
                # are materialized separately from raw tree/blob objects.
                await self._git(
                    pending_path,
                    f"--git-dir={git_identity.admin_dir}",
                    f"--work-tree={pending_path}",
                    "read-tree",
                    base_sha,
                    authority=authority_capability.derive(operation_class="git.index"),
                )
                await self._materialize_git_tree(
                    repository,
                    base_sha,
                    pending_path,
                    authority=authority_capability,
                )
                recovery_root = (self.root.parent / ".khaos-recovery").resolve()
                await asyncio.to_thread(
                    _install_protected_metadata_guards, pending_path
                )
                baseline = await asyncio.to_thread(
                    capture_workspace_snapshot, pending_path
                )
                if not baseline.complete:
                    raise WorkspaceError("TaskWorkspace storage baseline is incomplete")
                await self._git(
                    repository,
                    "worktree",
                    "move",
                    str(pending_path),
                    str(path),
                    authority=authority_capability,
                )
                active_path = path
                git_identity = await asyncio.to_thread(
                    capture_git_worktree_identity, repository, path
                )
                root_stat = path.stat()
                workspace = TaskWorkspace(
                    id=workspace_id,
                    task_id=task_id,
                    repository_root=repository,
                    worktree_path=path,
                    base_ref=base_ref,
                    base_sha=base_sha,
                    branch_name=branch,
                    state=WorkspaceState.READY,
                    writable_roots=(path,),
                    recovery_root=recovery_root,
                    storage_limits=self.storage_limits,
                    git_identity=git_identity,
                    principal_id=principal_id,
                    project_id=project_id,
                    creator_runtime_id=creator_runtime_id,
                    authority_generation=1,
                    root_device=int(root_stat.st_dev),
                    root_inode=int(root_stat.st_ino),
                    authority_envelope=authority_context,
                    authority_capability=authority_capability,
                )
                workspace.storage_baseline = baseline
                self._workspaces[workspace_id] = workspace
                self._task_ids.add(task_id)
                active_path = None
                return workspace
            except Exception:
                # A bootstrap failure must not leave a directory that looks
                # usable but is absent from the in-memory lifecycle registry.
                # Git owns the administrative metadata, so cleanup stays on
                # the trusted worktree path rather than using host ``rmtree``.
                if active_path is not None:
                    try:
                        await self._git(
                            repository,
                            "worktree",
                            "remove",
                            "--force",
                            str(active_path),
                            authority=authority_capability,
                        )
                    except Exception as cleanup_error:  # noqa: BLE001 - preserve original failure
                        logger.error(
                            "bootstrap cleanup failed for %s: %s",
                            active_path,
                            cleanup_error,
                        )
                self._workspaces.pop(workspace_id, None)
                self._task_ids.discard(task_id)
                raise

    async def transition(self, workspace_id: str, target: WorkspaceState) -> WorkspaceTransition:
        async with self._lock:
            workspace = self._workspaces.get(workspace_id)
            if workspace is None:
                return WorkspaceTransition.NOT_FOUND
            if target not in ALLOWED[workspace.state]:
                return WorkspaceTransition.INVALID
            workspace.state = target
            return WorkspaceTransition.UPDATED

    def get(self, workspace_id: str) -> TaskWorkspace | None:
        """Return a workspace without allowing callers to mutate its registry."""
        return self._workspaces.get(workspace_id)

    def require(
        self,
        workspace_id: str,
        *,
        task_id: str,
        principal_id: str,
        project_id: str,
        runtime_id: str,
    ) -> TaskWorkspace:
        """Return only a workspace owned by this exact task and tenant."""
        workspace = self._workspaces.get(workspace_id)
        if workspace is None or workspace.task_id != task_id:
            raise PermissionError("active TaskWorkspace identity does not match tool call")
        if workspace.principal_id != principal_id or workspace.project_id != project_id:
            raise PermissionError("TaskWorkspace owner does not match tool call")
        if workspace.creator_runtime_id != runtime_id:
            raise PermissionError("TaskWorkspace runtime owner does not match tool call")
        try:
            current = workspace.worktree_path.resolve(strict=True).stat()
        except OSError as exc:
            raise PermissionError("TaskWorkspace root is unavailable") from exc
        if (
            workspace.root_device != int(current.st_dev)
            or workspace.root_inode != int(current.st_ino)
        ):
            raise PermissionError("TaskWorkspace root identity drifted")
        return workspace

    def file_recovery_root(self, workspace_id: str) -> Path:
        """Return a private, authority-owned rollback directory."""
        workspace = self._workspaces.get(workspace_id)
        if workspace is None:
            raise WorkspaceError("workspace not found")
        base = workspace.recovery_root or (self.root.parent / ".khaos-recovery")
        root = (base / workspace.id / "file-tools").resolve()
        worktree = workspace.worktree_path.resolve()
        if root == worktree or worktree in root.parents or root in worktree.parents:
            raise WorkspaceError("file recovery root overlaps TaskWorkspace")
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        root.chmod(0o700)
        info = root.stat()
        if info.st_uid != os.getuid() or info.st_nlink < 1:
            raise WorkspaceError("file recovery root identity is invalid")
        return root

    async def verify_git_identity(self, workspace_id: str) -> None:
        """Fail closed when a TaskWorkspace Git pointer/admin inode drifts."""
        workspace = self._workspaces.get(workspace_id)
        if workspace is None or workspace.git_identity is None:
            raise WorkspaceError("TaskWorkspace Git identity is unavailable")
        try:
            await asyncio.to_thread(
                verify_git_worktree_identity, workspace.git_identity
            )
        except GitIdentityError as exc:
            raise WorkspaceError(str(exc)) from exc

    async def verify_execution_root(self, workspace_id: str) -> None:
        """Revalidate the worktree root inode AND Git identity before launch.

        Round-14 §1 / Round-15 A-3: ``require`` validates the root
        ``(dev, ino)`` early in ``ExecutionService.execute``, and
        ``verify_git_identity`` validates the ``.git`` pointer/admin dir —
        but both ran *before* the subprocess was actually launched
        (``create_subprocess_exec`` deep in the backend), leaving a TOCTOU
        window in which a concurrent writer (a prior subprocess, a hook
        fired by a git operation) could swap the worktree directory or the
        ``.git`` pointer out from under the validated path.  This helper
        re-runs BOTH the root-inode check and the git-identity check as
        close to dispatch as the caller can place it.  It is the pre-exec
        sibling of the post-exec ``_verify_or_quarantine_git_identity``
        detection in ExecutionService — turning a successful swap into a
        refusal before the child runs, not a quarantine after.
        """
        workspace = self._workspaces.get(workspace_id)
        if workspace is None:
            raise WorkspaceError("TaskWorkspace is unavailable")
        try:
            current = workspace.worktree_path.resolve(strict=True).stat()
        except OSError as exc:
            raise WorkspaceError("TaskWorkspace root is unavailable") from exc
        if (
            workspace.root_device != int(current.st_dev)
            or workspace.root_inode != int(current.st_ino)
        ):
            raise WorkspaceError("TaskWorkspace root identity drifted before execution")
        # Round-15 A-3: also re-verify the Git pointer/admin-dir identity.
        # The Round-14 version only checked the inode; a ``.git`` swap was
        # only caught post-exec.  Re-run the same pinned-identity check the
        # post-exec path uses, so a swap is refused before the child runs.
        if workspace.git_identity is not None:
            try:
                await asyncio.to_thread(
                    verify_git_worktree_identity, workspace.git_identity
                )
            except GitIdentityError as exc:
                raise WorkspaceError(str(exc)) from exc

    async def mutate_with_storage_authority(
        self,
        workspace_id: str,
        task_id: str,
        operation: Callable[[], WorkspaceMutation[T]],
    ) -> T:
        """Serialize, account, and if necessary roll back one file-tool write."""
        async with self._lock:
            workspace = self._workspaces.get(workspace_id)
            if workspace is None or workspace.task_id != task_id:
                raise PermissionError("task/workspace binding is invalid")
            if workspace.state in {
                WorkspaceState.FAILED,
                WorkspaceState.CANCELLED,
                WorkspaceState.CLEANING,
                WorkspaceState.CLEANED,
            }:
                raise PermissionError("workspace is not writable")
            mutation_lock = self._storage_mutation_locks.setdefault(
                workspace_id, asyncio.Lock()
            )

        try:
            async with mutation_lock:
                async with self._lock:
                    current = self._workspaces.get(workspace_id)
                    if current is None or current is not workspace or current.state in {
                        WorkspaceState.FAILED,
                        WorkspaceState.CANCELLED,
                        WorkspaceState.CLEANING,
                        WorkspaceState.CLEANED,
                    }:
                        raise PermissionError("workspace is not writable")
                worker = asyncio.create_task(asyncio.to_thread(
                    self.storage_authority.mutate,
                    workspace_id,
                    workspace.worktree_path,
                    workspace.storage_baseline,
                    workspace.storage_limits,
                    operation,
                ))
                cancelled = False
                while not worker.done():
                    try:
                        await asyncio.shield(worker)
                    except asyncio.CancelledError:
                        # ``to_thread`` cannot be force-cancelled.  Keep the
                        # Workspace mutation/cleanup fence held until the
                        # authority has committed or rolled back, then
                        # propagate cancellation to the caller.
                        cancelled = True
                result = worker.result()
                if cancelled:
                    raise asyncio.CancelledError
                return result
        except WorkspaceStorageViolation as exc:
            if exc.quarantine_required:
                await self.quarantine(workspace_id)
            raise

    async def quarantine(self, workspace_id: str) -> WorkspaceTransition:
        """Fail closed and attempt forced cleanup without losing quarantine."""
        async with self._lock:
            workspace = self._workspaces.get(workspace_id)
            if workspace is None:
                return WorkspaceTransition.NOT_FOUND
            if workspace.state is WorkspaceState.CLEANED:
                return WorkspaceTransition.INVALID
            workspace.state = WorkspaceState.FAILED
        transition = await self.cleanup(workspace_id, force=True)
        if transition is not WorkspaceTransition.UPDATED:
            async with self._lock:
                workspace = self._workspaces.get(workspace_id)
                if workspace is not None and workspace.state is not WorkspaceState.CLEANED:
                    workspace.state = WorkspaceState.FAILED
        return transition

    async def build_changeset(self, workspace_id: str) -> ChangeSet:
        """Capture a stable ChangeSet while holding the shared mutation fence."""
        async with self._lock:
            workspace = self._workspaces.get(workspace_id)
            if workspace is None:
                raise WorkspaceError("workspace not found")
        async with self._changeset_mutation_scope(
            workspace_id, f"changeset:{uuid.uuid4().hex}"
        ):
            return await self._build_changeset_unfenced(workspace_id)

    async def _build_changeset_unfenced(self, workspace_id: str) -> ChangeSet:
        async with self._lock:
            workspace = self._workspaces.get(workspace_id)
            if workspace is None:
                raise WorkspaceError("workspace not found")
            if workspace.state in {
                WorkspaceState.CANCELLED,
                WorkspaceState.CLEANING,
                WorkspaceState.CLEANED,
            }:
                raise WorkspaceError("workspace is not available for ChangeSet creation")
            if (
                len(workspace.change_artifacts)
                + workspace.change_artifact_reservations
                >= MAX_CHANGESET_ARTIFACTS
                or workspace.change_artifact_bytes
                + (
                    workspace.change_artifact_reservations + 1
                ) * MAX_CHANGESET_BYTES
                > MAX_CHANGESET_ARTIFACT_BYTES
            ):
                raise WorkspaceError("workspace ChangeSet artifact quota is exhausted")
            workspace.change_artifact_reservations += 1
        index_file = workspace.worktree_path.parent / f".changeset-index-{uuid.uuid4().hex}"
        artifact_path: Path | None = None
        artifact_registered = False
        artifact_length = 0
        authority_generation = workspace.authority_generation
        git_identity = workspace.git_identity
        try:
            if git_identity is None:
                raise WorkspaceError("TaskWorkspace Git identity is missing")
            await self._assert_changeset_snapshot(
                workspace, authority_generation, git_identity
            )
            await self._prepare_raw_changeset_index(workspace, index_file)
            names_raw = await self._workspace_git_bytes_limited(
                workspace,
                "diff",
                "--cached",
                "--no-ext-diff",
                "--no-textconv",
                "--name-only",
                "-z",
                workspace.base_sha,
                max_bytes=MAX_CHANGESET_NAMES_BYTES,
                index_file=index_file,
            )
            changed_files = tuple(
                os.fsdecode(raw)
                for raw in names_raw.split(b"\0")
                if raw
            )
            if len(changed_files) > MAX_CHANGESET_FILES:
                raise WorkspaceError("changeset contains too many files")
            protected = {name.casefold() for name in PROTECTED_WORKSPACE_NAMES}
            for changed in changed_files:
                if any(part.casefold() in protected for part in Path(changed).parts):
                    raise WorkspaceError("changeset contains protected workspace metadata")
                _safe_workspace_target(workspace, changed)
            stat_raw = await self._workspace_git_bytes_limited(
                workspace,
                "diff",
                "--cached",
                "--no-ext-diff",
                "--no-textconv",
                "--stat",
                workspace.base_sha,
                max_bytes=MAX_CHANGESET_STAT_BYTES,
                index_file=index_file,
            )
            artifact_path = workspace.worktree_path.parent / f"{uuid.uuid4().hex[:12]}.patch"
            stream = await self._workspace_git_stream(
                workspace,
                "diff",
                "--cached",
                "--no-ext-diff",
                "--no-textconv",
                "--binary",
                workspace.base_sha,
                destination=artifact_path,
                max_bytes=MAX_CHANGESET_BYTES,
                index_file=index_file,
            )
            artifact_length = stream.byte_length
            async with self._lock:
                if (
                    workspace.change_artifact_bytes + stream.byte_length
                    > MAX_CHANGESET_ARTIFACT_BYTES
                ):
                    raise WorkspaceError(
                        "workspace ChangeSet artifact byte quota is exhausted"
                    )
                workspace.change_artifacts.add(artifact_path)
                workspace.change_artifact_bytes += stream.byte_length
                artifact_registered = True
            await self._assert_changeset_snapshot(
                workspace, authority_generation, git_identity
            )
            if stream.byte_length <= MAX_CHANGESET_INLINE_BYTES:
                inline_bytes = await asyncio.to_thread(
                    _read_verified_artifact,
                    artifact_path,
                    stream.byte_length,
                    stream.sha256,
                    MAX_CHANGESET_INLINE_BYTES,
                )
                patch = inline_bytes.decode("utf-8", errors="replace")
            else:
                patch = stream.preview
            artifact = ChangeSetArtifact(
                path=artifact_path,
                byte_length=stream.byte_length,
                sha256=stream.sha256,
                preview=stream.preview,
            )
            changeset = ChangeSet.create(
                id=artifact_path.stem,
                workspace_id=workspace_id,
                base_sha=workspace.base_sha,
                head_sha=None,
                patch=patch,
                diff_stat=stat_raw.decode("utf-8", errors="replace"),
                changed_files=changed_files,
                artifact=artifact,
            )
            return changeset
        except asyncio.CancelledError:
            await asyncio.shield(
                self._discard_changeset_artifact(
                    workspace, artifact_path, artifact_length, artifact_registered
                )
            )
            raise
        except BaseException:
            await asyncio.shield(
                self._discard_changeset_artifact(
                    workspace, artifact_path, artifact_length, artifact_registered
                )
            )
            raise
        finally:
            await asyncio.shield(self._finish_changeset_build(workspace, index_file))

    async def read_changeset_patch(
        self, workspace_id: str, changeset: ChangeSet
    ) -> str:
        """Read only a small patch inline; large artifacts require paging."""
        workspace = self._workspaces.get(workspace_id)
        if workspace is None or changeset.workspace_id != workspace_id:
            raise WorkspaceError("workspace or changeset not found")
        if changeset.artifact is None:
            if len(changeset.patch.encode("utf-8")) > MAX_CHANGESET_INLINE_BYTES:
                raise WorkspaceError("large changesets must be consumed as artifacts")
            return changeset.patch
        path = _verified_changeset_artifact_path(workspace, changeset)
        data = await asyncio.to_thread(
            _read_verified_artifact,
            path,
            changeset.artifact.byte_length,
            changeset.artifact.sha256,
            MAX_CHANGESET_INLINE_BYTES,
        )
        return data.decode("utf-8", errors="replace")

    async def export_changeset_artifact(
        self, workspace_id: str, changeset: ChangeSet, destination: Path
    ) -> None:
        """Copy a verified artifact with a bounded, digest-checked stream."""
        workspace = self._workspaces.get(workspace_id)
        if workspace is None or changeset.workspace_id != workspace_id:
            raise WorkspaceError("workspace or changeset not found")
        destination = destination.absolute()
        try:
            destination.parent.resolve(strict=True).relative_to(self.root)
        except (OSError, ValueError) as exc:
            raise WorkspaceError("changeset export destination is outside the private root") from exc
        if changeset.artifact is None:
            payload = changeset.patch.encode("utf-8")
            if len(payload) > MAX_CHANGESET_BYTES:
                raise WorkspaceError("changeset exceeds the artifact limit")
            await asyncio.to_thread(_write_exclusive_artifact, destination, payload)
            return
        path = _verified_changeset_artifact_path(workspace, changeset)
        await asyncio.to_thread(
            _copy_verified_artifact,
            path,
            destination,
            changeset.artifact.byte_length,
            changeset.artifact.sha256,
        )

    async def commit_in_worktree(
        self, workspace_id: str, changeset: ChangeSet, message: str
    ) -> str:
        """Commit an approved ChangeSet while holding the workspace fence."""
        async with self._changeset_mutation_scope(
            workspace_id, f"commit:{uuid.uuid4().hex}"
        ):
            return await self._commit_in_worktree_unfenced(
                workspace_id, changeset, message
            )

    async def _commit_in_worktree_unfenced(
        self, workspace_id: str, changeset: ChangeSet, message: str
    ) -> str:
        workspace = self._workspaces.get(workspace_id)
        if workspace is None or changeset.workspace_id != workspace_id:
            raise WorkspaceError("workspace or changeset not found")
        current_head = await self._workspace_git(workspace, "rev-parse", "HEAD")
        current_digest = await self._workspace_diff_digest(workspace)
        if current_head != changeset.base_sha or current_digest != changeset.content_hash:
            raise WorkspaceError("changeset content changed; approval is stale")

        await self._workspace_git(workspace, "read-tree", workspace.base_sha)
        for relative in changeset.changed_files:
            _target, safe_relative = _safe_workspace_target(workspace, relative)
            try:
                filesystem = SafeWorkspaceFS(workspace.worktree_path)
                try:
                    info = filesystem.lstat(safe_relative)
                finally:
                    filesystem.close()
            except FileNotFoundError:
                await self._workspace_git(
                    workspace, "update-index", "--remove", "--", safe_relative
                )
                continue
            except (OSError, SafePathError, WorkspaceBoundaryError) as exc:
                raise WorkspaceError(str(exc)) from exc
            if info is None:
                await self._workspace_git(
                    workspace, "update-index", "--remove", "--", safe_relative
                )
                continue
            object_id, mode = await self._hash_workspace_entry(
                workspace, safe_relative, info
            )
            if len(object_id) != len(workspace.base_sha) or any(
                character not in "0123456789abcdef" for character in object_id
            ):
                raise WorkspaceError("Git returned an object id for the wrong repository format")
            await self._workspace_git(
                workspace,
                "update-index",
                "--add",
                "--cacheinfo",
                f"{mode},{object_id},{safe_relative}",
            )

        tree = await self._workspace_git(workspace, "write-tree")
        message_bytes = message.encode("utf-8")
        if not message_bytes or len(message_bytes) > 64 * 1024 or b"\0" in message_bytes:
            raise WorkspaceError("commit message is empty, too large, or contains NUL")
        commit_id = await self._workspace_git_input(
            workspace,
            "commit-tree",
            tree,
            "-p",
            current_head,
            input_bytes=message_bytes,
        )
        ref = _safe_branch_ref(workspace.branch_name)
        await self._workspace_git(workspace, "update-ref", ref, commit_id, current_head)
        return await self._workspace_git(workspace, "rev-parse", "HEAD")

    async def cleanup(self, workspace_id: str, *, force: bool = False) -> WorkspaceTransition:
        """Clean up a workspace worktree.

        Batch 2.6 §4: if a lease invalidation hook is registered, calls it
        BEFORE removing the worktree. If the hook raises, cleanup FAILS
        CLOSED — the worktree is NOT removed, the workspace does NOT enter
        CLEANED, and ``WorkspaceTransition.FAILED`` is returned. The
        workspace stays in its current state so cleanup can be retried.

        Batch 2.6 §5: if a mutation fence is registered, acquires it
        BEFORE the manager lock (fence-first ordering) so cleanup is
        serialized with active lease acquisition / Batch 3 execution /
        RepositoryIndexer generation updates. Owner is
        ``"cleanup:{workspace_id}"``.

        Invariant: ``WorkspaceState.CLEANED`` ⇒ ACTIVE lease count = 0.
        """
        # Batch 2.6 §5: acquire the mutation fence FIRST (outermost lock)
        # so cleanup is serialized with lease acquisition. If no fence is
        # configured, fall back to the old behavior.
        if self._mutation_fence is not None:
            async with self._mutation_fence.use(
                workspace_id, owner=f"cleanup:{workspace_id}",
            ):
                return await self._cleanup_impl(workspace_id, force=force)
        return await self._cleanup_impl(workspace_id, force=force)

    async def _cleanup_impl(self, workspace_id: str, *, force: bool) -> WorkspaceTransition:
        """Internal cleanup — assumes fence (if any) is already held."""
        async with self._lock:
            storage_lock = self._storage_mutation_locks.setdefault(
                workspace_id, asyncio.Lock()
            )
        async with storage_lock:
            return await self._cleanup_under_storage_lock(
                workspace_id, force=force
            )

    async def _cleanup_under_storage_lock(
        self, workspace_id: str, *, force: bool
    ) -> WorkspaceTransition:
        """Remove a Worktree while file-tool storage mutations are excluded."""
        async with self._lock:
            workspace = self._workspaces.get(workspace_id)
            if workspace is None:
                return WorkspaceTransition.NOT_FOUND
            if workspace.state not in {WorkspaceState.APPLIED, WorkspaceState.FAILED, WorkspaceState.CANCELLED} and not force:
                return WorkspaceTransition.INVALID
            if workspace.change_artifact_reservations:
                logger.warning(
                    "cleanup refused while ChangeSet artifact build is active: %s",
                    workspace_id,
                )
                return WorkspaceTransition.FAILED
            # Release any ACTIVE execution lease for this workspace.
            # Batch 2.6 §4: fail closed on lease invalidation error — do
            # NOT continue to CLEANING/CLEANED. The workspace stays in its
            # current state so cleanup can be retried after the lease
            # issue is resolved.
            if self._lease_invalidation_hook is not None:
                try:
                    self._lease_invalidation_hook(workspace_id=workspace_id)
                except Exception as exc:  # noqa: BLE001 - lease hooks are fail-closed boundaries
                    logger.warning(
                        "lease invalidation failed for workspace %s; "
                        "cleanup refused (fail-closed): %s",
                        workspace_id, exc,
                    )
                    return WorkspaceTransition.FAILED
            workspace.state = WorkspaceState.CLEANING
            try:
                if workspace.git_identity is not None:
                    await asyncio.to_thread(
                        restore_git_pointer_for_cleanup,
                        workspace.git_identity,
                    )
                authority = workspace.authority_capability
                if authority is None:
                    raise WorkspaceError("TaskWorkspace authority capability is missing")
                if force:
                    await self._git(
                        workspace.repository_root,
                        "worktree",
                        "remove",
                        "--force",
                        str(workspace.worktree_path),
                        authority=authority.derive(operation_class="git.cleanup"),
                    )
                else:
                    await self._git(
                        workspace.repository_root,
                        "worktree",
                        "remove",
                        str(workspace.worktree_path),
                        authority=authority.derive(operation_class="git.cleanup"),
                    )
            except Exception:  # noqa: BLE001 - worktree cleanup failure is persisted
                workspace.state = WorkspaceState.FAILED
                return WorkspaceTransition.FAILED
            try:
                for artifact in tuple(workspace.change_artifacts):
                    if artifact.parent != workspace.worktree_path.parent:
                        raise WorkspaceError("changeset artifact escaped its authority root")
                    artifact.unlink(missing_ok=True)
                workspace.change_artifacts.clear()
                workspace.change_artifact_bytes = 0
            except (OSError, WorkspaceError):
                workspace.state = WorkspaceState.FAILED
                return WorkspaceTransition.FAILED
            workspace.state = WorkspaceState.CLEANED
            self._task_ids.discard(workspace.task_id)
            self.storage_authority.release(workspace_id)
            recovery_root = (
                workspace.recovery_root / workspace.id / "file-tools"
                if workspace.recovery_root is not None else None
            )
            if recovery_root is not None:
                import shutil

                shutil.rmtree(recovery_root, ignore_errors=True)
            self._storage_mutation_locks.pop(workspace_id, None)
            return WorkspaceTransition.UPDATED
