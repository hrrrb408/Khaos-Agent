"""Async Git Worktree lifecycle manager."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import stat
import tempfile
import uuid
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, TypeVar

from khaos.coding.workspace.artifacts import (
    MAX_CHANGESET_BYTES,
)
from khaos.coding.workspace.artifacts import (
    copy_verified_artifact as _copy_verified_artifact,
)
from khaos.coding.workspace.artifacts import (
    read_verified_artifact as _read_verified_artifact,
)
from khaos.coding.workspace.artifacts import (
    verified_artifact_path as _verified_changeset_artifact_path,
)
from khaos.coding.workspace.artifacts import (
    write_exclusive_artifact as _write_exclusive_artifact,
)
from khaos.coding.workspace.boundary import (
    SafePathError,
    SafeWorkspaceFS,
    WorkspaceBoundaryError,
)
from khaos.coding.workspace.errors import WorkspaceError
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
from khaos.coding.workspace.policy import (
    PROTECTED_WORKSPACE_NAMES,
    path_reaches_protected_metadata,
)
from khaos.coding.workspace.storage import (
    WorkspaceMutation,
    WorkspaceStorageAuthority,
    WorkspaceStorageLimits,
    WorkspaceStorageViolation,
    capture_workspace_snapshot,
)
from khaos.coding.workspace.trusted_git import (
    AuthorityInput,
    GitEffect,
    TrustedGitError,
    TrustedGitRunner,
    WorkspaceBootstrapLimits,
    _parse_index_listing,
)
from khaos.runtime_profile import RuntimeProfile, resolve_runtime_profile
from khaos.security.authority import AuthorityEnvelope
from khaos.security.authority_broker import (
    AuthorityBroker,
    AuthorityBrokerError,
    EffectCapability,
)
from khaos.security.resource_scope import (
    GIT_SCOPE_OPERATIONS,
    GitRefScope,
    ResourceScopeError,
    TypedResourcePartialOrder,
    configured_git_worktree_authority_root,
)

logger = logging.getLogger(__name__)
T = TypeVar("T")
FileIdentity = tuple[int, int, int, int]
MAX_CHANGESET_PREVIEW_BYTES = 64 * 1024
MAX_CHANGESET_FILES = 10_000
MAX_CHANGESET_NAMES_BYTES = 8 * 1024 * 1024
MAX_CHANGESET_STAT_BYTES = 1024 * 1024
MAX_CHANGESET_ARTIFACTS = 64
MAX_CHANGESET_ARTIFACT_BYTES = 256 * 1024 * 1024


@dataclass
class WorkspaceBootstrapTransaction:
    """Durable in-memory ownership record for a worktree bootstrap.

    A worktree and its branch are real Git resources before ``TaskWorkspace``
    is published to ``_workspaces``.  Keeping this transaction in a parent
    registry closes that acquire-to-publish gap: cancellation or a late Git
    failure cannot make the directory/branch disappear from the lifecycle
    graph merely because the normal workspace object was never constructed.
    """

    workspace_id: str
    task_id: str
    repository: Path
    branch_name: str
    base_sha: str
    pending_path: Path
    final_path: Path
    authority_grant: AuthorityEnvelope
    phase: str = "admitted"
    branch_created: bool = False
    published: bool = False
    cleanup_error: BaseException | None = None


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
    if path_reaches_protected_metadata(path):
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


def _safe_verified_artifact_id(storage_id: str) -> str:
    """Validate the opaque name used for manager-owned verified artifacts."""
    if (
        type(storage_id) is not str
        or not storage_id
        or len(storage_id) > 256
        or any(character not in "0123456789abcdef-" for character in storage_id)
    ):
        raise WorkspaceError("verified artifact storage id is invalid")
    return storage_id


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
        authorization_epoch: int = 1,
        resource_order: TypedResourcePartialOrder | None = None,
        runtime_profile: RuntimeProfile | str | None = None,
        authority_broker: AuthorityBroker | None = None,
        principal_id: str = "",
        principal_kind: str = "",
        parent_principal_id: str = "",
        delegation_digest: str = "",
        session_id: str = "",
        source_transport: str = "",
        project_id: str = "",
        runtime_id: str = "",
    ) -> None:
        if root is None:
            try:
                configured_root = configured_git_worktree_authority_root()
            except ResourceScopeError as exc:
                raise WorkspaceError(str(exc)) from exc
            if configured_root is None:
                configured_root = Path(tempfile.gettempdir()) / "khaos" / "worktrees"
        else:
            configured_root = root
        configured_root = configured_root.expanduser().absolute()
        self.runtime_profile = resolve_runtime_profile(runtime_profile)
        if self.runtime_profile.is_production and authority_broker is None:
            raise WorkspaceError(
                "production WorkspaceManager requires the runtime authority broker"
            )
        self._typed_git_worktree_bound = bool(
            resource_order is not None
            and any(
                isinstance(scope, GitRefScope) and scope.worktree_root is not None
                for scope in resource_order.scopes.values()
            )
        )
        self.root, self._root_identity = _open_private_authority_root(
            configured_root
        )
        self._authority_broker = authority_broker or AuthorityBroker.default(
            runtime_profile=self.runtime_profile
        )
        self._principal_id = principal_id
        self._principal_kind = principal_kind
        self._parent_principal_id = parent_principal_id
        self._delegation_digest = delegation_digest
        self._session_id = session_id
        self._source_transport = source_transport
        self._project_id = project_id
        self._runtime_id = runtime_id
        try:
            self._git_runner = TrustedGitRunner.for_authority_root(
                self.root,
                self._root_identity,
                authority_broker=self._authority_broker,
                resource_order=resource_order,
                runtime_profile=self.runtime_profile,
            )
        except TrustedGitError as exc:
            raise WorkspaceError(str(exc)) from exc
        self._sync_git_runner_state()
        self.policy_digest = policy_digest
        if (
            resource_order is not None
            and resource_order.policy_digest is not None
            and resource_order.policy_digest != policy_digest
        ):
            raise WorkspaceError(
                "WorkspaceManager typed resource catalog does not match policy"
            )
        self.resource_order = resource_order
        if authorization_epoch <= 0:
            raise ValueError("workspace authorization epoch must be positive")
        self.authorization_epoch = authorization_epoch
        self.storage_limits = storage_limits or WorkspaceStorageLimits()
        self.storage_authority = storage_authority or WorkspaceStorageAuthority()
        self.bootstrap_limits = bootstrap_limits or WorkspaceBootstrapLimits()
        self._workspaces: dict[str, TaskWorkspace] = {}
        self._task_ids: set[str] = set()
        self._bootstrap_transactions: dict[str, WorkspaceBootstrapTransaction] = {}
        self._quarantined_bootstraps: dict[str, WorkspaceBootstrapTransaction] = {}
        # Verified publication artifacts are independent of disposable
        # worktrees.  Their registry is the sole in-process owner; merge
        # orchestration must release each entry before reporting terminal
        # success.
        self._verified_artifacts: dict[str, ChangeSetArtifact] = {}
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

    @property
    def authority_broker(self) -> AuthorityBroker:
        """Return the one runtime authority used by every workspace effect."""
        return self._authority_broker

    def _sync_git_runner_state(self) -> None:
        """Persist a runner's selected, revalidated executable identity."""
        self._git_executable = self._git_runner.executable
        self._git_identity = self._git_runner.git_identity
        self._git_digest = self._git_runner.git_digest

    def set_lease_invalidation_hook(self, hook: Any) -> None:
        """Register a callable invoked during cleanup to release execution leases."""
        self._lease_invalidation_hook = hook

    def set_mutation_fence(self, fence: Any) -> None:
        """Batch 2.6 §5: register the shared per-workspace mutation fence."""
        self._mutation_fence = fence

    def owned_resources(self) -> tuple[str, ...]:
        """Describe workspaces and bootstrap transactions still owned here."""
        resources = [f"workspace:{workspace_id}" for workspace_id in self._workspaces]
        resources.extend(
            f"bootstrap:{workspace_id}"
            for workspace_id in {
                *self._bootstrap_transactions,
                *self._quarantined_bootstraps,
            }
        )
        resources.extend(
            f"verified-artifact:{storage_id}"
            for storage_id in self._verified_artifacts
        )
        runner_resources = getattr(self._git_runner, "owned_resources", None)
        if callable(runner_resources):
            resources.extend(f"git:{item}" for item in runner_resources())
        return tuple(sorted(resources))

    def terminal_postcondition(self) -> bool:
        """Prove that no bootstrap or child Git process is unaccounted for."""
        runner_terminal = getattr(self._git_runner, "terminal_postcondition", None)
        return (
            not self._bootstrap_transactions
            and not self._quarantined_bootstraps
            and not self._verified_artifacts
            and (not callable(runner_terminal) or bool(runner_terminal()))
        )

    @property
    def is_quarantined(self) -> bool:
        """Whether a bootstrap cleanup failure retained an owned resource."""
        return bool(self._quarantined_bootstraps)

    async def retry_quarantined_bootstraps(self) -> None:
        """Retry retained bootstrap cleanup without dropping its ownership."""
        for workspace_id in tuple(self._quarantined_bootstraps):
            transaction = self._quarantined_bootstraps[workspace_id]
            try:
                await self._rollback_bootstrap(transaction)
            except BaseException as exc:  # noqa: BLE001 - retain quarantine
                transaction.cleanup_error = exc
                logger.error(
                    "workspace bootstrap remains quarantined: %s: %s",
                    workspace_id,
                    exc,
                )
                continue
            try:
                self._authority_broker.revoke_grant(transaction.authority_grant)
            except BaseException as exc:  # noqa: BLE001 - retain live grant ownership
                transaction.cleanup_error = exc
                logger.error(
                    "workspace bootstrap grant remains live: %s: %s",
                    workspace_id,
                    exc,
                )
                continue
            self._quarantined_bootstraps.pop(workspace_id, None)
            self._task_ids.discard(transaction.task_id)

    async def close(self) -> None:
        """Close the trusted Git owner after all bootstrap transactions settle."""
        await self.retry_quarantined_bootstraps()
        close_runner = getattr(self._git_runner, "close", None)
        if callable(close_runner):
            await close_runner()
        if not self.terminal_postcondition():
            raise WorkspaceError(
                "WorkspaceManager close could not prove bootstrap/Git ownership is terminal"
            )

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
                workspace.change_artifact_files.pop(artifact_path, None)
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
            principal_id=self._principal_id or "legacy",
            project_id=self._project_id or "local",
            runtime_id=self._runtime_id or "workspace-manager",
            task_id="host-git",
            workspace_id=repository.name or "repository",
            workspace_generation=1,
            policy_digest=self.policy_digest,
            operation_class="git.host",
            authorization_epoch=self.authorization_epoch,
            resource_digest=self._git_resource_digest(repository),
            principal_kind=self._principal_kind,
            parent_principal_id=self._parent_principal_id,
            session_id=self._session_id,
            delegation_digest=self._delegation_digest,
            source_transport=self._source_transport,
        )

    def _git_resource_digest(self, repository: Path) -> str:
        """Return the catalog-bound Git scope for one canonical repository."""
        canonical_repository = repository.resolve()
        if self.resource_order is None:
            return hashlib.sha256(
                str(canonical_repository).encode("utf-8")
            ).hexdigest()
        scope = GitRefScope(
            repository=str(canonical_repository),
            refs=frozenset({"HEAD"}),
            ref_namespaces=frozenset({"refs/heads/khaos/task/"}),
            operations=GIT_SCOPE_OPERATIONS,
            worktree_root=str(self.root) if self._typed_git_worktree_bound else None,
        )
        try:
            return self.resource_order.require_scope(scope)
        except ResourceScopeError as exc:
            raise WorkspaceError(
                "repository is not represented by the typed authority catalog"
            ) from exc

    @staticmethod
    def _workspace_authority(
        workspace: TaskWorkspace, operation_class: str
    ) -> AuthorityInput:
        """Return a renewable grant, with legacy receipt compatibility."""
        if workspace.authority_envelope is not None:
            return workspace.authority_envelope.derive(
                operation_class=operation_class
            )
        if workspace.authority_capability is not None:
            return workspace.authority_capability.derive(
                operation_class=operation_class
            )
        raise WorkspaceError("TaskWorkspace authority grant is missing")

    async def _git(
        self,
        repository: Path,
        *args: str,
        authority: EffectCapability | None = None,
        authority_grant: AuthorityEnvelope | None = None,
        preserve_output: bool = False,
        effect: GitEffect | None = None,
    ) -> str:
        try:
            # Keep one manager-owned runner so every Git process owner is
            # visible to the parent lifecycle registry.  Re-apply the
            # manager's startup/revalidation fields before each call so the
            # existing digest-drift fail-closed contract remains intact.
            runner = self._git_runner
            runner.executable = self._git_executable
            runner.git_identity = self._git_identity
            runner.git_digest = self._git_digest
            if authority is None:
                context = authority_grant or self._default_git_authority(repository)
                if not isinstance(context, AuthorityEnvelope):
                    raise WorkspaceError("trusted Git authority grant is invalid")
                effect_authority: AuthorityInput = context
            elif isinstance(authority, EffectCapability):
                effect_authority = authority
            else:
                raise WorkspaceError(
                    "trusted Git requires a broker-issued capability; "
                    "AuthorityEnvelope is context only"
                )
            if effect is not None and tuple(args) != effect.args:
                raise WorkspaceError(
                    "structured Git effect does not match the requested argv"
                )
            if effect is None:
                return await runner.run(
                    repository,
                    *args,
                    authority=effect_authority,
                    preserve_output=preserve_output,
                )
            return await runner.run_effect(
                repository,
                effect,
                authority=effect_authority,
                preserve_output=preserve_output,
            )
        except TrustedGitError as exc:
            raise WorkspaceError(str(exc)) from exc
        finally:
            self._sync_git_runner_state()

    async def _materialize_git_tree(
        self,
        repository: Path,
        base_sha: str,
        worktree: Path,
        *,
        authority: AuthorityInput,
    ) -> None:
        try:
            runner = self._git_runner
            runner.executable = self._git_executable
            runner.git_identity = self._git_identity
            runner.git_digest = self._git_digest
            await runner.materialize_tree(
                repository,
                base_sha,
                worktree,
                authority=authority.derive(operation_class="git.materialize"),
                limits=self.bootstrap_limits,
            )
        except TrustedGitError as exc:
            raise WorkspaceError(str(exc)) from exc
        finally:
            self._sync_git_runner_state()

    async def _workspace_git(
        self,
        workspace: TaskWorkspace,
        *args: str,
        preserve_output: bool = False,
        index_file: Path | None = None,
        effect: GitEffect | None = None,
    ) -> str:
        """Run Git only against the pinned admin dir and worktree."""
        identity = workspace.git_identity
        if identity is None:
            raise WorkspaceError("TaskWorkspace Git identity is missing")
        try:
            await asyncio.to_thread(verify_git_worktree_identity, identity)
        except GitIdentityError as exc:
            raise WorkspaceError(str(exc)) from exc
        authority = self._workspace_authority(
            workspace,
            f"git.{effect.required_operation}"
            if effect is not None and effect.required_operation is not None
            else "git.workspace",
        )
        try:
            if effect is not None and tuple(args) != effect.args:
                raise WorkspaceError(
                    "structured Git effect does not match the requested argv"
                )
            if effect is None:
                return await self._git_runner.run(
                    workspace.worktree_path,
                    f"--git-dir={identity.admin_dir}",
                    f"--work-tree={workspace.worktree_path}",
                    *args,
                    authority=authority,
                    preserve_output=preserve_output,
                    index_file=index_file,
                )
            effect = effect.with_prefix(
                (
                    f"--git-dir={identity.admin_dir}",
                    f"--work-tree={workspace.worktree_path}",
                )
            )
            return await self._git_runner.run_effect(
                workspace.worktree_path,
                effect,
                authority=authority,
                preserve_output=preserve_output,
                index_file=index_file,
            )
        except TrustedGitError as exc:
            raise WorkspaceError(str(exc)) from exc
        finally:
            self._sync_git_runner_state()

    async def _workspace_git_input(
        self,
        workspace: TaskWorkspace,
        *args: str,
        input_bytes: bytes,
        max_input_bytes: int = 64 * 1024,
        index_file: Path | None = None,
        effect: GitEffect | None = None,
    ) -> str:
        """Run one audited Git plumbing operation with bounded stdin."""
        identity = workspace.git_identity
        if identity is None:
            raise WorkspaceError("TaskWorkspace Git identity is missing")
        authority = self._workspace_authority(
            workspace,
            f"git.{effect.required_operation}"
            if effect is not None and effect.required_operation is not None
            else "git.workspace",
        )
        try:
            await asyncio.to_thread(verify_git_worktree_identity, identity)
            if effect is not None and tuple(args) != effect.args:
                raise WorkspaceError(
                    "structured Git effect does not match the requested argv"
                )
            if effect is None:
                return await self._git_runner.run_with_input(
                    workspace.worktree_path,
                    f"--git-dir={identity.admin_dir}",
                    f"--work-tree={workspace.worktree_path}",
                    *args,
                    input_bytes=input_bytes,
                    max_input_bytes=max_input_bytes,
                    authority=authority,
                    index_file=index_file,
                )
            effect = effect.with_prefix(
                (
                    f"--git-dir={identity.admin_dir}",
                    f"--work-tree={workspace.worktree_path}",
                )
            )
            return await self._git_runner.run_effect_with_input(
                workspace.worktree_path,
                effect,
                input_bytes=input_bytes,
                max_input_bytes=max_input_bytes,
                authority=authority,
                index_file=index_file,
            )
        except (GitIdentityError, TrustedGitError) as exc:
            raise WorkspaceError(str(exc)) from exc
        finally:
            self._sync_git_runner_state()

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
        if identity is None:
            raise WorkspaceError("TaskWorkspace Git identity is missing")
        authority = self._workspace_authority(workspace, "git.workspace")
        try:
            await asyncio.to_thread(verify_git_worktree_identity, identity)
            return await self._git_runner.hash_fd(
                workspace.worktree_path,
                descriptor,
                expected,
                authority=authority,
                max_bytes=max_bytes,
            )
        except (GitIdentityError, TrustedGitError) as exc:
            raise WorkspaceError(str(exc)) from exc
        finally:
            self._sync_git_runner_state()

    async def _workspace_git_bytes_limited(
        self,
        workspace: TaskWorkspace,
        *args: str,
        max_bytes: int,
        index_file: Path | None = None,
    ) -> bytes:
        """Run one workspace Git read with an explicit output cap."""
        identity = workspace.git_identity
        if identity is None:
            raise WorkspaceError("TaskWorkspace Git identity is missing")
        authority = self._workspace_authority(workspace, "git.workspace")
        try:
            await asyncio.to_thread(verify_git_worktree_identity, identity)
            return await self._git_runner.run_bytes_limited(
                workspace.worktree_path,
                f"--git-dir={identity.admin_dir}",
                f"--work-tree={workspace.worktree_path}",
                *args,
                authority=authority,
                max_bytes=max_bytes,
                index_file=index_file,
            )
        except (GitIdentityError, TrustedGitError) as exc:
            raise WorkspaceError(str(exc)) from exc
        finally:
            self._sync_git_runner_state()

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
        if identity is None:
            raise WorkspaceError("TaskWorkspace Git identity is missing")
        authority = self._workspace_authority(workspace, "git.workspace")
        try:
            await asyncio.to_thread(verify_git_worktree_identity, identity)
            return await self._git_runner.stream_to_file(
                workspace.worktree_path,
                f"--git-dir={identity.admin_dir}",
                f"--work-tree={workspace.worktree_path}",
                *args,
                destination=destination,
                authority=authority,
                max_bytes=max_bytes,
                preview_bytes=MAX_CHANGESET_PREVIEW_BYTES,
                index_file=index_file,
            )
        except (GitIdentityError, TrustedGitError) as exc:
            raise WorkspaceError(str(exc)) from exc
        finally:
            self._sync_git_runner_state()

    async def _workspace_diff_digest(
        self, workspace: TaskWorkspace, *, base_sha: str | None = None
    ) -> str:
        """Hash the current raw diff without materializing it in Python memory."""
        diff_base = base_sha or workspace.base_sha
        index_file = workspace.worktree_path.parent / f".binding-index-{uuid.uuid4().hex}"
        temporary = workspace.worktree_path.parent / f".binding-{uuid.uuid4().hex}.patch"
        try:
            await self._prepare_raw_changeset_index(
                workspace, index_file, base_sha=diff_base
            )
            result = await self._workspace_git_stream(
                workspace,
                "diff",
                "--cached",
                "--no-ext-diff",
                "--no-textconv",
                "--binary",
                diff_base,
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
        self,
        workspace: TaskWorkspace,
        index_file: Path,
        *,
        base_sha: str | None = None,
    ) -> None:
        """Build a temporary raw-byte index, bypassing all clean filters."""
        index_base = base_sha or workspace.base_sha
        tracked_listing = await self._workspace_git_bytes_limited(
            workspace, "ls-files", "--stage", "-z", max_bytes=MAX_CHANGESET_NAMES_BYTES
        )
        tracked = _parse_index_listing(
            tracked_listing, object_id_length=len(index_base)
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
            index_base,
            index_file=index_file,
            effect=GitEffect.read_tree(
                repository_id=str(workspace.repository_root.resolve()),
                treeish=index_base,
                required_operation="index",
            ),
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
                    effect=GitEffect.update_index_remove(
                        repository_id=str(workspace.repository_root.resolve()),
                        path=safe_relative,
                        required_operation="index",
                    ),
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
                    effect=GitEffect.update_index_remove(
                        repository_id=str(workspace.repository_root.resolve()),
                        path=safe_relative,
                        required_operation="index",
                    ),
                )
                continue
            object_id, mode = await self._hash_workspace_entry(
                workspace, safe_relative, info
            )
            if len(object_id) != len(index_base) or any(
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
                effect=GitEffect.update_index_cacheinfo(
                    repository_id=str(workspace.repository_root.resolve()),
                    mode=mode,
                    object_id=object_id,
                    path=safe_relative,
                    required_operation="index",
                ),
            )

    async def _rollback_bootstrap(
        self, transaction: WorkspaceBootstrapTransaction
    ) -> None:
        """Remove every Git resource acquired by a failed bootstrap.

        The operation is deliberately idempotent and uses Git for both
        worktree administration and branch deletion.  A CAS old-value on the
        branch prevents a late cleanup from deleting a ref that advanced
        outside this transaction.
        """
        transaction.phase = "rolling-back"
        errors: list[BaseException] = []
        for candidate in (transaction.pending_path, transaction.final_path):
            if not candidate.exists() and not candidate.is_symlink():
                continue
            try:
                await self._git(
                    transaction.repository,
                    "worktree",
                    "remove",
                    "--force",
                    str(candidate),
                    authority_grant=transaction.authority_grant.derive(
                        operation_class="git.cleanup"
                    ),
                    effect=GitEffect.worktree_remove(
                        repository_id=str(transaction.repository.resolve()),
                        path=str(candidate),
                        force=True,
                        required_operation="cleanup",
                    ),
                )
            except BaseException as exc:  # noqa: BLE001 - quarantine on proof failure
                errors.append(exc)
        for candidate in (transaction.pending_path, transaction.final_path):
            if candidate.exists() or candidate.is_symlink():
                errors.append(
                    WorkspaceError(
                        f"bootstrap worktree path remains after rollback: {candidate}"
                    )
                )
        if transaction.branch_created:
            try:
                await self._git(
                    transaction.repository,
                    "update-ref",
                    "-d",
                    _safe_branch_ref(transaction.branch_name),
                    transaction.base_sha,
                    authority_grant=transaction.authority_grant.derive(
                        operation_class="git.cleanup-ref"
                    ),
                    effect=GitEffect.update_ref(
                        repository_id=str(transaction.repository.resolve()),
                        ref_name=_safe_branch_ref(transaction.branch_name),
                        new_oid=None,
                        expected_old_oid=transaction.base_sha,
                        delete=True,
                        required_operation="cleanup-ref",
                    ),
                )
            except BaseException as exc:  # noqa: BLE001 - retain branch ownership
                errors.append(exc)
        if errors:
            transaction.phase = "quarantined"
            raise WorkspaceError(
                "bootstrap rollback did not prove terminal cleanup: "
                + "; ".join(type(error).__name__ for error in errors)
            ) from errors[0]
        transaction.phase = "rolled-back"
        transaction.branch_created = False
        transaction.published = False

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
            if task_id in self._task_ids or any(
                transaction.task_id == task_id
                for transaction in (
                    *self._bootstrap_transactions.values(),
                    *self._quarantined_bootstraps.values(),
                )
            ):
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
                authorization_epoch=self.authorization_epoch,
                resource_digest=self._git_resource_digest(repository),
                principal_kind=self._principal_kind,
                parent_principal_id=self._parent_principal_id,
                session_id=self._session_id,
                delegation_digest=self._delegation_digest,
                source_transport=self._source_transport,
            )
            branch = f"khaos/task/{task_id}"
            path = (self.root / workspace_id).resolve()
            pending_path = (self.root / f".pending-{workspace_id}").resolve()
            transaction = WorkspaceBootstrapTransaction(
                workspace_id=workspace_id,
                task_id=task_id,
                repository=repository,
                branch_name=branch,
                base_sha="",
                pending_path=pending_path,
                final_path=path,
                authority_grant=authority_context,
            )
            self._bootstrap_transactions[workspace_id] = transaction
            self._task_ids.add(task_id)
            try:
                dirty = await self._git(
                    repository,
                    "status",
                    "--porcelain",
                    authority_grant=authority_context,
                )
                if dirty:
                    raise WorkspaceError("主工作树存在未提交修改，拒绝创建可写 Worktree")
                base_sha = await self._git(
                    repository,
                    "rev-parse",
                    base_ref,
                    authority_grant=authority_context,
                )
                transaction.base_sha = base_sha
                path.parent.mkdir(parents=True, exist_ok=True)
                if (
                    path.exists()
                    or path.is_symlink()
                    or pending_path.exists()
                    or pending_path.is_symlink()
                ):
                    raise WorkspaceError("workspace bootstrap path already exists")
                transaction.phase = "creating-worktree"
                await self._git(
                    repository,
                    "worktree",
                    "add",
                    "--no-checkout",
                    "-b",
                    branch,
                    str(pending_path),
                    base_sha,
                    authority_grant=authority_context.derive(
                        operation_class="git.workspace"
                    ),
                    effect=GitEffect.worktree_add(
                        repository_id=str(repository.resolve()),
                        branch=branch,
                        path=str(pending_path),
                        base_oid=base_sha,
                        required_operation="workspace",
                    ),
                )
                transaction.branch_created = True
                transaction.phase = "worktree-created"
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
                    authority_grant=authority_context.derive(operation_class="git.index"),
                    effect=GitEffect.read_tree(
                        repository_id=str(repository.resolve()),
                        treeish=base_sha,
                        prefix=(
                            f"--git-dir={git_identity.admin_dir}",
                            f"--work-tree={pending_path}",
                        ),
                        required_operation="index",
                    ),
                )
                await self._materialize_git_tree(
                    repository,
                    base_sha,
                    pending_path,
                    authority=authority_context,
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
                    authority_grant=authority_context.derive(
                        operation_class="git.workspace"
                    ),
                    effect=GitEffect.worktree_move(
                        repository_id=str(repository.resolve()),
                        source=str(pending_path),
                        destination=str(path),
                        required_operation="workspace",
                    ),
                )
                transaction.published = True
                transaction.phase = "published"
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
                    authority_capability=None,
                )
                workspace.storage_baseline = baseline
                self._workspaces[workspace_id] = workspace
                transaction.phase = "committed"
                self._bootstrap_transactions.pop(workspace_id, None)
                return workspace
            except BaseException:
                # Cancellation is part of the transaction protocol: cleanup
                # must finish (or be retained in quarantine) before the
                # caller receives the original cancellation/failure.
                cleanup_task = asyncio.create_task(
                    self._rollback_bootstrap(transaction),
                    name=f"khaos-bootstrap-rollback:{workspace_id}",
                )
                cleanup_error: BaseException | None = None
                while not cleanup_task.done():
                    try:
                        await asyncio.shield(cleanup_task)
                    except asyncio.CancelledError:
                        continue
                try:
                    await cleanup_task
                except BaseException as exc:  # noqa: BLE001 - retain ownership
                    cleanup_error = exc
                if cleanup_error is None:
                    try:
                        self._authority_broker.revoke_grant(authority_context)
                    except BaseException as exc:  # noqa: BLE001 - retain live grant ownership
                        cleanup_error = exc
                self._workspaces.pop(workspace_id, None)
                self._bootstrap_transactions.pop(workspace_id, None)
                if cleanup_error is None:
                    self._task_ids.discard(task_id)
                else:
                    transaction.cleanup_error = cleanup_error
                    self._quarantined_bootstraps[workspace_id] = transaction
                    logger.error(
                        "bootstrap cleanup failed; transaction quarantined: %s: %s",
                        workspace_id,
                        cleanup_error,
                    )
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

    async def current_head(self, workspace_id: str) -> str:
        """Read the server-owned HEAD of one registered TaskWorkspace."""
        workspace = self._workspaces.get(workspace_id)
        if workspace is None:
            raise WorkspaceError("workspace not found")
        return await self._workspace_git(workspace, "rev-parse", "HEAD")

    async def current_tree(self, workspace_id: str, *, commit: str | None = None) -> str:
        """Return the trusted Git tree object for a registered workspace commit."""
        workspace = self._workspaces.get(workspace_id)
        if workspace is None:
            raise WorkspaceError("workspace not found")
        target = commit or await self.current_head(workspace_id)
        if (
            type(target) is not str
            or len(target) not in {40, 64}
            or any(character not in "0123456789abcdef" for character in target)
        ):
            raise WorkspaceError("workspace commit is not a valid Git object id")
        tree = await self._workspace_git(workspace, "rev-parse", f"{target}^{{tree}}")
        if (
            len(tree) not in {40, 64}
            or any(character not in "0123456789abcdef" for character in tree)
        ):
            raise WorkspaceError("Git returned an invalid tree object id")
        return tree

    async def require_stable(
        self,
        workspace_id: str,
        *,
        task_id: str,
        expected_generation: int | None = None,
    ) -> tuple[str, int]:
        """Return ``(HEAD, generation)`` only for a clean stable workspace."""
        async with self.stable_workspace_scope(
            workspace_id,
            task_id=task_id,
            expected_generation=expected_generation,
        ) as snapshot:
            return snapshot[0], snapshot[1]

    @asynccontextmanager
    async def stable_workspace_scope(
        self,
        workspace_id: str,
        *,
        task_id: str,
        expected_generation: int | None = None,
    ) -> AsyncIterator[tuple[str, int, TaskWorkspace]]:
        """Hold the storage fence while validating and exposing a clean snapshot.

        Child bootstrap callers use this scope to close the gap between a
        stable-parent check and creation of the child Worktree.  The yielded
        ``(HEAD, generation, workspace)`` remains bound to the same manager
        object while the per-workspace storage fence is held.
        """
        async with self.workspace_storage_scope(workspace_id, task_id) as workspace:
            if workspace.state not in {WorkspaceState.READY, WorkspaceState.RUNNING}:
                raise WorkspaceError("workspace is not in a stable coding state")
            if workspace.change_artifact_reservations:
                raise WorkspaceError("workspace has an in-flight ChangeSet capture")
            if expected_generation is not None and workspace.generation != expected_generation:
                raise WorkspaceError("workspace generation is stale")
            await self.verify_execution_root(workspace_id)
            head = await self._workspace_git(workspace, "rev-parse", "HEAD")
            if await self._workspace_diff_digest(workspace, base_sha=head) != hashlib.sha256(b"").hexdigest():
                raise WorkspaceError("workspace has uncommitted changes")
            yield head, workspace.generation, workspace

    async def apply_verified_patch(
        self,
        workspace_id: str,
        patch_path: Path,
        patch_sha256: str,
        patch_length: int,
        *,
        expected_head: str | None = None,
        require_clean: bool = True,
    ) -> None:
        """Apply one authority-owned artifact through the Trusted Git gate."""
        workspace = self._workspaces.get(workspace_id)
        if workspace is None:
            raise WorkspaceError("workspace not found")
        if workspace.state in {
            WorkspaceState.FAILED,
            WorkspaceState.CANCELLED,
            WorkspaceState.CLEANING,
            WorkspaceState.CLEANED,
        }:
            raise WorkspaceError("workspace is not writable")
        candidate = patch_path.absolute()
        try:
            if candidate.resolve(strict=True) != candidate:
                raise WorkspaceError("patch artifact path is not canonical")
            candidate.parent.resolve(strict=True).relative_to(self.root)
            info = candidate.stat()
        except WorkspaceError:
            raise
        except (OSError, ValueError) as exc:
            raise WorkspaceError(
                "patch artifact is outside the private authority root"
            ) from exc
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise WorkspaceError("patch artifact is not a private regular file")
        try:
            await asyncio.to_thread(
                _read_verified_artifact,
                candidate,
                patch_length,
                patch_sha256,
                MAX_CHANGESET_BYTES,
            )
        except (OSError, WorkspaceError) as exc:
            raise WorkspaceError("patch artifact digest or length drifted") from exc
        current_head = await self._workspace_git(workspace, "rev-parse", "HEAD")
        if expected_head is not None and current_head != expected_head:
            raise WorkspaceError("workspace HEAD changed before patch application")
        if require_clean and await self._workspace_diff_digest(
            workspace, base_sha=current_head
        ) != hashlib.sha256(b"").hexdigest():
            raise WorkspaceError("workspace is dirty before patch application")
        try:
            effect = GitEffect.apply_index_file(
                repository_id=str(workspace.repository_root.resolve()),
                patch_path=str(candidate),
                patch_sha256=patch_sha256,
                patch_length=patch_length,
                required_operation="merge-apply",
            )
        except ValueError as exc:
            raise WorkspaceError(str(exc)) from exc
        await self._workspace_git(
            workspace,
            "apply",
            "--index",
            str(candidate),
            effect=effect,
        )

    async def mutate_with_storage_authority(
        self,
        workspace_id: str,
        task_id: str,
        operation: Callable[[], WorkspaceMutation[T]],
        *,
        advance_generation: bool = True,
    ) -> T:
        """Serialize, account, and if necessary roll back one file-tool write.

        A successful mutation advances the server-owned TaskWorkspace
        generation while the per-workspace storage lock is still held.  This
        is the CAS authority consumed by edit transactions and repository
        freshness checks; callers cannot supply or advance it themselves.
        """
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
                mutation_advances_generation = True

                def governed_operation() -> WorkspaceMutation[T]:
                    nonlocal mutation_advances_generation
                    mutation = operation()
                    mutation_advances_generation = mutation.advances_generation
                    return mutation

                worker = asyncio.create_task(asyncio.to_thread(
                    self.storage_authority.mutate,
                    workspace_id,
                    workspace.worktree_path,
                    workspace.storage_baseline,
                    workspace.storage_limits,
                    governed_operation,
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
                if advance_generation and mutation_advances_generation:
                    async with self._lock:
                        current = self._workspaces.get(workspace_id)
                        if current is None or current is not workspace:
                            raise WorkspaceError(
                                "TaskWorkspace identity changed after mutation"
                            )
                        if (
                            type(current.generation) is not int
                            or current.generation <= 0
                        ):
                            raise WorkspaceError(
                                "TaskWorkspace generation is invalid"
                            )
                        current.generation += 1
                if cancelled:
                    raise asyncio.CancelledError
                return result
        except WorkspaceStorageViolation as exc:
            if exc.quarantine_required:
                await self.quarantine(workspace_id)
            raise

    @asynccontextmanager
    async def workspace_storage_scope(
        self,
        workspace_id: str,
        task_id: str,
    ) -> AsyncIterator[TaskWorkspace]:
        """Serialize a bounded workspace read with storage mutations.

        Preview and other read-only projections use this scope so they cannot
        observe a multi-file mutation between individual publishes while the
        server-owned workspace generation still has its old value.
        """
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
                raise PermissionError("workspace is not readable")
            storage_lock = self._storage_mutation_locks.setdefault(
                workspace_id, asyncio.Lock()
            )
        async with storage_lock:
            async with self._lock:
                current = self._workspaces.get(workspace_id)
                if current is None or current is not workspace:
                    raise PermissionError("workspace identity changed")
                if current.state in {
                    WorkspaceState.FAILED,
                    WorkspaceState.CANCELLED,
                    WorkspaceState.CLEANING,
                    WorkspaceState.CLEANED,
                }:
                    raise PermissionError("workspace is not readable")
            yield workspace

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

    async def build_changeset(
        self, workspace_id: str, *, base_sha: str | None = None
    ) -> ChangeSet:
        """Capture a stable ChangeSet while holding the shared mutation fence.

        ``base_sha`` is a controlled publication seam.  It is accepted only
        when it names the workspace's current HEAD; callers cannot use it to
        reinterpret a stale worktree as a fresh ChangeSet.
        """
        async with self._lock:
            workspace = self._workspaces.get(workspace_id)
            if workspace is None:
                raise WorkspaceError("workspace not found")
        async with self._changeset_mutation_scope(
            workspace_id, f"changeset:{uuid.uuid4().hex}"
        ):
            return await self._build_changeset_unfenced(
                workspace_id, base_sha=base_sha
            )

    async def _build_changeset_unfenced(
        self, workspace_id: str, *, base_sha: str | None = None
    ) -> ChangeSet:
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
        changeset_base = base_sha or workspace.base_sha
        index_file = workspace.worktree_path.parent / f".changeset-index-{uuid.uuid4().hex}"
        artifact_path: Path | None = None
        artifact_registered = False
        artifact_length = 0
        authority_generation = workspace.authority_generation
        git_identity = workspace.git_identity
        try:
            current_head = await self._workspace_git(workspace, "rev-parse", "HEAD")
            if current_head != changeset_base:
                raise WorkspaceError("ChangeSet base SHA is stale")
            if git_identity is None:
                raise WorkspaceError("TaskWorkspace Git identity is missing")
            await self._assert_changeset_snapshot(
                workspace, authority_generation, git_identity
            )
            await self._prepare_raw_changeset_index(
                workspace, index_file, base_sha=changeset_base
            )
            names_raw = await self._workspace_git_bytes_limited(
                workspace,
                "diff",
                "--cached",
                "--no-ext-diff",
                "--no-textconv",
                "--name-only",
                "-z",
                changeset_base,
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
                changeset_base,
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
                changeset_base,
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
                workspace.change_artifact_files[artifact_path] = changed_files
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
                base_sha=changeset_base,
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

    def changeset_artifact_files(
        self, workspace_id: str, artifact_path: Path
    ) -> tuple[str, ...]:
        """Return the manager-captured paths for one live artifact.

        The mapping is intentionally owned by ``WorkspaceManager`` and is
        available only while the producing workspace is live.  Callers cannot
        register arbitrary paths; ``build_changeset`` records the Git-derived
        list at the same time it registers the bounded artifact.
        """
        workspace = self._workspaces.get(workspace_id)
        if workspace is None:
            raise WorkspaceError("workspace not found")
        candidate = artifact_path.absolute()
        try:
            return workspace.change_artifact_files[candidate]
        except KeyError as exc:
            raise WorkspaceError("changeset artifact is not owned by workspace") from exc

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

    def _verified_artifact_path(self, storage_id: str) -> Path:
        """Derive one canonical path below the private authority root."""
        safe_id = _safe_verified_artifact_id(storage_id)
        return self.root / f".khaos-verified-{safe_id}.patch"

    async def freeze_verified_changeset_artifact(
        self,
        workspace_id: str,
        changeset: ChangeSet,
        *,
        storage_id: str,
    ) -> ChangeSetArtifact:
        """Promote a ChangeSet artifact to an independent merge-owned file.

        The source remains owned by the producing workspace while it is
        copied.  The destination is created exclusively below the manager's
        private root, verified by digest/length, and then registered under a
        separate lifecycle owner so worktree cleanup cannot delete the
        publication input.
        """
        workspace = self._workspaces.get(workspace_id)
        if workspace is None or changeset.workspace_id != workspace_id:
            raise WorkspaceError("workspace or changeset not found")
        if changeset.artifact is None:
            raise WorkspaceError("verified publication requires a ChangeSet artifact")
        safe_id = _safe_verified_artifact_id(storage_id)
        destination = self._verified_artifact_path(safe_id)
        async with self._lock:
            existing = self._verified_artifacts.get(safe_id)
            if existing is not None:
                if (
                    existing.sha256 != changeset.artifact.sha256
                    or existing.byte_length != changeset.artifact.byte_length
                ):
                    raise WorkspaceError("verified artifact storage identity is already bound")
                return existing
            if destination.exists() or destination.is_symlink():
                raise WorkspaceError("verified artifact destination already exists")
        await self.export_changeset_artifact(workspace_id, changeset, destination)
        try:
            await asyncio.to_thread(
                _read_verified_artifact,
                destination,
                changeset.artifact.byte_length,
                changeset.artifact.sha256,
                MAX_CHANGESET_BYTES,
            )
        except BaseException:
            destination.unlink(missing_ok=True)
            raise
        artifact = ChangeSetArtifact(
            path=destination,
            byte_length=changeset.artifact.byte_length,
            sha256=changeset.artifact.sha256,
            preview=changeset.artifact.preview,
        )
        async with self._lock:
            existing = self._verified_artifacts.get(safe_id)
            if existing is not None:
                destination.unlink(missing_ok=True)
                if (
                    existing.sha256 != artifact.sha256
                    or existing.byte_length != artifact.byte_length
                ):
                    raise WorkspaceError("verified artifact storage identity is already bound")
                return existing
            self._verified_artifacts[safe_id] = artifact
        return artifact

    async def load_verified_artifact(
        self,
        *,
        storage_id: str,
        sha256: str,
        byte_length: int,
    ) -> ChangeSetArtifact:
        """Re-admit a durable verified artifact after restart by exact identity."""
        safe_id = _safe_verified_artifact_id(storage_id)
        if type(sha256) is not str or len(sha256) != 64:
            raise WorkspaceError("verified artifact digest is invalid")
        if type(byte_length) is not int or byte_length <= 0:
            raise WorkspaceError("verified artifact length is invalid")
        path = self._verified_artifact_path(safe_id)
        await asyncio.to_thread(
            _read_verified_artifact,
            path,
            byte_length,
            sha256,
            MAX_CHANGESET_BYTES,
        )
        artifact = ChangeSetArtifact(
            path=path,
            byte_length=byte_length,
            sha256=sha256,
            preview="",
        )
        async with self._lock:
            existing = self._verified_artifacts.get(safe_id)
            if existing is not None and (
                existing.sha256 != sha256 or existing.byte_length != byte_length
            ):
                raise WorkspaceError("verified artifact identity changed during recovery")
            self._verified_artifacts[safe_id] = existing or artifact
            return self._verified_artifacts[safe_id]

    async def get_verified_artifact(self, storage_id: str) -> ChangeSetArtifact:
        """Return a manager-owned verified artifact, rechecking its bytes."""
        safe_id = _safe_verified_artifact_id(storage_id)
        async with self._lock:
            artifact = self._verified_artifacts.get(safe_id)
        if artifact is None:
            raise WorkspaceError("verified artifact is not owned by the manager")
        await asyncio.to_thread(
            _read_verified_artifact,
            artifact.path,
            artifact.byte_length,
            artifact.sha256,
            MAX_CHANGESET_BYTES,
        )
        return artifact

    async def release_verified_artifact(self, storage_id: str) -> WorkspaceTransition:
        """Release one merge-owned artifact only after its lifecycle settles."""
        safe_id = _safe_verified_artifact_id(storage_id)
        async with self._lock:
            artifact = self._verified_artifacts.get(safe_id)
            if artifact is None:
                return WorkspaceTransition.NOT_FOUND
            try:
                await asyncio.to_thread(
                    _read_verified_artifact,
                    artifact.path,
                    artifact.byte_length,
                    artifact.sha256,
                    MAX_CHANGESET_BYTES,
                )
            except (OSError, WorkspaceError):
                # A tampered publication input is retained as an owned
                # resource.  Do not turn a failed integrity check into a
                # successful release/quiescent manager state.
                return WorkspaceTransition.FAILED
            try:
                artifact.path.unlink(missing_ok=True)
            except OSError:
                return WorkspaceTransition.FAILED
            self._verified_artifacts.pop(safe_id, None)
            return WorkspaceTransition.UPDATED

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

    async def commit_current_changeset(
        self,
        workspace_id: str,
        changeset: ChangeSet,
        message: str,
        *,
        expected_head: str,
        expected_generation: int,
    ) -> str:
        """Commit a ChangeSet against a parent HEAD with a generation CAS.

        Normal child commits retain the historical ``commit_in_worktree``
        behavior.  Parent publication uses this explicit seam so a merge
        cannot silently commit on a newer parent branch or generation.
        """
        async with self._changeset_mutation_scope(
            workspace_id, f"publish:{uuid.uuid4().hex}"
        ):
            workspace = self._workspaces.get(workspace_id)
            if workspace is None or changeset.workspace_id != workspace_id:
                raise WorkspaceError("workspace or changeset not found")
            if workspace.generation != expected_generation:
                raise WorkspaceError("parent workspace generation changed")
            return await self._commit_in_worktree_unfenced(
                workspace_id,
                changeset,
                message,
                expected_head=expected_head,
                advance_generation=True,
            )

    async def _commit_in_worktree_unfenced(
        self,
        workspace_id: str,
        changeset: ChangeSet,
        message: str,
        *,
        expected_head: str | None = None,
        advance_generation: bool = False,
    ) -> str:
        workspace = self._workspaces.get(workspace_id)
        if workspace is None or changeset.workspace_id != workspace_id:
            raise WorkspaceError("workspace or changeset not found")
        current_head = await self._workspace_git(workspace, "rev-parse", "HEAD")
        if expected_head is not None and current_head != expected_head:
            raise WorkspaceError("workspace HEAD changed; approval is stale")
        current_digest = await self._workspace_diff_digest(
            workspace, base_sha=changeset.base_sha
        )
        if current_head != changeset.base_sha or current_digest != changeset.content_hash:
            raise WorkspaceError("changeset content changed; approval is stale")

        repository_id = str(workspace.repository_root.resolve())
        await self._workspace_git(
            workspace,
            "read-tree",
            changeset.base_sha,
            effect=GitEffect.read_tree(
                repository_id=repository_id,
                treeish=changeset.base_sha,
                required_operation="index",
            ),
        )
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
                    workspace,
                    "update-index",
                    "--remove",
                    "--",
                    safe_relative,
                    effect=GitEffect.update_index_remove(
                        repository_id=repository_id,
                        path=safe_relative,
                        required_operation="index",
                    ),
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
                    effect=GitEffect.update_index_remove(
                        repository_id=repository_id,
                        path=safe_relative,
                        required_operation="index",
                    ),
                )
                continue
            object_id, mode = await self._hash_workspace_entry(
                workspace, safe_relative, info
            )
            if len(object_id) != len(changeset.base_sha) or any(
                character not in "0123456789abcdef" for character in object_id
            ):
                raise WorkspaceError("Git returned an object id for the wrong repository format")
            await self._workspace_git(
                workspace,
                "update-index",
                "--add",
                "--cacheinfo",
                f"{mode},{object_id},{safe_relative}",
                effect=GitEffect.update_index_cacheinfo(
                    repository_id=repository_id,
                    mode=mode,
                    object_id=object_id,
                    path=safe_relative,
                    required_operation="index",
                ),
            )

        tree = await self._workspace_git(
            workspace,
            "write-tree",
            effect=GitEffect.write_tree(
                repository_id=repository_id,
                required_operation="workspace",
            ),
        )
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
            effect=GitEffect.commit_tree(
                repository_id=repository_id,
                tree_oid=tree,
                parent_oid=current_head,
                stdin_sha256=hashlib.sha256(message_bytes).hexdigest(),
                required_operation="workspace",
            ),
        )
        ref = _safe_branch_ref(workspace.branch_name)
        await self._workspace_git(
            workspace,
            "update-ref",
            ref,
            commit_id,
            current_head,
            effect=GitEffect.update_ref(
                repository_id=repository_id,
                ref_name=ref,
                new_oid=commit_id,
                expected_old_oid=current_head,
                required_operation="workspace",
            ),
        )
        committed_head = await self._workspace_git(workspace, "rev-parse", "HEAD")
        workspace.head_sha = committed_head
        if advance_generation:
            async with self._lock:
                current = self._workspaces.get(workspace_id)
                if current is not workspace:
                    raise WorkspaceError("TaskWorkspace identity changed after commit")
                current.generation += 1
        return committed_head

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
            if not workspace.git_cleanup_complete:
                try:
                    if workspace.git_identity is not None:
                        await asyncio.to_thread(
                            restore_git_pointer_for_cleanup,
                            workspace.git_identity,
                        )
                    authority = self._workspace_authority(workspace, "git.cleanup")
                    if force:
                        await self._git(
                            workspace.repository_root,
                            "worktree",
                            "remove",
                            "--force",
                            str(workspace.worktree_path),
                            authority_grant=authority,
                            effect=GitEffect.worktree_remove(
                                repository_id=str(workspace.repository_root.resolve()),
                                path=str(workspace.worktree_path),
                                force=True,
                                required_operation="cleanup",
                            ),
                        )
                    else:
                        await self._git(
                            workspace.repository_root,
                            "worktree",
                            "remove",
                            str(workspace.worktree_path),
                            authority_grant=authority,
                            effect=GitEffect.worktree_remove(
                                repository_id=str(workspace.repository_root.resolve()),
                                path=str(workspace.worktree_path),
                                force=False,
                                required_operation="cleanup",
                            ),
                        )
                    # A successful worktree removal does not remove the local
                    # task ref.  Delete it with the last known commit as a CAS so
                    # cleanup cannot erase a ref that advanced outside this
                    # workspace owner.
                    cleanup_head = workspace.head_sha or workspace.base_sha
                    await self._git(
                        workspace.repository_root,
                        "update-ref",
                        "-d",
                        _safe_branch_ref(workspace.branch_name),
                        cleanup_head,
                        authority_grant=self._workspace_authority(workspace, "git.cleanup-ref"),
                        effect=GitEffect.update_ref(
                            repository_id=str(workspace.repository_root.resolve()),
                            ref_name=_safe_branch_ref(workspace.branch_name),
                            new_oid=None,
                            expected_old_oid=cleanup_head,
                            delete=True,
                            required_operation="cleanup-ref",
                        ),
                    )
                    workspace.git_cleanup_complete = True
                except Exception:  # noqa: BLE001 - worktree cleanup failure is persisted
                    workspace.state = WorkspaceState.FAILED
                    return WorkspaceTransition.FAILED
            try:
                for artifact in tuple(workspace.change_artifacts):
                    if artifact.parent != workspace.worktree_path.parent:
                        raise WorkspaceError("changeset artifact escaped its authority root")
                    artifact.unlink(missing_ok=True)
                workspace.change_artifacts.clear()
                workspace.change_artifact_files.clear()
                workspace.change_artifact_bytes = 0
            except (OSError, WorkspaceError):
                workspace.state = WorkspaceState.FAILED
                return WorkspaceTransition.FAILED
            try:
                if workspace.authority_envelope is not None:
                    self._authority_broker.revoke_grant(workspace.authority_envelope)
            except (AuthorityBrokerError, OSError, ValueError) as exc:
                workspace.state = WorkspaceState.FAILED
                logger.warning(
                    "workspace authority grant revocation failed for %s: %s",
                    workspace_id,
                    exc,
                )
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
