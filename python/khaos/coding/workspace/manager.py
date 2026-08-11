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
from pathlib import Path
from typing import Any, TypeVar

from khaos.coding.workspace.boundary import PROTECTED_WORKSPACE_NAMES
from khaos.coding.workspace.git_identity import (
    GitIdentityError,
    capture_git_worktree_identity,
    restore_git_pointer_for_cleanup,
    verify_git_worktree_identity,
)
from khaos.coding.workspace.models import (
    ChangeSet,
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
)
from khaos.security.authority import AuthorityEnvelope

logger = logging.getLogger(__name__)
T = TypeVar("T")
FileIdentity = tuple[int, int, int, int]


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


def _open_private_authority_root(configured: Path) -> tuple[Path, FileIdentity]:
    """Create a private root without following attacker-controlled components."""
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
        policy_digest: str = "legacy-unbound",
    ) -> None:
        configured_root = (
            root or Path(tempfile.gettempdir()) / "khaos" / "worktrees"
        ).expanduser().absolute()
        self.root, self._root_identity = _open_private_authority_root(
            configured_root
        )
        try:
            self._git_runner = TrustedGitRunner.for_authority_root(
                self.root, self._root_identity
            )
        except TrustedGitError as exc:
            raise WorkspaceError(str(exc)) from exc
        self._git_executable = self._git_runner.executable
        self._git_identity = self._git_runner.git_identity
        self._git_digest = self._git_runner.git_digest
        self.policy_digest = policy_digest
        self.storage_limits = storage_limits or WorkspaceStorageLimits()
        self.storage_authority = storage_authority or WorkspaceStorageAuthority()
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

    def _default_git_authority(self, repository: Path) -> AuthorityEnvelope:
        return AuthorityEnvelope(
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
        authority: AuthorityEnvelope | None = None,
        preserve_output: bool = False,
    ) -> str:
        try:
            runner = TrustedGitRunner(
                self._git_executable,
                self._git_identity,
                self._git_digest,
                self.root,
                self._root_identity,
            )
            return await runner.run(
                repository,
                *args,
                authority=authority or self._default_git_authority(repository),
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
        authority: AuthorityEnvelope,
    ) -> None:
        try:
            runner = TrustedGitRunner(
                self._git_executable,
                self._git_identity,
                self._git_digest,
                self.root,
                self._root_identity,
            )
            await runner.materialize_tree(
                repository,
                base_sha,
                worktree,
                authority=authority.derive(operation_class="git.materialize"),
            )
        except TrustedGitError as exc:
            raise WorkspaceError(str(exc)) from exc

    async def _workspace_git(
        self,
        workspace: TaskWorkspace,
        *args: str,
        preserve_output: bool = False,
    ) -> str:
        """Run Git only against the pinned admin dir and worktree."""
        identity = workspace.git_identity
        if identity is None:
            raise WorkspaceError("TaskWorkspace Git identity is missing")
        try:
            await asyncio.to_thread(verify_git_worktree_identity, identity)
        except GitIdentityError as exc:
            raise WorkspaceError(str(exc)) from exc
        authority = workspace.authority_envelope
        if authority is None:
            raise WorkspaceError("TaskWorkspace authority envelope is missing")
        try:
            return await self._git_runner.run(
                workspace.worktree_path,
                f"--git-dir={identity.admin_dir}",
                f"--work-tree={workspace.worktree_path}",
                *args,
                authority=authority.derive(operation_class="git.workspace"),
                preserve_output=preserve_output,
            )
        except TrustedGitError as exc:
            raise WorkspaceError(str(exc)) from exc

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
            authority_context = AuthorityEnvelope(
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
            dirty = await self._git(
                repository,
                "status",
                "--porcelain",
                authority=authority_context,
            )
            if dirty:
                raise WorkspaceError("主工作树存在未提交修改，拒绝创建可写 Worktree")
            base_sha = await self._git(
                repository,
                "rev-parse",
                base_ref,
                authority=authority_context,
            )
            branch = f"khaos/task/{task_id}"
            path = (self.root / workspace_id).resolve()
            path.parent.mkdir(parents=True, exist_ok=True)
            await self._git(
                repository,
                "worktree",
                "add",
                "--no-checkout",
                "-b",
                branch,
                str(path),
                base_sha,
                authority=authority_context,
            )
            try:
                git_identity = await asyncio.to_thread(
                    capture_git_worktree_identity, repository, path
                )
            except GitIdentityError:
                await self._git(
                    repository,
                    "worktree",
                    "remove",
                    "--force",
                    str(path),
                    authority=authority_context,
                )
                raise
            # ``--no-checkout`` deliberately leaves the worktree empty.  Set
            # the linked index to the approved tree without ``-u`` so Git
            # does not invoke any smudge/filter driver; tracked bytes are
            # materialized separately from raw tree/blob objects below.
            await self._git(
                path,
                f"--git-dir={git_identity.admin_dir}",
                f"--work-tree={path}",
                "read-tree",
                base_sha,
                authority=authority_context.derive(operation_class="git.index"),
            )
            recovery_root = (self.root.parent / ".khaos-recovery").resolve()
            try:
                await self._materialize_git_tree(
                    repository,
                    base_sha,
                    path,
                    authority=authority_context,
                )
            except Exception:
                await self._git(
                    repository,
                    "worktree",
                    "remove",
                    "--force",
                    str(path),
                    authority=authority_context,
                )
                raise
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
            )
            try:
                await asyncio.to_thread(_install_protected_metadata_guards, path)
            except Exception:
                await self._git(
                    repository,
                    "worktree",
                    "remove",
                    "--force",
                    str(path),
                    authority=authority_context,
                )
                raise
            baseline = await asyncio.to_thread(capture_workspace_snapshot, path)
            if not baseline.complete:
                await self._git(
                    repository,
                    "worktree",
                    "remove",
                    "--force",
                    str(path),
                    authority=authority_context,
                )
                raise WorkspaceError("TaskWorkspace storage baseline is incomplete")
            workspace.storage_baseline = baseline
            self._workspaces[workspace_id] = workspace
            self._task_ids.add(task_id)
            return workspace

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
                    if current is not workspace or current.state in {
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
        workspace = self._workspaces.get(workspace_id)
        if workspace is None:
            raise WorkspaceError("workspace not found")
        patch = await self._workspace_git(workspace, "diff", "--no-ext-diff", "--binary", workspace.base_sha, preserve_output=True)
        stat = await self._workspace_git(workspace, "diff", "--no-ext-diff", "--stat", workspace.base_sha)
        names = await self._workspace_git(workspace, "diff", "--no-ext-diff", "--name-only", workspace.base_sha)
        protected = {name.casefold() for name in PROTECTED_WORKSPACE_NAMES}
        for changed in names.splitlines():
            if any(part.casefold() in protected for part in Path(changed).parts):
                raise WorkspaceError("changeset contains protected workspace metadata")
        changeset = ChangeSet.create(id=uuid.uuid4().hex[:12], workspace_id=workspace_id, base_sha=workspace.base_sha, head_sha=None, patch=patch, diff_stat=stat, changed_files=tuple(line for line in names.splitlines() if line))
        artifact = workspace.worktree_path.parent / f"{changeset.id}.patch"
        artifact.write_text(patch, encoding="utf-8")
        return changeset

    async def commit_in_worktree(self, workspace_id: str, changeset: ChangeSet, message: str) -> str:
        workspace = self._workspaces.get(workspace_id)
        if workspace is None or changeset.workspace_id != workspace_id:
            raise WorkspaceError("workspace or changeset not found")
        current = await self._workspace_git(workspace, "diff", "--no-ext-diff", "--binary", workspace.base_sha, preserve_output=True)
        if current.encode("utf-8") != changeset.patch.encode("utf-8"):
            raise WorkspaceError("changeset content changed; approval is stale")
        await self._workspace_git(workspace, "add", "--", *changeset.changed_files)
        await self._workspace_git(workspace, "commit", "-m", message)
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
                authority = workspace.authority_envelope
                if authority is None:
                    raise WorkspaceError("TaskWorkspace authority envelope is missing")
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
