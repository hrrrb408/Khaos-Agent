"""Async Git Worktree lifecycle manager."""

from __future__ import annotations

import asyncio
import logging
import os
import tempfile
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeVar

from khaos.coding.workspace.models import ChangeSet, TaskWorkspace, WorkspaceState, WorkspaceTransition
from khaos.coding.workspace.git_identity import (
    GitIdentityError,
    capture_git_worktree_identity,
    restore_git_pointer_for_cleanup,
    verify_git_worktree_identity,
)
from khaos.coding.workspace.storage import (
    WorkspaceMutation,
    WorkspaceStorageAuthority,
    WorkspaceStorageLimits,
    WorkspaceStorageViolation,
    capture_workspace_snapshot,
)

logger = logging.getLogger(__name__)
T = TypeVar("T")


class WorkspaceError(RuntimeError):
    """Raised when a worktree operation cannot be completed safely."""


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
    ) -> None:
        self.root = (root or Path(tempfile.gettempdir()) / "khaos" / "worktrees").expanduser().resolve()
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

    async def _git(self, repository: Path, *args: str, preserve_output: bool = False) -> str:
        environment = os.environ.copy()
        environment.update({
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
        })
        process = await asyncio.create_subprocess_exec(
            "git", *args, cwd=str(repository), env=environment,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        if process.returncode != 0:
            raise WorkspaceError(stderr.decode("utf-8", errors="replace").strip() or "git command failed")
        output = stdout.decode("utf-8", errors="replace")
        return output if preserve_output else output.strip()

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
        return await self._git(
            workspace.worktree_path,
            f"--git-dir={identity.admin_dir}",
            f"--work-tree={workspace.worktree_path}",
            "-c", f"core.hooksPath={os.devnull}",
            "-c", "core.fsmonitor=false",
            "-c", "core.untrackedCache=false",
            *args,
            preserve_output=preserve_output,
        )

    async def create(self, repository_root: Path, task_id: str, *, base_ref: str = "HEAD") -> TaskWorkspace:
        repository = repository_root.resolve()
        async with self._lock:
            if task_id in self._task_ids:
                raise WorkspaceError(f"task already has an active workspace: {task_id}")
            if not (repository / ".git").exists():
                raise WorkspaceError(f"not a git repository: {repository}")
            dirty = await self._git(repository, "status", "--porcelain")
            if dirty:
                raise WorkspaceError("主工作树存在未提交修改，拒绝创建可写 Worktree")
            base_sha = await self._git(repository, "rev-parse", base_ref)
            workspace_id = uuid.uuid4().hex[:12]
            branch = f"khaos/task/{task_id}"
            path = (self.root / workspace_id).resolve()
            path.parent.mkdir(parents=True, exist_ok=True)
            await self._git(repository, "worktree", "add", "-b", branch, str(path), base_sha)
            try:
                git_identity = await asyncio.to_thread(
                    capture_git_worktree_identity, repository, path
                )
            except GitIdentityError:
                await self._git(
                    repository, "worktree", "remove", "--force", str(path)
                )
                raise
            recovery_root = (self.root.parent / ".khaos-recovery").resolve()
            workspace = TaskWorkspace(
                workspace_id, task_id, repository, path, base_ref, base_sha,
                branch, WorkspaceState.READY, (path,), recovery_root=recovery_root,
                storage_limits=self.storage_limits,
                git_identity=git_identity,
            )
            baseline = await asyncio.to_thread(capture_workspace_snapshot, path)
            if not baseline.complete:
                await self._git(
                    repository, "worktree", "remove", "--force", str(path)
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
                except Exception as exc:
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
                if force:
                    await self._git(workspace.repository_root, "worktree", "remove", "--force", str(workspace.worktree_path))
                else:
                    await self._git(workspace.repository_root, "worktree", "remove", str(workspace.worktree_path))
            except Exception:
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
