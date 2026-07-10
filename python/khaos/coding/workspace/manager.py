"""Async Git Worktree lifecycle manager."""

from __future__ import annotations

import asyncio
import uuid
from pathlib import Path

from khaos.coding.workspace.models import ChangeSet, TaskWorkspace, WorkspaceState, WorkspaceTransition


class WorkspaceError(RuntimeError):
    """Raised when a worktree operation cannot be completed safely."""


ALLOWED: dict[WorkspaceState, frozenset[WorkspaceState]] = {
    WorkspaceState.CREATING: frozenset({WorkspaceState.READY, WorkspaceState.FAILED}),
    WorkspaceState.READY: frozenset({WorkspaceState.INDEXING, WorkspaceState.RUNNING, WorkspaceState.CANCELLED}),
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

    def __init__(self, root: Path | None = None) -> None:
        self.root = (root or Path.home() / ".cache" / "khaos" / "worktrees").expanduser().resolve()
        self._workspaces: dict[str, TaskWorkspace] = {}
        self._task_ids: set[str] = set()
        self._lock = asyncio.Lock()

    async def _git(self, repository: Path, *args: str) -> str:
        process = await asyncio.create_subprocess_exec(
            "git", *args, cwd=str(repository), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        if process.returncode != 0:
            raise WorkspaceError(stderr.decode("utf-8", errors="replace").strip() or "git command failed")
        return stdout.decode("utf-8", errors="replace").strip()

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
            workspace = TaskWorkspace(workspace_id, task_id, repository, path, base_ref, base_sha, branch, WorkspaceState.READY, (path,))
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

    async def build_changeset(self, workspace_id: str) -> ChangeSet:
        workspace = self._workspaces.get(workspace_id)
        if workspace is None:
            raise WorkspaceError("workspace not found")
        patch = await self._git(workspace.worktree_path, "diff", "--binary", workspace.base_sha)
        stat = await self._git(workspace.worktree_path, "diff", "--stat", workspace.base_sha)
        names = await self._git(workspace.worktree_path, "diff", "--name-only", workspace.base_sha)
        return ChangeSet.create(id=uuid.uuid4().hex[:12], workspace_id=workspace_id, base_sha=workspace.base_sha, head_sha=None, patch=patch, diff_stat=stat, changed_files=tuple(line for line in names.splitlines() if line))

    async def cleanup(self, workspace_id: str, *, force: bool = False) -> WorkspaceTransition:
        async with self._lock:
            workspace = self._workspaces.get(workspace_id)
            if workspace is None:
                return WorkspaceTransition.NOT_FOUND
            if workspace.state not in {WorkspaceState.APPLIED, WorkspaceState.FAILED, WorkspaceState.CANCELLED} and not force:
                return WorkspaceTransition.INVALID
            workspace.state = WorkspaceState.CLEANING
            if force:
                await self._git(workspace.repository_root, "worktree", "remove", "--force", str(workspace.worktree_path))
            else:
                await self._git(workspace.repository_root, "worktree", "remove", str(workspace.worktree_path))
            workspace.state = WorkspaceState.CLEANED
            self._task_ids.discard(workspace.task_id)
            return WorkspaceTransition.UPDATED
