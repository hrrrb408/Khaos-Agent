"""Single ChangeSet application service with one-shot approval checks."""

from __future__ import annotations

import time
from hashlib import sha256

from khaos.coding.workspace.apply import OutputMode, output_changeset
from khaos.coding.workspace.manager import WorkspaceError, WorkspaceManager
from khaos.coding.workspace.models import ChangeSet, WorkspaceState


class ChangeSetApplicationService:
    def __init__(self, manager: WorkspaceManager, approval_broker) -> None:
        self.manager = manager
        self.approval_broker = approval_broker
        self._used: set[str] = set()

    async def request_approval(
        self,
        *,
        task_id: str,
        workspace_id: str,
        changeset: ChangeSet,
        operation: OutputMode,
        requester: str,
        expiry: float,
        principal_id: str | None = None,
    ) -> str:
        """Register a one-shot immutable approval before an external apply."""
        workspace = self._workspace(task_id, workspace_id)
        approval_key = changeset.approval_key(operation.value)
        await self.approval_broker.register_operation(
            approval_key,
            await self._binding(
                workspace, task_id, changeset, operation, requester,
                principal_id or requester,
            ),
            expiry,
        )
        return approval_key

    async def apply(
        self,
        *,
        task_id: str,
        workspace_id: str,
        changeset: ChangeSet,
        operation: OutputMode,
        approval_key: str,
        expiry: float,
        requester: str = "",
        principal_id: str | None = None,
    ) -> str:
        """Apply only an approved, unchanged ChangeSet exactly once."""
        workspace = self._workspace(task_id, workspace_id)
        binding = await self._binding(
            workspace, task_id, changeset, operation, requester,
            principal_id or requester,
        )
        if time.time() >= expiry or approval_key in self._used or approval_key != changeset.approval_key(operation.value):
            raise PermissionError("approval is expired, replayed, or bound to another operation")
        if not await self.approval_broker.consume_operation(approval_key, binding):
            raise PermissionError("approval is missing, stale, replayed, or bound to another requester")
        self._used.add(approval_key)
        try:
            return await output_changeset(self.manager, workspace_id, changeset, operation)
        except Exception:
            raise

    def _workspace(self, task_id: str, workspace_id: str):
        workspace = self.manager.get(workspace_id)
        if workspace is None or workspace.task_id != task_id or workspace.state in {WorkspaceState.CANCELLED, WorkspaceState.CLEANED, WorkspaceState.CLEANING}:
            raise WorkspaceError("invalid task workspace")
        return workspace

    async def _binding(self, workspace, task_id: str, changeset: ChangeSet, operation: OutputMode, requester: str, principal_id: str) -> dict:
        """Recompute mutable Git facts, invalidating approvals after drift."""
        current_head = await self.manager._git(workspace.worktree_path, "rev-parse", "HEAD")
        patch = await self.manager._git(
            workspace.worktree_path, "diff", "--binary", workspace.base_sha, preserve_output=True
        )
        return {
            "principal_id": principal_id,
            "session_id": requester,
            "requester": requester,
            "task_id": task_id,
            "workspace_id": workspace.id,
            "changeset_id": changeset.id,
            "content_hash": changeset.content_hash,
            "operation": operation.value,
            "base_sha": changeset.base_sha,
            "head": current_head,
            "diff_hash": sha256(patch.encode("utf-8")).hexdigest(),
        }
