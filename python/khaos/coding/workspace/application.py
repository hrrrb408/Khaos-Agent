"""Single ChangeSet application service with one-shot approval checks."""

from __future__ import annotations

import time

from khaos.coding.workspace.apply import OutputMode, output_changeset
from khaos.coding.workspace.manager import WorkspaceError, WorkspaceManager
from khaos.coding.workspace.models import ChangeSet, WorkspaceState


class ChangeSetApplicationService:
    def __init__(self, manager: WorkspaceManager, approval_broker) -> None:
        self.manager = manager
        self.approval_broker = approval_broker
        self._used: set[str] = set()

    async def apply(self, *, task_id: str, workspace_id: str, changeset: ChangeSet, operation: OutputMode, approval_key: str, expiry: float) -> str:
        workspace = self.manager.get(workspace_id)
        if workspace is None or workspace.task_id != task_id or workspace.state in {WorkspaceState.CANCELLED, WorkspaceState.CLEANED, WorkspaceState.CLEANING}:
            raise WorkspaceError("invalid task workspace")
        if time.time() >= expiry or approval_key in self._used or approval_key != changeset.approval_key(operation.value):
            raise PermissionError("approval is expired, replayed, or bound to another operation")
        self._used.add(approval_key)
        try:
            return await output_changeset(self.manager, workspace_id, changeset, operation)
        except Exception:
            raise
