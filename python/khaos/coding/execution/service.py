"""Single execution entry point for terminal, tests, sandbox and LSP."""

from __future__ import annotations

from khaos.coding.execution.models import ExecutionRequest, ExecutionResult
from khaos.coding.workspace.models import WorkspaceState


class ExecutionService:
    def __init__(self, backend, workspace_manager=None) -> None:
        self.backend = backend
        self.workspace_manager = workspace_manager
        self._active: dict[str, tuple[str, str]] = {}

    async def execute(self, request: ExecutionRequest) -> ExecutionResult:
        if request.access_mode == "workspace-write":
            if self.workspace_manager is None or not request.task_id or not request.workspace_id:
                raise PermissionError("workspace-write requires an active TaskWorkspace")
            workspace = self.workspace_manager.get(request.workspace_id)
            if workspace is None or workspace.task_id != request.task_id:
                raise PermissionError("task/workspace binding is invalid")
            if workspace.state in {WorkspaceState.CANCELLED, WorkspaceState.CLEANING, WorkspaceState.CLEANED, WorkspaceState.FAILED}:
                raise PermissionError("workspace is not executable")
            root = workspace.worktree_path.resolve()
            cwd = request.cwd.expanduser().resolve()
            if cwd != root and root not in cwd.parents:
                raise PermissionError("cwd is outside the task workspace")
            request = ExecutionRequest(request.argv, cwd, (root,), request.environment, request.allowed_environment_keys, request.network_policy, request.budget, request.task_id, request.workspace_id, request.access_mode)
        result = await self.backend.execute(request)
        if request.task_id:
            self._active[result.execution_id] = (request.task_id, request.workspace_id or "")
        return result

    async def terminate(self, execution_id: str) -> None:
        await self.backend.terminate(execution_id)
        self._active.pop(execution_id, None)

    async def shutdown(self) -> None:
        for execution_id in tuple(self._active):
            await self.terminate(execution_id)
