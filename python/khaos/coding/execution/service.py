"""Single execution entry point for terminal, tests, sandbox and LSP."""

from __future__ import annotations

from khaos.coding.execution.models import ExecutionRequest, ExecutionResult


class ExecutionService:
    def __init__(self, backend) -> None:
        self.backend = backend

    async def execute(self, request: ExecutionRequest) -> ExecutionResult:
        return await self.backend.execute(request)

    async def terminate(self, execution_id: str) -> None:
        await self.backend.terminate(execution_id)
