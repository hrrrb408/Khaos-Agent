from __future__ import annotations

from khaos.coding.execution import (
    ExecutionRequest,
    ExecutionService,
    HostExecutionBackend,
    ResourceBudget,
    UnsupportedBackend,
)
from khaos.coding.verification.detector import ProjectDetector
from khaos.coding.verification.models import VerificationStepResult
from khaos.coding.verification.planner import VerificationPlanner


class VerificationPipeline:
    def __init__(
        self,
        backend: HostExecutionBackend | None = None,
        *,
        execution_service: ExecutionService | None = None,
    ) -> None:
        self.detector = ProjectDetector()
        self.planner = VerificationPlanner()
        self.execution = execution_service or ExecutionService(backend or UnsupportedBackend())

    def plan(self, root):
        return self.planner.plan(self.detector.detect(root))

    async def run(self, plan, *, task_id: str | None = None, workspace_id: str | None = None):
        results = []
        for step in plan.steps:
            execution = await self.execution.execute(
                ExecutionRequest(
                    step.command,
                    step.cwd,
                    (step.cwd,),
                    budget=ResourceBudget(timeout_seconds=step.timeout_seconds),
                    task_id=task_id,
                    workspace_id=workspace_id,
                    access_mode="workspace-write" if task_id and workspace_id else "read-only",
                )
            )
            results.append(VerificationStepResult(step.id, execution.status, execution.return_code, execution.stdout, execution.stderr, execution.diagnostics))
            if step.required and execution.status != "passed":
                break
        return tuple(results)
