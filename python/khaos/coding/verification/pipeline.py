from __future__ import annotations

from khaos.coding.execution import ExecutionRequest, HostExecutionBackend, ResourceBudget
from khaos.coding.verification.detector import ProjectDetector
from khaos.coding.verification.models import VerificationStepResult
from khaos.coding.verification.planner import VerificationPlanner


class VerificationPipeline:
    def __init__(self, backend: HostExecutionBackend | None = None) -> None:
        self.detector = ProjectDetector()
        self.planner = VerificationPlanner()
        self.backend = backend or HostExecutionBackend()

    def plan(self, root):
        return self.planner.plan(self.detector.detect(root))

    async def run(self, plan):
        results = []
        for step in plan.steps:
            execution = await self.backend.execute(
                ExecutionRequest(step.command, step.cwd, (step.cwd,), budget=ResourceBudget(timeout_seconds=step.timeout_seconds))
            )
            results.append(VerificationStepResult(step.id, execution.status, execution.return_code, execution.stdout, execution.stderr, execution.diagnostics))
            if step.required and execution.status != "passed":
                break
        return tuple(results)
