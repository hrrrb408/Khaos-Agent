from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace
from typing import Any

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
from khaos.memory.core.authority import (
    _TRUSTED_ISSUER_CAPABILITY,
    VerificationReceiptIssuer,
    VerificationReceiptVerifier,
    candidate_digest,
    memory_digest,
)
from khaos.memory.core.contracts import (
    MemoryCandidate,
    MemoryDecision,
    MemoryEventType,
    RuntimeMemoryContext,
    canonical_json,
)
from khaos.memory.events import MemoryEventBridge


@dataclass(frozen=True)
class VerificationMemoryOutcome:
    """Result of verification plus the optional Broker promotion decision."""

    verification_run_id: str
    results: tuple[VerificationStepResult, ...]
    passed: bool
    promotion: MemoryDecision | None = None


class VerificationPipeline:
    # Marker consumed by the Memory verification issuer.  The issuer is
    # created by this trusted pipeline object, never by a generic Provider or
    # MemoryBroker.
    __khaos_trusted_verification__ = True

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

    def memory_receipt_issuer(
        self,
        verifier: VerificationReceiptVerifier,
    ) -> VerificationReceiptIssuer:
        """Return the only issuer seam accepted by Memory V2."""

        return VerificationReceiptIssuer(
            verifier,
            owner=self,
            _capability=_TRUSTED_ISSUER_CAPABILITY,
        )

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

    async def run_with_memory(
        self,
        plan,
        *,
        broker: Any,
        runtime: RuntimeMemoryContext,
        candidate: MemoryCandidate | None = None,
        memory_id: str | None = None,
        verification_run_id: str,
    ) -> VerificationMemoryOutcome:
        """Run verification and close the Memory promotion capability chain.

        The pipeline is the only production owner that can create the
        receipt issuer.  The Broker still validates the one-shot receipt,
        candidate/memory digest, and complete runtime scope before promotion.
        Callers must supply either a new candidate or an already-admitted
        memory id; an unscoped verification result is never promoted.
        """

        if not verification_run_id:
            raise ValueError("verification_run_id must be non-empty")
        if (candidate is None) == (memory_id is None):
            raise ValueError("exactly one of candidate or memory_id is required")
        bridge = MemoryEventBridge(broker)
        target_hit = None
        target_digest = candidate_digest(candidate) if candidate is not None else ""
        if memory_id is not None:
            target_hit = await broker.get(memory_id, runtime, include_historical=True)
            if target_hit is None:
                raise RuntimeError("verified memory target is out of scope or missing")
            target_digest = memory_digest(target_hit)
        await bridge.record(
            MemoryEventType.VERIFICATION_STARTED,
            runtime,
            {
                "verification_run_id": verification_run_id,
                "target_memory_id": memory_id or "",
                "target_digest": target_digest,
            },
            source_type="VERIFICATION",
            source_ref=verification_run_id,
        )
        results = await self.run(
            plan,
            task_id=runtime.task_id,
            workspace_id=runtime.workspace_id,
        )
        required = {
            step.id: step
            for step in getattr(plan, "steps", ())
            if getattr(step, "required", True)
        }
        result_by_id = {result.step_id: result for result in results}
        passed = all(
            result_by_id.get(step_id) is not None
            and result_by_id[step_id].status == "passed"
            for step_id in required
        )
        result_digest = hashlib.sha256(
            canonical_json(
                [
                    {
                        "step_id": result.step_id,
                        "status": result.status,
                        "return_code": result.return_code,
                    }
                    for result in results
                ]
            ).encode("utf-8")
        ).hexdigest()
        await bridge.verification(
            runtime,
            result=passed,
            verification_run_id=verification_run_id,
            result_digest=result_digest,
            required_steps=sorted(required),
            target_memory_id=memory_id or "",
            target_digest=target_digest,
        )
        if not passed:
            return VerificationMemoryOutcome(
                verification_run_id,
                results,
                False,
                None,
            )

        issuer = self.memory_receipt_issuer(broker.verification_verifier)
        if memory_id is not None:
            hit = target_hit
            assert hit is not None
            receipt = issuer.issue_memory(
                hit,
                verification_run_id,
                principal_id=runtime.principal_id,
                project_id=runtime.project_id,
                session_id=runtime.session_id,
                task_id=runtime.task_id,
                workspace_id=runtime.workspace_id,
                result_digest=result_digest,
            )
            promotion = await broker.promote_memory(
                memory_id,
                runtime,
                verification_run_id=verification_run_id,
                verification_proof=receipt.token,
                verification_result_digest=result_digest,
            )
        else:
            assert candidate is not None
            candidate = replace(
                candidate,
                authority="VERIFICATION_CONFIRMED",
                verification_run_id=verification_run_id,
                verification_result_digest=result_digest,
            )
            receipt = issuer.issue(
                candidate,
                verification_run_id,
                principal_id=runtime.principal_id,
                project_id=runtime.project_id,
                session_id=runtime.session_id,
                task_id=runtime.task_id,
                workspace_id=runtime.workspace_id,
                result_digest=result_digest,
            )
            promotion = await broker.propose_memory(
                replace(
                    candidate,
                    verification_proof=receipt.token,
                ),
                runtime,
            )
        return VerificationMemoryOutcome(
            verification_run_id,
            results,
            True,
            promotion,
        )
