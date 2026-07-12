"""Shared live-plan validator (spec §5, §6).

A single :class:`PlanLiveValidator` is used at FOUR stages so they can never
diverge:

1. Creating an approval request (:meth:`PlanApprovalService.request_approval`).
2. Applying a broker decision (:meth:`PlanApprovalService.apply_broker_decision`).
3. Minting an authorization (:meth:`PlanExecutionGate.authorize_execution`).
4. Consuming an authorization (:meth:`PlanExecutionGate.require_authorization`).

The validator reads the AUTHORITATIVE plan from a :class:`PlanRepository`
(not the caller's plan object), the live repository state from a
:class:`ContextProvider`, recomputes the binding digest, and returns a frozen
:class:`PlanValidationContext`. Any drift (HEAD, generation, file hash,
symbol, destination, verification config, binding) raises
:class:`PlanStaleError`.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from khaos.coding.planning.approval.models import (
    PlanValidationContext,
    compute_plan_binding_digest,
    compute_verification_digest,
)
from khaos.coding.planning.approval.requirement import evaluate_approval_requirement
# NOTE: these errors are defined here (not imported from service.py) to avoid
# a circular import. service.py re-exports them for back-compat; the gate
# imports them from here directly.


class PlanStaleError(Exception):
    """Raised when the plan or repository state has drifted."""


class PlanNotRequestableError(Exception):
    """Raised when the plan/task/workspace is not in a requestable state."""


if TYPE_CHECKING:  # pragma: no cover - typing only
    from khaos.coding.planning.approval.repository import PlanRepository
    from khaos.coding.planning.approval.service import ContextProvider, CurrentRepositoryState
    from khaos.coding.planning.contracts import ImplementationPlan


class PlanLiveValidator:
    """Single source of truth for live plan validation.

    Constructed once and shared by the approval service and the execution
    gate so the four validation stages are literally the same code path.
    """

    def __init__(
        self,
        plan_repository: "PlanRepository",
        context_provider: "ContextProvider",
        planning_service: object | None = None,
    ) -> None:
        self._plan_repository = plan_repository
        self._context_provider = context_provider
        self._planning_service = planning_service

    def validate(
        self,
        plan_id: str,
        *,
        expected_repository_id: str | None = None,
        expected_task_id: str | None = None,
        expected_workspace_id: str | None = None,
    ) -> PlanValidationContext:
        """Validate the authoritative plan snapshot for ``plan_id``.

        Raises :class:`PlanNotRequestableError` if the plan is missing or its
        task/workspace is terminal, :class:`PlanStaleError` on any drift.
        """
        # Read the AUTHORITATIVE snapshot — never a caller-supplied plan.
        plan = self._plan_repository.get(plan_id)
        if plan is None:
            raise PlanNotRequestableError(f"no authoritative plan snapshot for {plan_id}")

        # Caller may assert scope (used by the gate to double-check the
        # authorization's bound scope against the live plan).
        if expected_repository_id is not None and plan.repository_id != expected_repository_id:
            raise PlanNotRequestableError("repository id mismatch against authoritative plan")
        if expected_task_id is not None and plan.task_id != expected_task_id:
            raise PlanNotRequestableError("task id mismatch against authoritative plan")
        if expected_workspace_id is not None and plan.workspace_id != expected_workspace_id:
            raise PlanNotRequestableError("workspace id mismatch against authoritative plan")

        return self._validate_plan(plan)

    def validate_plan(self, plan: "ImplementationPlan") -> PlanValidationContext:
        """Validate a plan object directly (used by the approval service at
        request-creation time, where the plan was just produced server-side
        and registered into the repository in the same call)."""
        return self._validate_plan(plan)

    def _validate_plan(self, plan: "ImplementationPlan") -> PlanValidationContext:
        # Plan self-status gate.
        status = plan.status
        status_value = getattr(status, "value", str(status))
        if status_value in {"blocked", "stale"}:
            raise PlanNotRequestableError(f"plan status is {status_value}")

        # Live repository / task / workspace state.
        state = self._context_provider.current_state(
            repository_id=plan.repository_id,
            task_id=plan.task_id,
            workspace_id=plan.workspace_id,
        )
        if state.repository_id != plan.repository_id:
            raise PlanNotRequestableError("repository id mismatch")
        if state.task_id != plan.task_id:
            raise PlanNotRequestableError("task id mismatch")
        if state.workspace_id != plan.workspace_id:
            raise PlanNotRequestableError("workspace id mismatch")
        if state.task_terminal:
            raise PlanNotRequestableError("task is terminal")
        if state.workspace_terminal:
            raise PlanNotRequestableError("workspace is terminal")

        # HEAD + repository generation drift.
        if state.head_sha != plan.base_sha:
            raise PlanStaleError(
                f"head drift: plan={plan.base_sha} current={state.head_sha}"
            )
        if int(state.repository_generation) != int(plan.repository_generation):
            raise PlanStaleError(
                f"generation drift: plan={plan.repository_generation} "
                f"current={state.repository_generation}"
            )

        # Delegate deeper file/symbol/config/destination drift detection to
        # the deterministic planner's validate_plan when wired (it queries
        # the live index). Fail closed on planner errors.
        if self._planning_service is not None:
            try:
                result = self._planning_service.validate_plan(
                    plan,
                    current_head=state.head_sha,
                    current_repository_generation=state.repository_generation,
                )
                if not result.valid:
                    raise PlanStaleError(
                        "planner validation failed: "
                        + ",".join(d.code for d in result.diagnostics)
                    )
            except PlanStaleError:
                raise
            except Exception as exc:
                raise PlanNotRequestableError(f"planner validation error: {exc}")

        # Server-authoritative approval requirement (IGNORES client fields).
        outcome = evaluate_approval_requirement(plan)

        # Binding + verification digests.
        binding_digest = compute_plan_binding_digest(plan)
        verification_digest = compute_verification_digest(plan.verification_requirements)

        return PlanValidationContext(
            plan=plan,
            state=state,
            binding_digest=binding_digest,
            verification_digest=verification_digest,
            risk_level=outcome.risk_level,
            requires_approval=outcome.requires_approval,
            reason_codes=outcome.reason_codes,
        )

class ShallowTestPlanValidator:
    """Explicit shallow validator fixture; production runtime rejects it."""
    _unsafe_test_only = True
    def validate_plan(self, plan, **kwargs):
        from khaos.coding.planning.contracts import PlanStatus, PlanValidationResult
        return PlanValidationResult(plan.status is PlanStatus.READY, plan.status)
