"""Fail-closed production bootstrap for approval and lease runtime."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from khaos.coding.planning.approval.gate import PlanExecutionGate
from khaos.coding.planning.approval.repository import PersistedPlanRepository
from khaos.coding.planning.approval.service import PlanApprovalService

@dataclass(frozen=True)
class BootContext:
    server_epoch: int
    boot_id: str

class ApprovalRuntime:
    def __init__(self, *, store: Any, broker: Any, context_provider: Any, plan_repository: PersistedPlanRepository, planning_service: Any) -> None:
        if not isinstance(plan_repository, PersistedPlanRepository):
            raise TypeError("production ApprovalRuntime requires PersistedPlanRepository")
        if planning_service is None or getattr(planning_service, "_unsafe_test_only", False) or not callable(getattr(planning_service, "validate_plan", None)):
            raise TypeError("production ApprovalRuntime requires deep planning validator")
        if context_provider is None or not callable(getattr(context_provider, "current_state", None)):
            raise TypeError("production ApprovalRuntime requires ContextProvider")
        self._store=store; self._broker=broker; self._context_provider=context_provider
        self._plan_repository=plan_repository; self._planning_service=planning_service
        self.service=None; self.gate=None; self.boot_context=None; self.ready=False

    def initialize(self) -> BootContext:
        epoch, boot_id, _ = self._store.rotate_epoch()
        self.boot_context=BootContext(epoch,boot_id)
        self.gate=PlanExecutionGate(store=self._store,context_provider=self._context_provider,plan_repository=self._plan_repository,planning_service=self._planning_service)
        self.service=PlanApprovalService(store=self._store,broker=self._broker,context_provider=self._context_provider,plan_repository=self._plan_repository,planning_service=self._planning_service)
        self.service.reconcile()
        self.ready=True
        return self.boot_context

    def require_ready(self) -> None:
        if not self.ready or self.gate is None:
            raise RuntimeError("approval runtime is not initialized")

    def authorize_execution(self, **kwargs: Any):
        self.require_ready(); return self.gate.authorize_execution(**kwargs)

    def acquire_lease(self, **kwargs: Any):
        self.require_ready(); return self.gate.acquire_lease(**kwargs)

    def require_active_lease(self, *args: Any, **kwargs: Any):
        self.require_ready(); return self.gate.require_active_lease(*args, **kwargs)

    def shutdown(self) -> None:
        if self.ready:
            self._store.rotate_epoch()
            self.ready=False

class WorkspaceExecutionLeaseCoordinator:
    """Coordinates planned mutation preconditions without performing mutation."""
    def __init__(self, runtime: ApprovalRuntime) -> None:
        self._runtime=runtime

    def require_owner(self, ctx: Any) -> None:
        self._runtime.require_ready()
        if not self._runtime.gate.require_active_lease(ctx.lease_id,owner_execution_id=ctx.owner_execution_id,expected_task_id=ctx.task_id,expected_workspace_id=ctx.workspace_id,expected_repository_id=ctx.repository_id,expected_plan_id=ctx.plan_id):
            raise PermissionError("planned mutation requires active lease owner")

    def before_generation_or_head_update(self, ctx: Any) -> None:
        self.require_owner(ctx)

    def cancel_task(self, approval_request_id: str) -> None:
        self._runtime.require_ready()
        self._runtime._store.invalidate_request_authorizations_leases_and_receipt(approval_request_id,target_status=__import__("khaos.coding.planning.approval.models",fromlist=["PlanApprovalStatus"]).PlanApprovalStatus.REVOKED,expected_statuses={__import__("khaos.coding.planning.approval.models",fromlist=["PlanApprovalStatus"]).PlanApprovalStatus.APPROVED})

    def cleanup_workspace(self, approval_request_id: str) -> None:
        self.cancel_task(approval_request_id)

    def shutdown(self) -> None:
        self._runtime.shutdown()
