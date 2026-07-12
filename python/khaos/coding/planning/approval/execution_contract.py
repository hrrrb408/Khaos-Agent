"""Batch 3 execution contract.

Defines the seam that every *planned* execution path in Batch 3 must go
through. In this batch (Batch 2) the contract only provides:

* A typed handle (:class:`AuthorizedExecutionContext`) that the gate returns
  and that downstream (Batch 3) services MUST accept as their sole entry
  parameter — plain ``plan_id`` strings are NOT accepted.
* A :class:`PlannedExecutionGuard` whose individual methods raise
  :class:`NotImplementedError` so that wiring them up early FAILS LOUDLY
  instead of silently bypassing the gate.

This intentionally does NOT perform any file write, tool invocation,
verification run or ChangeSet creation/apply. It only establishes the
contract that Batch 3 will implement on top of
:class:`PlanExecutionGate.require_authorization`.
"""
from __future__ import annotations

from dataclasses import dataclass
import secrets
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - typing only
    from khaos.coding.planning.approval.gate import PlanExecutionGate
    from khaos.coding.planning.approval.models import PlanExecutionAuthorization


@dataclass(frozen=True)
class AuthorizedExecutionContext:
    """The ONLY context Batch 3 planned execution paths may accept.

    Carries the consumed :class:`PlanExecutionAuthorization` plus the
    verified scope (plan/task/workspace/repository ids). Constructing this
    object from scratch is impossible outside the guard because it requires a
    consumed authorization whose status is ``CONSUMED`` — which only
    :meth:`PlanExecutionGate.require_authorization` can produce.
    """

    authorization: "PlanExecutionAuthorization"
    plan_id: str
    task_id: str
    workspace_id: str
    repository_id: str
    lease_id: str
    owner_execution_id: str
    lease_expiry: float
    server_epoch: int
    boot_id: str
    authorization_id: str
    binding_digest: str
    execution_context_id: str

    def __post_init__(self) -> None:
        # Defense in depth: refuse to wrap an unconsumed authorization.
        from khaos.coding.planning.approval.models import AuthorizationStatus

        if self.authorization.status != AuthorizationStatus.CONSUMED:
            raise ValueError(
                "AuthorizedExecutionContext requires a CONSUMED authorization"
            )
        if self.authorization.plan_id != self.plan_id:
            raise ValueError("plan id mismatch in AuthorizedExecutionContext")
        if self.authorization.task_id != self.task_id:
            raise ValueError("task id mismatch in AuthorizedExecutionContext")
        if self.authorization.workspace_id != self.workspace_id:
            raise ValueError("workspace id mismatch in AuthorizedExecutionContext")
        if self.authorization.repository_id != self.repository_id:
            raise ValueError("repository id mismatch in AuthorizedExecutionContext")


class PlannedExecutionGuard:
    """Single guard that Batch 3 planned execution paths must call.

    Every method takes an :class:`AuthorizedExecutionContext` as its FIRST
    positional argument — never a bare ``plan_id``. In Batch 2 the methods
    raise :class:`NotImplementedError` so that any premature wiring fails
    loudly. Batch 3 will replace the bodies with real implementations that
    still go through this guard.
    """

    def __init__(self, gate: "PlanExecutionGate", *, lease_authority: object | None = None) -> None:
        self._gate = gate
        self.__lease_authority = lease_authority
        self._contexts: dict[str, AuthorizedExecutionContext] = {}
        # Batch 2.6 §5: optional per-workspace mutation fence. When set,
        # every planned_* method verifies the fence is held by
        # "lease:{ctx.lease_id}" before proceeding.
        self._mutation_fence: Any = None
        self._mutation_engine: Any = None
        self.__mutation_call_authority: object | None = None

    def set_mutation_fence(self, fence: Any) -> None:
        """Batch 2.6 §5: register the shared per-workspace mutation fence."""
        self._mutation_fence = fence

    def set_mutation_engine(self, engine: Any, *, call_authority: object) -> None:
        """Runtime-only wiring for the capability-constructed mutation engine."""
        self._mutation_engine = engine
        self.__mutation_call_authority = call_authority

    def require_active_execution_context(self, ctx: AuthorizedExecutionContext) -> None:
        """Validate the opaque server-issued capability and its live lease.

        Batch 2.6 §5: if a mutation fence is configured, also verifies the
        fence is held by ``"lease:{ctx.lease_id}"`` so that non-owner
        planned mutations are rejected.
        """
        registered = self._contexts.get(getattr(ctx, "execution_context_id", ""))
        if registered is not ctx:
            raise PermissionError("execution context was not issued by this guard")
        if not self._gate.require_active_lease(
            ctx.lease_id, owner_execution_id=ctx.owner_execution_id,
            expected_task_id=ctx.task_id, expected_workspace_id=ctx.workspace_id,
            expected_repository_id=ctx.repository_id, expected_plan_id=ctx.plan_id,
        ):
            raise PermissionError("execution context lease is not active")
        # Batch 2.6 §5: verify the mutation fence is held by this lease.
        if self._mutation_fence is None and not getattr(self._gate, "_unsafe_test_only", False):
            raise PermissionError("planned execution guard requires mutation fence")
        if self._mutation_fence is not None:
            self._mutation_fence.assert_owner(ctx.workspace_id, f"lease:{ctx.lease_id}")

    def planned_workspace_edit(
        self, ctx: AuthorizedExecutionContext, *, bundle: Any = None,
        edit: dict | None = None,
    ) -> Any:
        """Apply one server-validated edit bundle in the active workspace."""
        self.require_active_execution_context(ctx)
        if bundle is None:
            raise NotImplementedError(
                "individual planned edits are forbidden; use a PlannedEditBundle"
            )
        if self._mutation_engine is None:
            raise PermissionError("planned mutation engine is not runtime configured")
        return self._mutation_engine.apply_bundle(
            context=ctx, bundle=bundle,
            _call_authority=self.__mutation_call_authority,
        )

    def planned_tool_invocation(self, ctx: AuthorizedExecutionContext, *, invocation: dict) -> None:
        """Invoke a planned tool. (Batch 3)"""
        self.require_active_execution_context(ctx)
        raise NotImplementedError("planned_tool_invocation is implemented in Batch 3")

    def planned_verification_execution(self, ctx: AuthorizedExecutionContext, *, verification: dict) -> None:
        """Run a planned verification command. (Batch 3)"""
        self.require_active_execution_context(ctx)
        raise NotImplementedError(
            "planned_verification_execution is implemented in Batch 3"
        )

    def planned_changeset_creation(self, ctx: AuthorizedExecutionContext, *, changeset_spec: dict) -> None:
        """Create a planned ChangeSet. (Batch 3)"""
        self.require_active_execution_context(ctx)
        raise NotImplementedError(
            "planned_changeset_creation is implemented in Batch 3"
        )

    def planned_changeset_apply(self, ctx: AuthorizedExecutionContext, *, changeset_id: str) -> None:
        """Apply a planned ChangeSet. (Batch 3)"""
        self.require_active_execution_context(ctx)
        raise NotImplementedError("planned_changeset_apply is implemented in Batch 3")

    # ------------------------------------------------------------------
    # Factory: build an AuthorizedExecutionContext from an authorization id.
    # This is the only sanctioned way for Batch 3 callers to obtain a
    # context, ensuring they always pass through the gate.
    # ------------------------------------------------------------------

    def authorize(
        self,
        authorization_id: str,
        nonce: str,
        *,
        expected_plan_id: str,
        expected_task_id: str,
        expected_workspace_id: str,
        expected_repository_id: str,
        owner_execution_id: str = "exec_default",
    ) -> AuthorizedExecutionContext:
        """Lease-first consume: acquire an execution lease AND consume the
        authorization, returning the execution context + lease.

        Batch 2.3: delegates to :meth:`PlanExecutionGate.acquire_lease` — the
        ONLY public consume entry point. A bare PlanExecutionAuthorization is
        never returned to Batch 3 callers.
        """
        consumed, lease = self._gate.acquire_lease(
            authorization_id=authorization_id,
            nonce=nonce,
            expected_plan_id=expected_plan_id,
            expected_task_id=expected_task_id,
            expected_workspace_id=expected_workspace_id,
            expected_repository_id=expected_repository_id,
            owner_execution_id=owner_execution_id,
            _lease_authority=self.__lease_authority,
        )
        context_id = f"execctx_{secrets.token_hex(24)}"
        ctx = AuthorizedExecutionContext(
            authorization=consumed,
            plan_id=expected_plan_id,
            task_id=expected_task_id,
            workspace_id=expected_workspace_id,
            repository_id=expected_repository_id,
            lease_id=lease.lease_id,
            owner_execution_id=lease.owner_execution_id,
            lease_expiry=lease.expiry,
            server_epoch=self._gate.server_epoch,
            boot_id=self._gate.boot_id,
            authorization_id=consumed.authorization_id,
            binding_digest=consumed.binding_digest,
            execution_context_id=context_id,
        )
        self._contexts[context_id] = ctx
        return ctx
