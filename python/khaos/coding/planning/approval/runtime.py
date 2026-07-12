"""Fail-closed production bootstrap for approval and lease runtime."""
from __future__ import annotations

import enum
import logging
from dataclasses import dataclass
from typing import Any

from khaos.coding.planning.approval.gate import PlanExecutionGate
from khaos.coding.planning.approval.repository import PersistedPlanRepository
from khaos.coding.planning.approval.service import PlanApprovalService

logger = logging.getLogger(__name__)

@dataclass(frozen=True)
class BootContext:
    server_epoch: int
    boot_id: str


class RuntimeState(enum.Enum):
    """Batch 2.6 §3: initialization state machine.

    UNINITIALIZED → ROTATING → RECEIPT_BOUND → RECONCILING → READY

    Failure at any step triggers ``_rollback()`` which reverts to
    UNINITIALIZED, clears the broker writer, and invalidates all
    auth/leases minted under the failed boot_id.
    """
    UNINITIALIZED = 0
    ROTATING = 1
    RECEIPT_BOUND = 2
    RECONCILING = 3
    READY = 4


@dataclass(frozen=True)
class RuntimeCapability:
    """Opaque capability token issued by :class:`ApprovalRuntime`.

    Batch 2.6 §2: production :class:`PlanExecutionGate` and
    :class:`PlanApprovalService` require this token at construction. It
    carries the boot context so the gate/service can verify the persisted
    epoch + boot_id on every operation (stale-runtime fence).

    This class is intentionally NOT exported from the production package
    ``__all__`` — only :class:`ApprovalRuntime` mints instances, and only
    production Gate/Service consume them. Test code must use the explicit
    ``UnsafeTest*`` subclasses in ``tests/coding/_m4_batch2_helpers.py``.
    """
    boot_context: BootContext

class ApprovalRuntime:
    """Production bootstrap for the approval + lease runtime.

    Batch 2.6 §3: initialization follows an explicit state machine
    (UNINITIALIZED → ROTATING → RECEIPT_BOUND → RECONCILING → READY).
    On failure at any step, ``_rollback()`` reverts to UNINITIALIZED,
    clears the broker's receipt writer, invalidates all auth/leases for
    the failed boot_id, and ensures the runtime is safe to retry.
    """

    def __init__(self, *, store: Any, broker: Any, context_provider: Any, plan_repository: PersistedPlanRepository, planning_service: Any) -> None:
        if not isinstance(plan_repository, PersistedPlanRepository):
            raise TypeError("production ApprovalRuntime requires PersistedPlanRepository")
        if planning_service is None or getattr(planning_service, "_unsafe_test_only", False) or not callable(getattr(planning_service, "validate_plan", None)):
            raise TypeError("production ApprovalRuntime requires deep planning validator")
        if context_provider is None or not callable(getattr(context_provider, "current_state", None)):
            raise TypeError("production ApprovalRuntime requires ContextProvider")
        # Batch 2.5 §1: validate broker type and authenticator BEFORE wiring.
        if broker is None or broker.__class__.__module__ != "khaos.agent.approval" or broker.__class__.__name__ != "ApprovalBroker":
            raise TypeError("production ApprovalRuntime requires a real ApprovalBroker")
        if getattr(broker, "_authenticator", None) is None:
            raise TypeError("production ApprovalRuntime requires broker with ApprovalAuthenticator")
        self._store=store; self._broker=broker; self._context_provider=context_provider
        self._plan_repository=plan_repository; self._planning_service=planning_service
        # Runtime-internal token — opaque object that only this instance
        # possesses. Used to register the receipt sink with the broker so
        # that forged callers cannot replace it.
        self._runtime_token = object()
        self.service=None; self.gate=None; self.boot_context=None; self.ready=False
        self._state = RuntimeState.UNINITIALIZED

    @property
    def state(self) -> RuntimeState:
        """Current initialization state (Batch 2.6 §3)."""
        return self._state

    def initialize(self) -> BootContext:
        """Initialize the runtime: wire receipts, construct services, reconcile.

        Batch 2.6 §3: explicit state machine with rollback on failure.
        UNINITIALIZED → ROTATING → RECEIPT_BOUND → RECONCILING → READY.
        On failure, ``_rollback()`` reverts to UNINITIALIZED and clears
        all partial state. The runtime is safe to retry after a failure.
        """
        if self.ready:
            raise RuntimeError("approval runtime is already initialized — call shutdown() first")
        self._state = RuntimeState.ROTATING
        try:
            # 1. Rotate epoch (generates fresh boot_id, revokes old auths/leases)
            epoch, boot_id, _ = self._store.rotate_epoch()
            self.boot_context = BootContext(epoch, boot_id)

            # 2. Wire Broker → durable Receipt outbox (Batch 2.6 §1)
            self._state = RuntimeState.RECEIPT_BOUND
            signer = self._broker.receipt_signer
            store = self._store
            # Load old signers (for verifying receipts from prior boots).
            for old_signer in store.load_receipt_signers():
                if old_signer.key_id != signer.key_id:
                    store._register_receipt_signer(
                        old_signer, runtime_token=self._runtime_token,
                    )
            # Persist the current signer and register it.
            store.persist_receipt_signer(signer)
            store._register_receipt_signer(
                signer, runtime_token=self._runtime_token,
            )
            def _writer(**fields):
                store._insert_signed_receipt(**fields)
            self._broker._install_runtime_receipt_writer(
                _writer, runtime_token=self._runtime_token,
            )

            # 3. Construct Gate and Service + reconcile (Batch 2.6 §2)
            self._state = RuntimeState.RECONCILING
            capability = RuntimeCapability(boot_context=self.boot_context)
            self.gate = PlanExecutionGate(
                store=self._store, context_provider=self._context_provider,
                plan_repository=self._plan_repository, planning_service=self._planning_service,
                runtime_capability=capability,
            )
            self.service = PlanApprovalService(
                store=self._store, broker=self._broker,
                context_provider=self._context_provider,
                plan_repository=self._plan_repository, planning_service=self._planning_service,
                runtime_capability=capability,
            )
            self.service.reconcile()

            # 4. Mark ready
            self._state = RuntimeState.READY
            self.ready = True
            logger.info("approval runtime initialized: epoch=%d boot=%s", epoch, boot_id[:8])
            return self.boot_context
        except Exception:
            self._rollback()
            raise

    def _rollback(self) -> None:
        """Batch 2.6 §3: roll back partial initialization.

        Reverts the runtime to UNINITIALIZED and ensures:
        * ``ready`` is False — no operations can proceed.
        * Broker does not retain the receipt writer — no receipts can be
          minted under the failed boot.
        * All auth/leases minted under the failed boot_id are invalidated.
        * ``boot_context`` is cleared — the old boot cannot be reused.
        * State is UNINITIALIZED — safe to retry ``initialize()``.
        """
        failed_state = self._state
        self._state = RuntimeState.UNINITIALIZED
        self.ready = False
        self.gate = None
        self.service = None

        # Clear the broker writer + store writer (if receipt wiring happened).
        if failed_state.value >= RuntimeState.RECEIPT_BOUND.value:
            try:
                self._broker._reset_runtime_receipt_writer()
            except Exception:
                pass
            try:
                self._store._reset_runtime_receipt_writer()
            except Exception:
                pass

        # Invalidate all auth/leases for the failed boot_id (if epoch was rotated).
        if failed_state.value >= RuntimeState.ROTATING.value and self.boot_context is not None:
            try:
                self._store.invalidate_active_execution_scope(
                    boot_id=self.boot_context.boot_id,
                    reason="runtime-init-failed",
                )
            except Exception:
                pass

        self.boot_context = None
        logger.warning("approval runtime initialization failed at %s; rolled back", failed_state.name)

    def require_ready(self) -> None:
        if not self.ready or self.gate is None:
            raise RuntimeError("approval runtime is not initialized")
        # Batch 2.5 §7: verify persisted boot context is still current
        if self.boot_context is not None:
            persisted_epoch, persisted_boot_id = self._store.get_current_epoch()
            if (persisted_epoch != self.boot_context.server_epoch
                    or persisted_boot_id != self.boot_context.boot_id):
                self.ready = False
                self._state = RuntimeState.UNINITIALIZED
                raise RuntimeError("approval runtime boot context is stale (another runtime initialized)")

    def authorize_execution(self, **kwargs: Any):
        self.require_ready(); return self.gate.authorize_execution(**kwargs)

    def acquire_lease(self, **kwargs: Any):
        self.require_ready(); return self.gate.acquire_lease(**kwargs)

    def require_active_lease(self, *args: Any, **kwargs: Any):
        self.require_ready(); return self.gate.require_active_lease(*args, **kwargs)

    def shutdown(self) -> None:
        """Atomically invalidate this boot's auth/lease/context.

        Batch 2.5 §7: first invalidates all ACTIVE execution scopes
        (leases + still-ACTIVE authorizations) for this boot, then rotates
        the epoch to fence any remaining state. After shutdown, all
        operations refuse.

        Batch 2.6 §1: also clears the broker's receipt writer and the
        store's signer registry so no further receipts can be minted or
        verified under this boot.
        """
        if self.ready:
            # Cancel all ACTIVE leases for this boot before rotating the epoch.
            self._store.invalidate_active_execution_scope(
                boot_id=self.boot_context.boot_id, reason="runtime-shutdown",
            )
            self._store.rotate_epoch()
            # Clear the broker's writer and the store's signer registry.
            try:
                self._broker._reset_runtime_receipt_writer()
            except Exception:
                pass
            try:
                self._store._reset_runtime_receipt_writer()
            except Exception:
                pass
            self.ready = False
            self.gate = None
            self.service = None
            self.boot_context = None
            self._state = RuntimeState.UNINITIALIZED
            logger.info("approval runtime shut down")

    def register_lease_coordinator(
        self, *, task_manager: Any = None, workspace_manager: Any = None,
        repository_indexer: Any = None,
    ) -> WorkspaceExecutionLeaseCoordinator:
        """Wire the lease coordinator hooks into real Managers.

        Batch 2.5 §4: connects TaskManager.cancel and WorkspaceManager.cleanup
        to the coordinator's invalidate_active_execution_scope via the
        Managers' lease_invalidation_hook. Returns the coordinator for
        planned-mutation precondition checks (generation/HEAD updates).

        Batch 2.6 §5: also wires the shared per-workspace mutation fence
        into TaskManager, WorkspaceManager, and RepositoryIndexer so that
        cleanup / cancel / generation updates are serialized with active
        lease acquisition and Batch 3 execution.
        """
        self.require_ready()
        coordinator = WorkspaceExecutionLeaseCoordinator(self)
        # Batch 2.6 §5: create the shared mutation fence and wire it into
        # all real components that mutate workspace state.
        from khaos.coding.planning.approval.mutation_fence import (
            WorkspaceMutationFence,
        )
        self._mutation_fence = WorkspaceMutationFence()
        if task_manager is not None:
            if hasattr(task_manager, "set_lease_invalidation_hook"):
                task_manager.set_lease_invalidation_hook(coordinator.cancel_task)
            if hasattr(task_manager, "set_mutation_fence"):
                task_manager.set_mutation_fence(self._mutation_fence)
        if workspace_manager is not None:
            if hasattr(workspace_manager, "set_lease_invalidation_hook"):
                workspace_manager.set_lease_invalidation_hook(coordinator.cleanup_workspace)
            if hasattr(workspace_manager, "set_mutation_fence"):
                workspace_manager.set_mutation_fence(self._mutation_fence)
        if repository_indexer is not None and hasattr(repository_indexer, "set_mutation_fence"):
            repository_indexer.set_mutation_fence(self._mutation_fence)
        return coordinator

    @property
    def mutation_fence(self) -> Any:
        """Batch 2.6 §5: the shared per-workspace mutation fence (or None)."""
        return getattr(self, "_mutation_fence", None)


class WorkspaceExecutionLeaseCoordinator:
    """Coordinates planned mutation preconditions without performing mutation.

    Batch 2.5 §3+§4: ``cancel_task`` and ``cleanup_workspace`` use the new
    ``invalidate_active_execution_scope`` store transaction that correctly
    handles CONSUMED approval requests (does NOT try CONSUMED → REVOKED).
    """
    def __init__(self, runtime: ApprovalRuntime) -> None:
        self._runtime=runtime

    def require_owner(self, ctx: Any) -> None:
        self._runtime.require_ready()
        if not self._runtime.gate.require_active_lease(ctx.lease_id,owner_execution_id=ctx.owner_execution_id,expected_task_id=ctx.task_id,expected_workspace_id=ctx.workspace_id,expected_repository_id=ctx.repository_id,expected_plan_id=ctx.plan_id):
            raise PermissionError("planned mutation requires active lease owner")

    def before_generation_or_head_update(self, ctx: Any) -> None:
        self.require_owner(ctx)

    def cancel_task(self, *, task_id: str | None = None, workspace_id: str | None = None, owner_execution_id: str | None = None, reason: str = "task-cancelled", now: float | None = None) -> int:
        """Cancel active execution scope by task and/or workspace.

        Batch 2.5 §3: uses ``invalidate_active_execution_scope`` which
        correctly handles CONSUMED approval requests — it revokes the
        ACTIVE lease and authorization without trying to roll back the
        CONSUMED approval request status.
        """
        self._runtime.require_ready()
        return self._runtime._store.invalidate_active_execution_scope(
            task_id=task_id, workspace_id=workspace_id,
            owner_execution_id=owner_execution_id, reason=reason, now=now,
        )

    def cleanup_workspace(self, *, task_id: str | None = None, workspace_id: str | None = None, owner_execution_id: str | None = None, reason: str = "workspace-cleanup", now: float | None = None) -> int:
        """Clean up active execution scope for a workspace."""
        self._runtime.require_ready()
        return self._runtime._store.invalidate_active_execution_scope(
            task_id=task_id, workspace_id=workspace_id,
            owner_execution_id=owner_execution_id, reason=reason, now=now,
        )

    def shutdown(self) -> None:
        self._runtime.shutdown()
