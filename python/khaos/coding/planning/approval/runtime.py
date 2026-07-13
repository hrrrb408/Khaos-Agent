"""Fail-closed production bootstrap for approval and lease runtime."""
from __future__ import annotations

import enum
import logging
import secrets
import threading
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
    __slots__ = ("_capability_id",)
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        raise TypeError("RuntimeCapability cannot be constructed directly")


class _RuntimeAuthorityRegistry:
    def __init__(self) -> None:
        self._lock=threading.Lock(); self._boots={}; self._capabilities={}

    def register_boot(self, boot: BootContext) -> str:
        runtime_id=secrets.token_hex(32)
        with self._lock: self._boots[runtime_id]=boot
        return runtime_id

    def issue(self, runtime_id: str, scope: str) -> RuntimeCapability:
        with self._lock:
            if runtime_id not in self._boots: raise PermissionError("runtime authority is revoked")
            cap_id=secrets.token_hex(32); self._capabilities[cap_id]=(runtime_id,scope,False)
        cap=object.__new__(RuntimeCapability); object.__setattr__(cap,"_capability_id",cap_id); return cap

    def consume(self, capability: Any, scope: str) -> BootContext:
        cap_id=getattr(capability,"_capability_id","")
        with self._lock:
            record=self._capabilities.get(cap_id)
            if record is None or record[1] != scope or record[2]: raise PermissionError("invalid or reused runtime capability")
            runtime_id=record[0]; boot=self._boots.get(runtime_id)
            if boot is None: raise PermissionError("runtime authority is revoked")
            self._capabilities[cap_id]=(runtime_id,scope,True); return boot

    def revoke(self, runtime_id: str | None) -> None:
        if runtime_id is None: return
        with self._lock:
            self._boots.pop(runtime_id,None)
            for cap_id,record in list(self._capabilities.items()):
                if record[0] == runtime_id: self._capabilities.pop(cap_id,None)

    def is_active(self, runtime_id: str | None, boot: BootContext) -> bool:
        if runtime_id is None:
            return False
        with self._lock:
            return self._boots.get(runtime_id) == boot

_RUNTIME_AUTHORITIES = _RuntimeAuthorityRegistry()

def _consume_runtime_capability(capability: Any, scope: str) -> BootContext:
    return _RUNTIME_AUTHORITIES.consume(capability, scope)

class ApprovalRuntime:
    """Production bootstrap for the approval + lease runtime.

    Batch 2.6 §3: initialization follows an explicit state machine
    (UNINITIALIZED → ROTATING → RECEIPT_BOUND → RECONCILING → READY).
    On failure at any step, ``_rollback()`` reverts to UNINITIALIZED,
    clears the broker's receipt writer, invalidates all auth/leases for
    the failed boot_id, and ensures the runtime is safe to retry.
    """

    def __init__(self, *, store: Any, broker: Any, context_provider: Any, plan_repository: PersistedPlanRepository, planning_service: Any, task_manager: Any = None, workspace_manager: Any = None, repository_indexer: Any = None) -> None:
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
        self._task_manager=task_manager; self._workspace_manager=workspace_manager; self._repository_indexer=repository_indexer
        # Runtime-internal token — opaque object that only this instance
        # possesses. Used to register the receipt sink with the broker so
        # that forged callers cannot replace it.
        self._runtime_token = object()
        self.service=None; self.gate=None; self.boot_context=None; self.ready=False
        self._state = RuntimeState.UNINITIALIZED
        self._runtime_authority_id: str | None = None

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
            self._runtime_authority_id = _RUNTIME_AUTHORITIES.register_boot(self.boot_context)

            # Execution readiness requires one shared mutation fence wired to
            # every mutable workspace subsystem before Gate construction.
            for name, dependency in (("TaskManager",self._task_manager),("WorkspaceManager",self._workspace_manager),("RepositoryIndexer",self._repository_indexer)):
                if dependency is None or not callable(getattr(dependency,"set_mutation_fence",None)):
                    raise TypeError(f"execution-ready ApprovalRuntime requires {name}")
            from khaos.coding.planning.approval.mutation_fence import WorkspaceMutationFence, PlannedHeadMutationAdapter
            from khaos.coding.planning.approval.execution_contract import PlannedExecutionGuard
            self._mutation_fence=WorkspaceMutationFence()
            self._store.reconcile_terminal_run_poison_scopes()
            for poisoned_workspace, poison_reason in self._store.list_poisoned_workspaces():
                self._mutation_fence.poison(poisoned_workspace, poison_reason)
            for poisoned_workspace, poison_owner, poison_reason in self._store.list_workspace_poison_scopes():
                self._mutation_fence.poison(
                    poisoned_workspace, poison_reason, owner=poison_owner
                )
            for dependency in (self._task_manager, self._workspace_manager):
                dependency.set_mutation_fence(self._mutation_fence)

            # 2. Wire Broker → durable Receipt outbox (Batch 2.6 §1)
            self._state = RuntimeState.RECEIPT_BOUND
            store = self._store
            self._broker._rotate_receipt_signing_authority(epoch, boot_id)
            verifier = self._broker._receipt_public_verifier()
            store_receipt_capability = _RUNTIME_AUTHORITIES.issue(
                self._runtime_authority_id, "receipt-store"
            )
            broker_receipt_capability = _RUNTIME_AUTHORITIES.issue(
                self._runtime_authority_id, "receipt-broker"
            )
            def _writer(**fields):
                if not _RUNTIME_AUTHORITIES.is_active(
                    self._runtime_authority_id, self.boot_context
                ):
                    raise PermissionError("receipt runtime authority is revoked")
                store._insert_signed_receipt(runtime_token=self._runtime_token, **fields)
            store._install_runtime_receipt_writer(
                _writer,
                runtime_token=self._runtime_token,
                runtime_capability=store_receipt_capability,
            )
            store._persist_receipt_verifier(verifier, runtime_token=self._runtime_token)
            self._broker._install_runtime_receipt_writer(
                _writer,
                runtime_token=self._runtime_token,
                runtime_capability=broker_receipt_capability,
            )

            # 3. Construct Gate and Service + reconcile (Batch 2.6 §2)
            self._state = RuntimeState.RECONCILING
            gate_capability = _RUNTIME_AUTHORITIES.issue(self._runtime_authority_id, "gate")
            service_capability = _RUNTIME_AUTHORITIES.issue(self._runtime_authority_id, "service")
            self._lease_authority=object()
            self.gate = PlanExecutionGate(
                store=self._store, context_provider=self._context_provider,
                plan_repository=self._plan_repository, planning_service=self._planning_service,
                runtime_capability=gate_capability,
                lease_authority=self._lease_authority,
            )
            self.service = PlanApprovalService(
                store=self._store, broker=self._broker,
                context_provider=self._context_provider,
                plan_repository=self._plan_repository, planning_service=self._planning_service,
                runtime_capability=service_capability,
            )
            self.service.reconcile()
            self.guard=PlannedExecutionGuard(self.gate,lease_authority=self._lease_authority)
            self.guard.set_mutation_fence(self._mutation_fence)
            self._coordinator=WorkspaceExecutionLeaseCoordinator(self)
            self._head_mutation_adapter=PlannedHeadMutationAdapter(self._mutation_fence,self._coordinator)
            mutation_capability = _RUNTIME_AUTHORITIES.issue(
                self._runtime_authority_id, "mutation-engine"
            )
            self._mutation_call_authority = object()
            from khaos.coding.planning.workspace_mutation import WorkspaceMutationEngine
            self._mutation_engine = WorkspaceMutationEngine(
                store=self._store, plan_repository=self._plan_repository,
                workspace_manager=self._workspace_manager,
                context_provider=self._context_provider, guard=self.guard,
                mutation_fence=self._mutation_fence,
                runtime_capability=mutation_capability,
                call_authority=self._mutation_call_authority,
            )
            self.guard.set_mutation_engine(
                self._mutation_engine,
                call_authority=self._mutation_call_authority,
            )
            self._repository_indexer.set_mutation_fence(
                self._mutation_fence,
                workspace_resolver=self._coordinator.resolve_repository_workspace,
            )
            if callable(getattr(self._task_manager, "set_execution_scope_resolver", None)):
                self._task_manager.set_execution_scope_resolver(
                    self._coordinator.resolve_task_workspace
                )
            if callable(getattr(self._task_manager, "set_lease_invalidation_hook", None)):
                self._task_manager.set_lease_invalidation_hook(self._coordinator.cancel_task)
            if callable(getattr(self._workspace_manager, "set_lease_invalidation_hook", None)):
                self._workspace_manager.set_lease_invalidation_hook(
                    self._coordinator.cleanup_workspace
                )
            self._mutation_engine.recover_incomplete_runs()

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
        _RUNTIME_AUTHORITIES.revoke(self._runtime_authority_id)
        self._runtime_authority_id = None
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
        raise PermissionError("bare lease acquisition is closed; use acquire_execution_context")

    def acquire_execution_context(self, **kwargs: Any):
        self.require_ready()
        from khaos.coding.planning.approval.mutation_fence import fenced_acquire_lease
        return fenced_acquire_lease(self._coordinator,self._mutation_fence,self.guard,**kwargs)

    def apply_edit_bundle(self, *, context: Any, bundle: Any) -> Any:
        """Only public planned-mutation route: Runtime → Guard → Engine."""
        self.require_ready()
        return self.guard.planned_workspace_edit(context, bundle=bundle)

    def require_active_lease(self, *args: Any, **kwargs: Any):
        self.require_ready(); return self.gate.require_active_lease(*args, **kwargs)

    def recover_poisoned_workspace(
        self, workspace_id: str, *, force: bool = False
    ) -> bool:
        """Run the controlled lease reaper and clear in-memory quarantine."""
        self.require_ready()
        recovered = self._store.recover_poisoned_workspace(
            workspace_id, force=force
        )
        if recovered:
            self._mutation_fence.clear_poison(workspace_id)
        return recovered

    def shutdown(self) -> None:
        """Atomically invalidate this boot's auth/lease/context.

        Batch 2.5 §7: first invalidates all ACTIVE execution scopes
        (leases + still-ACTIVE authorizations) for this boot, then rotates
        the epoch to fence any remaining state. After shutdown, all
        operations refuse.

        Also clears the broker/store writer binding so no further receipts
        can be minted under this boot. Persisted public keys remain usable.
        """
        if self.ready:
            # Cancel all ACTIVE leases for this boot before rotating the epoch.
            self._store.invalidate_active_execution_scope(
                boot_id=self.boot_context.boot_id, reason="runtime-shutdown",
            )
            self._store.rotate_epoch()
            # Clear runtime writer bindings; public verifiers are durable.
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
            _RUNTIME_AUTHORITIES.revoke(self._runtime_authority_id)
            self._runtime_authority_id = None
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
        coordinator = self._coordinator
        if task_manager is not None:
            if hasattr(task_manager, "set_lease_invalidation_hook"):
                task_manager.set_lease_invalidation_hook(coordinator.cancel_task)
            if hasattr(task_manager, "set_mutation_fence"):
                task_manager.set_mutation_fence(self._mutation_fence)
            if hasattr(task_manager, "set_execution_scope_resolver"):
                task_manager.set_execution_scope_resolver(
                    coordinator.resolve_task_workspace
                )
        if workspace_manager is not None:
            if hasattr(workspace_manager, "set_lease_invalidation_hook"):
                workspace_manager.set_lease_invalidation_hook(coordinator.cleanup_workspace)
            if hasattr(workspace_manager, "set_mutation_fence"):
                workspace_manager.set_mutation_fence(self._mutation_fence)
        if repository_indexer is not None and hasattr(repository_indexer, "set_mutation_fence"):
            repository_indexer.set_mutation_fence(
                self._mutation_fence,
                workspace_resolver=coordinator.resolve_repository_workspace,
            )
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

    def resolve_task_workspace(self, task_id: str) -> str | None:
        """Resolve Task→Workspace from the durable ACTIVE lease relation."""
        self._runtime.require_ready()
        return self._runtime._store.active_lease_scope_for_task(task_id)

    def resolve_repository_workspace(
        self, repository_id: str, workspace_id: str
    ) -> str:
        """Validate an explicit canonical workspace mutation scope."""
        self._runtime.require_ready()
        workspace_getter = getattr(self._runtime._workspace_manager, "get", None)
        if callable(workspace_getter):
            workspace = workspace_getter(workspace_id)
            if workspace is None or getattr(workspace, "repository_root", None) is None:
                raise RuntimeError("workspace is missing or inactive")
        if not self._runtime._store.validate_repository_workspace_scope(
            repository_id, workspace_id
        ):
            raise RuntimeError("repository/workspace scope is ambiguous")
        return workspace_id

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
