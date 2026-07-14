"""Fail-closed production bootstrap for approval and lease runtime."""
from __future__ import annotations

import enum
import logging
import secrets
import threading
import time
import uuid
from contextlib import asynccontextmanager
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


class VerificationSnapshotProvider:
    """Batch 3.1.5 §2: trusted provider that computes and persists the
    :class:`ApprovedVerificationPlanSnapshot` before human approval.

    The provider is constructed by :class:`ApprovalRuntime` after trusted
    verification is configured (image probed, toolchains attested).  It has
    access to the runtime's verification components (command factory, profile,
    attestations) and the workspace manager (to build the catalog from the
    plan's workspace).

    ``compute_snapshot(plan)`` is called by
    :meth:`PlanApprovalService.request_approval` BEFORE the PENDING/NOT_REQUIRED
    row is created.  The returned snapshot's digest enters
    :func:`compute_plan_binding_digest` so any drift in commands, catalog,
    profile, image attestation, or toolchain attestations invalidates the
    approval.
    """

    def __init__(
        self,
        *,
        workspace_manager: Any,
        command_factory: Any,
        profile: Any,
        image_attestation: Any,
        toolchain_attestations: tuple,
        verification_store: Any,
        boot_context: Any,
    ) -> None:
        self._workspace_manager = workspace_manager
        self._command_factory = command_factory
        self._profile = profile
        self._image_attestation = image_attestation
        self._toolchain_attestations = toolchain_attestations
        self._verification_store = verification_store
        self._boot_context = boot_context

    def compute_snapshot(self, plan: Any) -> Any:
        """Compute, persist, and return the ApprovedVerificationPlanSnapshot."""
        import uuid as _uuid
        from khaos.coding.planning.approval.models import compute_verification_digest
        from khaos.coding.planning.verification_catalog import VerificationCatalog
        from khaos.coding.planning.verification_execution_models import (
            ApprovedVerificationPlanSnapshot,
            compute_approved_verification_plan_digest,
            compute_image_toolchain_policy_fingerprint,
        )

        workspace = self._workspace_manager.get(plan.workspace_id)
        if workspace is None:
            raise RuntimeError(
                f"workspace {plan.workspace_id} not found for snapshot computation"
            )
        catalog = VerificationCatalog(
            workspace.worktree_path, repository_id=plan.repository_id,
        )
        commands = self._command_factory.build(
            plan.verification_requirements, catalog.entries,
            profile_id=self._profile.profile_id,
        )
        ordered_command_digests = tuple(c.command_digest for c in commands)
        config_hashes = tuple(sorted(catalog.config_hashes.values()))
        image_content_digest = ""
        if self._image_attestation is not None:
            image_content_digest = (
                getattr(self._image_attestation, "content_digest", "")
                or getattr(self._image_attestation, "attestation_digest", "")
            )
        ordered_tc_digests = tuple(
            getattr(att, "attestation_digest", "") for att in self._toolchain_attestations
        )
        binary_digests = tuple(
            getattr(att, "binary_digest", "") for att in self._toolchain_attestations
        )
        version_output_digests = tuple(
            getattr(att, "version_output_digest", "") for att in self._toolchain_attestations
        )
        parsed_versions = tuple(
            getattr(att, "parsed_version", "") for att in self._toolchain_attestations
        )
        # image_toolchain_policy_fingerprint: binds image + toolchain + profile
        # policy into a single digest.  Any change to the approved image,
        # toolchain set, or sandbox profile invalidates the fingerprint.
        image_toolchain_policy_fingerprint = (
            compute_image_toolchain_policy_fingerprint(
                image_attestation_content_digest=image_content_digest,
                ordered_toolchain_attestation_content_digests=ordered_tc_digests,
                sandbox_profile_digest=self._profile.digest,
            )
        )

        verification_requirements_digest = compute_verification_digest(
            plan.verification_requirements
        )
        approved_verification_plan_id = f"avp_{_uuid.uuid4().hex}"
        created_at = time.time()
        snapshot_digest = compute_approved_verification_plan_digest(
            plan_id=plan.plan_id,
            plan_content_hash=plan.content_hash,
            verification_requirements_digest=verification_requirements_digest,
            catalog_fingerprint=catalog.fingerprint,
            ordered_command_digests=ordered_command_digests,
            config_hashes=config_hashes,
            sandbox_profile_digest=self._profile.digest,
            image_attestation_content_digest=image_content_digest,
            ordered_toolchain_attestation_content_digests=ordered_tc_digests,
            binary_digests=binary_digests,
            version_output_digests=version_output_digests,
            parsed_versions=parsed_versions,
            image_toolchain_policy_fingerprint=image_toolchain_policy_fingerprint,
        )
        snapshot = ApprovedVerificationPlanSnapshot(
            approved_verification_plan_id=approved_verification_plan_id,
            plan_id=plan.plan_id,
            plan_content_hash=plan.content_hash,
            verification_requirements_digest=verification_requirements_digest,
            catalog_fingerprint=catalog.fingerprint,
            ordered_command_digests=ordered_command_digests,
            config_hashes=config_hashes,
            sandbox_profile_digest=self._profile.digest,
            image_attestation_content_digest=image_content_digest,
            ordered_toolchain_attestation_content_digests=ordered_tc_digests,
            binary_digests=binary_digests,
            version_output_digests=version_output_digests,
            parsed_versions=parsed_versions,
            image_toolchain_policy_fingerprint=image_toolchain_policy_fingerprint,
            created_at=created_at,
            approved_verification_plan_digest=snapshot_digest,
        )
        self._verification_store.persist_approved_verification_plan_snapshot(
            snapshot, boot_id=self._boot_context.boot_id,
        )
        return snapshot


class ApprovalRuntime:
    """Production bootstrap for the approval + lease runtime.

    Batch 2.6 §3: initialization follows an explicit state machine
    (UNINITIALIZED → ROTATING → RECEIPT_BOUND → RECONCILING → READY).
    On failure at any step, ``_rollback()`` reverts to UNINITIALIZED,
    clears the broker's receipt writer, invalidates all auth/leases for
    the failed boot_id, and ensures the runtime is safe to retry.
    """

    def __init__(self, *, store: Any, broker: Any, context_provider: Any,
                 plan_repository: PersistedPlanRepository, planning_service: Any,
                 task_manager: Any = None, workspace_manager: Any = None,
                 repository_indexer: Any = None,
                 verification_docker_executable: str = "/usr/local/bin/docker") -> None:
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
        self._verification_contexts: dict[str, Any] = {}
        self._verification_cancel_events: dict[str, Any] = {}
        self._verification_runner: Any = None
        self._verification_store: Any = None
        self._verification_toolchain_attestations: tuple = ()
        self._verification_actual_image_id: str = ""
        # Batch 3.1.3 §4: full image attestation (RepoDigests, config ID, platform)
        self._verification_image_attestation: Any = None
        self._verification_config_state: str = "UNCONFIGURED"
        # Batch 3.1.4 §3: approved attestation digests frozen at configuration
        # time.  At execution time, the runner re-probes and verifies match.
        self._approved_image_attestation_digest: str = ""
        self._approved_toolchain_attestation_digests: tuple[str, ...] = ()
        self._verification_docker_executable = verification_docker_executable

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
        from khaos.coding.planning.verification_storage import (
            VERIFICATION_STORAGE_REGISTRY,
        )
        VERIFICATION_STORAGE_REGISTRY.revoke_runtime(self._runtime_authority_id)
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

    def configure_trusted_verification(
        self, *, config: Any, command_factory: Any, profile: Any,
    ) -> None:
        """Install the production-only trusted verifier after Runtime startup.

        Batch 3.1.4 §2: accepts a typed ``ProductionVerificationConfig``
        instead of a caller-provided backend instance.  The runtime
        constructs the exact ``DockerVerificationSandboxBackend``
        internally via a private factory, signed with a runtime-issued
        factory marker.  Callers cannot pass backend instances.

        Batch 3.1.1 §7: probes the backend image (``--pull=never``) and
        verifies the actual image ID matches the profile's pinned digest
        BEFORE installing the runner.  The probe is synchronous to
        ``configure_trusted_verification`` so a misconfigured image fails
        at configuration time, not at verification execution time.

        Batch 3.1.1 §8: follows a configuration state machine:
        UNCONFIGURED → PROBING_BACKEND → VERIFYING_TOOLCHAINS →
        RECONCILING_SANDBOXES → READY.  On failure, the verifier is
        NOT installed and the runtime is safe to retry.
        """
        self.require_ready()
        from khaos.coding.planning.verification_sandbox import (
            ProductionVerificationConfig,
        )
        if not isinstance(config, ProductionVerificationConfig):
            raise TypeError(
                "configure_trusted_verification requires a "
                "ProductionVerificationConfig — caller-provided backends "
                "are not accepted"
            )
        from khaos.coding.planning.verification_storage import (
            VERIFICATION_STORAGE_REGISTRY,
        )
        artifact_capability = VERIFICATION_STORAGE_REGISTRY.resolve(
            config.artifact_storage_capability_id,
            runtime_id=self._runtime_authority_id,
            boot_id=self.boot_context.boot_id, kind="artifact",
        )
        snapshot_capability = VERIFICATION_STORAGE_REGISTRY.resolve(
            config.snapshot_storage_capability_id,
            runtime_id=self._runtime_authority_id,
            boot_id=self.boot_context.boot_id, kind="snapshot",
        )
        backend = self._construct_production_backend(config, profile)
        self._configure_trusted_verification_internal(
            backend=backend, command_factory=command_factory,
            workspace_factory=None, artifact_root=None, profile=profile,
            artifact_capability=artifact_capability,
            snapshot_capability=snapshot_capability,
        )

    def issue_verification_storage_capabilities(
        self, *, artifact_root: Any, snapshot_root: Any,
    ) -> Any:
        """Issue opaque boot-scoped storage IDs from trusted runtime roots."""
        self.require_ready()
        from pathlib import Path as _Path
        from khaos.coding.planning.verification_sandbox import (
            ProductionVerificationConfig,
        )
        from khaos.coding.planning.verification_storage import (
            VERIFICATION_STORAGE_REGISTRY,
        )
        forbidden: list[_Path] = []
        workspaces = getattr(self._workspace_manager, "_workspaces", {})
        for workspace in workspaces.values():
            for value in (
                workspace.repository_root, workspace.worktree_path,
                workspace.recovery_root,
            ):
                if value is not None:
                    forbidden.append(_Path(value))
        for row in self._store._conn.execute("PRAGMA database_list").fetchall():
            database_path = row[2]
            if database_path:
                forbidden.append(_Path(database_path))
                forbidden.append(_Path(database_path).parent)
        artifact_id, snapshot_id = VERIFICATION_STORAGE_REGISTRY.issue_pair(
            runtime_id=self._runtime_authority_id,
            boot_id=self.boot_context.boot_id,
            artifact_root=_Path(artifact_root), snapshot_root=_Path(snapshot_root),
            forbidden_roots=tuple(forbidden),
        )
        return ProductionVerificationConfig(
            artifact_storage_capability_id=artifact_id,
            snapshot_storage_capability_id=snapshot_id,
        )

    def _construct_production_backend(
        self, config: Any, profile: Any,
    ) -> Any:
        """Batch 3.1.4 §2 / Batch 3.1.5 §1: private factory that constructs
        the exact backend.

        Verifies:
        - Profile ID matches the config.
        - ``config.approved_image_reference`` matches the profile's
          ``requested_image_reference`` (or ``image_digest`` for
          backward-compatible test profiles).
        - Docker executable exists and matches the config.
        - The backend is exactly ``DockerVerificationSandboxBackend``.

        Signs the backend with a runtime-issued factory marker that
        ``ProductionVerificationAuthority.sign`` verifies before signing.
        """
        from pathlib import Path as _Path
        from khaos.coding.planning.verification_sandbox import (
            DockerVerificationSandboxBackend, ProductionVerificationAuthority,
        )
        docker_path = _Path(self._verification_docker_executable).resolve(strict=True)
        # Construct the exact backend — no caller object.
        backend = DockerVerificationSandboxBackend(
            profile=profile, docker_executable=docker_path,
        )
        # Batch 3.1.4 §2: set the runtime factory marker before signing.
        # This marker is an opaque object that only this runtime possesses.
        factory_marker = object()
        object.__setattr__(backend, "_runtime_factory_marker", factory_marker)
        # Sign with the authority that carries the factory marker.
        authority = ProductionVerificationAuthority(factory_marker=factory_marker)
        authority.sign(backend)
        return backend

    def _configure_trusted_verification_unsafe(
        self, *, backend: Any, command_factory: Any, workspace_factory: Any,
        artifact_root: Any, profile: Any,
    ) -> None:
        """Batch 3.1.4 §2: UNSAFE test-only configuration path.

        Accepts a caller-provided backend for testing.  This method is
        explicitly unsafe — production code must use
        ``configure_trusted_verification`` with a
        ``ProductionVerificationConfig`` instead.

        The backend is signed with a test-only authority that does NOT
        carry the runtime factory marker.  The production runner rejects
        backends without the factory marker.
        """
        self.require_ready()
        from khaos.coding.planning.verification_sandbox import (
            ProductionVerificationAuthority,
        )
        # Batch 3.1.4 §2: sign with a test-only authority (no factory marker).
        # The runner must accept this via the _unsafe_test_only flag.
        object.__setattr__(backend, "_production_authority", "khaos-production-v1")
        object.__setattr__(backend, "_unsafe_test_only", True)
        self._configure_trusted_verification_internal(
            backend=backend, command_factory=command_factory,
            workspace_factory=workspace_factory, artifact_root=artifact_root,
            profile=profile,
        )

    def _configure_trusted_verification_internal(
        self, *, backend: Any, command_factory: Any, workspace_factory: Any,
        artifact_root: Any, profile: Any, artifact_capability: Any = None,
        snapshot_capability: Any = None,
    ) -> None:
        """Internal configuration shared by production and unsafe paths."""
        import asyncio as _asyncio
        from khaos.coding.planning.trusted_verification_runner import TrustedVerificationRunner
        from khaos.coding.planning.verification_sandbox import (
            DockerVerificationSandboxBackend, ProductionVerificationAuthority,
        )
        from khaos.coding.planning.verification_store import VerificationExecutionStore

        # Batch 3.1.1 §8 / Batch 3.1.5 §1: PROBING_BACKEND
        self._verification_config_state = "PROBING_BACKEND"
        try:
            # Batch 3.1.5 §1: only ONE authoritative image probe flow.
            # The old ``backend.probe()`` that conflated local config ID
            # with repository manifest digest is NO LONGER called separately.
            # ``probe_image_attestation()`` performs the complete validation:
            #   - reference exists locally (image inspect)
            #   - RepoDigests contains approved repository digest
            #   - local config ID is non-empty
            #   - platform matches (when approved_platform is set)
            import asyncio as _aio
            import concurrent.futures as _cf
            probe_attestation = getattr(backend, "probe_image_attestation", None)
            if callable(probe_attestation):
                with _cf.ThreadPoolExecutor(max_workers=1) as pool_img:
                    image_attestation = pool_img.submit(
                        lambda: _aio.run(probe_attestation())
                    ).result()
                self._verification_image_attestation = image_attestation
                # Batch 3.1.5 §1: extract the local config ID from the
                # attestation (not from a separate probe() call).
                self._verification_actual_image_id = (
                    image_attestation.local_config_image_id
                )
            else:
                # Test backends without probe_image_attestation: fall back
                # to probe() for backward compatibility.
                with _cf.ThreadPoolExecutor(max_workers=1) as pool:
                    actual_image_id = pool.submit(
                        lambda: _aio.run(backend.probe())
                    ).result()
                self._verification_actual_image_id = actual_image_id
                self._verification_image_attestation = None
        except Exception as exc:
            self._verification_config_state = "UNCONFIGURED"
            raise RuntimeError(
                f"trusted verification backend probe failed: {exc}"
            ) from exc

        # Batch 3.1.1 §8: VERIFYING_TOOLCHAINS
        # Batch 3.1.2 §5: real toolchain attestation — run attestation
        # containers (no Workspace mount) to compute the actual binary
        # SHA-256, run the fixed version argv, parse the output, and
        # verify the parsed version matches the approved version.  The
        # old string-format-only check (``binary_digest.startswith``) is
        # no longer sufficient.
        self._verification_config_state = "VERIFYING_TOOLCHAINS"
        # Initialize the verification store early so attestation rows can
        # be persisted before sandbox reconciliation runs.
        self._verification_store = VerificationExecutionStore(self._store)
        toolchains = tuple(getattr(command_factory, "_tools", {}).values())
        # Batch 3.1.3 §5: production declaration-only fallback is forbidden.
        # DockerVerificationSandboxBackend must have attest_toolchains.
        is_production_docker = isinstance(backend, DockerVerificationSandboxBackend)
        attest_toolchains = getattr(backend, "attest_toolchains", None)
        if is_production_docker and not callable(attest_toolchains):
            self._verification_config_state = "UNCONFIGURED"
            raise RuntimeError(
                "production DockerVerificationSandboxBackend must provide "
                "attest_toolchains — declaration-only fallback is forbidden"
            )
        # If the backend supports real attestation, run it.  Otherwise
        # fall back to the declaration-only check (test backends only).
        if callable(attest_toolchains) and toolchains:
            # Batch 3.1.3 §5: bind the image attestation digest to each
            # toolchain attestation.  This enters the Approval binding.
            image_attestation_digest = ""
            if self._verification_image_attestation is not None:
                image_attestation_digest = self._verification_image_attestation.attestation_digest
            # Batch 3.1.5 §3: inject the verification store, boot context,
            # and image attestation into the backend so each probe container
            # is persisted through the full PREPARED → CREATED_ATTESTED →
            # RUNNING → TERMINATED lifecycle with absence proof.
            try:
                setattr(backend, "_verification_store", self._verification_store)
                setattr(backend, "_boot_context", self.boot_context)
                setattr(
                    backend, "_image_attestation", self._verification_image_attestation,
                )
            except Exception:
                pass
            try:
                import concurrent.futures as _cf_tc
                import asyncio as _aio_tc
                with _cf_tc.ThreadPoolExecutor(max_workers=1) as pool_tc:
                    attestations = pool_tc.submit(lambda: _aio_tc.run(
                        attest_toolchains(
                            toolchains=toolchains,
                            image_digest=profile.image_digest,
                            image_attestation_digest=image_attestation_digest,
                        )
                    )).result()
            except Exception as exc:
                self._verification_config_state = "UNCONFIGURED"
                raise RuntimeError(
                    f"trusted verification toolchain attestation failed: {exc}"
                ) from exc
            # Batch 3.1.5 §3: attestation result is only persisted AFTER all
            # probe containers have reached TERMINATED (absence proven).
            # The persistent lifecycle in _run_attestation_command guarantees
            # each probe container is terminated before its result is used.
            # Persist each attestation, bound to the current boot.
            for attestation in attestations:
                self._verification_store.persist_toolchain_attestation(
                    attestation,
                    boot_id=self.boot_context.boot_id,
                    server_epoch=self.boot_context.server_epoch,
                )
            # Clear stale attestations from previous boots.
            self._verification_store.clear_toolchain_attestations_for_boot(
                boot_id=self.boot_context.boot_id,
            )
            self._verification_toolchain_attestations = tuple(attestations)
            # Batch 3.1.4 §3: freeze the approved attestation content digests.
            # These are stable across re-probes (attested_at excluded).
            if self._verification_image_attestation is not None:
                self._approved_image_attestation_digest = (
                    self._verification_image_attestation.attestation_digest
                )
            self._approved_toolchain_attestation_digests = tuple(
                att.attestation_digest for att in attestations
            )
        else:
            # Declaration-only fallback (test backends without Docker).
            for toolchain in toolchains:
                if toolchain.image_digest != profile.image_digest:
                    self._verification_config_state = "UNCONFIGURED"
                    raise RuntimeError(
                        f"toolchain {toolchain.language}:{toolchain.executable_id} "
                        f"image mismatch: {toolchain.image_digest} != {profile.image_digest}"
                    )
                if toolchain.binary_digest and not toolchain.binary_digest.startswith("sha256:"):
                    self._verification_config_state = "UNCONFIGURED"
                    raise RuntimeError(
                        f"toolchain {toolchain.language}:{toolchain.executable_id} "
                        f"has invalid binary_digest: {toolchain.binary_digest}"
                    )
            self._verification_toolchain_attestations = ()

        # Batch 3.1.2 §2: Boot-agnostic crash reconciliation
        self._verification_config_state = "RECONCILING_SANDBOXES"
        # recover_interrupted() is called in VerificationExecutionStore.__init__
        # via TrustedVerificationRunner.__init__.  It transitions any
        # PREPARING/RUNNING runs to ERRORED.
        #
        # §2: Read ALL non-terminal sandbox instances (including old boots).
        # DO NOT mark all as ORPHANED first — reconcile each record
        # individually, then update state + run + execution atomically.
        # Current Boot ID is NOT a filter — old boot records must be cleaned.
        from khaos.coding.planning.verification_sandbox_instance import (
            SandboxInstanceState,
        )
        import concurrent.futures as _cf2
        import asyncio as _aio2
        non_terminal = self._verification_store.list_active_sandbox_instances()
        reconcile_by_record = getattr(backend, "reconcile_instance_by_record", None)
        if non_terminal:
            if not callable(reconcile_by_record):
                raise RuntimeError(
                    f"backend does not support reconcile_instance_by_record; "
                    f"cannot reconcile {len(non_terminal)} residual sandbox instances"
                )
            mismatches: list[str] = []
            cleanup_failures: list[str] = []
            for instance in non_terminal:
                # Batch 3.1.5 §3: construct expected labels based on instance_kind.
                # Verification instances use the verification label set;
                # toolchain-attestation instances use the toolchain label set.
                if instance.instance_kind == "toolchain-attestation":
                    expected_labels = {
                        "khaos.kind": "toolchain-attestation",
                        "khaos.sandbox-instance-id": instance.sandbox_instance_id,
                        "khaos.boot-id": instance.boot_id,
                        "khaos.image-attestation-digest": instance.image_attestation_digest[:63],
                        "khaos.toolchain-id": instance.toolchain_id[:63],
                        "khaos.probe-ordinal": str(instance.probe_ordinal),
                    }
                else:
                    expected_labels = {
                        "khaos.run-id": instance.verification_run_id,
                        "khaos.step-id": instance.step_run_id,
                        "khaos.sandbox-instance-id": instance.sandbox_instance_id,
                        "khaos.boot-id": instance.boot_id,
                        "khaos.manifest-digest": instance.workspace_manifest_digest[:63],
                    }
                try:
                    with _cf2.ThreadPoolExecutor(max_workers=1) as pool2:
                        report = pool2.submit(lambda: _aio2.run(
                            reconcile_by_record(
                                container_id=instance.container_id,
                                instance_name=instance.backend_instance_name,
                                expected_labels=expected_labels,
                                expected_image_digest=instance.expected_image_digest,
                                expected_manifest_digest=instance.workspace_manifest_digest,
                            )
                        )).result()
                except Exception as exc:
                    # §2: backend reconciliation exception → fail-closed.
                    raise RuntimeError(
                        f"backend reconciliation exception for instance "
                        f"{instance.sandbox_instance_id}: {exc}"
                    ) from exc
                status = report.get("status", "")
                is_toolchain = instance.instance_kind == "toolchain-attestation"
                # Look up execution_run_id for atomic terminalization
                # (verification instances only — toolchain-attestation
                # instances have no associated step/run/execution).
                execution_run_id = ""
                if not is_toolchain and instance.verification_run_id:
                    run = self._verification_store.get_run(instance.verification_run_id)
                    execution_run_id = run.execution_run_id if run else ""
                if status == "terminated":
                    # Full match — container was terminated and removed.
                    # §3: atomic crash terminalization.
                    if is_toolchain:
                        self._verification_store.reconcile_toolchain_attestation_instance_atomic(
                            sandbox_instance_id=instance.sandbox_instance_id,
                            instance_state=SandboxInstanceState.ORPHANED_CLEANED,
                            failure_code="crash-reconciled",
                        )
                    else:
                        self._verification_store.reconcile_sandbox_instance_atomic(
                            sandbox_instance_id=instance.sandbox_instance_id,
                            step_run_id=instance.step_run_id,
                            verification_run_id=instance.verification_run_id,
                            execution_run_id=execution_run_id,
                            instance_state=SandboxInstanceState.ORPHANED_CLEANED,
                            failure_code="crash-reconciled",
                        )
                elif status == "missing":
                    # Container ID not found — deterministic missing.
                    if is_toolchain:
                        self._verification_store.reconcile_toolchain_attestation_instance_atomic(
                            sandbox_instance_id=instance.sandbox_instance_id,
                            instance_state=SandboxInstanceState.TERMINATED,
                            failure_code="container-missing",
                        )
                    else:
                        self._verification_store.reconcile_sandbox_instance_atomic(
                            sandbox_instance_id=instance.sandbox_instance_id,
                            step_run_id=instance.step_run_id,
                            verification_run_id=instance.verification_run_id,
                            execution_run_id=execution_run_id,
                            instance_state=SandboxInstanceState.TERMINATED,
                            failure_code="container-missing",
                        )
                elif status == "ownership-mismatch":
                    # Batch 3.1.3 §3: any label/image/manifest mismatch is
                    # OWNERSHIP_MISMATCH — never terminate, fail closed.
                    mismatches.append(
                        f"{instance.sandbox_instance_id}: {report.get('reason', 'ownership-mismatch')}"
                    )
                    self._verification_store.mark_sandbox_instance_cleanup_failed(
                        instance.sandbox_instance_id,
                        failure_code=report.get("reason", "ownership-mismatch"),
                    )
                elif status == "cleanup-failed":
                    cleanup_failures.append(
                        f"{instance.sandbox_instance_id}: {report.get('reason', 'cleanup-failed')}"
                    )
                    self._verification_store.mark_sandbox_instance_cleanup_failed(
                        instance.sandbox_instance_id,
                        failure_code=report.get("reason", "cleanup-failed"),
                    )
            # §2: Fail-closed — don't continue to READY if any issues.
            if mismatches or cleanup_failures:
                raise RuntimeError(
                    f"verification runtime cannot be READY: "
                    f"{len(mismatches)} label/image mismatches, "
                    f"{len(cleanup_failures)} cleanup failures"
                )
        # Batch 3.1.3 §3: unknown Khaos containers (partial label matches
        # that don't belong to any record) are listed read-only.  These must
        # be 0 for READY.  list_unknown_khaos_containers() NEVER terminates
        # or removes — two different Khaos Runtimes must not delete each
        # other's containers.
        list_unknown = getattr(backend, "list_unknown_khaos_containers", None)
        if callable(list_unknown):
            try:
                with _cf2.ThreadPoolExecutor(max_workers=1) as pool3:
                    unknown = pool3.submit(lambda: _aio2.run(
                        list_unknown()
                    )).result()
                if unknown:
                    raise RuntimeError(
                        f"verification runtime cannot be READY: "
                        f"{len(unknown)} unknown Khaos containers found: {unknown}"
                    )
            except Exception as exc:
                raise RuntimeError(
                    f"backend list_unknown_khaos_containers failed: {exc}"
                ) from exc

        # Batch 3.1.1 §8: READY
        self._verification_config_state = "READY"
        self._verification_runner = TrustedVerificationRunner(
            approval_store=self._store, plan_repository=self._plan_repository,
            workspace_manager=self._workspace_manager,
            context_provider=self._context_provider, backend=backend,
            command_factory=command_factory, workspace_factory=workspace_factory,
            artifact_root=artifact_root, profile=profile,
            runtime_boot=self.boot_context,
            context_registry=self._verification_contexts,
            mutation_fence=self._mutation_fence,
            toolchain_attestations=self._verification_toolchain_attestations,
            approved_image_attestation_digest=self._approved_image_attestation_digest,
            approved_toolchain_attestation_digests=self._approved_toolchain_attestation_digests,
            image_attestation=self._verification_image_attestation,
            artifact_capability=artifact_capability,
            snapshot_capability=snapshot_capability,
        )
        self.guard.set_verification_runner(self._verification_runner)
        # Batch 3.1.5 §2: wire the VerificationSnapshotProvider into the
        # approval service so request_approval() computes and persists the
        # ApprovedVerificationPlanSnapshot before the PENDING/NOT_REQUIRED row.
        # The snapshot digest enters compute_plan_binding_digest, binding the
        # supply chain snapshot through broker → authorization → execution →
        # verification.  Any drift invalidates the approval (STALE).
        if self.service is not None:
            self.service._snapshot_provider = VerificationSnapshotProvider(
                workspace_manager=self._workspace_manager,
                command_factory=command_factory,
                profile=profile,
                image_attestation=self._verification_image_attestation,
                toolchain_attestations=self._verification_toolchain_attestations,
                verification_store=self._verification_store,
                boot_context=self.boot_context,
            )

    @asynccontextmanager
    async def acquire_verification_context(
        self, *, execution_run_id: str, owner_execution_id: str = "verify_default",
        ttl_seconds: float = 900.0,
    ):
        """Mint one boot-scoped verification continuation lease under the fence."""
        self.require_ready()
        if self._verification_store is None:
            raise PermissionError("trusted verification is not configured")
        run = self._store.get_execution_run(execution_run_id)
        if run is None:
            raise KeyError(execution_run_id)
        attestation = self._store.get_final_mutation_attestation(execution_run_id)
        if attestation is None:
            raise PermissionError("verification continuation requires final attestation")
        pending_owner = f"verification-pending:{execution_run_id}"
        async with self._mutation_fence.use(run.workspace_id, owner=pending_owner):
            self.require_ready()
            lease_id = self._verification_store.acquire_phase_lease(
                execution_run_id=execution_run_id, owner_execution_id=owner_execution_id,
                task_id=run.task_id, workspace_id=run.workspace_id,
                repository_id=run.repository_id, plan_id=run.plan_id,
                bundle_digest=run.edit_bundle_digest,
                attestation_digest=attestation.attestation_digest,
                binding_digest=run.binding_digest,
                server_epoch=self.boot_context.server_epoch,
                boot_id=self.boot_context.boot_id,
                expiry=time.time() + ttl_seconds,
            )
            self._mutation_fence.transfer_owner(
                run.workspace_id, f"verification-lease:{lease_id}",
            )
            from khaos.coding.planning.verification_execution_models import VerificationPhaseContext
            context = VerificationPhaseContext(
                verification_context_id=f"vctx_{uuid.uuid4().hex}",
                phase_lease_id=lease_id, execution_run_id=execution_run_id,
                plan_id=run.plan_id, task_id=run.task_id,
                workspace_id=run.workspace_id, repository_id=run.repository_id,
                bundle_digest=run.edit_bundle_digest,
                attestation_digest=attestation.attestation_digest,
                binding_digest=run.binding_digest,
                owner_execution_id=owner_execution_id,
                server_epoch=self.boot_context.server_epoch,
                boot_id=self.boot_context.boot_id, expiry=time.time() + ttl_seconds,
            )
            self._verification_contexts[context.verification_context_id] = context
            try:
                yield context
            finally:
                self._verification_contexts.pop(context.verification_context_id, None)
                self._verification_store.release_phase_lease(lease_id)

    async def run_trusted_verification(
        self, *, context: Any, cancellation: Any = None,
    ) -> Any:
        self.require_ready()
        import asyncio
        event = cancellation or asyncio.Event()
        self._verification_cancel_events[context.verification_context_id] = event
        try:
            return await self.guard.trusted_verification_execution(
                context, cancellation=event,
            )
        finally:
            self._verification_cancel_events.pop(
                context.verification_context_id, None,
            )

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
            for event in tuple(self._verification_cancel_events.values()):
                event.set()
            # Cancel all ACTIVE leases for this boot before rotating the epoch.
            self._store.invalidate_active_execution_scope(
                boot_id=self.boot_context.boot_id, reason="runtime-shutdown",
            )
            if self._verification_store is not None:
                self._verification_store.invalidate_phase_leases(
                    boot_id=self.boot_context.boot_id,
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
            from khaos.coding.planning.verification_storage import (
                VERIFICATION_STORAGE_REGISTRY,
            )
            VERIFICATION_STORAGE_REGISTRY.revoke_runtime(
                self._runtime_authority_id,
            )
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
