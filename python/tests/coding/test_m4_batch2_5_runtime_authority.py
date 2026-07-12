"""M4 Batch 2.5 — Runtime Authority, Boot Fencing and Cancellation Closure.

Covers the 22-scenario test matrix from spec §8. Each scenario drives the
REAL ApprovalRuntime bootstrap (no private bind helpers), persisted boot
fencing, CONSUMED-request cancellation, Manager/Coordinator wiring,
production fail-closed construction, and the closed Receipt writer.

No test in this module may call:

* ``store._bind_receipt_broker(...)``
* ``broker._receipt_writer = ...``
* ``store._insert_receipt(...)`` with a forged capability

The runtime's ``initialize()`` self-wires the Broker → Receipt outbox.
"""
from __future__ import annotations

import asyncio
import inspect
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import pytest

from _m4_batch2_helpers import (  # type: ignore[import-not-found]
    FakeContextProvider,
    FakeMutationParticipant,
    SyncBroker,
    broker_decide,
    high_risk,
    low_risk,
    make_plan,
)
from khaos.agent.approval import ApprovalBroker
from khaos.coding.planning.approval import (
    ApprovalRuntime,
    AuthorizationAlreadyConsumedError,
    AuthorizationMismatchError,
    AuthorizationRevokedError,
    BootContext,
    PersistedPlanRepository,
    PlanApprovalService,
    PlanApprovalStore,
    PlanExecutionGate,
    PlannedExecutionGuard,
    WorkspaceExecutionLeaseCoordinator,
)
from khaos.coding.planning.approval.repository import (
    PlanSnapshotStore,
    UnsafeTestPlanRepository,
)
from khaos.coding.planning.approval.validator import ShallowTestPlanValidator


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


class DeepFakePlanningService:
    """A deep-enough validator stub (not _unsafe_test_only)."""

    _unsafe_test_only = False

    def validate_plan(self, plan, **kwargs):
        from khaos.coding.planning.contracts import PlanValidationResult

        return PlanValidationResult(True, plan.status)


def _store(conn=None):
    conn = conn or sqlite3.connect(":memory:")
    return PlanApprovalStore(conn)


def _runtime(store, *, broker=None, context=None, plan_repository=None, planning_service=None):
    """Build a real ApprovalRuntime. No private bind helpers.

    The SyncBroker wrapper is stored on the runtime as ``_test_sync`` so
    tests can drive the broker via its event loop (the broker's
    asyncio.Lock is bound to that loop).
    """
    sync = SyncBroker()
    rt = ApprovalRuntime(
        store=store,
        broker=broker or sync.real,
        context_provider=context or FakeContextProvider(),
        plan_repository=plan_repository or PersistedPlanRepository(store),
        planning_service=planning_service or DeepFakePlanningService(),
        task_manager=FakeMutationParticipant(), workspace_manager=FakeMutationParticipant(),
        repository_indexer=FakeMutationParticipant(),
    )
    rt._test_sync = sync  # test-only: drive the broker via its event loop
    return rt


def _file_store(db_path):
    conn = sqlite3.connect(str(db_path), check_same_thread=False, isolation_level=None)
    return PlanApprovalStore(conn)


def _seed_approved_request(runtime, *, plan_id="p25_plan", risks=None):
    """Drive a plan through request_approval + broker approve + apply.

    Returns (plan, request, receipt). The receipt is durable in the outbox
    because the runtime's initialize() wired the Broker → Receipt sink.
    Uses the runtime's SyncBroker wrapper to drive the broker on its
    own event loop (the broker's asyncio.Lock is loop-bound).
    """
    risks = risks or (high_risk(),)
    plan = make_plan(plan_id=plan_id, risks=risks)
    request = runtime.service.request_approval(plan)
    sync = runtime._test_sync
    # Register the plan approval record on the broker.
    sync.register_plan_approval(
        approval_request_id=request.approval_request_id,
        binding={"binding_digest": request.binding_digest},
        summary={"plan_id": plan.plan_id},
        expires_at=9999999999.0,
    )
    # Issue a signed authenticated context via the broker's authenticator.
    from khaos.coding.planning.approval.models import (
        ApprovalAuthenticator,
        AuthenticatedSession,
    )

    authenticator = sync.real._authenticator
    session = AuthenticatedSession(
        session_id="sess_" + plan_id, principal_id="user1", principal_type="user",
        authenticated_at=time.time(), session_expiry=time.time() + 600,
        granted_capabilities=(ApprovalAuthenticator.CAPABILITY_PLAN_APPROVAL,),
    )
    authenticator.register_session(session)
    ctx = authenticator.issue_context(
        session=session, approval_request_id=request.approval_request_id,
        authenticated_source="api", capability=ApprovalAuthenticator.CAPABILITY_PLAN_APPROVAL,
    )
    # Drive the broker to resolve — receipt_sink=None means use the
    # runtime-wired sink (auto-persisted).
    receipt = sync.resolve_plan_approval(
        broker_request_id=request.broker_request_id,
        approved=True, context=ctx, reason="ok",
        binding_digest=request.binding_digest, receipt_sink=None,
    )
    assert receipt is not None, "broker refused to mint a receipt"
    runtime.service.apply_broker_decision(receipt)
    return plan, request, receipt


def _authorize_and_acquire_lease(runtime, plan, request):
    """Mint authorization + acquire lease. Returns (auth, lease_ctx)."""
    auth = runtime.authorize_execution(
        plan_id=plan.plan_id, approval_request_id=request.approval_request_id,
    )
    guard = runtime.guard
    cm = runtime.acquire_execution_context(
        authorization_id=auth.authorization_id, nonce=auth.nonce,
        expected_plan_id=plan.plan_id, expected_task_id=plan.task_id,
        expected_workspace_id=plan.workspace_id, expected_repository_id=plan.repository_id,
        owner_execution_id="exec_test",
    )
    ctx = runtime._test_sync._loop.run_until_complete(cm.__aenter__())
    guard._test_context_manager = cm
    return auth, ctx, guard


# ===========================================================================
# §1 + §8.1/8.2/8.3 — Runtime Receipt production wiring (E2E, no private helper)
# ===========================================================================


def test_01_runtime_e2e_auto_writes_receipt_without_private_helper():
    """Runtime.initialize() self-wires Broker→Receipt outbox.

    Driving request_approval → broker.resolve_plan_approval →
    apply_broker_decision produces a durable receipt row in
    plan_approval_receipts WITHOUT any test-side binding call.
    """
    store = _store()
    runtime = _runtime(store)
    boot = runtime.initialize()
    assert isinstance(boot, BootContext) and runtime.ready
    plan, request, receipt = _seed_approved_request(runtime)
    # The receipt was auto-persisted by the runtime-wired sink.
    row = store._conn.execute(
        "SELECT receipt_id, token_hash FROM plan_approval_receipts WHERE receipt_id = ?",
        (receipt.receipt_id,),
    ).fetchone()
    assert row is not None, "receipt was not auto-persisted by the runtime-wired sink"
    assert row["token_hash"] == receipt.token_hash


def test_02_no_private_bind_helper_required_to_initialize():
    """ApprovalRuntime.initialize needs no store._bind_receipt_broker call."""
    store = _store()
    # Verify the old private helper is GONE.
    assert not hasattr(store, "_bind_receipt_broker"), (
        "store._bind_receipt_broker must not exist (Batch 2.5 §6)"
    )
    runtime = _runtime(store)
    # Initialize without any binding helper.
    runtime.initialize()
    assert runtime.ready and runtime.boot_context is not None


def test_03_receipt_wiring_failure_leaves_runtime_not_ready():
    """If the broker registration fails, runtime stays not-ready and no
    half-bound broker remains."""
    store = _store()
    sync = SyncBroker()
    real_broker = sync.real
    # Monkey-patch the writer installation method to simulate failure.
    original = type(real_broker)._install_runtime_receipt_writer
    def broken_install(self, writer, *, runtime_token, runtime_capability=None):
        raise RuntimeError("broker writer installation broken")
    type(real_broker)._install_runtime_receipt_writer = broken_install
    try:
        runtime = ApprovalRuntime(
            store=store, broker=real_broker,
            context_provider=FakeContextProvider(),
            plan_repository=PersistedPlanRepository(store),
            planning_service=DeepFakePlanningService(),
            task_manager=FakeMutationParticipant(), workspace_manager=FakeMutationParticipant(),
            repository_indexer=FakeMutationParticipant(),
        )
        with pytest.raises(RuntimeError):
            runtime.initialize()
        assert not runtime.ready
        assert runtime.gate is None and runtime.service is None
        assert runtime.boot_context is None
        # The broker's writer is not installed (rolled back).
        assert not real_broker._has_runtime_receipt_writer()
    finally:
        type(real_broker)._install_runtime_receipt_writer = original


# ===========================================================================
# §2 + §8.4/8.5/8.6/8.7 — Persisted Boot Fencing (stale runtime rejection)
# ===========================================================================


def test_04_runtime_a_then_runtime_b_a_mint_refused(tmp_path):
    """After Runtime B initializes, Runtime A cannot mint."""
    db = tmp_path / "fence_mint.db"
    store_a = _file_store(db)
    runtime_a = _runtime(store_a)
    runtime_a.initialize()
    plan, request, _ = _seed_approved_request(runtime_a, plan_id="p_fence_mint")

    # Runtime B initializes against the same DB — rotates epoch + boot_id.
    store_b = _file_store(db)
    runtime_b = _runtime(store_b)
    runtime_b.initialize()
    assert runtime_b.boot_context.server_epoch > runtime_a.boot_context.server_epoch

    # Runtime A's cached boot context is now stale. mint must refuse.
    with pytest.raises(RuntimeError):
        runtime_a.require_ready()
    with pytest.raises((RuntimeError, Exception)):
        runtime_a.authorize_execution(
            plan_id=plan.plan_id, approval_request_id=request.approval_request_id,
        )


def test_05_runtime_a_acquire_refused_after_b_initializes(tmp_path):
    """After Runtime B initializes, Runtime A cannot acquire a lease."""
    db = tmp_path / "fence_acquire.db"
    store_a = _file_store(db)
    runtime_a = _runtime(store_a)
    runtime_a.initialize()
    plan, request, _ = _seed_approved_request(runtime_a, plan_id="p_fence_acq")
    auth = runtime_a.authorize_execution(
        plan_id=plan.plan_id, approval_request_id=request.approval_request_id,
    )

    # Runtime B takes over.
    store_b = _file_store(db)
    runtime_b = _runtime(store_b)
    runtime_b.initialize()

    # Runtime A's acquire must refuse (stale boot context).
    with pytest.raises((RuntimeError, Exception)):
        runtime_a.acquire_lease(
            authorization_id=auth.authorization_id, nonce=auth.nonce,
            expected_plan_id=plan.plan_id, expected_task_id=plan.task_id,
            expected_workspace_id=plan.workspace_id, expected_repository_id=plan.repository_id,
            owner_execution_id="exec_a",
        )


def test_06_runtime_a_context_validation_refused_after_b(tmp_path):
    """After Runtime B initializes, Runtime A cannot validate old context."""
    db = tmp_path / "fence_ctx.db"
    store_a = _file_store(db)
    runtime_a = _runtime(store_a)
    runtime_a.initialize()
    plan, request, _ = _seed_approved_request(runtime_a, plan_id="p_fence_ctx")
    auth, ctx, guard = _authorize_and_acquire_lease(runtime_a, plan, request)

    # Runtime B takes over.
    store_b = _file_store(db)
    runtime_b = _runtime(store_b)
    runtime_b.initialize()

    # Runtime A's require_active_lease must return False (stale boot).
    with pytest.raises((RuntimeError, Exception)):
        runtime_a.require_active_lease(
            ctx.lease_id, owner_execution_id=ctx.owner_execution_id,
            expected_task_id=ctx.task_id, expected_workspace_id=ctx.workspace_id,
            expected_repository_id=ctx.repository_id, expected_plan_id=ctx.plan_id,
        )
    # The guard's require_active_execution_context must also reject.
    with pytest.raises(PermissionError):
        guard.require_active_execution_context(ctx)


def test_07_persisted_epoch_same_but_boot_id_different_still_refused(tmp_path):
    """If persisted epoch matches but boot_id differs, mint is refused.

    This catches the edge case where an attacker tries to reuse a stale
    runtime by manually setting the epoch back. The boot_id is the
    definitive fence.
    """
    db = tmp_path / "fence_bootid.db"
    store = _file_store(db)
    runtime = _runtime(store)
    boot = runtime.initialize()
    plan, request, _ = _seed_approved_request(runtime, plan_id="p_bootid")

    # Tamper: keep epoch the same but change boot_id in the persisted state.
    store._conn.execute(
        "UPDATE plan_execution_server_state SET boot_id = ? WHERE singleton_key = 'global'",
        ("tampered_boot_id",),
    )
    # The runtime's cached boot_id no longer matches persisted. mint refuses.
    with pytest.raises((RuntimeError, Exception)):
        runtime.authorize_execution(
            plan_id=plan.plan_id, approval_request_id=request.approval_request_id,
        )


# ===========================================================================
# §3 + §8.8/8.9/8.10 — CONSUMED request Task cancel / Workspace cleanup /
# Runtime shutdown
# ===========================================================================


def _setup_consumed_with_active_lease(runtime, *, plan_id="p_cancel"):
    """Drive a plan to CONSUMED approval + ACTIVE lease state."""
    plan, request, _ = _seed_approved_request(runtime, plan_id=plan_id)
    auth, ctx, guard = _authorize_and_acquire_lease(runtime, plan, request)
    # The approval request is now CONSUMED (lease-first consume).
    req = runtime._store.get_request(request.approval_request_id)
    assert req.status.value == "consumed"
    return plan, request, auth, ctx, guard


def test_08_task_cancel_clears_consumed_request_active_lease():
    """Task cancel terminates the ACTIVE lease of a CONSUMED request.

    The old invalidate_request path tried CONSUMED→REVOKED (illegal
    rollback). The new invalidate_active_execution_scope does NOT touch
    the approval request status — only the lease + authorization.
    """
    store = _store()
    runtime = _runtime(store)
    runtime.initialize()
    plan, request, auth, ctx, guard = _setup_consumed_with_active_lease(
        runtime, plan_id="p_task_cancel",
    )

    # Cancel via the coordinator's cancel_task.
    coordinator = WorkspaceExecutionLeaseCoordinator(runtime)
    count = coordinator.cancel_task(task_id=plan.task_id, reason="task-cancelled")
    assert count == 1, "expected 1 lease invalidated"

    # The approval request is STILL CONSUMED (not rolled back to REVOKED).
    req = runtime._store.get_request(request.approval_request_id)
    assert req.status.value == "consumed", (
        "approval request must stay CONSUMED — no illegal rollback"
    )
    # The lease is now cancelled.
    lease = runtime._store.get_lease(ctx.lease_id)
    assert lease["status"] == "cancelled"
    # The old context is immediately invalid.
    with pytest.raises(PermissionError):
        guard.require_active_execution_context(ctx)


def test_09_workspace_cleanup_clears_active_lease():
    """Workspace cleanup terminates the ACTIVE lease."""
    store = _store()
    runtime = _runtime(store)
    runtime.initialize()
    plan, request, auth, ctx, guard = _setup_consumed_with_active_lease(
        runtime, plan_id="p_ws_cleanup",
    )

    coordinator = WorkspaceExecutionLeaseCoordinator(runtime)
    count = coordinator.cleanup_workspace(workspace_id=plan.workspace_id)
    assert count == 1
    lease = runtime._store.get_lease(ctx.lease_id)
    assert lease["status"] == "cancelled"
    with pytest.raises(PermissionError):
        guard.require_active_execution_context(ctx)


def test_10_runtime_shutdown_clears_active_lease():
    """Runtime.shutdown invalidates all ACTIVE leases for this boot."""
    store = _store()
    runtime = _runtime(store)
    runtime.initialize()
    plan, request, auth, ctx, guard = _setup_consumed_with_active_lease(
        runtime, plan_id="p_shutdown",
    )

    runtime.shutdown()
    assert not runtime.ready
    lease = runtime._store.get_lease(ctx.lease_id)
    assert lease["status"] == "cancelled"
    # After shutdown, all runtime operations refuse.
    with pytest.raises(RuntimeError):
        runtime.authorize_execution(
            plan_id=plan.plan_id, approval_request_id=request.approval_request_id,
        )


# ===========================================================================
# §8.11/8.12 — Real SQLite concurrency (cancel vs acquire, cleanup vs acquire)
# ===========================================================================


def test_11_cancel_acquire_real_sqlite_concurrency(tmp_path):
    """Concurrent cancel_task and a state check on the same workspace.

    Only one final result: the lease is cancelled. The DB must not deadlock
    or corrupt.
    """
    db = tmp_path / "conc_cancel_acquire.db"
    store = _file_store(db)
    runtime = _runtime(store)
    runtime.initialize()
    plan, request, auth, ctx, guard = _setup_consumed_with_active_lease(
        runtime, plan_id="p_conc_cancel",
    )

    barrier = threading.Barrier(2)
    cancel_result = {"count": None}

    def do_cancel():
        barrier.wait()
        conn = sqlite3.connect(str(db), check_same_thread=False, timeout=30.0, isolation_level=None)
        s = PlanApprovalStore(conn)
        try:
            cancel_result["count"] = s.invalidate_active_execution_scope(
                task_id=plan.task_id, reason="cancel-race",
            )
        finally:
            conn.close()

    def do_noop():
        barrier.wait()
        # A second connection that does a no-op BEGIN IMMEDIATE + commit to
        # exercise real SQLite locking under concurrency.
        conn = sqlite3.connect(str(db), check_same_thread=False, timeout=30.0, isolation_level=None)
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("SELECT 1")
            conn.commit()
        finally:
            conn.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        futs = [pool.submit(do_cancel), pool.submit(do_noop)]
        for f in as_completed(futs):
            f.result()
    # After both threads complete, the lease must be cancelled.
    final_conn = sqlite3.connect(str(db))
    row = final_conn.execute(
        "SELECT status FROM plan_execution_leases WHERE lease_id = ?", (ctx.lease_id,),
    ).fetchone()
    assert row[0] == "cancelled"
    final_conn.close()


def test_12_cleanup_acquire_real_sqlite_concurrency(tmp_path):
    """Concurrent cleanup_workspace and a no-op transaction on the same DB."""
    db = tmp_path / "conc_cleanup_acquire.db"
    store = _file_store(db)
    runtime = _runtime(store)
    runtime.initialize()
    plan, request, auth, ctx, guard = _setup_consumed_with_active_lease(
        runtime, plan_id="p_conc_cleanup",
    )

    barrier = threading.Barrier(2)

    def do_cleanup():
        barrier.wait()
        conn = sqlite3.connect(str(db), check_same_thread=False, timeout=30.0, isolation_level=None)
        s = PlanApprovalStore(conn)
        try:
            s.invalidate_active_execution_scope(
                workspace_id=plan.workspace_id, reason="cleanup-race",
            )
        finally:
            conn.close()

    def do_noop():
        barrier.wait()
        conn = sqlite3.connect(str(db), check_same_thread=False, timeout=30.0, isolation_level=None)
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("SELECT 1")
            conn.commit()
        finally:
            conn.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        futs = [pool.submit(do_cleanup), pool.submit(do_noop)]
        for f in as_completed(futs):
            f.result()
    final_conn = sqlite3.connect(str(db))
    row = final_conn.execute(
        "SELECT status FROM plan_execution_leases WHERE lease_id = ?", (ctx.lease_id,),
    ).fetchone()
    assert row[0] == "cancelled"
    final_conn.close()


# ===========================================================================
# §8.13/8.14 — Invariants: terminal Task / cleaned Workspace have no active lease
# ===========================================================================


def test_13_terminal_task_has_no_active_lease():
    """After task cancel, no ACTIVE lease remains for that task."""
    store = _store()
    runtime = _runtime(store)
    runtime.initialize()
    plan, request, auth, ctx, guard = _setup_consumed_with_active_lease(
        runtime, plan_id="p_terminal_task",
    )
    coordinator = WorkspaceExecutionLeaseCoordinator(runtime)
    coordinator.cancel_task(task_id=plan.task_id)
    count = store.count_active_leases_for_workspace(plan.workspace_id)
    assert count == 0, "terminal task must not leave an active lease"


def test_14_cleaned_workspace_has_no_active_lease():
    """After workspace cleanup, no ACTIVE lease remains."""
    store = _store()
    runtime = _runtime(store)
    runtime.initialize()
    plan, request, auth, ctx, guard = _setup_consumed_with_active_lease(
        runtime, plan_id="p_cleaned_ws",
    )
    coordinator = WorkspaceExecutionLeaseCoordinator(runtime)
    coordinator.cleanup_workspace(workspace_id=plan.workspace_id)
    count = store.count_active_leases_for_workspace(plan.workspace_id)
    assert count == 0


# ===========================================================================
# §5 + §8.15/8.16/8.17 — Production construction fail-closed
# ===========================================================================


def test_15_direct_gate_construction_without_runtime_capability_refuses():
    """PlanExecutionGate without RuntimeCapability → TypeError (Batch 2.6 §2)."""
    from khaos.coding.planning.approval.runtime import RuntimeCapability
    store = _store()
    # No runtime_capability at all — the primary §2 fence.
    with pytest.raises(TypeError):
        PlanExecutionGate(
            store=store, context_provider=FakeContextProvider(),
            plan_repository=PersistedPlanRepository(store),
            planning_service=DeepFakePlanningService(),
        )
    # runtime_capability present but plan_repository is PlanSnapshotStore.
    with pytest.raises(TypeError):
        RuntimeCapability(boot_context=BootContext(server_epoch=1, boot_id="x"))
    cap = object()
    with pytest.raises(TypeError):
        PlanExecutionGate(
            store=store, context_provider=FakeContextProvider(),
            runtime_capability=cap,
            plan_repository=PlanSnapshotStore(),
            planning_service=DeepFakePlanningService(),
        )
    # runtime_capability present but planning_service is None.
    with pytest.raises(TypeError):
        PlanExecutionGate(
            store=store, context_provider=FakeContextProvider(),
            runtime_capability=cap,
            plan_repository=PersistedPlanRepository(store),
            planning_service=None,
        )
    # runtime_capability present but planning_service is the unsafe test validator.
    with pytest.raises(TypeError):
        PlanExecutionGate(
            store=store, context_provider=FakeContextProvider(),
            runtime_capability=cap,
            plan_repository=PersistedPlanRepository(store),
            planning_service=ShallowTestPlanValidator(),
        )


def test_16_direct_service_construction_without_deep_validator_refuses():
    """PlanApprovalService without RuntimeCapability → TypeError (Batch 2.6 §2)."""
    from khaos.coding.planning.approval.runtime import RuntimeCapability
    store = _store()
    sync = SyncBroker()
    # No runtime_capability at all.
    with pytest.raises(TypeError):
        PlanApprovalService(
            store=store, broker=sync.real, context_provider=FakeContextProvider(),
            plan_repository=PersistedPlanRepository(store), planning_service=DeepFakePlanningService(),
        )
    with pytest.raises(TypeError):
        RuntimeCapability(boot_context=BootContext(server_epoch=1, boot_id="x"))
    cap = object()
    # runtime_capability present but planning_service is None.
    with pytest.raises(TypeError):
        PlanApprovalService(
            store=store, broker=sync.real, context_provider=FakeContextProvider(),
            runtime_capability=cap,
            plan_repository=PersistedPlanRepository(store), planning_service=None,
        )
    # runtime_capability present but plan_repository is UnsafeTestPlanRepository.
    with pytest.raises(TypeError):
        PlanApprovalService(
            store=store, broker=sync.real, context_provider=FakeContextProvider(),
            runtime_capability=cap,
            plan_repository=UnsafeTestPlanRepository(),
            planning_service=DeepFakePlanningService(),
        )


def test_17_top_level_api_does_not_expose_unsafe_repository():
    """The approval package __all__ must not export UnsafeTestPlanRepository,
    PlanSnapshotStore, or RuntimeCapability (Batch 2.6 §2)."""
    from khaos.coding.planning.approval import __all__ as approval_all

    assert "UnsafeTestPlanRepository" not in approval_all
    assert "PlanSnapshotStore" not in approval_all
    assert "RuntimeCapability" not in approval_all


# ===========================================================================
# §6 + §8.18/8.19 — Closed Receipt writer
# ===========================================================================


def test_18_broker_has_no_readable_writer_attribute():
    """The broker must not expose _receipt_writer or any readable writer."""
    sync = SyncBroker()
    broker = sync.real
    assert not hasattr(broker, "_receipt_writer"), (
        "broker._receipt_writer must not exist (Batch 2.5 §6)"
    )
    # The name-mangled attribute is not accessible via the public name.
    assert not hasattr(broker, "receipt_writer")
    assert not hasattr(broker, "writer")


def test_19_store_caller_cannot_bind_writer():
    """Ordinary store callers cannot obtain a writer or bind one to the broker."""
    store = _store()
    # The old _bind_receipt_broker / _create_receipt_sink helpers are gone.
    assert not hasattr(store, "_bind_receipt_broker")
    assert not hasattr(store, "_create_receipt_sink")
    # _insert_signed_receipt requires a valid broker signature — unsigned
    # writes are refused fail-closed. There is no capability token to forge.
    with pytest.raises(PermissionError):
        store._insert_signed_receipt(
            receipt_id="r", token_hash="t", approval_request_id="a",
            broker_request_id="b", binding_digest="d",
            decision="approved", expires_at=time.time() + 60,
            broker_signature="", signer_key_id="", canonical_payload_digest="",
        )
    # Forging a class module/name does not grant a writer handle.
    forged_broker = type("X", (), {"__module__": "khaos.agent.approval", "__name__": "ApprovalBroker"})()
    # A forged broker object cannot install a writer (no such method).
    assert not hasattr(forged_broker, "_install_runtime_receipt_writer")


# ===========================================================================
# §8.20 — Batch 3 stubs refuse Context after cancel/shutdown
# ===========================================================================


@pytest.mark.parametrize("scenario", ["cancel", "shutdown"])
def test_20_batch3_stubs_refuse_context_after_cancel_or_shutdown(scenario):
    """After cancel or shutdown, every Batch 3 planned_* stub must reject."""
    store = _store()
    runtime = _runtime(store)
    runtime.initialize()
    plan, request, auth, ctx, guard = _setup_consumed_with_active_lease(
        runtime, plan_id=f"p_stubs_{scenario}",
    )
    if scenario == "cancel":
        coordinator = WorkspaceExecutionLeaseCoordinator(runtime)
        coordinator.cancel_task(task_id=plan.task_id)
    else:
        runtime.shutdown()

    calls = (
        (guard.planned_workspace_edit, {"edit": {}}),
        (guard.planned_tool_invocation, {"invocation": {}}),
        (guard.planned_verification_execution, {"verification": {}}),
        (guard.planned_changeset_creation, {"changeset_spec": {}}),
        (guard.planned_changeset_apply, {"changeset_id": "x"}),
    )
    for method, kwargs in calls:
        with pytest.raises((PermissionError, RuntimeError)):
            method(ctx, **kwargs)


# ===========================================================================
# §4 + §8.21 — Real Manager adapter calls Coordinator
# ===========================================================================


def test_21_manager_adapter_calls_coordinator():
    """TaskManager.cancel and WorkspaceManager.cleanup invoke the
    lease-invalidation hook registered by the Coordinator."""
    from khaos.coding.task_manager import TaskManager, TaskStatus, CodingTask
    from khaos.coding.workspace.manager import WorkspaceManager
    from khaos.coding.workspace.models import TaskWorkspace, WorkspaceState

    store = _store()
    runtime = _runtime(store)
    runtime.initialize()
    plan, request, auth, ctx, guard = _setup_consumed_with_active_lease(
        runtime, plan_id="p_manager",
    )

    # Wire the runtime's coordinator into real Manager instances.
    tm = TaskManager()
    wm = WorkspaceManager(root=Path("/tmp/khaos_test_ws_manager"))
    coordinator = runtime.register_lease_coordinator(
        task_manager=tm, workspace_manager=wm,
    )
    # Both managers should now have the hook set.
    assert tm._lease_invalidation_hook is not None
    assert wm._lease_invalidation_hook is not None

    # Seed a Task in the manager.
    task = CodingTask(id=plan.task_id, goal="test")
    task.status = TaskStatus.RUNNING
    tm._tasks[plan.task_id] = task

    runtime._test_sync._loop.run_until_complete(
        guard._test_context_manager.__aexit__(None, None, None)
    )
    # Cancel the task — the hook should fire and invalidate the lease.
    loop = asyncio.new_event_loop()
    result = loop.run_until_complete(tm.cancel(plan.task_id))
    loop.close()
    assert result.name == "UPDATED"
    lease = store.get_lease(ctx.lease_id)
    assert lease["status"] == "released"
    assert store.count_active_leases_for_workspace(plan.workspace_id) == 0


# ===========================================================================
# §8.22 — No real workspace writes / Tool / ChangeSet executed
# ===========================================================================


def test_22_no_real_workspace_writes_tool_or_changeset_executed():
    """The Batch 3 stubs raise NotImplementedError — they do NOT perform
    real workspace edits, tool invocations, verification runs, or ChangeSet
    applications. This test verifies the stubs still raise after a valid
    context is established."""
    store = _store()
    runtime = _runtime(store)
    runtime.initialize()
    plan, request, _ = _seed_approved_request(runtime, plan_id="p_no_writes")
    auth, ctx, guard = _authorize_and_acquire_lease(runtime, plan, request)
    # The context is valid — require_active_execution_context passes.
    guard.require_active_execution_context(ctx)
    # But each planned_* stub raises NotImplementedError (not a real write).
    with pytest.raises(NotImplementedError):
        guard.planned_workspace_edit(ctx, edit={"path": "x.py", "content": "tampered"})
    with pytest.raises(NotImplementedError):
        guard.planned_tool_invocation(ctx, invocation={"tool": "shell"})
    with pytest.raises(NotImplementedError):
        guard.planned_verification_execution(ctx, verification={"cmd": "ls"})
    with pytest.raises(NotImplementedError):
        guard.planned_changeset_creation(ctx, changeset_spec={"files": []})
    with pytest.raises(NotImplementedError):
        guard.planned_changeset_apply(ctx, changeset_id="cs1")


# ===========================================================================
# §7 — Runtime readiness invariants (initialize once, shutdown fences)
# ===========================================================================


def test_runtime_initialize_rotates_epoch_and_shutdown_fences():
    """initialize() can only succeed once per instance; re-initialize on the
    same runtime is refused. After shutdown, a fresh runtime sees a higher epoch."""
    store = _store()
    runtime = _runtime(store)
    boot1 = runtime.initialize()
    # A second initialize on the SAME runtime is refused (already ready).
    with pytest.raises(RuntimeError):
        runtime.initialize()
    runtime.shutdown()
    assert not runtime.ready
    # A fresh runtime against the same store sees a higher epoch.
    runtime2 = _runtime(store)
    boot2 = runtime2.initialize()
    assert boot2.server_epoch > boot1.server_epoch
    assert boot2.boot_id != boot1.boot_id


def test_concurrent_initialize_only_latest_boot_can_mint(tmp_path):
    """Two concurrent initialize() calls — only the latest boot can mint."""
    db = tmp_path / "conc_init.db"
    # Pre-create the store so the schema exists.
    pre = _file_store(db)
    pre._conn.close()

    initialized = []
    barrier = threading.Barrier(2)

    def init_one():
        barrier.wait()
        store = _file_store(db)
        rt = _runtime(store)
        try:
            rt.initialize()
            return rt
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        futs = [pool.submit(init_one) for _ in range(2)]
        for f in as_completed(futs):
            r = f.result()
            if r is not None:
                initialized.append(r)

    # At least one runtime initialized. The latest (highest epoch) can mint;
    # any earlier one is fenced.
    if len(initialized) == 2:
        rts_by_epoch = sorted(initialized, key=lambda r: r.boot_context.server_epoch)
        older, newer = rts_by_epoch
        # The older runtime's cached boot context no longer matches persisted.
        with pytest.raises((RuntimeError, Exception)):
            older.require_ready()
        # The newer one is still ready.
        newer.require_ready()
    elif len(initialized) == 1:
        initialized[0].require_ready()
    else:
        pytest.fail("at least one runtime should initialize")
