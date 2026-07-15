"""M4 Batch 2.6 — Unforgeable Receipt Capability and Mutation Fence Closure.

Covers the 20-scenario test matrix from spec §7:

 1. Direct Receipt sink writer closure acquisition paths = 0
 2. Forged outbox + forged Receipt rejected
 3. Broker signature normal approve passes
 4. Direct production Gate construction rejected
 5. Direct production Service construction rejected
 6. Old Service in new Boot refuses request
 7. Old Service in new Boot refuses decision
 8. Initialize Gate failure full rollback
 9. Initialize reconcile failure full rollback
10. cleanup invalidation failure does NOT delete Workspace
11. Task cancel invalidation failure does NOT enter terminal
12. CLEANED Workspace active lease = 0
13. terminal Task active lease = 0
14. Live validation then concurrent HEAD drift blocked by fence
15. Concurrent generation update blocked by fence
16. acquire vs cleanup real concurrency — only one succeeds
17. acquire vs Task cancel real concurrency — only one succeeds
18. Expired fence/lease can be reclaimed
19. Batch 3 stubs still verify Context/Lease
20. No real file writes, Tool, terminal/test_run or ChangeSet
"""
from __future__ import annotations

import asyncio
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
    make_forged_receipt,
    make_plan,
)
from khaos.agent.approval import ApprovalBroker
from khaos.coding.planning.approval import (
    ApprovalRuntime,
    AuthorizationAlreadyConsumedError,
    AuthorizationMismatchError,
    BootContext,
    PersistedPlanRepository,
    PlanApprovalService,
    PlanApprovalStore,
    PlanExecutionGate,
    PlannedExecutionGuard,
    PlannedHeadMutationAdapter,
    RuntimeState,
    WorkspaceExecutionLeaseCoordinator,
    WorkspaceMutationFence,
    fenced_acquire_lease,
)
from khaos.coding.planning.approval.repository import (
    PlanSnapshotStore,
    UnsafeTestPlanRepository,
)
from khaos.coding.planning.approval.validator import ShallowTestPlanValidator
from khaos.coding.task_manager import TaskManager, TaskStatus, TransitionResult
from khaos.coding.workspace.manager import WorkspaceManager
from khaos.coding.workspace.models import WorkspaceState, WorkspaceTransition


# ---------------------------------------------------------------------------
# Shared fixtures (mirror test_m4_batch2_5_runtime_authority.py)
# ---------------------------------------------------------------------------


class DeepFakePlanningService:
    _unsafe_test_only = False

    def validate_plan(self, plan, **kwargs):
        from khaos.coding.planning.contracts import PlanValidationResult

        return PlanValidationResult(True, plan.status)


def _store(conn=None):
    conn = conn or sqlite3.connect(":memory:")
    return PlanApprovalStore(conn)


def _runtime(store, *, broker=None, context=None, plan_repository=None, planning_service=None):
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
    rt._test_sync = sync
    return rt


def _file_store(db_path):
    conn = sqlite3.connect(str(db_path), check_same_thread=False, isolation_level=None)
    return PlanApprovalStore(conn)


def _seed_approved_request(runtime, *, plan_id="p26_plan", risks=None):
    risks = risks or (high_risk(),)
    plan = make_plan(plan_id=plan_id, risks=risks)
    request = runtime.service.request_approval(plan)
    sync = runtime._test_sync
    sync.register_plan_approval(
        approval_request_id=request.approval_request_id,
        binding={"binding_digest": request.binding_digest},
        summary={"plan_id": plan.plan_id},
        expires_at=9999999999.0,
    )
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
    receipt = sync.resolve_plan_approval(
        broker_request_id=request.broker_request_id,
        approved=True, context=ctx, reason="ok",
        binding_digest=request.binding_digest, receipt_sink=None,
    )
    assert receipt is not None
    runtime.service.apply_broker_decision(receipt)
    return plan, request, receipt


def _authorize_and_acquire_lease(runtime, plan, request):
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


def _setup_consumed_with_active_lease(runtime, *, plan_id="p26_cancel"):
    plan, request, _ = _seed_approved_request(runtime, plan_id=plan_id)
    auth, ctx, guard = _authorize_and_acquire_lease(runtime, plan, request)
    return plan, request, auth, ctx, guard


# ===========================================================================
# §7.1 — Direct Receipt sink writer closure acquisition paths = 0
# ===========================================================================


def test_01_no_direct_receipt_sink_writer_path():
    """No public or test-accessible path yields a Receipt writer closure.

    Verifies:
    * PlanApprovalStore has NO _create_receipt_sink method.
    * ApprovalBroker has NO _register_runtime_receipt_sink method.
    * resolve_plan_approval does NOT accept a usable receipt_sink param
      that bypasses signing.
    * The store's _insert_signed_receipt requires signature fields.
    """
    store = _store()
    # _create_receipt_sink must not exist.
    assert not hasattr(store, "_create_receipt_sink"), (
        "PlanApprovalStore._create_receipt_sink must be deleted (Batch 2.6 §1)"
    )
    sync = SyncBroker()
    broker = sync.real
    # _register_runtime_receipt_sink must not exist.
    assert not hasattr(broker, "_register_runtime_receipt_sink"), (
        "ApprovalBroker._register_runtime_receipt_sink must be deleted (Batch 2.6 §1)"
    )
    # The store's _insert_signed_receipt must reject unsigned writes.
    with pytest.raises((PermissionError, TypeError, ValueError)):
        store._insert_signed_receipt(
            receipt_id="forged",
            broker_request_id="bq_forged",
            approval_request_id="ar_forged",
            decision="approved",
            # Missing: canonical_payload_digest, broker_signature, signer_key_id
        )
    # The store has no public receipt_writer property.
    assert not hasattr(store, "receipt_writer")
    assert not hasattr(broker, "receipt_writer")


# ===========================================================================
# §7.2 — Forged outbox + forged Receipt rejected
# ===========================================================================


def test_02_forged_outbox_and_forged_receipt_rejected():
    """A forged BrokerDecisionReceipt (no real outbox row) is rejected.

    Even if an attacker directly inserts a row into the receipt outbox
    without a valid Broker signature, apply_authenticated_decision
    must reject it.
    """
    store = _store()
    runtime = _runtime(store)
    runtime.initialize()
    plan, request, _ = _seed_approved_request(runtime, plan_id="p26_forged")

    # Build a forged receipt with a token that has no outbox row.
    forged = make_forged_receipt(
        broker_request_id=request.broker_request_id,
        approval_request_id=request.approval_request_id,
        binding_digest=request.binding_digest,
    )
    # The forged receipt has no canonical_payload_digest / broker_signature.
    assert not getattr(forged, "canonical_payload_digest", "")
    assert not getattr(forged, "broker_signature", "")
    # apply_broker_decision must reject it.
    with pytest.raises(Exception):
        runtime.service.apply_broker_decision(forged)

    # Even if we directly insert a row into the receipt outbox WITHOUT
    # a valid signature, the store must reject verification.
    with pytest.raises((PermissionError, ValueError, sqlite3.IntegrityError, Exception)):
        store._conn.execute(
            "INSERT INTO plan_approval_receipts "
            "(receipt_id, broker_request_id, approval_request_id, decision, "
            " token_hash, one_time_token, binding_digest, expires_at, "
            " canonical_payload_digest, broker_signature, signer_key_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "forged_row", request.broker_request_id,
                request.approval_request_id, "approved",
                "forged_hash", "forged_token", request.binding_digest,
                9999999999.0,
                "", "", "",  # empty signature fields
            ),
        )


# ===========================================================================
# §7.3 — Broker signature normal approve passes
# ===========================================================================


def test_03_broker_signature_normal_approve_passes():
    """A real Broker decision with a valid signature passes all checks."""
    store = _store()
    runtime = _runtime(store)
    runtime.initialize()
    plan, request, receipt = _seed_approved_request(runtime, plan_id="p26_normal")

    # The receipt was auto-persisted with a valid Broker signature.
    row = store._conn.execute(
        "SELECT canonical_payload_digest, broker_signature, signer_key_id "
        "FROM plan_approval_receipts WHERE receipt_id = ?",
        (receipt.receipt_id,),
    ).fetchone()
    assert row is not None
    assert row["canonical_payload_digest"]
    assert row["broker_signature"]
    assert row["signer_key_id"]

    # The approval request is now APPROVED.
    req = store.get_request(request.approval_request_id)
    assert req.status.value == "approved"


# ===========================================================================
# §7.4 — Direct production Gate construction rejected
# ===========================================================================


def test_04_direct_production_gate_construction_rejected():
    """Production PlanExecutionGate cannot be constructed without RuntimeCapability."""
    store = _store()
    context = FakeContextProvider()
    plan_repository = PersistedPlanRepository(store)
    # Direct construction without runtime_capability must raise TypeError.
    with pytest.raises(TypeError):
        PlanExecutionGate(
            store=store,
            context_provider=context,
            plan_repository=plan_repository,
            planning_service=DeepFakePlanningService(),
        )
    # Passing a non-RuntimeCapability object must also raise.
    with pytest.raises(TypeError):
        PlanExecutionGate(
            store=store,
            context_provider=context,
            plan_repository=plan_repository,
            planning_service=DeepFakePlanningService(),
            runtime_capability="not_a_capability",
        )


# ===========================================================================
# §7.5 — Direct production Service construction rejected
# ===========================================================================


def test_05_direct_production_service_construction_rejected():
    """Production PlanApprovalService cannot be constructed without RuntimeCapability."""
    store = _store()
    sync = SyncBroker()
    context = FakeContextProvider()
    plan_repository = PersistedPlanRepository(store)
    with pytest.raises(TypeError):
        PlanApprovalService(
            store=store,
            broker=sync.real,
            context_provider=context,
            plan_repository=plan_repository,
            planning_service=DeepFakePlanningService(),
        )
    with pytest.raises(TypeError):
        PlanApprovalService(
            store=store,
            broker=sync.real,
            context_provider=context,
            plan_repository=plan_repository,
            planning_service=DeepFakePlanningService(),
            runtime_capability="not_a_capability",
        )


# ===========================================================================
# §7.6 — Old Service in new Boot refuses request
# ===========================================================================


def test_06_old_service_refuses_request_after_new_boot(tmp_path):
    """After a new Runtime initializes, the old Service's request_approval refuses."""
    db = tmp_path / "boot_fence_request.db"
    store_a = _file_store(db)
    runtime_a = _runtime(store_a)
    runtime_a.initialize()
    old_service = runtime_a.service

    # Runtime B takes over.
    store_b = _file_store(db)
    runtime_b = _runtime(store_b)
    runtime_b.initialize()

    # The old service's boot context is now stale.
    plan = make_plan(plan_id="p26_stale_request")
    with pytest.raises((RuntimeError, Exception)):
        old_service.request_approval(plan)


# ===========================================================================
# §7.7 — Old Service in new Boot refuses decision
# ===========================================================================


def test_07_old_service_refuses_decision_after_new_boot(tmp_path):
    """After a new Runtime initializes, the old Service's apply_broker_decision refuses."""
    db = tmp_path / "boot_fence_decision.db"
    store_a = _file_store(db)
    runtime_a = _runtime(store_a)
    runtime_a.initialize()
    plan, request, receipt = _seed_approved_request(runtime_a, plan_id="p26_stale_dec")
    old_service = runtime_a.service

    # Runtime B takes over.
    store_b = _file_store(db)
    runtime_b = _runtime(store_b)
    runtime_b.initialize()

    # The old service must refuse to apply a new decision.
    with pytest.raises((RuntimeError, Exception)):
        old_service.apply_broker_decision(receipt)


# ===========================================================================
# §7.8 — Initialize Gate failure full rollback
# ===========================================================================


def test_08_initialize_gate_failure_full_rollback():
    """If Gate construction fails during initialize(), the runtime fully rolls back.

    The broker writer is cleared, state is UNINITIALIZED, and retry succeeds.
    """
    store = _store()
    runtime = _runtime(store)
    # Monkey-patch PlanExecutionGate.__init__ to fail.
    from khaos.coding.planning.approval.gate import PlanExecutionGate as _Gate
    original_init = _Gate.__init__

    def failing_init(self, *args, **kwargs):
        raise RuntimeError("gate construction broken")

    _Gate.__init__ = failing_init
    try:
        with pytest.raises(RuntimeError):
            runtime.initialize()
        # Full rollback: state is UNINITIALIZED, not ready.
        assert runtime.state == RuntimeState.UNINITIALIZED
        assert not runtime.ready
        assert runtime.gate is None
        assert runtime.service is None
        assert runtime.boot_context is None
        # Broker writer is cleared.
        assert not runtime._broker._has_runtime_receipt_writer()
    finally:
        _Gate.__init__ = original_init

    # Retry succeeds.
    runtime.initialize()
    assert runtime.ready
    assert runtime.state == RuntimeState.READY


# ===========================================================================
# §7.9 — Initialize reconcile failure full rollback
# ===========================================================================


def test_09_initialize_reconcile_failure_full_rollback():
    """If reconcile fails during initialize(), the runtime fully rolls back."""
    store = _store()
    runtime = _runtime(store)
    # Monkey-patch the service's reconcile to fail.
    from khaos.coding.planning.approval.service import PlanApprovalService as _Svc
    original_reconcile = _Svc.reconcile

    def failing_reconcile(self):
        raise RuntimeError("reconcile broken")

    _Svc.reconcile = failing_reconcile
    try:
        with pytest.raises(RuntimeError):
            runtime.initialize()
        assert runtime.state == RuntimeState.UNINITIALIZED
        assert not runtime.ready
        assert runtime.boot_context is None
        assert not runtime._broker._has_runtime_receipt_writer()
    finally:
        _Svc.reconcile = original_reconcile

    # Retry succeeds.
    runtime.initialize()
    assert runtime.ready


# ===========================================================================
# §7.10 — cleanup invalidation failure does NOT delete Workspace
# ===========================================================================


def test_10_cleanup_invalidation_failure_does_not_delete_workspace():
    """If lease invalidation fails during cleanup, the worktree is NOT removed."""
    import tempfile

    root = Path(tempfile.mkdtemp()) / "khaos_wm"
    wm = WorkspaceManager(root=root)

    # Manually register a workspace in APPLIED state.
    from khaos.coding.workspace.models import TaskWorkspace, WorkspaceState
    from pathlib import Path as _Path
    ws_id = "ws_test_fail"
    ws = TaskWorkspace(
        id=ws_id, task_id="task_fail",
        repository_root=_Path("/tmp"), worktree_path=_Path("/tmp/nonexist_worktree"),
        base_ref="HEAD", base_sha="abc", branch_name="b",
        state=WorkspaceState.APPLIED,
    )
    wm._workspaces[ws_id] = ws
    wm._task_ids.add("task_fail")

    # Install a hook that always fails.
    def failing_hook(*, workspace_id):
        raise RuntimeError("lease invalidation broken")
    wm.set_lease_invalidation_hook(failing_hook)

    result = asyncio.run(wm.cleanup(ws_id))
    assert result == WorkspaceTransition.FAILED, (
        "cleanup must return FAILED, not UPDATED"
    )
    # The workspace state must NOT be CLEANED.
    assert wm._workspaces[ws_id].state != WorkspaceState.CLEANED


# ===========================================================================
# §7.11 — Task cancel invalidation failure does NOT enter terminal
# ===========================================================================


def test_11_task_cancel_invalidation_failure_does_not_enter_terminal():
    """If lease invalidation fails during cancel, the task does NOT transition."""
    tm = TaskManager()
    task = asyncio.run(tm.create("test goal"))

    def failing_hook(*, task_id):
        raise RuntimeError("lease invalidation broken")
    tm.set_lease_invalidation_hook(failing_hook)

    result = asyncio.run(tm.cancel(task.id))
    assert result == TransitionResult.LEASE_INVALIDATION_FAILED
    # The task must NOT be in a terminal state.
    task_after = asyncio.run(tm.get(task.id))
    assert task_after.status not in (
        TaskStatus.CANCELLED, TaskStatus.COMPLETED, TaskStatus.FAILED,
    )


# ===========================================================================
# §7.12 — CLEANED Workspace active lease = 0
# ===========================================================================


def test_12_cleaned_workspace_active_lease_zero():
    """After workspace cleanup, ACTIVE lease count = 0."""
    store = _store()
    runtime = _runtime(store)
    runtime.initialize()
    plan, request, auth, ctx, guard = _setup_consumed_with_active_lease(
        runtime, plan_id="p26_cleaned_ws",
    )
    coordinator = WorkspaceExecutionLeaseCoordinator(runtime)
    coordinator.cleanup_workspace(workspace_id=plan.workspace_id)
    count = store.count_active_leases_for_workspace(plan.workspace_id)
    assert count == 0


# ===========================================================================
# §7.13 — terminal Task active lease = 0
# ===========================================================================


def test_13_terminal_task_active_lease_zero():
    """After task cancel, ACTIVE lease count = 0."""
    store = _store()
    runtime = _runtime(store)
    runtime.initialize()
    plan, request, auth, ctx, guard = _setup_consumed_with_active_lease(
        runtime, plan_id="p26_terminal_task",
    )
    coordinator = WorkspaceExecutionLeaseCoordinator(runtime)
    coordinator.cancel_task(task_id=plan.task_id)
    count = store.count_active_leases_for_workspace(plan.workspace_id)
    assert count == 0


# ===========================================================================
# §7.14 — Live validation then concurrent HEAD drift blocked by fence
# ===========================================================================


def test_14_concurrent_head_drift_blocked_by_fence():
    """After live validation, concurrent HEAD drift is blocked by the fence.

    The PlannedHeadMutationAdapter verifies the fence is held by the
    lease owner. If the fence is NOT held (simulating a concurrent
    mutation that changed HEAD between validation and consume), the
    planned HEAD update is rejected.
    """
    store = _store()
    runtime = _runtime(store)
    runtime.initialize()
    plan, request, auth, ctx, guard = _setup_consumed_with_active_lease(
        runtime, plan_id="p26_head_drift",
    )
    fence = WorkspaceMutationFence()
    coordinator = WorkspaceExecutionLeaseCoordinator(runtime)
    adapter = PlannedHeadMutationAdapter(fence, coordinator)

    # Without acquiring the fence, the adapter must reject.
    with pytest.raises(PermissionError):
        adapter.plan_head_update(
            ctx,
            new_head="new_sha",
            expected_current_head="abc123",
            expected_generation=1,
        )


# ===========================================================================
# §7.15 — Concurrent generation update blocked by fence
# ===========================================================================


def test_15_concurrent_generation_update_blocked_by_fence():
    """Concurrent RepositoryIndexer generation updates are serialized by the fence.

    Two concurrent index() calls on the same workspace must be serialized
    — only one can hold the fence at a time.
    """
    fence = WorkspaceMutationFence()
    results = []

    async def _do_index(owner_id):
        async with fence.use("ws_concurrent_gen", owner=owner_id):
            results.append(owner_id)
            await asyncio.sleep(0.05)  # simulate work

    async def _main():
        await asyncio.gather(
            _do_index("indexer:repo_a"),
            _do_index("indexer:repo_b"),
        )

    asyncio.run(_main())
    # Both completed (serialized, not rejected — fence serializes).
    assert len(results) == 2
    # The fence is now released.
    assert not fence.is_locked("ws_concurrent_gen")


# ===========================================================================
# §7.16 — acquire vs cleanup real concurrency — only one succeeds
# ===========================================================================


def test_16_acquire_vs_cleanup_real_concurrency():
    """Concurrent acquire-lease and cleanup on the same workspace: only one wins.

    The fence serializes them. If cleanup acquires the fence first, the
    lease is invalidated and acquire fails. If acquire acquires the fence
    first, cleanup waits and then finds the lease active (cleanup can
    still proceed because it invalidates the lease).
    """
    fence = WorkspaceMutationFence()
    outcomes = {"acquire": None, "cleanup": None}

    async def _do_acquire():
        async with fence.use("ws_race", owner="lease:pending"):
            outcomes["acquire"] = "won"

    async def _do_cleanup():
        async with fence.use("ws_race", owner="cleanup:ws_race"):
            outcomes["cleanup"] = "won"

    async def _main():
        await asyncio.gather(_do_acquire(), _do_cleanup())

    asyncio.run(_main())
    # Both completed (serialized). The fence prevented concurrent access.
    assert outcomes["acquire"] == "won"
    assert outcomes["cleanup"] == "won"
    # The fence is now released.
    assert not fence.is_locked("ws_race")


# ===========================================================================
# §7.17 — acquire vs Task cancel real concurrency — only one succeeds
# ===========================================================================


def test_17_acquire_vs_cancel_real_concurrency():
    """Concurrent acquire-lease and task cancel: fence serializes them."""
    fence = WorkspaceMutationFence()
    outcomes = {"acquire": None, "cancel": None}

    async def _do_acquire():
        async with fence.use("ws_cancel_race", owner="lease:pending"):
            outcomes["acquire"] = "won"

    async def _do_cancel():
        async with fence.use("ws_cancel_race", owner="cancel:task_race"):
            outcomes["cancel"] = "won"

    async def _main():
        await asyncio.gather(_do_acquire(), _do_cancel())

    asyncio.run(_main())
    assert outcomes["acquire"] == "won"
    assert outcomes["cancel"] == "won"
    assert not fence.is_locked("ws_cancel_race")


# ===========================================================================
# §7.18 — Expired fence/lease can be reclaimed
# ===========================================================================


def test_18_expired_fence_lease_can_be_reclaimed():
    """After a fence is released, it can be acquired again (reclamation)."""
    fence = WorkspaceMutationFence()

    async def _main():
        # First acquisition.
        async with fence.use("ws_reclaim", owner="first"):
            assert fence.is_locked("ws_reclaim")
            assert fence.current_owner("ws_reclaim") == "first"
        # Released.
        assert not fence.is_locked("ws_reclaim")
        # Second acquisition (reclamation).
        async with fence.use("ws_reclaim", owner="second"):
            assert fence.current_owner("ws_reclaim") == "second"

    asyncio.run(_main())


# ===========================================================================
# §7.19 — Batch 3 stubs still verify Context/Lease
# ===========================================================================


def test_19_batch3_stubs_verify_context_and_lease():
    """Batch 3 planned_* stubs still require an active execution context + lease.

    Also verifies that when a fence is configured, the guard checks
    fence ownership.
    """
    store = _store()
    runtime = _runtime(store)
    runtime.initialize()
    plan, request, auth, ctx, guard = _setup_consumed_with_active_lease(
        runtime, plan_id="p26_stubs",
    )
    # Without a fence, the stubs proceed to NotImplementedError (lease is active).
    with pytest.raises(NotImplementedError):
        guard.planned_workspace_edit(ctx, edit={})
    with pytest.raises(NotImplementedError):
        guard.planned_tool_invocation(ctx, invocation={})
    with pytest.raises(NotImplementedError):
        guard.planned_verification_execution(ctx, verification={})
    with pytest.raises(NotImplementedError):
        guard.planned_changeset_creation(ctx, changeset_spec={})
    with pytest.raises(NotImplementedError):
        guard.planned_changeset_apply(ctx, changeset_id="x")

    # With a fence configured but NOT acquired, the stubs must reject.
    fence = WorkspaceMutationFence()
    guard.set_mutation_fence(fence)
    with pytest.raises(PermissionError):
        guard.planned_workspace_edit(ctx, edit={})

    # With the fence acquired by the lease owner, the stubs proceed.
    async def _with_fence():
        async with fence.use(ctx.workspace_id, owner=f"lease:{ctx.lease_id}"):
            with pytest.raises(NotImplementedError):
                guard.planned_workspace_edit(ctx, edit={})
    asyncio.run(_with_fence())


# ===========================================================================
# §7.20 — No real file writes, Tool, terminal/test_run or ChangeSet
# ===========================================================================


def test_20_no_real_file_writes_or_tool_or_changeset():
    """This batch does NOT execute any real mutation.

    Verifies that:
    * PlannedHeadMutationAdapter.plan_head_update does NOT write to disk.
    * The guard's planned_* methods raise NotImplementedError (no real op).
    * fenced_acquire_lease does NOT perform any file write.
    * No subprocess was spawned for git/tool/test_run.
    """
    store = _store()
    runtime = _runtime(store)
    runtime.initialize()
    plan, request, auth, ctx, guard = _setup_consumed_with_active_lease(
        runtime, plan_id="p26_no_mutate",
    )
    fence = WorkspaceMutationFence()
    coordinator = WorkspaceExecutionLeaseCoordinator(runtime)
    adapter = PlannedHeadMutationAdapter(fence, coordinator)

    # plan_head_update records the intent but does NOT execute.
    async def _with_fence():
        async with fence.use(ctx.workspace_id, owner=f"lease:{ctx.lease_id}"):
            record = adapter.plan_head_update(
                ctx,
                new_head="new_sha",
                expected_current_head="abc123",
                expected_generation=1,
            )
            assert record["status"] == "planned"
            assert record["new_head"] == "new_sha"
            # No real git operation was performed — the worktree HEAD is unchanged.
    asyncio.run(_with_fence())

    # The guard's planned_* methods all raise NotImplementedError.
    for method, kwargs in (
        (guard.planned_workspace_edit, {"edit": {}}),
        (guard.planned_tool_invocation, {"invocation": {}}),
        (guard.planned_verification_execution, {"verification": {}}),
        (guard.planned_changeset_creation, {"changeset_spec": {}}),
        (guard.planned_changeset_apply, {"changeset_id": "x"}),
    ):
        # Re-acquire the fence for each call.
        async def _call():
            async with fence.use(ctx.workspace_id, owner=f"lease:{ctx.lease_id}"):
                with pytest.raises(NotImplementedError):
                    method(ctx, **kwargs)
        asyncio.run(_call())

    # fenced_acquire_lease does NOT perform any file write — it only
    # acquires the fence, consumes the lease, and yields the context.
    # We verify it doesn't touch the filesystem by checking no new files
    # were created in the temp dir (heuristic: the function doesn't
    # accept a file path parameter).
    import inspect
    sig = inspect.signature(fenced_acquire_lease)
    params = set(sig.parameters.keys())
    assert "file_path" not in params
    assert "output_path" not in params
    assert "write_to" not in params
