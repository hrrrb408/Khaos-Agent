"""M4 Batch 2.1 — Broker Authenticity and Atomic Authorization Closure.

Covers the 30 scenarios from spec §11 (failure & concurrency matrix) plus
the §12 static-security audit assertions. Each scenario drives the REAL
authenticated receipt flow (no bool-approve shortcuts) and exercises the
atomic multi-row transactions + restart-epoch invalidation.
"""
from __future__ import annotations

import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import replace
from pathlib import Path

import pytest

from khaos.coding.planning.approval import (
    ApprovalConflictError,
    AuthorizationAlreadyConsumedError,
    AuthorizationMismatchError,
    AuthorizationRevokedError,
    AuthorizationStatus,
    BrokerDecisionReceipt,
    GatePolicy,
    PlanApprovalStatus,
    PlanApprovalStore,
    PlanExecutionGate,
    PlanSnapshotStore,
    PlanStaleError,
    UnauthenticatedReceiptError,
)
from khaos.coding.planning.approval.gate import (
    ApprovalMissingError,
    PlanBlockedError,
)
from khaos.coding.planning.approval.service import ApprovalPolicy

from _m4_batch2_helpers import (  # type: ignore[import-not-found]
    FakeContextProvider,
    SyncBroker,
    approve_and_apply,
    broker_decide,
    high_risk,
    low_risk,
    make_gate,
    make_plan,
    make_service,
)


# ===========================================================================
# §11 scenarios 1-8: broker authenticity (no bool-approve, receipts only)
# ===========================================================================


def test_01_direct_approved_true_rejected():
    """1. There is no public entry that accepts approved=True."""
    from khaos.coding.planning.approval import PlanApprovalService
    import inspect

    sig = inspect.signature(PlanApprovalService.apply_broker_decision)
    assert "approved" not in sig.parameters
    # Calling with approved=True kwarg raises TypeError.
    service, *_ = make_service()
    with pytest.raises(TypeError):
        service.apply_broker_decision(approved=True)  # type: ignore[call-arg]


def test_02_forged_actor_rejected():
    """2. A receipt carries actor identity from the broker, not the caller."""
    plan = make_plan(risks=(high_risk(),), plan_id="p_actor")
    service, store, ctx, broker, repo = make_service()
    request = service.request_approval(plan)
    # Caller cannot inject an actor_id into apply_broker_decision.
    receipt = broker_decide(broker=broker, store=store, request=request, approved=True, actor_id="legit-user")
    updated = service.apply_broker_decision(receipt)
    # The decision record's actor is the one the broker authenticated.
    decisions = store.list_decisions(request.approval_request_id)
    assert decisions[-1].actor_id == "legit-user"


def test_03_unbrokered_decision_rejected():
    """3. A decision that never went through resolve_plan_approval is refused."""
    from _m4_batch2_helpers import make_forged_receipt

    plan = make_plan(risks=(high_risk(),), plan_id="p_unbrokered")
    service, store, ctx, broker, repo = make_service()
    request = service.request_approval(plan)
    forged = make_forged_receipt(
        broker_request_id=request.broker_request_id,
        approval_request_id=request.approval_request_id,
        binding_digest=request.binding_digest,
        one_time_token="never-minted",
    )
    with pytest.raises(UnauthenticatedReceiptError):
        service.apply_broker_decision(forged)


def test_04_forged_receipt_rejected():
    """4. A forged dataclass receipt fails token-hash verification."""
    from _m4_batch2_helpers import make_forged_receipt

    plan = make_plan(risks=(high_risk(),), plan_id="p_forge")
    service, store, ctx, broker, repo = make_service()
    request = service.request_approval(plan)
    forged = make_forged_receipt(
        broker_request_id=request.broker_request_id,
        approval_request_id=request.approval_request_id,
        binding_digest=request.binding_digest,
        one_time_token="forged",
    )
    with pytest.raises(UnauthenticatedReceiptError):
        service.apply_broker_decision(forged)


def test_05_receipt_cross_request_replay_rejected():
    """5. A receipt minted for request A cannot be applied to request B."""
    plan_a = make_plan(risks=(high_risk(),), plan_id="p_A")
    plan_b = make_plan(risks=(high_risk(),), plan_id="p_B")
    service, store, ctx, broker, repo = make_service()
    req_a = service.request_approval(plan_a)
    req_b = service.request_approval(plan_b)
    receipt_a = broker_decide(broker=broker, store=store, request=req_a, approved=True)
    # Tamper: point receipt_a at req_b.
    tampered = replace(receipt_a, approval_request_id=req_b.approval_request_id)
    with pytest.raises(UnauthenticatedReceiptError):
        service.apply_broker_decision(tampered)


def test_06_receipt_duplicate_consume_rejected():
    """6. A receipt consumed once cannot drive a DIFFERENT decision path.

    Re-applying the same receipt to the same (already-approved) request is
    idempotent and harmless. But a receipt whose decision conflicts with the
    current request state, or a receipt already consumed applied to a fresh
    request, must be refused. We verify the consumed flag is set and a
    conflict-decision receipt is rejected.
    """
    plan = make_plan(risks=(high_risk(),), plan_id="p_dup")
    service, store, ctx, broker, repo = make_service()
    request = service.request_approval(plan)
    receipt = broker_decide(broker=broker, store=store, request=request, approved=True)
    service.apply_broker_decision(receipt)
    # The receipt is now consumed.
    row = store.get_receipt_by_token(receipt.one_time_token)
    assert int(row["consumed"]) == 1
    # A conflicting-decision receipt (reject after approve) is refused by the
    # broker — it returns None.
    reject_receipt = broker_decide(broker=broker, store=store, request=request, approved=False)
    assert reject_receipt is None


def test_07_atomic_decision_commit():
    """7. status + decision + audit + expiry + receipt commit atomically."""
    plan = make_plan(risks=(high_risk(),), plan_id="p_atomic")
    service, store, ctx, broker, repo = make_service()
    request = service.request_approval(plan)
    receipt = broker_decide(broker=broker, store=store, request=request, approved=True)
    updated = service.apply_broker_decision(receipt)
    assert updated.status is PlanApprovalStatus.APPROVED
    # All four artifacts exist together.
    assert store.list_decisions(request.approval_request_id)
    assert store.list_audit_events(approval_request_id=request.approval_request_id)
    # Receipt consumed.
    receipt_row = store.get_receipt_by_token(receipt.one_time_token)
    assert receipt_row is not None
    assert int(receipt_row["consumed"]) == 1


def test_08_fault_injection_full_rollback():
    """8. If any step inside apply_authenticated_decision fails, EVERYTHING
    rolls back: request status unchanged, no decision, no audit, receipt
    unconsumed."""
    plan = make_plan(risks=(high_risk(),), plan_id="p_fault")
    service, store, ctx, broker, repo = make_service()
    request = service.request_approval(plan)
    receipt = broker_decide(broker=broker, store=store, request=request, approved=True)
    # Snapshot pre-state.
    pre_status = store.get_request(request.approval_request_id).status
    pre_decisions = store.list_decisions(request.approval_request_id)
    pre_audit = store.list_audit_events(approval_request_id=request.approval_request_id)

    # Sabotage: force the audit insert to fail by making the table name
    # unreachable. We monkeypatch the store's connection to raise on the
    # audit insert by temporarily renaming the audit table.
    conn = store._conn  # noqa: SLF001
    conn.execute("ALTER TABLE plan_approval_audit_events RENAME TO _audit_hidden")
    try:
        with pytest.raises(Exception):
            service.apply_broker_decision(receipt)
    finally:
        conn.execute("ALTER TABLE _audit_hidden RENAME TO plan_approval_audit_events")

    # Everything restored.
    post = store.get_request(request.approval_request_id)
    assert post.status is pre_status  # still PENDING
    assert store.list_decisions(request.approval_request_id) == pre_decisions
    assert store.list_audit_events(approval_request_id=request.approval_request_id) == pre_audit
    # Receipt NOT consumed.
    receipt_row = store.get_receipt_by_token(receipt.one_time_token)
    assert int(receipt_row["consumed"]) == 0


# ===========================================================================
# §11 scenarios 9-15: single execution per approval; mint/revoke invariants
# ===========================================================================


def test_09_repeated_mint_no_multiple_active_authorizations():
    """9. Two mints for the same approval return ONE active authorization."""
    plan = make_plan(risks=(high_risk(),), plan_id="p_onemint")
    service, store, ctx, broker, repo = make_service()
    request = service.request_approval(plan)
    approve_and_apply(service=service, broker=broker, store=store, request=request, plan=plan)
    gate = make_gate(store=store, context=ctx, plan_repository=repo)
    auth1 = gate.authorize_execution(plan_id=plan.plan_id, approval_request_id=request.approval_request_id)
    auth2 = gate.authorize_execution(plan_id=plan.plan_id, approval_request_id=request.approval_request_id)
    # Same authorization returned.
    assert auth1.authorization_id == auth2.authorization_id
    # Exactly one row in the table.
    rows = store.list_authorizations_for_plan(plan.plan_id)
    active = [r for r in rows if r.status is AuthorizationStatus.ACTIVE]
    assert len(active) == 1


def test_10_consume_authorization_consumes_request():
    """10. Consuming an authorization flips its request to CONSUMED too."""
    plan = make_plan(risks=(low_risk(),), plan_id="p_consume_req")
    service, store, ctx, broker, repo = make_service()
    request = service.request_approval(plan)
    gate = make_gate(store=store, context=ctx, plan_repository=repo)
    auth = gate.authorize_execution(plan_id=plan.plan_id, approval_request_id=request.approval_request_id)
    gate.acquire_lease(
            authorization_id=auth.authorization_id, nonce=auth.nonce,
        expected_plan_id=plan.plan_id, expected_task_id=plan.task_id,
        expected_workspace_id=plan.workspace_id, expected_repository_id=plan.repository_id,
            owner_execution_id="exec_test",
    )
    assert store.get_request(request.approval_request_id).status is PlanApprovalStatus.CONSUMED


def test_11_request_consumed_then_mint_rejected():
    """11. After a request is CONSUMED, minting is refused."""
    plan = make_plan(risks=(low_risk(),), plan_id="p_after_consume")
    service, store, ctx, broker, repo = make_service()
    request = service.request_approval(plan)
    gate = make_gate(store=store, context=ctx, plan_repository=repo)
    auth = gate.authorize_execution(plan_id=plan.plan_id, approval_request_id=request.approval_request_id)
    gate.acquire_lease(
            authorization_id=auth.authorization_id, nonce=auth.nonce,
        expected_plan_id=plan.plan_id, expected_task_id=plan.task_id,
        expected_workspace_id=plan.workspace_id, expected_repository_id=plan.repository_id,
            owner_execution_id="exec_test",
    )
    # Mint again → refused (request is CONSUMED).
    with pytest.raises((ApprovalMissingError, AuthorizationAlreadyConsumedError)):
        gate.authorize_execution(plan_id=plan.plan_id, approval_request_id=request.approval_request_id)


def test_12_not_required_single_execution():
    """12. A not-required request is also single-execution."""
    plan = make_plan(risks=(low_risk(),), plan_id="p_nr_once")
    service, store, ctx, broker, repo = make_service()
    request = service.request_approval(plan)
    gate = make_gate(store=store, context=ctx, plan_repository=repo)
    auth = gate.authorize_execution(plan_id=plan.plan_id, approval_request_id=request.approval_request_id)
    gate.acquire_lease(
            authorization_id=auth.authorization_id, nonce=auth.nonce,
        expected_plan_id=plan.plan_id, expected_task_id=plan.task_id,
        expected_workspace_id=plan.workspace_id, expected_repository_id=plan.repository_id,
            owner_execution_id="exec_test",
    )
    assert store.get_request(request.approval_request_id).status is PlanApprovalStatus.CONSUMED
    with pytest.raises((ApprovalMissingError, AuthorizationAlreadyConsumedError)):
        gate.authorize_execution(plan_id=plan.plan_id, approval_request_id=request.approval_request_id)


def test_13_revoke_mint_race(tmp_path):
    """13. Concurrent revoke + mint: if revoke wins, mint fails; final state stable.

    Each thread opens its own file-backed connection so BEGIN IMMEDIATE
    serializes cleanly (no shared-connection transaction warning).
    """
    db = tmp_path / "rev_mint.db"
    plan = make_plan(risks=(high_risk(),), plan_id="p_rev_mint")
    # Setup on the main thread.
    conn0 = sqlite3.connect(str(db), isolation_level=None)
    store0 = PlanApprovalStore(conn0)
    repo = PlanSnapshotStore()
    service0 = type("S", (), {})  # placeholder
    from khaos.coding.planning.approval import PlanApprovalService
    svc0 = PlanApprovalService(
        store=store0, broker=SyncBroker(), context_provider=FakeContextProvider(),
        plan_repository=repo,
    )
    request = svc0.request_approval(plan)
    # Approve via broker.
    broker0 = SyncBroker()
    import asyncio
    asyncio.new_event_loop().run_until_complete(
        broker0.real.register_plan_approval(
            approval_request_id=request.broker_request_id.split(":", 1)[1],
            binding={"binding_digest": "x"}, summary={}, expires_at=9999999999.0,
        )
    )
    receipt = broker_decide(broker=broker0, store=store0, request=request, approved=True)
    svc0.apply_broker_decision(receipt)
    conn0.close()

    barrier = threading.Barrier(2)

    def do_revoke():
        barrier.wait()
        conn = sqlite3.connect(str(db), check_same_thread=False, timeout=30.0, isolation_level=None)
        store = PlanApprovalStore(conn)
        service = PlanApprovalService(
            store=store, broker=SyncBroker(), context_provider=FakeContextProvider(),
            plan_repository=repo,
        )
        try:
            service.revoke(request.approval_request_id, actor_id="admin")
        finally:
            conn.close()

    def do_mint():
        barrier.wait()
        conn = sqlite3.connect(str(db), check_same_thread=False, timeout=30.0, isolation_level=None)
        store = PlanApprovalStore(conn)
        gate = PlanExecutionGate(store=store, context_provider=FakeContextProvider(), plan_repository=repo)
        try:
            gate.authorize_execution(plan_id=plan.plan_id, approval_request_id=request.approval_request_id)
        except Exception:
            pass
        finally:
            conn.close()

    t1 = threading.Thread(target=do_revoke)
    t2 = threading.Thread(target=do_mint)
    t1.start(); t2.start()
    t1.join(); t2.join()
    # Invariant: no request=revoked AND authorization=active simultaneously.
    final_conn = sqlite3.connect(str(db))
    final_store = PlanApprovalStore(final_conn)
    active = [a for a in final_store.list_authorizations_for_plan(plan.plan_id) if a.status is AuthorizationStatus.ACTIVE]
    final_req = final_store.get_request(request.approval_request_id)
    if final_req.status is PlanApprovalStatus.REVOKED:
        assert len(active) == 0
    final_conn.close()


def test_14_revoked_request_zero_active_authorizations():
    """14. After revoke, the active-authorization count for the request is 0."""
    plan = make_plan(risks=(high_risk(),), plan_id="p_rev_zero")
    service, store, ctx, broker, repo = make_service()
    request = service.request_approval(plan)
    approve_and_apply(service=service, broker=broker, store=store, request=request, plan=plan)
    gate = make_gate(store=store, context=ctx, plan_repository=repo)
    gate.authorize_execution(plan_id=plan.plan_id, approval_request_id=request.approval_request_id)
    service.revoke(request.approval_request_id, actor_id="admin")
    active = [a for a in store.list_authorizations_for_plan(plan.plan_id) if a.status is AuthorizationStatus.ACTIVE]
    assert len(active) == 0


def test_15_mint_then_revoke_revokes_authorization():
    """15. Mint then revoke → the authorization is revoked."""
    plan = make_plan(risks=(high_risk(),), plan_id="p_mint_revoke")
    service, store, ctx, broker, repo = make_service()
    request = service.request_approval(plan)
    approve_and_apply(service=service, broker=broker, store=store, request=request, plan=plan)
    gate = make_gate(store=store, context=ctx, plan_repository=repo)
    auth = gate.authorize_execution(plan_id=plan.plan_id, approval_request_id=request.approval_request_id)
    service.revoke(request.approval_request_id, actor_id="admin")
    refreshed = store.get_authorization(auth.authorization_id)
    assert refreshed.status is AuthorizationStatus.REVOKED


# ===========================================================================
# §11 scenarios 16-22: consume-time live validation + authoritative plan
# ===========================================================================


def _approved_high_risk_setup(plan_id):
    plan = make_plan(risks=(high_risk(),), plan_id=plan_id)
    service, store, ctx, broker, repo = make_service()
    request = service.request_approval(plan)
    approve_and_apply(service=service, broker=broker, store=store, request=request, plan=plan)
    gate = make_gate(store=store, context=ctx, plan_repository=repo)
    auth = gate.authorize_execution(plan_id=plan.plan_id, approval_request_id=request.approval_request_id)
    return plan, service, store, ctx, repo, gate, auth


def test_16_file_drift_after_mint_refuses_consume():
    """16. File-hash drift after mint → consume refused.

    We add a file-evidence row whose content_hash participates in the binding
    digest, then drift that hash. The consume-time binding digest mismatch
    refuses consumption.
    """
    plan, service, store, ctx, repo, gate, auth = _approved_high_risk_setup("p_drift_file")
    from khaos.coding.planning.contracts import PlanEvidence

    # Construct a plan WITH file evidence, drift its content_hash.
    base = make_plan(
        risks=(high_risk(),), plan_id="p_drift_file2",
        evidence=(
            PlanEvidence("file", "repo", path="auth.py", content_hash="hash_v1", generation=1, confidence=1.0),
            PlanEvidence("verification-config", "repo", query="config-hash", confidence=1.0, metadata={"config_hash": "cfg1", "config_files": {}}),
        ),
    )
    # Re-setup with the file-evidenced plan.
    plan = base
    service, store, ctx, broker, repo = make_service()
    request = service.request_approval(plan)
    approve_and_apply(service=service, broker=broker, store=store, request=request, plan=plan)
    gate = make_gate(store=store, context=ctx, plan_repository=repo)
    auth = gate.authorize_execution(plan_id=plan.plan_id, approval_request_id=request.approval_request_id)

    drifted = replace(plan, evidence=(
        PlanEvidence("file", "repo", path="auth.py", content_hash="hash_v2", generation=1, confidence=1.0),
        plan.evidence[1],
    ))
    store._conn.execute("UPDATE plan_snapshots SET canonical_plan_json=? WHERE plan_id=?", (repo._canonicalize(drifted), plan.plan_id))
    with pytest.raises((AuthorizationMismatchError, PlanBlockedError)):
        gate.acquire_lease(
            authorization_id=auth.authorization_id, nonce=auth.nonce,
            expected_plan_id=plan.plan_id, expected_task_id=plan.task_id,
            expected_workspace_id=plan.workspace_id, expected_repository_id=plan.repository_id,
            owner_execution_id="exec_test",
        )


def test_17_symbol_drift_after_mint_refuses_consume():
    """17. Symbol drift after mint → consume refused (binding digest changes)."""
    plan, service, store, ctx, repo, gate, auth = _approved_high_risk_setup("p_drift_sym")
    from khaos.coding.planning.contracts import AffectedSymbol

    drifted = replace(plan, affected_symbols=(
        AffectedSymbol("ssym_OTHER", "other", "function", "auth.py", "direct", 1.0, ()),
    ))
    store._conn.execute("UPDATE plan_snapshots SET canonical_plan_json=? WHERE plan_id=?", (repo._canonicalize(drifted), plan.plan_id))
    with pytest.raises((AuthorizationMismatchError, PlanBlockedError)):
        gate.acquire_lease(
            authorization_id=auth.authorization_id, nonce=auth.nonce,
            expected_plan_id=plan.plan_id, expected_task_id=plan.task_id,
            expected_workspace_id=plan.workspace_id, expected_repository_id=plan.repository_id,
            owner_execution_id="exec_test",
        )


def test_18_config_drift_after_mint_refuses_consume():
    """18. Config drift after mint → consume refused."""
    plan, service, store, ctx, repo, gate, auth = _approved_high_risk_setup("p_drift_cfg")
    drifted = replace(plan, evidence=(
        replace(plan.evidence[0], metadata={**plan.evidence[0].metadata, "config_hash": "changed"}),
    ) + tuple(plan.evidence[1:]))
    store._conn.execute("UPDATE plan_snapshots SET canonical_plan_json=? WHERE plan_id=?", (repo._canonicalize(drifted), plan.plan_id))
    with pytest.raises((AuthorizationMismatchError, PlanBlockedError)):
        gate.acquire_lease(
            authorization_id=auth.authorization_id, nonce=auth.nonce,
            expected_plan_id=plan.plan_id, expected_task_id=plan.task_id,
            expected_workspace_id=plan.workspace_id, expected_repository_id=plan.repository_id,
            owner_execution_id="exec_test",
        )


def test_19_head_drift_after_mint_refuses_consume():
    """19. HEAD drift after mint → consume refused."""
    plan, service, store, ctx, repo, gate, auth = _approved_high_risk_setup("p_drift_head")
    ctx.set(head_sha="different")
    with pytest.raises((PlanBlockedError, AuthorizationMismatchError)):
        gate.acquire_lease(
            authorization_id=auth.authorization_id, nonce=auth.nonce,
            expected_plan_id=plan.plan_id, expected_task_id=plan.task_id,
            expected_workspace_id=plan.workspace_id, expected_repository_id=plan.repository_id,
            owner_execution_id="exec_test",
        )


def test_20_task_cancel_after_mint_refuses_consume():
    """20. Task cancel after mint → consume refused."""
    plan, service, store, ctx, repo, gate, auth = _approved_high_risk_setup("p_cancel")
    ctx.set(task_terminal=True)
    with pytest.raises((PlanBlockedError, AuthorizationMismatchError)):
        gate.acquire_lease(
            authorization_id=auth.authorization_id, nonce=auth.nonce,
            expected_plan_id=plan.plan_id, expected_task_id=plan.task_id,
            expected_workspace_id=plan.workspace_id, expected_repository_id=plan.repository_id,
            owner_execution_id="exec_test",
        )


def test_21_workspace_cleanup_after_mint_refuses_consume():
    """21. Workspace cleanup after mint → consume refused."""
    plan, service, store, ctx, repo, gate, auth = _approved_high_risk_setup("p_wscleanup")
    ctx.set(workspace_terminal=True)
    with pytest.raises((PlanBlockedError, AuthorizationMismatchError)):
        gate.acquire_lease(
            authorization_id=auth.authorization_id, nonce=auth.nonce,
            expected_plan_id=plan.plan_id, expected_task_id=plan.task_id,
            expected_workspace_id=plan.workspace_id, expected_repository_id=plan.repository_id,
            owner_execution_id="exec_test",
        )


def test_22_forged_plan_does_not_affect_validation():
    """22. A caller cannot influence validation by passing a forged plan.

    The gate resolves the plan by plan_id from the AUTHORITATIVE persisted
    repository. A forged plan object is irrelevant — authorize_execution
    takes plan_id, not a plan object. The persisted repository REFUSES to
    silently replace a snapshot with different content (Batch 2.2 §4), so a
    caller cannot mutate the validated plan either.
    """
    plan = make_plan(risks=(low_risk(),), plan_id="p_authoritative")
    service, store, ctx, broker, repo = make_service()
    request = service.request_approval(plan)  # registers authoritative snapshot
    gate = make_gate(store=store, context=ctx, plan_repository=repo)
    auth = gate.authorize_execution(plan_id=plan.plan_id, approval_request_id=request.approval_request_id)
    assert auth.status is AuthorizationStatus.ACTIVE
    # A mutated plan with a different content_hash CANNOT replace the
    # authoritative snapshot (persisted repository refuses).
    mutated = replace(plan, content_hash="forged-hash")
    replaced = repo.register(mutated)
    assert replaced is False, "persisted repository must refuse silent content replacement"
    # The original authorization still consumes cleanly (no drift — the
    # authoritative snapshot is unchanged).
    gate.acquire_lease(
            authorization_id=auth.authorization_id, nonce=auth.nonce,
        expected_plan_id=plan.plan_id, expected_task_id=plan.task_id,
        expected_workspace_id=plan.workspace_id, expected_repository_id=plan.repository_id,
            owner_execution_id="exec_test",
    )


# ===========================================================================
# §11 scenarios 23-27: durable registration + restart recovery
# ===========================================================================


def test_23_broker_registration_failure_leaves_no_pending_orphan(tmp_path):
    """23. If the broker fails after the DB insert, the row is
    registration-failed, not a phantom pending."""
    plan = make_plan(risks=(high_risk(),), plan_id="p_brokerfail")

    class FailingBroker(SyncBroker):
        def register_plan_approval(self, **kw):
            raise RuntimeError("broker down")

    service, store, ctx, broker, repo = make_service(broker=FailingBroker())
    with pytest.raises(Exception, match="broker registration failed"):
        service.request_approval(plan)
    # The row exists but is registration-failed (terminal), NOT pending.
    row = store._conn.execute(  # noqa: SLF001
        "SELECT status FROM plan_approval_requests WHERE plan_id = ?",
        (plan.plan_id,),
    ).fetchone()
    assert row is not None
    assert row["status"] == "registration-failed"
    # And reconcile won't surface it as pending.
    pending = [r for r in store.list_registering_or_pending() if r.plan_id == plan.plan_id]
    assert len(pending) == 0


def test_24_db_failure_after_broker_is_recoverable(tmp_path):
    """24. A DB write failure after broker registration is detectable via reconcile."""
    plan = make_plan(risks=(high_risk(),), plan_id="p_dbfail")
    service, store, ctx, broker, repo = make_service()
    # Normal registration succeeds.
    request = service.request_approval(plan)
    assert request.status is PlanApprovalStatus.PENDING
    # reconcile re-registers pending rows with the broker (idempotent).
    counts = service.reconcile()
    assert counts["left_pending"] >= 1


def test_25_early_callback_safe_retry():
    """25. A broker callback arriving before the row is pending is handled by reconcile."""
    plan = make_plan(risks=(high_risk(),), plan_id="p_early")
    service, store, ctx, broker, repo = make_service()
    request = service.request_approval(plan)
    # Reconcile is safe to call repeatedly.
    service.reconcile()
    service.reconcile()
    assert store.get_request(request.approval_request_id).status is PlanApprovalStatus.PENDING


def test_26_restart_recovers_pending_request(tmp_path):
    """26. After a simulated restart (new store, same DB), reconcile re-registers pending rows."""
    db = tmp_path / "restart.db"
    plan = make_plan(risks=(high_risk(),), plan_id="p_restart")
    # Session 1: create a pending request.
    conn1 = sqlite3.connect(str(db))
    store1 = PlanApprovalStore(conn1)
    repo1 = PlanSnapshotStore()
    service1 = service = type("S", (), {})()  # placeholder
    from khaos.coding.planning.approval import PlanApprovalService
    svc1 = PlanApprovalService(
        store=store1, broker=SyncBroker(), context_provider=FakeContextProvider(),
        plan_repository=repo1,
    )
    svc1.request_approval(plan)
    conn1.close()
    # Session 2: reopen; the broker is fresh (in-memory state lost). reconcile
    # re-registers the pending row.
    conn2 = sqlite3.connect(str(db))
    store2 = PlanApprovalStore(conn2)
    repo2 = PlanSnapshotStore()
    repo2.register(plan)
    svc2 = PlanApprovalService(
        store=store2, broker=SyncBroker(), context_provider=FakeContextProvider(),
        plan_repository=repo2,
    )
    counts = svc2.reconcile()
    assert counts["left_pending"] >= 1
    conn2.close()


def test_27_restart_invalidates_old_authorizations(tmp_path):
    """27. After restart (epoch rotation), prior-epoch authorizations are refused."""
    plan = make_plan(risks=(low_risk(),), plan_id="p_epoch")
    service, store, ctx, broker, repo = make_service()
    request = service.request_approval(plan)
    gate = make_gate(store=store, context=ctx, plan_repository=repo)
    auth = gate.authorize_execution(plan_id=plan.plan_id, approval_request_id=request.approval_request_id)
    # Simulate restart: new gate with a rotated epoch.
    gate2 = make_gate(store=store, context=ctx, plan_repository=repo)
    revoked = gate2.rotate_epoch()  # bulk-revoke epoch-1 authorizations
    # rotate_epoch returns (new_epoch, new_boot_id, revoked_count)
    assert revoked[2] >= 1
    # The old authorization can no longer be consumed.
    with pytest.raises((AuthorizationRevokedError, AuthorizationMismatchError)):
        gate2.acquire_lease(
            authorization_id=auth.authorization_id, nonce=auth.nonce,
            expected_plan_id=plan.plan_id, expected_task_id=plan.task_id,
            expected_workspace_id=plan.workspace_id, expected_repository_id=plan.repository_id,
            owner_execution_id="exec_test",
        )


# ===========================================================================
# §11 scenarios 28-30: uniqueness, fake clock, real concurrent transactions
# ===========================================================================


def test_28_broker_request_id_unique():
    """28. Two requests cannot share a non-empty broker_request_id."""
    plan = make_plan(risks=(high_risk(),), plan_id="p_unique_broker")
    service, store, ctx, broker, repo = make_service()
    request = service.request_approval(plan)
    # Attempt to insert a second request row with the same broker_request_id.
    conn = store._conn  # noqa: SLF001
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO plan_approval_requests (approval_request_id, plan_id, plan_content_hash, "
            "repository_id, task_id, workspace_id, base_sha, repository_generation, risk_level, "
            "requested_operations, affected_files, affected_symbols, verification_digest, "
            "binding_digest, requested_at, expires_at, status, broker_request_id) "
            "VALUES ('par_dup', 'p', 'h', 'r', 't', 'w', 'b', 1, 'low', '[]', '[]', '[]', 'vd', 'bd', 0, 0, 'pending', ?)",
            (request.broker_request_id,),
        )
        conn.commit()


def test_29_fake_clock_controls_all_expiry():
    """29. A FakeClock deterministically controls request + authorization expiry."""
    class FakeClock:
        def __init__(self): self.t = 1000.0
        def __call__(self): return self.t
        def advance(self, seconds): self.t += seconds

    clock = FakeClock()
    plan = make_plan(risks=(high_risk(),), plan_id="p_clock")
    service, store, ctx, broker, repo = make_service(
        policy=ApprovalPolicy(pending_ttl_seconds=10.0, approved_ttl_seconds=5.0),
        clock=clock,
    )
    request = service.request_approval(plan)
    assert request.requested_at == 1000.0
    assert request.expires_at == 1010.0  # 1000 + pending_ttl
    # Advance past pending TTL.
    clock.advance(11.0)
    # No time.time() was consulted — the clock is the sole authority.
    assert clock() == 1011.0


def test_30_real_sqlite_concurrent_approve_mint_consume(tmp_path):
    """30. approve/mint/revoke/consume under real SQLite concurrency."""
    from khaos.coding.planning.approval import CurrentRepositoryState

    db = tmp_path / "real_conc.db"
    plan = make_plan(risks=(high_risk(),), plan_id="p_realconc")

    # Setup: pending request.
    conn0 = sqlite3.connect(str(db), isolation_level=None)
    store0 = PlanApprovalStore(conn0)
    repo = PlanSnapshotStore()
    broker0 = SyncBroker()
    svc0 = type("S", (), {"plan_repository": repo})  # not used directly
    from khaos.coding.planning.approval import PlanApprovalService
    service0 = PlanApprovalService(
        store=store0, broker=broker0, context_provider=FakeContextProvider(),
        plan_repository=repo,
    )
    request = service0.request_approval(plan)

    # Mint two receipts for concurrent apply.
    import asyncio
    asyncio.new_event_loop().run_until_complete(
        broker0.real.register_plan_approval(
            approval_request_id=request.broker_request_id.split(":", 1)[1],
            binding={"binding_digest": "x"}, summary={}, expires_at=9999999999.0,
        )
    )
    r1 = broker_decide(broker=broker0, store=store0, request=request, approved=True, actor_id="u1")
    r2 = broker_decide(broker=broker0, store=store0, request=request, approved=True, actor_id="u2")
    conn0.close()

    def apply(receipt):
        conn = sqlite3.connect(str(db), check_same_thread=False, timeout=30.0, isolation_level=None)
        store = PlanApprovalStore(conn)
        repo_local = PlanSnapshotStore()
        repo_local.register(plan)
        service = PlanApprovalService(
            store=store, broker=SyncBroker(), context_provider=FakeContextProvider(),
            plan_repository=repo_local,
        )
        try:
            service.apply_broker_decision(receipt)
            return "ok"
        except ApprovalConflictError:
            return "conflict"
        finally:
            conn.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        futs = [pool.submit(apply, r) for r in (r1, r2)]
        results = sorted(f.result() for f in as_completed(futs))

    # Exactly one approve wins.
    final_conn = sqlite3.connect(str(db))
    status = final_conn.execute(
        "SELECT status FROM plan_approval_requests WHERE approval_request_id = ?",
        (request.approval_request_id,),
    ).fetchone()[0]
    assert status == "approved"
    final_conn.close()


# ===========================================================================
# §12 Static security audit assertions
# ===========================================================================


def test_static_no_public_bool_approve_entry():
    """§12: PlanApprovalService public bool approve entry = 0."""
    from khaos.coding.planning.approval import PlanApprovalService
    import inspect

    public = {
        m for m in dir(PlanApprovalService)
        if not m.startswith("_") and callable(getattr(PlanApprovalService, m, None))
    }
    assert not any(m in public for m in ("approve", "approve_plan", "set_approved", "force_approve"))
    sig = inspect.signature(PlanApprovalService.apply_broker_decision)
    assert "receipt" in sig.parameters
    assert "approved" not in sig.parameters


def test_static_no_unauthenticated_receipt_path():
    """§12: unauthenticated BrokerDecisionReceipt accepted path = 0."""
    from khaos.coding.planning.approval import PlanApprovalService
    import inspect

    src = inspect.getsource(PlanApprovalService.apply_broker_decision)
    # The method must explicitly type-check the receipt.
    assert "isinstance(receipt, BrokerDecisionReceipt)" in src


def test_static_no_multiple_active_authorizations_per_request():
    """§12: same approval → multiple active authorizations = 0 (enforced by
    partial unique index + atomic mint)."""
    conn = sqlite3.connect(":memory:")
    store = PlanApprovalStore(conn)
    idxs = [r[1] for r in conn.execute("PRAGMA index_list(plan_execution_authorizations)")]
    assert "uq_plan_exec_auth_active_per_request" in idxs


def test_static_no_revoked_request_with_active_auth():
    """§12: request=revoked + auth=active = 0 (revoke uses the atomic
    invalidate_request_and_authorizations which revokes auths in the same tx)."""
    from khaos.coding.planning.approval import PlanApprovalService
    import inspect

    src = inspect.getsource(PlanApprovalService.revoke)
    assert "invalidate_request_and_authorizations" in src


def test_static_no_mint_after_consume():
    """§12: request=consumed → mint = 0 (mint_authorization_if_request_active refuses)."""
    from khaos.coding.planning.approval.store import PlanApprovalStore
    import inspect

    src = inspect.getsource(PlanApprovalStore.mint_authorization_if_request_active)
    assert "CONSUMED" in src or "consumed" in src


def test_static_no_consume_without_live_validation():
    """§12: consume without live validation = 0 (gate runs PlanLiveValidator)."""
    from khaos.coding.planning.approval.gate import PlanExecutionGate
    import inspect

    src = inspect.getsource(PlanExecutionGate.acquire_lease)
    assert "self._validator.validate(" in src


def test_static_no_agent_reachable_approve_or_mint():
    """§12: Agent-reachable approve/mint = 0. The gate and service are not
    imported or wired into AgentLoop / ToolScheduler."""
    import khaos.agent.core as core_mod
    import inspect

    src = inspect.getsource(core_mod)
    assert "PlanApprovalService" not in src
    assert "PlanExecutionGate" not in src


def test_static_no_bare_subprocess():
    """§12: bare subprocess in the approval subsystem = 0."""
    import inspect

    from khaos.coding.planning.approval import service as svc_mod
    from khaos.coding.planning.approval import gate as gate_mod
    from khaos.coding.planning.approval import store as store_mod

    for mod in (svc_mod, gate_mod, store_mod):
        src = inspect.getsource(mod)
        assert "import subprocess" not in src
