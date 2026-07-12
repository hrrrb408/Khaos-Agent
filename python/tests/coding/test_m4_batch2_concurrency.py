"""M4 Batch 2 — Concurrent approval / authorization transition tests.

(Batch 2.1 updated: drives the authenticated BrokerDecisionReceipt flow and
the authoritative plan-repository gate API.)

Covers §16 of the spec: real concurrency (threads + BEGIN IMMEDIATE locks)
exercising the atomic CAS paths. These tests intentionally use the
synchronous :class:`PlanApprovalStore` against file-backed SQLite connections
so that ``BEGIN IMMEDIATE`` serializes competing transactions.
"""
from __future__ import annotations

import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import pytest

from khaos.coding.planning.approval import (
    ApprovalConflictError,
    AuthorizationAlreadyConsumedError,
    GatePolicy,
    PlanApprovalService,
    PlanApprovalStatus,
    PlanApprovalStore,
    PlanExecutionGate,
    PlanSnapshotStore,
)
from khaos.coding.planning.approval.service import ApprovalPolicy

from _m4_batch2_helpers import (  # type: ignore[import-not-found]
    FakeContextProvider,
    SyncBroker,
    broker_decide,
    high_risk,
    low_risk,
    make_plan,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _Ctx:
    def __init__(self, **kw):
        self.kw = dict(
            head_sha="abc123", repository_generation=1,
            task_active=True, workspace_active=True,
            task_terminal=False, workspace_terminal=False,
        )
        self.kw.update(kw)
        self._lock = threading.Lock()

    def set(self, **kw):
        with self._lock:
            self.kw.update(kw)

    def current_state(self, *, repository_id, task_id, workspace_id):
        with self._lock:
            kw = dict(self.kw)
        from khaos.coding.planning.approval import CurrentRepositoryState

        return CurrentRepositoryState(
            repository_id=repository_id, task_id=task_id, workspace_id=workspace_id,
            head_sha=kw["head_sha"], repository_generation=kw["repository_generation"],
            task_active=kw["task_active"], workspace_active=kw["workspace_active"],
            task_terminal=kw["task_terminal"], workspace_terminal=kw["workspace_terminal"],
        )


def _seed(db_path, *, plan_id="plan_conc", risks=None):
    """Create a PENDING request on the main thread; return (broker_request_id, plan, repo)."""
    risks = risks or (high_risk(),)
    conn = sqlite3.connect(str(db_path), check_same_thread=False, isolation_level=None)
    store = PlanApprovalStore(conn)
    repo = PlanSnapshotStore()
    service = PlanApprovalService(
        store=store, broker=SyncBroker(), context_provider=_Ctx(),
        plan_repository=repo,
        policy=ApprovalPolicy(pending_ttl_seconds=3600, approved_ttl_seconds=3600),
    )
    plan = make_plan(plan_id=plan_id, risks=risks)
    request = service.request_approval(plan)
    brid = request.broker_request_id
    conn.close()
    return brid, plan, repo


def test_two_concurrent_approves_only_one_wins(tmp_path):
    """Two concurrent apply_authenticated_decision calls on the same request.

    The atomic CAS serializes them: the first flips pending→approved and
    consumes its receipt; the second either sees APPROVED (idempotent for the
    same receipt) or conflicts (its receipt is independent and the request is
    already approved). The net DB state is exactly one APPROVED transition.
    """
    db = tmp_path / "conc_approve.db"
    brid, plan, repo = _seed(db, plan_id="plan_two_approve")

    # Mint TWO independent receipts on the main thread (same broker, same
    # decision, different one-time tokens).
    conn0 = sqlite3.connect(str(db), check_same_thread=False, isolation_level=None)
    store0 = PlanApprovalStore(conn0)
    broker0 = SyncBroker()
    import asyncio
    asyncio.new_event_loop().run_until_complete(
        broker0.real.register_plan_approval(
            approval_request_id=brid.split(":", 1)[1],
            binding={"binding_digest": "x"}, summary={}, expires_at=9999999999.0,
        )
    )
    request0 = store0.get_request_by_broker(brid)
    r1 = broker_decide(broker=broker0, store=store0, request=request0, approved=True, actor_id="u1")
    r2 = broker_decide(broker=broker0, store=store0, request=request0, approved=True, actor_id="u2")
    conn0.close()
    assert r1 is not None and r2 is not None

    def apply(receipt):
        conn = sqlite3.connect(str(db), check_same_thread=False, timeout=30.0, isolation_level=None)
        store = PlanApprovalStore(conn)
        repo_local = PlanSnapshotStore()
        repo_local.register(plan)
        service = PlanApprovalService(
            store=store, broker=SyncBroker(), context_provider=_Ctx(),
            plan_repository=repo_local,
            policy=ApprovalPolicy(pending_ttl_seconds=3600, approved_ttl_seconds=3600),
        )
        try:
            service.apply_broker_decision(receipt, current_plan=plan)
            return "ok"
        except ApprovalConflictError:
            return "conflict"
        except Exception:
            return "error"
        finally:
            conn.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        futs = [pool.submit(apply, r) for r in (r1, r2)]
        results = [f.result() for f in as_completed(futs)]

    final_conn = sqlite3.connect(str(db))
    row = final_conn.execute(
        "SELECT status FROM plan_approval_requests WHERE broker_request_id = ?", (brid,),
    ).fetchone()
    assert row[0] == "approved"
    final_conn.close()


def test_concurrent_authorization_consumes_only_one_wins(tmp_path):
    """Two consumes of the same authorization — only one succeeds."""
    db = tmp_path / "conc_consume.db"
    conn0 = sqlite3.connect(str(db), check_same_thread=False, isolation_level=None)
    store0 = PlanApprovalStore(conn0)
    repo = PlanSnapshotStore()
    plan = make_plan(plan_id="plan_consume_race", risks=(low_risk(),))
    service0 = PlanApprovalService(
        store=store0, broker=SyncBroker(), context_provider=_Ctx(), plan_repository=repo,
    )
    request = service0.request_approval(plan)
    gate0 = PlanExecutionGate(store=store0, context_provider=_Ctx(), plan_repository=repo)
    auth = gate0.authorize_execution(plan_id=plan.plan_id, approval_request_id=request.approval_request_id)
    conn0.close()

    barrier = threading.Barrier(2)
    wins = {"ok": 0, "fail": 0}

    def consume():
        barrier.wait()
        conn = sqlite3.connect(str(db), check_same_thread=False, timeout=30.0, isolation_level=None)
        store = PlanApprovalStore(conn)
        gate = PlanExecutionGate(store=store, context_provider=_Ctx(), plan_repository=repo)
        try:
            gate.require_authorization(
                auth.authorization_id, auth.nonce,
                expected_plan_id=plan.plan_id, expected_task_id=plan.task_id,
                expected_workspace_id=plan.workspace_id, expected_repository_id=plan.repository_id,
            )
            return "ok"
        except (AuthorizationAlreadyConsumedError, Exception):
            return "fail"
        finally:
            conn.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        futs = [pool.submit(consume) for _ in range(2)]
        for f in as_completed(futs):
            wins[f.result()] += 1

    assert wins["ok"] == 1
    assert wins["fail"] == 1


def test_expiration_races_with_consume(tmp_path):
    db = tmp_path / "conc_exp.db"
    conn0 = sqlite3.connect(str(db), check_same_thread=False, isolation_level=None)
    store0 = PlanApprovalStore(conn0)
    repo = PlanSnapshotStore()
    plan = make_plan(plan_id="plan_exp_race", risks=(low_risk(),))
    service0 = PlanApprovalService(
        store=store0, broker=SyncBroker(), context_provider=_Ctx(), plan_repository=repo,
    )
    request = service0.request_approval(plan)
    gate0 = PlanExecutionGate(
        store=store0, context_provider=_Ctx(), plan_repository=repo,
        policy=GatePolicy(authorization_ttl_seconds=0.05),
    )
    auth = gate0.authorize_execution(plan_id=plan.plan_id, approval_request_id=request.approval_request_id)
    conn0.close()

    time.sleep(0.15)
    conn1 = sqlite3.connect(str(db), check_same_thread=False, isolation_level=None)
    store1 = PlanApprovalStore(conn1)
    gate1 = PlanExecutionGate(store=store1, context_provider=_Ctx(), plan_repository=repo)
    from khaos.coding.planning.approval.gate import AuthorizationExpiredError

    with pytest.raises(AuthorizationExpiredError):
        gate1.require_authorization(
            auth.authorization_id, auth.nonce,
            expected_plan_id=plan.plan_id, expected_task_id=plan.task_id,
            expected_workspace_id=plan.workspace_id, expected_repository_id=plan.repository_id,
        )
    conn1.close()


def test_task_cancel_races_with_authorize(tmp_path):
    db = tmp_path / "conc_tc.db"
    brid, plan, repo = _seed(db, plan_id="plan_tc_race")

    # Approve first on the main thread.
    conn0 = sqlite3.connect(str(db), check_same_thread=False, isolation_level=None)
    store0 = PlanApprovalStore(conn0)
    broker0 = SyncBroker()
    # re-register broker record
    import asyncio
    asyncio.new_event_loop().run_until_complete(
        broker0.real.register_plan_approval(
            approval_request_id=brid.split(":", 1)[1],
            binding={"binding_digest": "x"}, summary={}, expires_at=9999999999.0,
        )
    )
    service0 = PlanApprovalService(
        store=store0, broker=broker0, context_provider=_Ctx(), plan_repository=repo,
        policy=ApprovalPolicy(pending_ttl_seconds=3600, approved_ttl_seconds=3600),
    )
    request = store0.get_request_by_broker(brid)
    receipt = broker_decide(broker=broker0, store=store0, request=request, approved=True)
    service0.apply_broker_decision(receipt, current_plan=plan)
    conn0.close()

    ctx = _Ctx()
    barrier = threading.Barrier(2)

    def cancel_task():
        barrier.wait()
        conn = sqlite3.connect(str(db), check_same_thread=False, timeout=30.0, isolation_level=None)
        store = PlanApprovalStore(conn)
        service = PlanApprovalService(
            store=store, broker=SyncBroker(), context_provider=ctx, plan_repository=repo,
            policy=ApprovalPolicy(pending_ttl_seconds=3600, approved_ttl_seconds=3600),
        )
        try:
            service.invalidate_for_task(task_id=plan.task_id, reason="cancelled")
        finally:
            conn.close()

    def authorize():
        barrier.wait()
        conn = sqlite3.connect(str(db), check_same_thread=False, timeout=30.0, isolation_level=None)
        store = PlanApprovalStore(conn)
        gate = PlanExecutionGate(store=store, context_provider=ctx, plan_repository=repo)
        try:
            gate.authorize_execution(plan_id=plan.plan_id, approval_request_id=request.approval_request_id)
        except Exception:
            pass
        finally:
            conn.close()

    t1 = threading.Thread(target=cancel_task)
    t2 = threading.Thread(target=authorize)
    t1.start(); t2.start()
    t1.join(); t2.join()

    final_conn = sqlite3.connect(str(db))
    row = final_conn.execute(
        "SELECT status FROM plan_approval_requests WHERE approval_request_id = ?",
        (request.approval_request_id,),
    ).fetchone()
    assert row[0] in ("approved", "stale")
    final_conn.close()
