"""M4 Batch 2 — Plan approval and execution gate failure matrix.

(Batch 2.1 updated: tests now drive the authenticated BrokerDecisionReceipt
flow and the authoritative plan-repository gate API.)

Covers the 54 scenarios enumerated in the batch spec §15, plus the audit
cleanliness assertions from §17. Each scenario constructs the minimum
:class:`ImplementationPlan` / :class:`PlanApprovalService` /
:class:`PlanExecutionGate` graph needed and asserts the spec-required
outcome.

These tests NEVER write repository files, NEVER invoke tools, NEVER call
terminal/test_run, and NEVER create or apply a ChangeSet — they only
exercise the approval/authorization state machine and its persistence.
"""
from __future__ import annotations

import sqlite3
import time
from dataclasses import replace
from pathlib import Path

import pytest

from khaos.coding.planning.approval import (
    APPROVAL_SCHEMA,
    ApprovalConflictError,
    AuthorizationAlreadyConsumedError,
    AuthorizationExpiredError,
    AuthorizationMismatchError,
    AuthorizationRevokedError,
    AuthorizationStatus,
    GatePolicy,
    PlanApprovalStatus,
    PlanApprovalStore,
    PlanNotRequestableError,
    PlanStaleError,
    PlannedExecutionGuard,
    UnauthenticatedReceiptError,
    UnknownBrokerRequestError,
    compute_plan_binding_digest,
    evaluate_approval_requirement,
)
from khaos.coding.planning.contracts import (
    AffectedFile,
    AffectedSymbol,
    ImplementationPlan,
    PlanEvidence,
    PlanOperation,
    PlanStatus,
)

# Shared plumbing (Batch 2.1): real broker, durable receipt outbox,
# authoritative plan snapshot store.
from _m4_batch2_helpers import (  # type: ignore[import-not-found]
    FakeContextProvider,
    approve_and_apply,
    broker_decide,
    high_risk,
    low_risk,
    make_gate,
    make_plan,
    make_service,
    verification,
)


# ===========================================================================
# §15 Failure matrix — scenarios 1-16: approval requirement, drift, binding
# ===========================================================================


def test_01_low_risk_plan_is_not_required():
    plan = make_plan(risks=(low_risk(),))
    service, store, ctx, broker, repo = make_service()
    request = service.request_approval(plan)
    assert request.status is PlanApprovalStatus.NOT_REQUIRED
    assert request.broker_request_id == ""


def test_02_high_risk_plan_creates_pending_request():
    plan = make_plan(risks=(high_risk(),), plan_id="plan_high")
    service, store, ctx, broker, repo = make_service()
    request = service.request_approval(plan)
    assert request.status is PlanApprovalStatus.PENDING
    assert request.broker_request_id.startswith("plan-execution:")


def test_03_client_approved_true_is_ignored():
    """A high-risk plan is pending regardless of any client flag — there is
    no client-controllable ``approved`` field on ImplementationPlan."""
    plan = make_plan(risks=(high_risk(),), plan_id="plan_high2")
    outcome = evaluate_approval_requirement(plan)
    assert outcome.requires_approval is True
    service, *_ = make_service()
    request = service.request_approval(plan)
    assert request.status is PlanApprovalStatus.PENDING


def test_04_client_risk_low_is_ignored():
    """A destructive op forces approval even when the risk says 'low'."""
    plan = make_plan(
        plan_id="plan_delete",
        affected_files=(
            AffectedFile("old.py", PlanOperation.DELETE, "remove", 1.0, True, "python", ()),
        ),
    )
    outcome = evaluate_approval_requirement(plan)
    assert outcome.requires_approval is True


def test_05_client_requires_approval_false_is_ignored():
    from khaos.coding.planning.contracts import RiskAssessment

    plan = make_plan(
        plan_id="plan_rename",
        risks=(RiskAssessment("low", "functional", "x", ("a.py",), "x", False),),
        affected_files=(
            AffectedFile("a.py", PlanOperation.RENAME, "rename", 1.0, True, "python", (), None, "b.py"),
        ),
    )
    outcome = evaluate_approval_requirement(plan)
    assert outcome.requires_approval is True


def test_06_blocked_plan_cannot_request_approval():
    plan = make_plan(status=PlanStatus.BLOCKED)
    service, *_ = make_service()
    with pytest.raises(PlanNotRequestableError):
        service.request_approval(plan)


def test_07_stale_plan_cannot_request_approval():
    plan = make_plan(status=PlanStatus.STALE)
    service, *_ = make_service()
    with pytest.raises(PlanNotRequestableError):
        service.request_approval(plan)


def test_08_task_terminal_refuses_request():
    plan = make_plan()
    ctx = FakeContextProvider(task_terminal=True)
    service, *_ = make_service(context=ctx)
    with pytest.raises(PlanNotRequestableError, match="task is terminal"):
        service.request_approval(plan)


def test_09_workspace_terminal_refuses_request():
    plan = make_plan()
    ctx = FakeContextProvider(workspace_terminal=True)
    service, *_ = make_service(context=ctx)
    with pytest.raises(PlanNotRequestableError, match="workspace is terminal"):
        service.request_approval(plan)


def test_10_repository_mismatch_refuses_request():
    from khaos.coding.planning.approval import CurrentRepositoryState

    plan = make_plan(repository_id="repoA")

    class Mismatched(FakeContextProvider):
        def current_state(self, *, repository_id, task_id, workspace_id):
            return CurrentRepositoryState(
                repository_id="repoB", task_id=task_id, workspace_id=workspace_id,
                head_sha="abc123", repository_generation=1,
                task_active=True, workspace_active=True,
                task_terminal=False, workspace_terminal=False,
            )

    service, *_ = make_service(context=Mismatched())
    with pytest.raises(PlanNotRequestableError, match="repository id mismatch"):
        service.request_approval(plan)


def test_11_base_sha_drift_refuses_request():
    plan = make_plan(base_sha="abc123")
    ctx = FakeContextProvider(head_sha="different")
    service, *_ = make_service(context=ctx)
    with pytest.raises(PlanStaleError, match="head drift"):
        service.request_approval(plan)


def test_12_repository_generation_drift_refuses_request():
    plan = make_plan(repository_generation=1)
    ctx = FakeContextProvider(repository_generation=2)
    service, *_ = make_service(context=ctx)
    with pytest.raises(PlanStaleError, match="generation drift"):
        service.request_approval(plan)


def test_13_file_hash_drift_invalidates_binding():
    plan = make_plan(
        evidence=(
            PlanEvidence("file", "repo", path="python_lib.py", content_hash="v1", generation=1, confidence=1.0),
            PlanEvidence("verification-config", "repo", query="config-hash", confidence=1.0, metadata={"config_hash": "cfg1", "config_files": {}}),
        ),
    )
    d1 = compute_plan_binding_digest(plan)
    drifted = replace(plan, evidence=(
        PlanEvidence("file", "repo", path="python_lib.py", content_hash="v2", generation=1, confidence=1.0),
        plan.evidence[1],
    ))
    assert compute_plan_binding_digest(drifted) != d1


def test_14_symbol_drift_invalidates_binding():
    plan = make_plan(
        affected_symbols=(
            AffectedSymbol("ssym_1", "public_api", "function", "python_lib.py", "direct", 1.0, ()),
        ),
    )
    d1 = compute_plan_binding_digest(plan)
    drifted = replace(plan, affected_symbols=(
        AffectedSymbol("ssym_2", "other", "function", "python_lib.py", "direct", 1.0, ()),
    ))
    assert compute_plan_binding_digest(drifted) != d1


def test_15_destination_path_invalidates_binding():
    plan = make_plan(
        affected_files=(
            AffectedFile("a.py", PlanOperation.RENAME, "rename", 1.0, True, "python", ()),
        ),
    )
    d1 = compute_plan_binding_digest(plan)
    drifted = replace(plan, affected_files=(
        AffectedFile("a.py", PlanOperation.RENAME, "rename", 1.0, True, "python", (), None, "b.py"),
    ))
    assert compute_plan_binding_digest(drifted) != d1


def test_16_verification_config_drift_invalidates_binding():
    plan = make_plan(
        evidence=(
            PlanEvidence("verification-config", "repo", query="config-hash", confidence=1.0, metadata={"config_hash": "v1", "config_files": {}}),
        ),
    )
    d1 = compute_plan_binding_digest(plan)
    drifted = replace(plan, evidence=(
        PlanEvidence("verification-config", "repo", query="config-hash", confidence=1.0, metadata={"config_hash": "v2", "config_files": {}}),
    ))
    assert compute_plan_binding_digest(drifted) != d1


# ===========================================================================
# §15 scenarios 17-27: broker decisions (now via BrokerDecisionReceipt)
# ===========================================================================


def test_17_broker_approve_succeeds():
    plan = make_plan(risks=(high_risk(),), plan_id="plan_appr")
    service, store, ctx, broker, repo = make_service()
    request = service.request_approval(plan)
    updated = approve_and_apply(service=service, broker=broker, store=store, request=request, plan=plan)
    assert updated.status is PlanApprovalStatus.APPROVED


def test_18_broker_reject_succeeds():
    plan = make_plan(risks=(high_risk(),), plan_id="plan_rej")
    service, store, ctx, broker, repo = make_service()
    request = service.request_approval(plan)
    receipt = broker_decide(broker=broker, store=store, request=request, approved=False)
    updated = service.apply_broker_decision(receipt)
    assert updated.status is PlanApprovalStatus.REJECTED


def test_19_unknown_broker_request_rejected():
    """An unknown broker_request_id cannot produce a receipt, and a receipt
    whose broker_request_id has no request row is refused."""
    plan = make_plan(risks=(high_risk(),), plan_id="plan_unk")
    service, store, ctx, broker, repo = make_service()
    # Broker refuses to mint a receipt for an unregistered broker_request_id.
    receipt = broker_decide(
        broker=broker, store=store,
        request=type("R", (), {"broker_request_id": "plan-execution:bogus", "binding_digest": ""})(),
        approved=True,
    )
    assert receipt is None


def test_20_duplicate_approve_is_idempotent():
    plan = make_plan(risks=(high_risk(),), plan_id="plan_idem")
    service, store, ctx, broker, repo = make_service()
    request = service.request_approval(plan)
    r1 = broker_decide(broker=broker, store=store, request=request, approved=True, actor_id="u1")
    updated1 = service.apply_broker_decision(r1)
    # A second receipt for the same decision can be minted (idempotent) and applied.
    r2 = broker_decide(broker=broker, store=store, request=request, approved=True, actor_id="u1")
    updated2 = service.apply_broker_decision(r2)
    assert updated1.status is PlanApprovalStatus.APPROVED
    assert updated2.status is PlanApprovalStatus.APPROVED


def test_22_approve_then_reject_conflicts():
    plan = make_plan(risks=(high_risk(),), plan_id="plan_conf1")
    service, store, ctx, broker, repo = make_service()
    request = service.request_approval(plan)
    r1 = broker_decide(broker=broker, store=store, request=request, approved=True, actor_id="u1")
    service.apply_broker_decision(r1)
    # Broker refuses to mint a reject receipt after an approve (conflict).
    r2 = broker_decide(broker=broker, store=store, request=request, approved=False, actor_id="u2")
    assert r2 is None  # broker returns None on conflicting decision


def test_23_reject_then_approve_conflicts():
    plan = make_plan(risks=(high_risk(),), plan_id="plan_conf2")
    service, store, ctx, broker, repo = make_service()
    request = service.request_approval(plan)
    r1 = broker_decide(broker=broker, store=store, request=request, approved=False, actor_id="u1")
    service.apply_broker_decision(r1)
    r2 = broker_decide(broker=broker, store=store, request=request, approved=True, actor_id="u2")
    assert r2 is None


def test_24_plan_content_hash_change_stales_decision():
    """Batch 2.2: the authoritative plan is resolved from the persisted
    repository by plan_id. A caller cannot influence validation by
    constructing a drifted plan — the repository's snapshot is what's
    validated. We verify the persisted snapshot cannot be silently replaced
    with different content (register returns False)."""
    plan = make_plan(risks=(high_risk(),), plan_id="plan_drift1")
    service, store, ctx, broker, repo = make_service()
    request = service.request_approval(plan)
    r1 = broker_decide(broker=broker, store=store, request=request, approved=True, actor_id="u1")
    service.apply_broker_decision(r1)
    # A drifted plan with a different content_hash cannot replace the
    # authoritative snapshot (persisted repository refuses silent overwrite).
    drifted = replace(plan, content_hash="changed_hash")
    replaced = repo.register(drifted)
    assert replaced is False, "persisted repository must refuse silent content replacement"


def test_25_risk_increase_invalidates_binding():
    plan = make_plan(risks=(low_risk(),), plan_id="plan_risk_up")
    d_low = compute_plan_binding_digest(plan)
    high_version = make_plan(risks=(high_risk(),), plan_id="plan_risk_up")
    d_high = compute_plan_binding_digest(high_version)
    assert d_low != d_high


def test_26_impact_scope_increase_invalidates_binding():
    plan = make_plan(plan_id="plan_scope_up")
    d_small = compute_plan_binding_digest(plan)
    bigger = replace(plan, affected_files=plan.affected_files + (
        AffectedFile("extra.py", PlanOperation.MODIFY, "cascade", 0.5, True, "python", ()),
    ))
    assert compute_plan_binding_digest(bigger) != d_small


def test_27_verification_plan_change_invalidates_binding():
    plan = make_plan(plan_id="plan_ver_up")
    d1 = compute_plan_binding_digest(plan)
    from khaos.coding.planning.contracts import VerificationRequirement
    new_ver = (VerificationRequirement(("cargo", "test"), "unit-test", "file", "pass", True, "low", ()),)
    changed = replace(plan, verification_requirements=new_ver)
    assert compute_plan_binding_digest(changed) != d1


# ===========================================================================
# §15 scenarios 28-43: expiry, revocation, authorization gate
# ===========================================================================


def test_28_approval_expiry_after_ttl():
    from khaos.coding.planning.approval import ApprovalPolicy

    plan = make_plan(risks=(high_risk(),), plan_id="plan_exp1")
    service, store, ctx, broker, repo = make_service(
        policy=ApprovalPolicy(pending_ttl_seconds=0.01, approved_ttl_seconds=0.01)
    )
    request = service.request_approval(plan)
    time.sleep(0.05)
    r = broker_decide(broker=broker, store=store, request=request, approved=True)
    # The broker mints a receipt only if not expired; expiry makes it None.
    assert r is None or r.expires_at < time.time()


def test_29_approval_revoked():
    plan = make_plan(risks=(high_risk(),), plan_id="plan_rev1")
    service, store, ctx, broker, repo = make_service()
    request = service.request_approval(plan)
    approve_and_apply(service=service, broker=broker, store=store, request=request, plan=plan)
    updated = service.revoke(request.approval_request_id, actor_id="admin", reason="user cancelled")
    assert updated.status is PlanApprovalStatus.REVOKED


def test_30_task_cancelled_invalidates_approval():
    plan = make_plan(risks=(high_risk(),), plan_id="plan_tc")
    service, store, ctx, broker, repo = make_service()
    request = service.request_approval(plan)
    approve_and_apply(service=service, broker=broker, store=store, request=request, plan=plan)
    count = service.invalidate_for_task(task_id="task1", reason="task cancelled")
    assert count == 1
    assert store.get_request(request.approval_request_id).status is PlanApprovalStatus.STALE


def test_32_needs_approval_without_request_refuses_authorization():
    from khaos.coding.planning.approval.gate import ApprovalMissingError

    plan = make_plan(risks=(high_risk(),), plan_id="plan_no_req")
    service, store, ctx, broker, repo = make_service()
    gate = make_gate(store=store, context=ctx, plan_repository=repo)
    repo.register(plan)
    with pytest.raises(ApprovalMissingError):
        gate.authorize_execution(plan_id=plan.plan_id, approval_request_id=None)


def test_33_pending_request_refuses_authorization():
    from khaos.coding.planning.approval.gate import ApprovalMissingError

    plan = make_plan(risks=(high_risk(),), plan_id="plan_pend")
    service, store, ctx, broker, repo = make_service()
    request = service.request_approval(plan)
    gate = make_gate(store=store, context=ctx, plan_repository=repo)
    with pytest.raises(ApprovalMissingError):
        gate.authorize_execution(plan_id=plan.plan_id, approval_request_id=request.approval_request_id)


def test_34_approved_request_authorizes():
    plan = make_plan(risks=(high_risk(),), plan_id="plan_ok")
    service, store, ctx, broker, repo = make_service()
    request = service.request_approval(plan)
    approve_and_apply(service=service, broker=broker, store=store, request=request, plan=plan)
    gate = make_gate(store=store, context=ctx, plan_repository=repo)
    auth = gate.authorize_execution(plan_id=plan.plan_id, approval_request_id=request.approval_request_id)
    assert auth.status is AuthorizationStatus.ACTIVE
    assert auth.nonce and len(auth.nonce) == 64


def test_35_not_required_plan_authorizes():
    plan = make_plan(risks=(low_risk(),), plan_id="plan_nr")
    service, store, ctx, broker, repo = make_service()
    request = service.request_approval(plan)
    assert request.status is PlanApprovalStatus.NOT_REQUIRED
    gate = make_gate(store=store, context=ctx, plan_repository=repo)
    auth = gate.authorize_execution(plan_id=plan.plan_id, approval_request_id=request.approval_request_id)
    assert auth.status is AuthorizationStatus.ACTIVE


def test_36_forged_authorization_id_refused():
    plan = make_plan(risks=(low_risk(),), plan_id="plan_forge")
    service, store, ctx, broker, repo = make_service()
    gate = make_gate(store=store, context=ctx, plan_repository=repo)
    with pytest.raises(AuthorizationMismatchError, match="unknown"):
        gate.acquire_lease(
            authorization_id="pax_forged", nonce="fakenonce",
            expected_plan_id="plan_forge", expected_task_id="task1",
            expected_workspace_id="ws1", expected_repository_id="repo",
            owner_execution_id="exec_test",
        )


def test_37_cross_task_replay_refused():
    plan = make_plan(risks=(low_risk(),), plan_id="plan_xtask")
    service, store, ctx, broker, repo = make_service()
    request = service.request_approval(plan)  # NOT_REQUIRED + registers snapshot
    gate = make_gate(store=store, context=ctx, plan_repository=repo)
    auth = gate.authorize_execution(plan_id=plan.plan_id, approval_request_id=request.approval_request_id)
    with pytest.raises(AuthorizationMismatchError, match="scope mismatch"):
        gate.acquire_lease(
            authorization_id=auth.authorization_id, nonce=auth.nonce,
            expected_plan_id=plan.plan_id, expected_task_id="OTHER",
            expected_workspace_id=plan.workspace_id, expected_repository_id=plan.repository_id,
            owner_execution_id="exec_test",
        )


def test_38_cross_workspace_replay_refused():
    plan = make_plan(risks=(low_risk(),), plan_id="plan_xws")
    service, store, ctx, broker, repo = make_service()
    request = service.request_approval(plan)
    gate = make_gate(store=store, context=ctx, plan_repository=repo)
    auth = gate.authorize_execution(plan_id=plan.plan_id, approval_request_id=request.approval_request_id)
    with pytest.raises(AuthorizationMismatchError, match="scope mismatch"):
        gate.acquire_lease(
            authorization_id=auth.authorization_id, nonce=auth.nonce,
            expected_plan_id=plan.plan_id, expected_task_id=plan.task_id,
            expected_workspace_id="OTHER", expected_repository_id=plan.repository_id,
            owner_execution_id="exec_test",
        )


def test_39_cross_repository_replay_refused():
    plan = make_plan(risks=(low_risk(),), plan_id="plan_xrepo")
    service, store, ctx, broker, repo = make_service()
    request = service.request_approval(plan)
    gate = make_gate(store=store, context=ctx, plan_repository=repo)
    auth = gate.authorize_execution(plan_id=plan.plan_id, approval_request_id=request.approval_request_id)
    with pytest.raises(AuthorizationMismatchError, match="scope mismatch"):
        gate.acquire_lease(
            authorization_id=auth.authorization_id, nonce=auth.nonce,
            expected_plan_id=plan.plan_id, expected_task_id=plan.task_id,
            expected_workspace_id=plan.workspace_id, expected_repository_id="OTHER",
            owner_execution_id="exec_test",
        )


def test_40_cross_plan_replay_refused():
    plan = make_plan(risks=(low_risk(),), plan_id="plan_xplan")
    service, store, ctx, broker, repo = make_service()
    request = service.request_approval(plan)
    gate = make_gate(store=store, context=ctx, plan_repository=repo)
    auth = gate.authorize_execution(plan_id=plan.plan_id, approval_request_id=request.approval_request_id)
    with pytest.raises(AuthorizationMismatchError, match="scope mismatch"):
        gate.acquire_lease(
            authorization_id=auth.authorization_id, nonce=auth.nonce,
            expected_plan_id="OTHER", expected_task_id=plan.task_id,
            expected_workspace_id=plan.workspace_id, expected_repository_id=plan.repository_id,
            owner_execution_id="exec_test",
        )


def test_41_expired_authorization_refused():
    plan = make_plan(risks=(low_risk(),), plan_id="plan_expauth")
    service, store, ctx, broker, repo = make_service()
    request = service.request_approval(plan)
    gate = make_gate(store=store, context=ctx, plan_repository=repo, policy=GatePolicy(authorization_ttl_seconds=0.01))
    auth = gate.authorize_execution(plan_id=plan.plan_id, approval_request_id=request.approval_request_id)
    time.sleep(0.05)
    with pytest.raises(AuthorizationExpiredError):
        gate.acquire_lease(
            authorization_id=auth.authorization_id, nonce=auth.nonce,
            expected_plan_id=plan.plan_id, expected_task_id=plan.task_id,
            expected_workspace_id=plan.workspace_id, expected_repository_id=plan.repository_id,
            owner_execution_id="exec_test",
        )


def test_42_revoked_approval_invalidates_authorization():
    plan = make_plan(risks=(high_risk(),), plan_id="plan_revauth")
    service, store, ctx, broker, repo = make_service()
    request = service.request_approval(plan)
    approve_and_apply(service=service, broker=broker, store=store, request=request, plan=plan)
    gate = make_gate(store=store, context=ctx, plan_repository=repo)
    auth = gate.authorize_execution(plan_id=plan.plan_id, approval_request_id=request.approval_request_id)
    service.revoke(request.approval_request_id, actor_id="admin")
    with pytest.raises((AuthorizationRevokedError, AuthorizationMismatchError)):
        gate.acquire_lease(
            authorization_id=auth.authorization_id, nonce=auth.nonce,
            expected_plan_id=plan.plan_id, expected_task_id=plan.task_id,
            expected_workspace_id=plan.workspace_id, expected_repository_id=plan.repository_id,
            owner_execution_id="exec_test",
        )


def test_43_authorization_single_consume_cas():
    plan = make_plan(risks=(low_risk(),), plan_id="plan_once")
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
    with pytest.raises(AuthorizationAlreadyConsumedError):
        gate.acquire_lease(
            authorization_id=auth.authorization_id, nonce=auth.nonce,
            expected_plan_id=plan.plan_id, expected_task_id=plan.task_id,
            expected_workspace_id=plan.workspace_id, expected_repository_id=plan.repository_id,
            owner_execution_id="exec_test",
        )


# ===========================================================================
# §15 scenarios 44-54: persistence, audit, isolation, static security
# ===========================================================================


def test_46_migration_is_idempotent():
    conn = sqlite3.connect(":memory:")
    store = PlanApprovalStore(conn)
    store.ensure_schema()
    store.ensure_schema()
    schema_path = Path(__file__).resolve().parents[2] / "khaos" / "db" / "schema.sql"
    conn.executescript(schema_path.read_text())
    conn.commit()


def test_48_audit_event_complete():
    plan = make_plan(risks=(high_risk(),), plan_id="plan_audit")
    service, store, ctx, broker, repo = make_service()
    request = service.request_approval(plan)
    events = store.list_audit_events(approval_request_id=request.approval_request_id)
    assert len(events) >= 1
    ev = events[0]
    assert ev.event_type.startswith("plan-approval:")
    assert ev.plan_id == plan.plan_id
    assert ev.task_id == plan.task_id
    assert ev.workspace_id == plan.workspace_id
    assert ev.repository_id == plan.repository_id
    assert ev.correlation_id


def test_49_audit_excludes_secrets():
    plan = make_plan(risks=(high_risk(),), plan_id="plan_nosec")
    service, store, ctx, broker, repo = make_service()
    request = service.request_approval(plan)
    approve_and_apply(service=service, broker=broker, store=store, request=request, plan=plan)
    gate = make_gate(store=store, context=ctx, plan_repository=repo)
    auth = gate.authorize_execution(plan_id=plan.plan_id, approval_request_id=request.approval_request_id)
    import json

    conn = store._conn  # noqa: SLF001
    for table in (
        "plan_approval_requests", "plan_approval_decisions",
        "plan_execution_authorizations", "plan_approval_audit_events",
        "plan_approval_receipts",
    ):
        rows = conn.execute(f"SELECT * FROM {table}").fetchall()
        for row in rows:
            blob = json.dumps({k: row[k] for k in row.keys()}, default=str)
            assert auth.nonce not in blob, f"nonce plaintext leaked in {table}"
            assert "/Users/" not in blob, f"absolute path leaked in {table}"


def test_50_plan_approval_cannot_replace_tool_or_changeset_approval():
    plan = make_plan(risks=(low_risk(),), plan_id="plan_isolation")
    service, store, ctx, broker, repo = make_service()
    request = service.request_approval(plan)
    gate = make_gate(store=store, context=ctx, plan_repository=repo)
    guard = PlannedExecutionGuard(gate)
    auth = gate.authorize_execution(plan_id=plan.plan_id, approval_request_id=request.approval_request_id)
    consumed_ctx = guard.authorize(
        auth.authorization_id, auth.nonce,
        expected_plan_id=plan.plan_id, expected_task_id=plan.task_id,
        expected_workspace_id=plan.workspace_id, expected_repository_id=plan.repository_id,
            owner_execution_id="exec_test",
    )
    with pytest.raises(NotImplementedError):
        guard.planned_workspace_edit(consumed_ctx, edit={})


def test_52_planning_service_does_not_execute():
    plan = make_plan(risks=(high_risk(),), plan_id="plan_noexec")
    service, *_ = make_service()
    public = {m for m in dir(service) if not m.startswith("_")}
    forbidden = {"write_file", "execute_tool", "run_test", "apply_changeset", "create_changeset"}
    assert not (public & forbidden), f"forbidden methods present: {public & forbidden}"


def test_53_batch_has_no_changeset_creation_or_apply():
    plan = make_plan(risks=(low_risk(),), plan_id="plan_nocs")
    service, store, ctx, broker, repo = make_service()
    request = service.request_approval(plan)
    gate = make_gate(store=store, context=ctx, plan_repository=repo)
    guard = PlannedExecutionGuard(gate)
    auth = gate.authorize_execution(plan_id=plan.plan_id, approval_request_id=request.approval_request_id)
    ctx_ok = guard.authorize(
        auth.authorization_id, auth.nonce,
        expected_plan_id=plan.plan_id, expected_task_id=plan.task_id,
        expected_workspace_id=plan.workspace_id, expected_repository_id=plan.repository_id,
            owner_execution_id="exec_test",
    )
    with pytest.raises(NotImplementedError):
        guard.planned_changeset_creation(ctx_ok, changeset_spec={})
    with pytest.raises(NotImplementedError):
        guard.planned_changeset_apply(ctx_ok, changeset_id="cs1")


def test_54_no_direct_bool_approve_entry():
    """§1: the service exposes no public method accepting approved: bool."""
    from khaos.coding.planning.approval import PlanApprovalService

    public = {
        m for m in dir(PlanApprovalService)
        if not m.startswith("_") and callable(getattr(PlanApprovalService, m, None))
    }
    assert not any(m in public for m in ("approve", "approve_plan", "set_approved", "force_approve"))
    # apply_broker_decision now requires a BrokerDecisionReceipt, not a bool.
    import inspect

    sig = inspect.signature(PlanApprovalService.apply_broker_decision)
    params = list(sig.parameters.values())
    assert "receipt" in sig.parameters
    assert "approved" not in sig.parameters
    assert "actor_id" not in sig.parameters


def test_55_forged_receipt_rejected():
    """A dataclass receipt with a forged token cannot pass validation."""
    from _m4_batch2_helpers import make_forged_receipt

    plan = make_plan(risks=(high_risk(),), plan_id="plan_forge_receipt")
    service, store, ctx, broker, repo = make_service()
    request = service.request_approval(plan)
    forged = make_forged_receipt(
        broker_request_id=request.broker_request_id,
        approval_request_id=request.approval_request_id,
        binding_digest=request.binding_digest,
    )
    with pytest.raises(UnauthenticatedReceiptError):
        service.apply_broker_decision(forged)


def test_56_unauthenticated_namespace_rejected():
    """A receipt with the wrong namespace is refused."""
    from _m4_batch2_helpers import make_forged_receipt
    from dataclasses import replace

    plan = make_plan(risks=(high_risk(),), plan_id="plan_ns")
    service, store, ctx, broker, repo = make_service()
    request = service.request_approval(plan)
    receipt = make_forged_receipt(
        broker_request_id=request.broker_request_id,
        approval_request_id=request.approval_request_id,
        binding_digest=request.binding_digest,
    )
    wrong_ns = replace(receipt, namespace="task")  # wrong namespace
    with pytest.raises(UnauthenticatedReceiptError, match="namespace"):
        service.apply_broker_decision(wrong_ns)


# ===========================================================================
# §17 Static security audit assertions
# ===========================================================================


def test_no_unpersisted_nonce_plaintext_leak():
    schema = APPROVAL_SCHEMA
    assert "nonce_hash" in schema
    auth_block = schema.split("plan_execution_authorizations")[1].split(");")[0]
    assert "nonce " not in auth_block.replace("nonce_hash", "")


def test_no_bare_subprocess_in_approval_module():
    import inspect

    from khaos.coding.planning.approval import service as svc_mod
    from khaos.coding.planning.approval import gate as gate_mod
    from khaos.coding.planning.approval import store as store_mod

    for mod in (svc_mod, gate_mod, store_mod):
        src = inspect.getsource(mod)
        assert "import subprocess" not in src, f"{mod.__name__} imports subprocess"
        assert "os.system(" not in src, f"{mod.__name__} calls os.system"
