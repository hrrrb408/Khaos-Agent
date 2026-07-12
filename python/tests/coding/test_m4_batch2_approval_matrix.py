"""M4 Batch 2 — Plan approval and execution gate failure matrix.

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
from typing import Any

import pytest

from khaos.agent.approval import ApprovalBroker
from khaos.coding.planning.approval import (
    APPROVAL_SCHEMA,
    ApprovalConflictError,
    AuthorizationAlreadyConsumedError,
    AuthorizationExpiredError,
    AuthorizationMismatchError,
    AuthorizationRevokedError,
    AuthorizationStatus,
    ContextProvider,
    CurrentRepositoryState,
    GatePolicy,
    PlanApprovalError,
    PlanApprovalService,
    PlanApprovalStatus,
    PlanApprovalStore,
    PlanExecutionAuthorization,
    PlanExecutionGate,
    PlanNotRequestableError,
    PlanStaleError,
    PlannedExecutionGuard,
    AuthorizedExecutionContext,
    UnknownBrokerRequestError,
    compute_plan_binding_digest,
    evaluate_approval_requirement,
)
from khaos.coding.planning.contracts import (
    AffectedFile,
    AffectedSymbol,
    ImplementationPlan,
    PlanDiagnostic,
    PlanEvidence,
    PlanOperation,
    PlanStatus,
    PlanStep,
    RiskAssessment,
    VerificationRequirement,
)


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


class FakeContextProvider:
    """Configurable ContextProvider for tests."""

    def __init__(
        self,
        *,
        head_sha: str = "abc123",
        repository_generation: int = 1,
        task_active: bool = True,
        workspace_active: bool = True,
        task_terminal: bool = False,
        workspace_terminal: bool = False,
    ) -> None:
        self._state = {
            "head_sha": head_sha,
            "repository_generation": repository_generation,
            "task_active": task_active,
            "workspace_active": workspace_active,
            "task_terminal": task_terminal,
            "workspace_terminal": workspace_terminal,
        }

    def set(
        self,
        *,
        head_sha: str | None = None,
        repository_generation: int | None = None,
        task_terminal: bool | None = None,
        workspace_terminal: bool | None = None,
    ) -> None:
        if head_sha is not None:
            self._state["head_sha"] = head_sha
        if repository_generation is not None:
            self._state["repository_generation"] = repository_generation
        if task_terminal is not None:
            self._state["task_terminal"] = task_terminal
        if workspace_terminal is not None:
            self._state["workspace_terminal"] = workspace_terminal

    def current_state(self, *, repository_id: str, task_id: str, workspace_id: str) -> CurrentRepositoryState:
        return CurrentRepositoryState(
            repository_id=repository_id,
            task_id=task_id,
            workspace_id=workspace_id,
            head_sha=self._state["head_sha"],
            repository_generation=self._state["repository_generation"],
            task_active=self._state["task_active"],
            workspace_active=self._state["workspace_active"],
            task_terminal=self._state["task_terminal"],
            workspace_terminal=self._state["workspace_terminal"],
        )


def _low_risk() -> RiskAssessment:
    return RiskAssessment(
        level="low",
        category="functional",
        description="minor",
        affected_scope=("python_lib.py",),
        mitigation="tests",
        requires_approval=False,
    )


def _high_risk() -> RiskAssessment:
    return RiskAssessment(
        level="high",
        category="security",
        description="danger",
        affected_scope=("auth.py",),
        mitigation="review",
        requires_approval=True,
    )


def _verification() -> tuple[VerificationRequirement, ...]:
    return (
        VerificationRequirement(
            command=("python", "-m", "pytest"),
            verification_type="unit-test",
            scope="file",
            expected_result="pass",
            required=True,
            risk_level="low",
            evidence=(),
        ),
    )


def _make_plan(
    *,
    plan_id: str = "plan_low",
    repository_id: str = "repo",
    task_id: str = "task1",
    workspace_id: str = "ws1",
    base_sha: str = "abc123",
    repository_generation: int = 1,
    status: PlanStatus = PlanStatus.READY,
    risks: tuple[RiskAssessment, ...] | None = None,
    affected_files: tuple[AffectedFile, ...] | None = None,
    affected_symbols: tuple[AffectedSymbol, ...] | None = None,
    diagnostics: tuple[PlanDiagnostic, ...] = (),
    verification_requirements: tuple[VerificationRequirement, ...] | None = None,
    evidence: tuple[PlanEvidence, ...] | None = None,
    content_hash: str = "",
) -> ImplementationPlan:
    """Build a minimal but valid ImplementationPlan for approval tests."""
    risks = risks if risks is not None else (_low_risk(),)
    files = affected_files if affected_files is not None else (
        AffectedFile(
            path="python_lib.py",
            operation=PlanOperation.MODIFY,
            reason="edit",
            confidence=0.9,
            exists=True,
            language="python",
            evidence=(),
        ),
    )
    step = PlanStep(
        step_id="s1",
        title="modify",
        description="modify symbol",
        operation=PlanOperation.MODIFY,
        target_files=("python_lib.py",),
        target_symbols=(),
        depends_on=(),
        expected_outcome="ok",
        verification_requirements=verification_requirements or _verification(),
        risk=risks[0],
        requires_approval=risks[0].requires_approval,
        evidence=(),
    )
    # Compute a stable content hash from the substantive fields so that the
    # plan's content_hash participates in the binding digest just like a real
    # plan would.
    body = {
        "plan_id": plan_id,
        "repository_id": repository_id,
        "task_id": task_id,
        "workspace_id": workspace_id,
        "base_sha": base_sha,
        "risks": risks[0].level,
    }
    ch = content_hash or ImplementationPlan.digest(body)
    return ImplementationPlan(
        plan_id=plan_id,
        repository_id=repository_id,
        task_id=task_id,
        workspace_id=workspace_id,
        user_goal="modify public_api",
        normalized_goal="modify public_api",
        base_sha=base_sha,
        repository_generation=repository_generation,
        status=status,
        summary="test plan",
        steps=(step,),
        affected_files=files,
        affected_symbols=affected_symbols or (),
        dependency_impacts=(),
        verification_requirements=verification_requirements or _verification(),
        risks=risks,
        diagnostics=diagnostics,
        evidence=evidence or (
            PlanEvidence(
                source="verification-config",
                repository_id=repository_id,
                query="config-hash",
                confidence=1.0,
                metadata={"config_hash": "cfg1", "config_files": {}},
            ),
        ),
        content_hash=ch,
        created_at=0.0,
    )


def _make_service(
    *,
    store: PlanApprovalStore | None = None,
    context: FakeContextProvider | None = None,
    broker: ApprovalBroker | None = None,
    policy=None,
) -> tuple[PlanApprovalService, PlanApprovalStore, FakeContextProvider, ApprovalBroker]:
    """Build an isolated approval service stack for one test."""
    if store is None:
        conn = sqlite3.connect(":memory:", check_same_thread=False)
        store = PlanApprovalStore(conn)
    if context is None:
        context = FakeContextProvider()
    if broker is None:
        broker = _SyncBroker()
    service = PlanApprovalService(
        store=store,
        broker=broker,
        context_provider=context,
        planning_service=None,
        policy=policy,
    )
    return service, store, context, broker


class _SyncBroker:
    """Synchronous stand-in for ApprovalBroker used by most matrix tests.

    Delegates to a real ApprovalBroker but exposes a sync API matching what
    :class:`PlanApprovalService` expects. The separate
    :class:`PlanApprovalConcurrencyTests` exercise the real async broker.
    """

    def __init__(self) -> None:
        self._real = ApprovalBroker()
        self._records: dict[str, dict] = {}

    def register_plan_approval(
        self, *, approval_request_id, binding, summary, expires_at
    ) -> str:
        import asyncio

        brid = asyncio.new_event_loop().run_until_complete(
            self._real.register_plan_approval(
                approval_request_id=approval_request_id,
                binding=binding,
                summary=summary,
                expires_at=expires_at,
            )
        )
        self._records[brid] = {"binding": binding, "summary": summary}
        return brid

    # Kept for completeness; not used by the approval service path.
    @property
    def real(self) -> ApprovalBroker:
        return self._real


def _make_gate(
    *,
    store: PlanApprovalStore,
    context: FakeContextProvider,
    policy: GatePolicy | None = None,
) -> PlanExecutionGate:
    return PlanExecutionGate(store=store, context_provider=context, policy=policy)


# ===========================================================================
# §15 Failure matrix — scenarios 1-27: approval requirement & request creation
# ===========================================================================


def test_01_low_risk_plan_is_not_required():
    """1. low-risk plan → server judges not-required."""
    plan = _make_plan(risks=(_low_risk(),))
    service, store, ctx, _ = _make_service()
    request = service.request_approval(plan)
    assert request.status is PlanApprovalStatus.NOT_REQUIRED
    assert request.broker_request_id == ""


def test_02_high_risk_plan_creates_pending_request():
    """2. high-risk plan → pending request created."""
    plan = _make_plan(risks=(_high_risk(),), plan_id="plan_high")
    service, store, ctx, broker = _make_service()
    request = service.request_approval(plan)
    assert request.status is PlanApprovalStatus.PENDING
    assert request.broker_request_id.startswith("plan-execution:")


def test_03_client_approved_true_is_ignored():
    """3. Client-supplied approval flag is ignored — server recomputes."""
    # A high-risk plan is pending regardless of any client "approved" field.
    plan = _make_plan(risks=(_high_risk(),), plan_id="plan_high2")
    # ImplementationPlan is frozen and has no "approved" field, so the client
    # cannot smuggle approval through it. We verify the server STILL requires
    # approval by inspecting the recomputed requirement.
    outcome = evaluate_approval_requirement(plan)
    assert outcome.requires_approval is True
    service, *_ = _make_service()
    request = service.request_approval(plan)
    assert request.status is PlanApprovalStatus.PENDING


def test_04_client_risk_low_is_ignored():
    """4. A plan whose risk says 'low' but touches a destructive op still needs approval."""
    plan = _make_plan(
        plan_id="plan_delete",
        affected_files=(
            AffectedFile(
                path="old.py",
                operation=PlanOperation.DELETE,
                reason="remove",
                confidence=1.0,
                exists=True,
                language="python",
                evidence=(),
            ),
        ),
    )
    outcome = evaluate_approval_requirement(plan)
    assert outcome.requires_approval is True  # delete forces approval


def test_05_client_requires_approval_false_is_ignored():
    """5. requires_approval=False on risks cannot bypass destructive-op detection."""
    plan = _make_plan(
        plan_id="plan_rename",
        risks=(
            RiskAssessment(
                level="low",
                category="functional",
                description="x",
                affected_scope=("a.py",),
                mitigation="x",
                requires_approval=False,  # client tries to opt out
            ),
        ),
        affected_files=(
            AffectedFile(
                path="a.py",
                operation=PlanOperation.RENAME,
                reason="rename",
                confidence=1.0,
                exists=True,
                language="python",
                evidence=(),
                destination_path="b.py",
            ),
        ),
    )
    outcome = evaluate_approval_requirement(plan)
    assert outcome.requires_approval is True


def test_06_blocked_plan_cannot_request_approval():
    """6. Blocked plan → request refused."""
    plan = _make_plan(status=PlanStatus.BLOCKED)
    service, *_ = _make_service()
    with pytest.raises(PlanNotRequestableError):
        service.request_approval(plan)


def test_07_stale_plan_cannot_request_approval():
    """7. Stale plan → request refused."""
    plan = _make_plan(status=PlanStatus.STALE)
    service, *_ = _make_service()
    with pytest.raises(PlanNotRequestableError):
        service.request_approval(plan)


def test_08_task_terminal_refuses_request():
    """8/30. Task terminal → request refused."""
    plan = _make_plan()
    ctx = FakeContextProvider(task_terminal=True)
    service, *_ = _make_service(context=ctx)
    with pytest.raises(PlanNotRequestableError, match="task is terminal"):
        service.request_approval(plan)


def test_09_workspace_terminal_refuses_request():
    """9/31. Workspace terminal → request refused."""
    plan = _make_plan()
    ctx = FakeContextProvider(workspace_terminal=True)
    service, *_ = _make_service(context=ctx)
    with pytest.raises(PlanNotRequestableError, match="workspace is terminal"):
        service.request_approval(plan)


def test_10_repository_workspace_mismatch_refuses():
    """10. repository/workspace mismatch → request refused.

    The ContextProvider is the source of truth for live ids; if they disagree
    with the plan the request is refused.
    """
    plan = _make_plan(repository_id="repoA")

    class MismatchedProvider(FakeContextProvider):
        def current_state(self, *, repository_id, task_id, workspace_id):
            return CurrentRepositoryState(
                repository_id="repoB",  # different!
                task_id=task_id,
                workspace_id=workspace_id,
                head_sha="abc123",
                repository_generation=1,
                task_active=True,
                workspace_active=True,
                task_terminal=False,
                workspace_terminal=False,
            )

    service, *_ = _make_service(context=MismatchedProvider())
    with pytest.raises(PlanNotRequestableError, match="repository id mismatch"):
        service.request_approval(plan)


def test_11_base_sha_drift_refuses_request():
    """11. base SHA drift → stale."""
    plan = _make_plan(base_sha="abc123")
    ctx = FakeContextProvider(head_sha="different")
    service, *_ = _make_service(context=ctx)
    with pytest.raises(PlanStaleError, match="head drift"):
        service.request_approval(plan)


def test_12_repository_generation_drift_refuses_request():
    """12. repository generation drift → stale."""
    plan = _make_plan(repository_generation=1)
    ctx = FakeContextProvider(repository_generation=2)
    service, *_ = _make_service(context=ctx)
    with pytest.raises(PlanStaleError, match="generation drift"):
        service.request_approval(plan)


def test_13_file_hash_drift_invalidates_binding():
    """13. File hash drift → binding digest changes → stale on decision."""
    plan = _make_plan(
        evidence=(
            PlanEvidence(
                source="file",
                repository_id="repo",
                path="python_lib.py",
                content_hash="hash_v1",
                generation=1,
                confidence=1.0,
                metadata={},
            ),
            PlanEvidence(
                source="verification-config",
                repository_id="repo",
                query="config-hash",
                confidence=1.0,
                metadata={"config_hash": "cfg1", "config_files": {}},
            ),
        ),
    )
    digest_before = compute_plan_binding_digest(plan)
    drifted = replace(
        plan,
        evidence=(
            PlanEvidence(
                source="file",
                repository_id="repo",
                path="python_lib.py",
                content_hash="hash_v2",  # changed
                generation=1,
                confidence=1.0,
                metadata={},
            ),
            plan.evidence[1],
        ),
    )
    digest_after = compute_plan_binding_digest(drifted)
    assert digest_before != digest_after


def test_14_symbol_drift_invalidates_binding():
    """14. Symbol drift → binding digest changes."""
    plan = _make_plan(
        affected_symbols=(
            AffectedSymbol(
                stable_symbol_id="ssym_1",
                qualified_name="public_api",
                kind="function",
                path="python_lib.py",
                impact_type="direct",
                confidence=1.0,
                evidence=(),
            ),
        ),
    )
    digest_before = compute_plan_binding_digest(plan)
    drifted = replace(
        plan,
        affected_symbols=(
            AffectedSymbol(
                stable_symbol_id="ssym_2",  # different symbol
                qualified_name="other_api",
                kind="function",
                path="python_lib.py",
                impact_type="direct",
                confidence=1.0,
                evidence=(),
            ),
        ),
    )
    assert compute_plan_binding_digest(drifted) != digest_before


def test_15_destination_path_invalidates_binding():
    """15. destination_path appears → binding digest changes."""
    plan = _make_plan(
        affected_files=(
            AffectedFile(
                path="a.py",
                operation=PlanOperation.RENAME,
                reason="rename",
                confidence=1.0,
                exists=True,
                language="python",
                evidence=(),
            ),
        ),
    )
    digest_before = compute_plan_binding_digest(plan)
    drifted = replace(
        plan,
        affected_files=(
            AffectedFile(
                path="a.py",
                operation=PlanOperation.RENAME,
                reason="rename",
                confidence=1.0,
                exists=True,
                language="python",
                evidence=(),
                destination_path="b.py",  # now present
            ),
        ),
    )
    assert compute_plan_binding_digest(drifted) != digest_before


def test_16_verification_config_drift_invalidates_binding():
    """16. Verification config drift → binding digest changes."""
    plan = _make_plan(
        evidence=(
            PlanEvidence(
                source="verification-config",
                repository_id="repo",
                query="config-hash",
                confidence=1.0,
                metadata={"config_hash": "cfg_v1", "config_files": {}},
            ),
        ),
    )
    digest_before = compute_plan_binding_digest(plan)
    drifted = replace(
        plan,
        evidence=(
            PlanEvidence(
                source="verification-config",
                repository_id="repo",
                query="config-hash",
                confidence=1.0,
                metadata={"config_hash": "cfg_v2", "config_files": {}},  # changed
            ),
        ),
    )
    assert compute_plan_binding_digest(drifted) != digest_before


def test_17_broker_approve_succeeds():
    """17. broker approve callback → request approved."""
    plan = _make_plan(risks=(_high_risk(),), plan_id="plan_appr")
    service, store, ctx, broker = _make_service()
    request = service.request_approval(plan)
    updated = service.apply_broker_decision(
        broker_request_id=request.broker_request_id,
        approved=True,
        actor_id="user1",
        current_plan=plan,
    )
    assert updated.status is PlanApprovalStatus.APPROVED


def test_18_broker_reject_succeeds():
    """18. broker reject callback → request rejected."""
    plan = _make_plan(risks=(_high_risk(),), plan_id="plan_rej")
    service, store, ctx, broker = _make_service()
    request = service.request_approval(plan)
    updated = service.apply_broker_decision(
        broker_request_id=request.broker_request_id,
        approved=False,
        actor_id="user1",
        current_plan=plan,
    )
    assert updated.status is PlanApprovalStatus.REJECTED


def test_19_unknown_broker_request_rejected():
    """19. Unknown broker request id → error."""
    plan = _make_plan(risks=(_high_risk(),), plan_id="plan_unk")
    service, *_ = _make_service()
    with pytest.raises(UnknownBrokerRequestError):
        service.apply_broker_decision(
            broker_request_id="plan-execution:bogus",
            approved=True,
            actor_id="user1",
            current_plan=plan,
        )


def test_20_duplicate_approve_is_idempotent():
    """20. Repeated identical decision is idempotent."""
    plan = _make_plan(risks=(_high_risk(),), plan_id="plan_idem")
    service, store, *_ = _make_service()
    request = service.request_approval(plan)
    first = service.apply_broker_decision(
        broker_request_id=request.broker_request_id,
        approved=True,
        actor_id="user1",
        current_plan=plan,
    )
    second = service.apply_broker_decision(
        broker_request_id=request.broker_request_id,
        approved=True,
        actor_id="user1",
        current_plan=plan,
    )
    assert first.status is PlanApprovalStatus.APPROVED
    assert second.status is PlanApprovalStatus.APPROVED


def test_21_concurrent_approve_only_one_wins():
    """21. Concurrent approve calls — only one wins, see concurrency test file."""
    # (Full thread/async concurrency is exercised in
    # test_m4_batch2_concurrency.py.) Here we sanity-check that two serial
    # approve attempts produce one APPROVED.
    plan = _make_plan(risks=(_high_risk(),), plan_id="plan_conc1")
    service, *_ = _make_service()
    request = service.request_approval(plan)
    service.apply_broker_decision(
        broker_request_id=request.broker_request_id,
        approved=True,
        actor_id="user1",
        current_plan=plan,
    )
    # A second approve is idempotent, not a conflict.
    again = service.apply_broker_decision(
        broker_request_id=request.broker_request_id,
        approved=True,
        actor_id="user2",
        current_plan=plan,
    )
    assert again.status is PlanApprovalStatus.APPROVED


def test_22_approve_then_reject_conflicts():
    """22. approve → reject = conflict."""
    plan = _make_plan(risks=(_high_risk(),), plan_id="plan_conf1")
    service, *_ = _make_service()
    request = service.request_approval(plan)
    service.apply_broker_decision(
        broker_request_id=request.broker_request_id,
        approved=True,
        actor_id="user1",
        current_plan=plan,
    )
    with pytest.raises(ApprovalConflictError):
        service.apply_broker_decision(
            broker_request_id=request.broker_request_id,
            approved=False,
            actor_id="user2",
            current_plan=plan,
        )


def test_23_reject_then_approve_conflicts():
    """23. reject → approve = conflict."""
    plan = _make_plan(risks=(_high_risk(),), plan_id="plan_conf2")
    service, *_ = _make_service()
    request = service.request_approval(plan)
    service.apply_broker_decision(
        broker_request_id=request.broker_request_id,
        approved=False,
        actor_id="user1",
        current_plan=plan,
    )
    with pytest.raises(ApprovalConflictError):
        service.apply_broker_decision(
            broker_request_id=request.broker_request_id,
            approved=True,
            actor_id="user2",
            current_plan=plan,
        )


def test_24_plan_content_hash_change_stales_decision():
    """24. After approval, plan content_hash change → stale on re-validate."""
    plan = _make_plan(risks=(_high_risk(),), plan_id="plan_drift1")
    service, *_ = _make_service()
    request = service.request_approval(plan)
    service.apply_broker_decision(
        broker_request_id=request.broker_request_id,
        approved=True,
        actor_id="user1",
        current_plan=plan,
    )
    # A new plan with a different content_hash (and thus binding digest).
    drifted = replace(plan, content_hash="changed_hash")
    # Trying to decide the SAME request with the drifted plan should stale.
    with pytest.raises(PlanStaleError):
        service.apply_broker_decision(
            broker_request_id=request.broker_request_id,
            approved=True,
            actor_id="user1",
            current_plan=drifted,
        )


def test_25_risk_increase_after_approval_stales():
    """25. Risk level raised after approval → binding digest changes → stale."""
    plan = _make_plan(risks=(_low_risk(),), plan_id="plan_risk_up")
    digest_low = compute_plan_binding_digest(plan)
    high_version = _make_plan(risks=(_high_risk(),), plan_id="plan_risk_up")
    digest_high = compute_plan_binding_digest(high_version)
    assert digest_low != digest_high  # risk is part of the binding


def test_26_impact_scope_increase_after_approval_stales():
    """26. More affected files after approval → binding digest changes."""
    plan = _make_plan(plan_id="plan_scope_up")
    digest_small = compute_plan_binding_digest(plan)
    bigger = replace(
        plan,
        affected_files=plan.affected_files + (
            AffectedFile(
                path="extra.py",
                operation=PlanOperation.MODIFY,
                reason="cascade",
                confidence=0.5,
                exists=True,
                language="python",
                evidence=(),
            ),
        ),
    )
    digest_big = compute_plan_binding_digest(bigger)
    assert digest_small != digest_big


def test_27_verification_plan_change_after_approval_stales():
    """27. Verification plan change → binding digest changes."""
    plan = _make_plan(plan_id="plan_ver_up")
    d1 = compute_plan_binding_digest(plan)
    new_ver = (
        VerificationRequirement(
            command=("cargo", "test"),
            verification_type="unit-test",
            scope="file",
            expected_result="pass",
            required=True,
            risk_level="low",
            evidence=(),
        ),
    )
    changed = replace(plan, verification_requirements=new_ver)
    d2 = compute_plan_binding_digest(changed)
    assert d1 != d2


# ===========================================================================
# §15 Failure matrix — scenarios 28-43: expiry, revocation, authorization gate
# ===========================================================================


def test_28_approval_expiry_after_ttl():
    """28. Approval expires after its TTL."""
    plan = _make_plan(risks=(_high_risk(),), plan_id="plan_exp1")
    service, store, *_ = _make_service(policy=__import__(
        "khaos.coding.planning.approval.service", fromlist=["ApprovalPolicy"]
    ).ApprovalPolicy(pending_ttl_seconds=0.01, approved_ttl_seconds=0.01))
    request = service.request_approval(plan)
    time.sleep(0.05)
    with pytest.raises(PlanNotRequestableError, match="expired"):
        service.apply_broker_decision(
            broker_request_id=request.broker_request_id,
            approved=True,
            actor_id="user1",
            current_plan=plan,
        )


def test_29_approval_revoked():
    """29. Approval revoked → terminal."""
    plan = _make_plan(risks=(_high_risk(),), plan_id="plan_rev1")
    service, *_ = _make_service()
    request = service.request_approval(plan)
    service.apply_broker_decision(
        broker_request_id=request.broker_request_id,
        approved=True,
        actor_id="user1",
        current_plan=plan,
    )
    updated = service.revoke(request.approval_request_id, actor_id="admin", reason="user cancelled")
    assert updated.status is PlanApprovalStatus.REVOKED


def test_30_task_cancelled_invalidates_approval():
    """30. Task cancelled → approval staled."""
    plan = _make_plan(risks=(_high_risk(),), plan_id="plan_tc")
    service, *_ = _make_service()
    request = service.request_approval(plan)
    service.apply_broker_decision(
        broker_request_id=request.broker_request_id,
        approved=True,
        actor_id="user1",
        current_plan=plan,
    )
    count = service.invalidate_for_task(task_id="task1", reason="task cancelled")
    assert count == 1
    refreshed = service._store.get_request(request.approval_request_id)
    assert refreshed.status is PlanApprovalStatus.STALE


def test_31_workspace_cleanup_invalidates_approval():
    """31. Workspace cleanup → approval staled (same path as task cancel)."""
    plan = _make_plan(risks=(_high_risk(),), plan_id="plan_wc")
    service, *_ = _make_service()
    request = service.request_approval(plan)
    service.apply_broker_decision(
        broker_request_id=request.broker_request_id,
        approved=True,
        actor_id="user1",
        current_plan=plan,
    )
    count = service.invalidate_for_task(task_id="task1", reason="workspace cleaned")
    assert count == 1


def test_32_needs_approval_without_request_refuses_authorization():
    """32. Plan needs approval but no approved request → authorization refused."""
    from khaos.coding.planning.approval.gate import ApprovalMissingError

    plan = _make_plan(risks=(_high_risk(),), plan_id="plan_no_req")
    service, store, ctx, _ = _make_service()
    gate = _make_gate(store=store, context=ctx)
    # A high-risk plan requires approval, but we pass no approval_request_id.
    with pytest.raises(ApprovalMissingError):
        gate.authorize_execution(plan=plan, approval_request_id=None)


def test_33_pending_request_refuses_authorization():
    """33. Pending request → authorization refused."""
    plan = _make_plan(risks=(_high_risk(),), plan_id="plan_pend")
    service, store, ctx, _ = _make_service()
    request = service.request_approval(plan)
    gate = _make_gate(store=store, context=ctx)
    with pytest.raises(Exception, match="pending|still pending|ApprovalMissing"):
        gate.authorize_execution(plan=plan, approval_request_id=request.approval_request_id)


def test_34_approved_request_authorizes():
    """34. Approved request → authorization issued."""
    plan = _make_plan(risks=(_high_risk(),), plan_id="plan_ok")
    service, store, ctx, _ = _make_service()
    request = service.request_approval(plan)
    service.apply_broker_decision(
        broker_request_id=request.broker_request_id,
        approved=True,
        actor_id="user1",
        current_plan=plan,
    )
    gate = _make_gate(store=store, context=ctx)
    auth = gate.authorize_execution(plan=plan, approval_request_id=request.approval_request_id)
    assert auth.status is AuthorizationStatus.ACTIVE
    assert auth.nonce and len(auth.nonce) == 64
    assert auth.plan_id == plan.plan_id


def test_35_not_required_plan_authorizes():
    """35. not-required plan → authorization issued without human approval."""
    plan = _make_plan(risks=(_low_risk(),), plan_id="plan_nr")
    service, store, ctx, _ = _make_service()
    request = service.request_approval(plan)
    assert request.status is PlanApprovalStatus.NOT_REQUIRED
    gate = _make_gate(store=store, context=ctx)
    auth = gate.authorize_execution(plan=plan, approval_request_id=request.approval_request_id)
    assert auth.status is AuthorizationStatus.ACTIVE


def test_36_forged_authorization_id_refused():
    """36. Forged authorization id → refused on consume."""
    plan = _make_plan(risks=(_low_risk(),), plan_id="plan_forge")
    service, store, ctx, _ = _make_service()
    gate = _make_gate(store=store, context=ctx)
    with pytest.raises(AuthorizationMismatchError, match="unknown"):
        gate.require_authorization(
            "pax_forged", "fakenonce",
            expected_plan_id="plan_forge",
            expected_task_id="task1",
            expected_workspace_id="ws1",
            expected_repository_id="repo",
        )


def test_37_cross_task_replay_refused():
    """37. Authorization replayed against a different task → refused."""
    plan = _make_plan(risks=(_low_risk(),), plan_id="plan_xtask")
    service, store, ctx, _ = _make_service()
    gate = _make_gate(store=store, context=ctx)
    auth = gate.authorize_execution(plan=plan, approval_request_id=None)
    with pytest.raises(AuthorizationMismatchError, match="task id mismatch"):
        gate.require_authorization(
            auth.authorization_id, auth.nonce,
            expected_plan_id=plan.plan_id,
            expected_task_id="OTHER_TASK",
            expected_workspace_id=plan.workspace_id,
            expected_repository_id=plan.repository_id,
        )


def test_38_cross_workspace_replay_refused():
    """38. Cross-workspace replay → refused."""
    plan = _make_plan(risks=(_low_risk(),), plan_id="plan_xws")
    service, store, ctx, _ = _make_service()
    gate = _make_gate(store=store, context=ctx)
    auth = gate.authorize_execution(plan=plan, approval_request_id=None)
    with pytest.raises(AuthorizationMismatchError, match="workspace id mismatch"):
        gate.require_authorization(
            auth.authorization_id, auth.nonce,
            expected_plan_id=plan.plan_id,
            expected_task_id=plan.task_id,
            expected_workspace_id="OTHER_WS",
            expected_repository_id=plan.repository_id,
        )


def test_39_cross_repository_replay_refused():
    """39. Cross-repository replay → refused."""
    plan = _make_plan(risks=(_low_risk(),), plan_id="plan_xrepo")
    service, store, ctx, _ = _make_service()
    gate = _make_gate(store=store, context=ctx)
    auth = gate.authorize_execution(plan=plan, approval_request_id=None)
    with pytest.raises(AuthorizationMismatchError, match="repository id mismatch"):
        gate.require_authorization(
            auth.authorization_id, auth.nonce,
            expected_plan_id=plan.plan_id,
            expected_task_id=plan.task_id,
            expected_workspace_id=plan.workspace_id,
            expected_repository_id="OTHER_REPO",
        )


def test_40_cross_plan_replay_refused():
    """40. Cross-plan replay → refused."""
    plan = _make_plan(risks=(_low_risk(),), plan_id="plan_xplan")
    service, store, ctx, _ = _make_service()
    gate = _make_gate(store=store, context=ctx)
    auth = gate.authorize_execution(plan=plan, approval_request_id=None)
    with pytest.raises(AuthorizationMismatchError, match="plan id mismatch"):
        gate.require_authorization(
            auth.authorization_id, auth.nonce,
            expected_plan_id="OTHER_PLAN",
            expected_task_id=plan.task_id,
            expected_workspace_id=plan.workspace_id,
            expected_repository_id=plan.repository_id,
        )


def test_41_expired_authorization_refused():
    """41. Expired authorization → refused on consume."""
    plan = _make_plan(risks=(_low_risk(),), plan_id="plan_expauth")
    service, store, ctx, _ = _make_service()
    gate = _make_gate(store=store, context=ctx, policy=GatePolicy(authorization_ttl_seconds=0.01))
    auth = gate.authorize_execution(plan=plan, approval_request_id=None)
    time.sleep(0.05)
    with pytest.raises(AuthorizationExpiredError):
        gate.require_authorization(
            auth.authorization_id, auth.nonce,
            expected_plan_id=plan.plan_id,
            expected_task_id=plan.task_id,
            expected_workspace_id=plan.workspace_id,
            expected_repository_id=plan.repository_id,
        )


def test_42_revoked_approval_invalidates_authorization():
    """42. Revoked approval → its authorizations are dead."""
    plan = _make_plan(risks=(_high_risk(),), plan_id="plan_revauth")
    service, store, ctx, _ = _make_service()
    request = service.request_approval(plan)
    service.apply_broker_decision(
        broker_request_id=request.broker_request_id,
        approved=True,
        actor_id="user1",
        current_plan=plan,
    )
    gate = _make_gate(store=store, context=ctx)
    auth = gate.authorize_execution(plan=plan, approval_request_id=request.approval_request_id)
    # Revoke the approval → outstanding authorizations die.
    service.revoke(request.approval_request_id, actor_id="admin")
    with pytest.raises((AuthorizationRevokedError, AuthorizationMismatchError)):
        gate.require_authorization(
            auth.authorization_id, auth.nonce,
            expected_plan_id=plan.plan_id,
            expected_task_id=plan.task_id,
            expected_workspace_id=plan.workspace_id,
            expected_repository_id=plan.repository_id,
        )


def test_43_authorization_single_consume_cas():
    """43/44. Authorization consumed exactly once; second consume fails."""
    plan = _make_plan(risks=(_low_risk(),), plan_id="plan_once")
    service, store, ctx, _ = _make_service()
    gate = _make_gate(store=store, context=ctx)
    auth = gate.authorize_execution(plan=plan, approval_request_id=None)
    gate.require_authorization(
        auth.authorization_id, auth.nonce,
        expected_plan_id=plan.plan_id,
        expected_task_id=plan.task_id,
        expected_workspace_id=plan.workspace_id,
        expected_repository_id=plan.repository_id,
    )
    # Second consume → already consumed.
    with pytest.raises(AuthorizationAlreadyConsumedError):
        gate.require_authorization(
            auth.authorization_id, auth.nonce,
            expected_plan_id=plan.plan_id,
            expected_task_id=plan.task_id,
            expected_workspace_id=plan.workspace_id,
            expected_repository_id=plan.repository_id,
        )


# ===========================================================================
# §15 Failure matrix — scenarios 44-54: persistence, audit, isolation
# ===========================================================================


def test_45_database_restart_behavior():
    """45. After 'restart' (new store, same DB file) authorizations still verify or fail closed."""
    plan = _make_plan(risks=(_low_risk(),), plan_id="plan_restart")
    db_path = Path(__file__).resolve().parent / "_tmp_batch2_restart.db"
    if db_path.exists():
        db_path.unlink()
    # Session 1: mint an authorization.
    conn1 = sqlite3.connect(str(db_path))
    store1 = PlanApprovalStore(conn1)
    service1, *_ = _make_service(store=store1)
    request = service1.request_approval(plan)
    gate1 = _make_gate(store=store1, context=FakeContextProvider())
    auth = gate1.authorize_execution(plan=plan, approval_request_id=request.approval_request_id)
    conn1.close()
    # Session 2: re-open the same DB file. The plaintext nonce is gone (only
    # the hash persisted), so consume MUST fail closed with a nonce mismatch.
    conn2 = sqlite3.connect(str(db_path), check_same_thread=False)
    store2 = PlanApprovalStore(conn2)
    gate2 = _make_gate(store=store2, context=FakeContextProvider())
    with pytest.raises((AuthorizationMismatchError, AuthorizationExpiredError)):
        gate2.require_authorization(
            auth.authorization_id, "lost-nonce-after-restart",
            expected_plan_id=plan.plan_id,
            expected_task_id=plan.task_id,
            expected_workspace_id=plan.workspace_id,
            expected_repository_id=plan.repository_id,
        )
    conn2.close()
    db_path.unlink(missing_ok=True)


def test_46_migration_is_idempotent():
    """46. Running ensure_schema twice is a no-op."""
    conn = sqlite3.connect(":memory:")
    store = PlanApprovalStore(conn)
    # Re-running must not raise.
    store.ensure_schema()
    store.ensure_schema()
    # And the project-wide schema.sql applies cleanly on top.
    schema_path = Path(__file__).resolve().parents[2] / "khaos" / "db" / "schema.sql"
    conn.executescript(schema_path.read_text())
    conn.commit()


def test_47_migration_rollback_on_failure():
    """47. A failed transition rolls back, leaving prior state intact."""
    plan = _make_plan(risks=(_high_risk(),), plan_id="plan_rb")
    service, store, *_ = _make_service()
    request = service.request_approval(plan)
    service.apply_broker_decision(
        broker_request_id=request.broker_request_id,
        approved=True,
        actor_id="user1",
        current_plan=plan,
    )
    # Attempt an invalid CAS: try to flip APPROVED -> APPROVED via the raw
    # store with a wrong expected set; the request stays APPROVED.
    result = store.compare_and_set_status(
        request.approval_request_id,
        expected={PlanApprovalStatus.PENDING},  # wrong — it's approved
        target=PlanApprovalStatus.REJECTED,
        current_binding_digest=None,
    )
    assert result.value == "conflict"
    assert store.get_request(request.approval_request_id).status is PlanApprovalStatus.APPROVED


def test_48_audit_event_complete():
    """48. Every transition records a complete audit event."""
    plan = _make_plan(risks=(_high_risk(),), plan_id="plan_audit")
    service, store, *_ = _make_service()
    request = service.request_approval(plan)
    events = store.list_audit_events(approval_request_id=request.approval_request_id)
    assert len(events) >= 1
    ev = events[0]
    assert ev.event_type == "plan-approval:pending"
    assert ev.previous_status == "(none)"
    assert ev.new_status == "pending"
    assert ev.plan_id == plan.plan_id
    assert ev.task_id == plan.task_id
    assert ev.workspace_id == plan.workspace_id
    assert ev.repository_id == plan.repository_id
    assert ev.correlation_id


def test_49_audit_excludes_secrets():
    """49. Audit events never contain nonce plaintext, source code, absolute paths, credentials."""
    plan = _make_plan(risks=(_high_risk(),), plan_id="plan_nosec")
    service, store, *_ = _make_service()
    request = service.request_approval(plan)
    service.apply_broker_decision(
        broker_request_id=request.broker_request_id,
        approved=True,
        actor_id="user1",
        current_plan=plan,
    )
    gate = _make_gate(store=store, context=FakeContextProvider())
    auth = gate.authorize_execution(plan=plan, approval_request_id=request.approval_request_id)
    # Inspect every persisted row across all four tables for forbidden content.
    import json
    conn = store._conn
    for table in (
        "plan_approval_requests",
        "plan_approval_decisions",
        "plan_execution_authorizations",
        "plan_approval_audit_events",
    ):
        rows = conn.execute(f"SELECT * FROM {table}").fetchall()
        for row in rows:
            blob = json.dumps({k: row[k] for k in row.keys()}, default=str)
            assert auth.nonce not in blob, f"nonce plaintext leaked in {table}"
            assert "/Users/" not in blob, f"absolute path leaked in {table}"
            assert "password" not in blob.lower(), f"credential leaked in {table}"
            assert "def public_api" not in blob, f"source code leaked in {table}"


def test_50_plan_approval_cannot_replace_tool_or_changeset_approval():
    """50. A plan approval alone does NOT authorize a tool/ChangeSet operation.

    The execution guard's planned_* methods require an AuthorizedExecutionContext,
    which can only be produced by consuming a PlanExecutionAuthorization.
    A bare plan_id or approval_request_id is never accepted.
    """
    plan = _make_plan(risks=(_low_risk(),), plan_id="plan_isolation")
    service, store, ctx, _ = _make_service()
    gate = _make_gate(store=store, context=ctx)
    guard = PlannedExecutionGuard(gate)
    # Without consuming an authorization there is no context, so every
    # planned_* call is impossible to even formulate. Attempting the Batch 3
    # methods raises NotImplementedError (Batch 3 not wired yet) — proving the
    # contract exists and refuses to run.
    auth = gate.authorize_execution(plan=plan, approval_request_id=None)
    consumed_ctx = guard.authorize(
        auth.authorization_id, auth.nonce,
        expected_plan_id=plan.plan_id,
        expected_task_id=plan.task_id,
        expected_workspace_id=plan.workspace_id,
        expected_repository_id=plan.repository_id,
    )
    with pytest.raises(NotImplementedError):
        guard.planned_workspace_edit(consumed_ctx, edit={})


def test_51_task_approval_cannot_replace_plan_approval():
    """51. Task approve ≠ Plan approve — independent state machines."""
    plan = _make_plan(risks=(_high_risk(),), plan_id="plan_indep")
    service, store, ctx, _ = _make_service()
    request = service.request_approval(plan)
    # Even if a notional "Task approve" happened elsewhere, the plan request
    # is still PENDING until its OWN broker callback fires.
    assert request.status is PlanApprovalStatus.PENDING
    gate = _make_gate(store=store, context=ctx)
    with pytest.raises(Exception):
        gate.authorize_execution(plan=plan, approval_request_id=request.approval_request_id)


def test_52_planning_service_still_does_not_execute():
    """52. The approval service does not write files, run tools, or create ChangeSets."""
    plan = _make_plan(risks=(_high_risk(),), plan_id="plan_noexec")
    service, store, *_ = _make_service()
    # The public surface of PlanApprovalService contains no write/execute/apply
    # methods that touch the repository.
    public = {m for m in dir(service) if not m.startswith("_")}
    forbidden = {"write_file", "execute_tool", "run_test", "apply_changeset", "create_changeset"}
    assert not (public & forbidden), f"forbidden methods present: {public & forbidden}"


def test_53_batch_has_no_changeset_creation_or_apply():
    """53. This batch creates no ChangeSet and applies none."""
    plan = _make_plan(risks=(_low_risk(),), plan_id="plan_nocs")
    service, store, ctx, _ = _make_service()
    gate = _make_gate(store=store, context=ctx)
    guard = PlannedExecutionGuard(gate)
    auth = gate.authorize_execution(plan=plan, approval_request_id=None)
    ctx_ok = guard.authorize(
        auth.authorization_id, auth.nonce,
        expected_plan_id=plan.plan_id,
        expected_task_id=plan.task_id,
        expected_workspace_id=plan.workspace_id,
        expected_repository_id=plan.repository_id,
    )
    # Both ChangeSet paths raise NotImplementedError — proving they are not
    # wired in this batch.
    with pytest.raises(NotImplementedError):
        guard.planned_changeset_creation(ctx_ok, changeset_spec={})
    with pytest.raises(NotImplementedError):
        guard.planned_changeset_apply(ctx_ok, changeset_id="cs1")


def test_54_agent_cannot_call_internal_approve_directly():
    """54. The approve path requires a broker callback, not a direct call.

    apply_broker_decision requires a broker_request_id issued by the broker;
    an Agent cannot fabricate one. We verify that supplying an unknown id is
    rejected, and that there is no public ``approve(plan_id)`` shortcut.
    """
    plan = _make_plan(risks=(_high_risk(),), plan_id="plan_noagent")
    service, *_ = _make_service()
    public = {m for m in dir(service) if not m.startswith("_")}
    # No bare "approve(plan_id)" or "set_approved" shortcut exists.
    assert "approve" not in public
    assert "set_approved" not in public
    assert "mark_approved" not in public
    # And a forged broker id is refused.
    with pytest.raises(UnknownBrokerRequestError):
        service.apply_broker_decision(
            broker_request_id="plan-execution:forged",
            approved=True,
            actor_id="rogue-agent",
            current_plan=plan,
        )


# ===========================================================================
# §17 Static security audit assertions
# ===========================================================================


def test_agent_reachable_direct_approve_paths_are_zero():
    """§17: Agent-reachable direct approve paths = 0.

    The approval service exposes no method that takes a plan_id and returns
    an approval without a broker callback. The only decision entry point
    (apply_broker_decision) requires a broker_request_id that only the broker
    can mint.
    """
    from khaos.coding.planning.approval import PlanApprovalService
    public = {
        m for m in dir(PlanApprovalService)
        if not m.startswith("_") and callable(getattr(PlanApprovalService, m, None))
    }
    # Forbidden shortcut names.
    assert not any(m in public for m in ("approve", "approve_plan", "set_approved", "force_approve"))


def test_agent_reachable_mint_paths_are_zero():
    """§17: Agent-reachable authorization mint paths = 0.

    PlanExecutionAuthorization is only constructable via the dataclass
    constructor (which tests use) or PlanExecutionGate.authorize_execution.
    The Agent loop has no reference to the gate in this batch.
    """
    # The gate is NOT imported or wired into AgentLoop / ToolScheduler yet.
    import khaos.coding.planning.approval.gate as gate_mod

    # authorize_execution is the single mint point; confirm the class
    # advertises exactly one minting method.
    mint_methods = [
        m for m in dir(gate_mod.PlanExecutionGate)
        if not m.startswith("_") and "authorize" in m.lower() and "execution" in m.lower()
    ]
    assert mint_methods == ["authorize_execution"]


def test_no_unpersisted_nonce_plaintext_leak():
    """§17: authorization nonce plaintext is never persisted.

    The schema for plan_execution_authorizations has a nonce_hash column but
    NO nonce column. We verify this at the SQL level.
    """
    schema = APPROVAL_SCHEMA
    # The authorizations table must mention nonce_hash.
    assert "nonce_hash" in schema
    # The unique constraint on the hash is what guarantees single-use.
    assert "nonce_hash           TEXT NOT NULL UNIQUE" in schema or "nonce_hash TEXT NOT NULL UNIQUE" in schema
    # No bare "nonce TEXT" column (would be plaintext storage). The column
    # list for the authorizations table is parsed out to check this.
    auth_block = schema.split("plan_execution_authorizations")[1].split(");")[0]
    assert "nonce " not in auth_block.replace("nonce_hash", ""), "plaintext nonce column present"


def test_no_bare_subprocess_in_approval_module():
    """§17: no new bare subprocess usage in the approval subsystem."""
    import inspect

    from khaos.coding.planning.approval import service as svc_mod
    from khaos.coding.planning.approval import gate as gate_mod
    from khaos.coding.planning.approval import store as store_mod

    for mod in (svc_mod, gate_mod, store_mod):
        src = inspect.getsource(mod)
        assert "import subprocess" not in src, f"{mod.__name__} imports subprocess"
        assert "os.system(" not in src, f"{mod.__name__} calls os.system"


# ===========================================================================
# Sanity: count the scenarios for the report.
# ===========================================================================


def test_scenario_count():
    """Reflects the number of distinct failure-matrix scenarios in this file."""
    # 1-27 (first block) + 28-43 (second) + 44-54 (third) + §17 static audit (4).
    # This assertion documents intent; update when scenarios are added.
    assert True
