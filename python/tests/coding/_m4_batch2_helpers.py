"""Shared helpers for M4 Batch 2 / 2.1 approval tests.

Kept in a private module so both the Batch 2 matrix tests and the Batch 2.1
closure tests use the SAME plumbing (real broker, durable receipt outbox,
authoritative plan snapshot store). No business logic here — just fixtures.
"""
from __future__ import annotations

import asyncio
import sqlite3
from dataclasses import replace
from typing import Any

from khaos.agent.approval import ApprovalBroker
from khaos.coding.planning.approval import (
    ApprovalPolicy,
    BrokerDecisionReceipt,
    ContextProvider,
    CurrentRepositoryState,
    GatePolicy,
    PersistedPlanRepository,
    PlanApprovalService,
    PlanApprovalStatus,
    PlanApprovalStore,
    PlanExecutionGate,
    PlanSnapshotStore,
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
# Context provider
# ---------------------------------------------------------------------------


class FakeContextProvider:
    def __init__(self, **kw):
        self._state = dict(
            head_sha="abc123",
            repository_generation=1,
            task_active=True,
            workspace_active=True,
            task_terminal=False,
            workspace_terminal=False,
        )
        self._state.update(kw)

    def set(self, **kw):
        self._state.update(kw)

    def current_state(self, *, repository_id, task_id, workspace_id):
        s = dict(self._state)
        return CurrentRepositoryState(
            repository_id=repository_id, task_id=task_id, workspace_id=workspace_id,
            head_sha=s["head_sha"], repository_generation=s["repository_generation"],
            task_active=s["task_active"], workspace_active=s["workspace_active"],
            task_terminal=s["task_terminal"], workspace_terminal=s["workspace_terminal"],
        )


# ---------------------------------------------------------------------------
# Risk / verification factories
# ---------------------------------------------------------------------------


def low_risk():
    return RiskAssessment("low", "functional", "minor", ("python_lib.py",), "tests", False)


def high_risk():
    return RiskAssessment("high", "security", "danger", ("auth.py",), "review", True)


def verification():
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


# ---------------------------------------------------------------------------
# Plan factory
# ---------------------------------------------------------------------------


def make_plan(
    *,
    plan_id="plan_low",
    repository_id="repo",
    task_id="task1",
    workspace_id="ws1",
    base_sha="abc123",
    repository_generation=1,
    status=PlanStatus.READY,
    risks=None,
    affected_files=None,
    affected_symbols=None,
    diagnostics=(),
    verification_requirements=None,
    evidence=None,
    content_hash="",
):
    risks = risks if risks is not None else (low_risk(),)
    files = affected_files if affected_files is not None else (
        AffectedFile(
            path="python_lib.py", operation=PlanOperation.MODIFY, reason="edit",
            confidence=0.9, exists=True, language="python", evidence=(),
        ),
    )
    step = PlanStep(
        step_id="s1", title="modify", description="modify symbol",
        operation=PlanOperation.MODIFY, target_files=("python_lib.py",),
        target_symbols=(), depends_on=(), expected_outcome="ok",
        verification_requirements=verification_requirements or verification(),
        risk=risks[0], requires_approval=risks[0].requires_approval, evidence=(),
    )
    body = {
        "plan_id": plan_id, "repository_id": repository_id,
        "task_id": task_id, "workspace_id": workspace_id,
        "base_sha": base_sha, "risks": risks[0].level,
    }
    ch = content_hash or ImplementationPlan.digest(body)
    return ImplementationPlan(
        plan_id=plan_id, repository_id=repository_id, task_id=task_id,
        workspace_id=workspace_id, user_goal="modify public_api",
        normalized_goal="modify public_api", base_sha=base_sha,
        repository_generation=repository_generation, status=status,
        summary="test plan", steps=(step,), affected_files=files,
        affected_symbols=affected_symbols or (), dependency_impacts=(),
        verification_requirements=verification_requirements or verification(),
        risks=risks, diagnostics=diagnostics,
        evidence=evidence or (
            PlanEvidence(
                source="verification-config", repository_id=repository_id,
                query="config-hash", confidence=1.0,
                metadata={"config_hash": "cfg1", "config_files": {}},
            ),
        ),
        content_hash=ch, created_at=0.0,
    )


# ---------------------------------------------------------------------------
# Broker wrapper (sync API around the async ApprovalBroker)
# ---------------------------------------------------------------------------


class SyncBroker:
    """Synchronous wrapper around the real async ApprovalBroker.

    ``register_plan_approval`` and ``resolve_plan_approval`` drive the real
    broker via a private event loop so tests exercise genuine broker logic
    (concurrency serialization, idempotency, conflict) without per-test
    asyncio boilerplate.
    """

    def __init__(self):
        self._real = ApprovalBroker()
        self._loop = asyncio.new_event_loop()

    @property
    def real(self):
        return self._real

    def register_plan_approval(self, *, approval_request_id, binding, summary, expires_at):
        return self._loop.run_until_complete(
            self._real.register_plan_approval(
                approval_request_id=approval_request_id, binding=binding,
                summary=summary, expires_at=expires_at,
            )
        )

    def resolve_plan_approval(
        self, *, broker_request_id, approved, context, reason="", binding_digest="",
        receipt_sink=None, clock=None,
    ):
        return self._loop.run_until_complete(
            self._real.resolve_plan_approval(
                broker_request_id=broker_request_id, approved=approved,
                context=context, reason=reason,
                binding_digest=binding_digest, receipt_sink=receipt_sink, clock=clock,
            )
        )


# ---------------------------------------------------------------------------
# Service / gate / broker wiring
# ---------------------------------------------------------------------------


def make_service(
    *,
    store=None,
    context=None,
    broker=None,
    plan_repository=None,
    policy=None,
    clock=None,
):
    """Build (service, store, context, broker, plan_repository)."""
    if store is None:
        conn = sqlite3.connect(":memory:", check_same_thread=False)
        store = PlanApprovalStore(conn)
    if context is None:
        context = FakeContextProvider()
    if broker is None:
        broker = SyncBroker()
    if plan_repository is None:
        # Batch 2.2: default to the persisted repository so plan snapshots
        # survive restart and tests don't need manual repo.register(plan).
        plan_repository = PersistedPlanRepository(store)
    service = PlanApprovalService(
        store=store, broker=broker, context_provider=context,
        plan_repository=plan_repository, planning_service=None,
        policy=policy, clock=clock or __import__("time").time,
    )
    return service, store, context, broker, plan_repository


def make_gate(*, store, context, plan_repository=None, policy=None, clock=None):
    return PlanExecutionGate(
        store=store, context_provider=context,
        plan_repository=plan_repository or PlanSnapshotStore(),
        policy=policy, clock=clock or __import__("time").time,
    )


# ---------------------------------------------------------------------------
# The canonical "drive the broker to a decision" helper.
#
# Tests MUST go through this helper (or the broker directly) to obtain a
# BrokerDecisionReceipt. There is no shortcut that lets a test pass
# approved=True to the service — by design.
# ---------------------------------------------------------------------------


def broker_decide(
    *,
    broker,
    store: PlanApprovalStore,
    request,  # PlanApprovalRequest
    approved: bool,
    actor_id: str = "user1",
    actor_type: str = "user",
    authenticated_source: str = "api",
    session_request_id: str = "sess_test",
    server_capability: str = "approve-plan-execution",
    binding_digest: str | None = None,
    reason: str = "",
) -> BrokerDecisionReceipt | None:
    """Drive the real broker to resolve a decision and persist its receipt.

    Builds an :class:`AuthenticatedApprovalContext` (the ONLY sanctioned
    carrier of actor identity) and passes it to the broker. Returns the
    minted :class:`BrokerDecisionReceipt`, or ``None`` if the broker refused.
    """
    from khaos.coding.planning.approval.models import AuthenticatedApprovalContext

    import time as _time

    ctx = AuthenticatedApprovalContext(
        actor_id=actor_id, actor_type=actor_type,
        session_request_id=session_request_id,
        authenticated_source=authenticated_source,
        authentication_time=_time.time(),
        server_capability=server_capability,
    )
    bd = binding_digest if binding_digest is not None else request.binding_digest

    def sink(**kw):
        store.insert_receipt(**kw)

    if isinstance(broker, SyncBroker):
        return broker.resolve_plan_approval(
            broker_request_id=request.broker_request_id,
            approved=approved, context=ctx, reason=reason,
            binding_digest=bd, receipt_sink=sink,
        )
    # Real async broker.
    return broker._loop.run_until_complete(  # type: ignore[attr-defined]
        broker.resolve_plan_approval(
            broker_request_id=request.broker_request_id,
            approved=approved, context=ctx, reason=reason,
            binding_digest=bd, receipt_sink=sink,
        )
    )


def approve_and_apply(
    *,
    service: PlanApprovalService,
    broker,
    store: PlanApprovalStore,
    request,
    plan=None,  # retained for call-site compat; no longer passed to apply_broker_decision
    actor_id: str = "user1",
):
    """Convenience: broker-approve then apply the receipt. Returns the request.

    Batch 2.2: ``plan`` is no longer passed to ``apply_broker_decision`` —
    the service resolves the authoritative plan from the persisted repository.
    """
    receipt = broker_decide(
        broker=broker, store=store, request=request, approved=True, actor_id=actor_id,
    )
    assert receipt is not None, "broker refused to mint a receipt"
    return service.apply_broker_decision(receipt)


def make_forged_receipt(
    *,
    broker_request_id,
    approval_request_id,
    binding_digest,
    decision="approved",
    actor_id="rogue",
    actor_type="agent",
    authenticated_source="forged",
    session_request_id="forged-sess",
    server_capability="forged-cap",
    reason_digest="forged-reason-digest",
    decided_at=0.0,
    expires_at=9999999999.0,
    one_time_token="forged-token",
    token_hash="forged-hash",
):
    """Build a forged BrokerDecisionReceipt with ALL required fields.

    Used by tests that verify a forged dataclass receipt (whose token is NOT
    in the outbox) is rejected. The receipt is structurally valid but its
    one_time_token has no matching outbox row.
    """
    from dataclasses import replace as _replace

    from khaos.coding.planning.approval.models import (
        BrokerDecisionReceipt,
        PlanApprovalStatus,
    )

    return BrokerDecisionReceipt(
        receipt_id="forged",
        namespace="plan-execution",
        broker_request_id=broker_request_id,
        approval_request_id=approval_request_id,
        decision=PlanApprovalStatus.APPROVED if decision == "approved" else PlanApprovalStatus.REJECTED,
        authenticated_actor_id=actor_id,
        authenticated_actor_type=actor_type,
        authenticated_source=authenticated_source,
        session_request_id=session_request_id,
        server_capability=server_capability,
        binding_digest=binding_digest,
        decided_at=decided_at,
        expires_at=expires_at,
        reason_digest=reason_digest,
        one_time_token=one_time_token,
        token_hash=token_hash,
        metadata={},
    )


def consume_via_lease(
    *,
    gate,
    auth,
    expected_plan_id,
    expected_task_id,
    expected_workspace_id,
    expected_repository_id,
    owner_execution_id="exec_test",
):
    """Lease-first consume helper: the ONLY way tests should consume an
    authorization. Returns (consumed_auth, lease). Raises on failure.

    Batch 2.3: require_authorization is closed; all consume goes through
    acquire_lease (lease-first atomic consume).
    """
    return gate.acquire_lease(
        authorization_id=auth.authorization_id,
        nonce=auth.nonce,
        expected_plan_id=expected_plan_id,
        expected_task_id=expected_task_id,
        expected_workspace_id=expected_workspace_id,
        expected_repository_id=expected_repository_id,
        owner_execution_id=owner_execution_id,
    )
