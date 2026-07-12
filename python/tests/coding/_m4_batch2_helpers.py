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
)
from khaos.coding.planning.approval.repository import PlanSnapshotStore
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
    plan = ImplementationPlan(
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
    if not content_hash:
        from khaos.coding.planning.approval.repository import PersistedPlanRepository
        plan = replace(plan, content_hash=PersistedPlanRepository._recompute_plan_content_hash(plan))
    return plan


# ---------------------------------------------------------------------------
# Broker wrapper (sync API around the async ApprovalBroker)
# ---------------------------------------------------------------------------


class SyncBroker:
    """Synchronous wrapper around the real async ApprovalBroker.

    Batch 2.3: wired with an ApprovalAuthenticator so plan-approval decisions
    can be signed and verified. ``register_plan_approval`` and
    ``resolve_plan_approval`` drive the real broker via a private event loop.
    """

    def __init__(self, authenticator=None):
        from khaos.coding.planning.approval.models import ApprovalAuthenticator
        self._authenticator = authenticator or ApprovalAuthenticator()
        self._real = ApprovalBroker(authenticator=self._authenticator)
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
# Batch 2.6 §2: production PlanExecutionGate / PlanApprovalService require
# RuntimeCapability. Test code must use the explicit UnsafeTest* subclasses
# below. These classes bypass the capability check and set _boot_context=None
# so _verify_boot() is a no-op (no persisted boot fence in tests).


import time as _time
from khaos.coding.planning.approval.gate import GatePolicy, PlanLiveValidator
from khaos.coding.planning.approval.repository import PlanSnapshotStore


class UnsafeTestPlanExecutionGate(PlanExecutionGate):
    """Test-only PlanExecutionGate that bypasses RuntimeCapability.

    Lives in the test helper module — NOT exported from the production
    package. Marks itself with ``_unsafe_test_only = True`` so production
    constructors reject it.
    """
    _unsafe_test_only = True

    def __init__(
        self,
        store,
        context_provider,
        *,
        plan_repository=None,
        planning_service=None,
        policy=None,
        clock=None,
    ) -> None:
        # Skip the production __init__ (which requires RuntimeCapability).
        # Replicate the old test-mode construction directly.
        self._store = store
        self._context_provider = context_provider
        self._policy = policy or GatePolicy()
        self._clock = clock or _time.time
        self._boot_context = None
        self._plan_repository = plan_repository or PlanSnapshotStore()
        self._server_epoch, self._boot_id = self._store.get_current_epoch()
        self._validator = PlanLiveValidator(
            plan_repository=self._plan_repository,
            context_provider=context_provider,
            planning_service=planning_service,
        )


class UnsafeTestPlanApprovalService(PlanApprovalService):
    """Test-only PlanApprovalService that bypasses RuntimeCapability.

    Lives in the test helper module — NOT exported from the production
    package. Marks itself with ``_unsafe_test_only = True`` so production
    constructors reject it.
    """
    _unsafe_test_only = True

    def __init__(
        self,
        store,
        broker,
        context_provider,
        *,
        plan_repository=None,
        planning_service=None,
        policy=None,
        clock=None,
    ) -> None:
        # Skip the production __init__ (which requires RuntimeCapability).
        from khaos.coding.planning.approval.service import ApprovalPolicy
        self._store = store
        self._broker = broker
        self._context_provider = context_provider
        self._policy = policy or ApprovalPolicy()
        self._clock = clock or _time.time
        self._boot_context = None
        self._plan_repository = plan_repository or PlanSnapshotStore()
        self._planning_service = planning_service
        self._validator = PlanLiveValidator(
            plan_repository=self._plan_repository,
            context_provider=context_provider,
            planning_service=planning_service,
        )


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
    service = UnsafeTestPlanApprovalService(
        store=store, broker=broker, context_provider=context,
        plan_repository=plan_repository, planning_service=None,
        policy=policy, clock=clock or __import__("time").time,
    )
    return service, store, context, broker, plan_repository


def make_gate(*, store, context, plan_repository=None, policy=None, clock=None):
    return UnsafeTestPlanExecutionGate(
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
    binding_digest: str | None = None,
    reason: str = "",
) -> BrokerDecisionReceipt | None:
    """Drive the real broker to resolve a decision and persist its receipt.

    Batch 2.3: uses the broker's wired ApprovalAuthenticator to issue a
    SIGNED AuthenticatedApprovalContext. A hand-constructed context would be
    rejected. The receipt sink passes the store's writer_capability so
    insert_receipt accepts the row.
    """
    from khaos.coding.planning.approval.models import ApprovalAuthenticator
    from khaos.coding.planning.approval.models import AuthenticatedSession

    # Use the broker's authenticator to issue a signed context.
    authenticator = broker._authenticator if isinstance(broker, SyncBroker) else broker._authenticator
    session = AuthenticatedSession(
        session_id=session_request_id, principal_id=actor_id,
        principal_type=actor_type, authenticated_at=__import__("time").time(),
        session_expiry=__import__("time").time() + 600,
        granted_capabilities=(ApprovalAuthenticator.CAPABILITY_PLAN_APPROVAL,),
    )
    authenticator.register_session(session)
    approval_request_id = getattr(request, "approval_request_id", request.broker_request_id.split(":", 1)[-1])
    ctx = authenticator.issue_context(
        session=session, approval_request_id=approval_request_id,
        authenticated_source=authenticated_source,
        capability=ApprovalAuthenticator.CAPABILITY_PLAN_APPROVAL,
    )
    bd = binding_digest if binding_digest is not None else request.binding_digest
    real_broker = broker._real if isinstance(broker, SyncBroker) else broker
    # Batch 2.6: install the signed receipt writer + register the broker's
    # ReceiptSigner with the store's verification registry. In production,
    # ApprovalRuntime.initialize() does this automatically. The writer is
    # name-mangled and token-gated so ordinary code cannot install one.
    signer = real_broker.receipt_signer
    _wire_test_receipt_writer(store, real_broker, signer)

    if isinstance(broker, SyncBroker):
        return broker.resolve_plan_approval(
            broker_request_id=request.broker_request_id,
            approved=approved, context=ctx, reason=reason,
            binding_digest=bd, receipt_sink=None,
        )
    # Real async broker.
    return broker._loop.run_until_complete(  # type: ignore[attr-defined]
        broker.resolve_plan_approval(
            broker_request_id=request.broker_request_id,
            approved=approved, context=ctx, reason=reason,
            binding_digest=bd, receipt_sink=None,
        )
    )


def _wire_test_receipt_writer(store, broker, signer):
    """Install the signed receipt writer + signer on store/broker for tests.

    Mirrors what ApprovalRuntime.initialize() does in production. Test-only.
    Persists the signer's key and loads old signers so receipts from prior
    broker instances remain verifiable (restart/concurrency scenarios).
    """
    token = object()
    # Load old signers (for verifying receipts from prior broker instances).
    for old_signer in store.load_receipt_signers():
        if old_signer.key_id != signer.key_id:
            store._register_receipt_signer(old_signer, runtime_token=token)
    # Persist the current signer and register it.
    store.persist_receipt_signer(signer)
    store._register_receipt_signer(signer, runtime_token=token)
    def _writer(**fields):
        store._insert_signed_receipt(**fields)
    broker._install_runtime_receipt_writer(_writer, runtime_token=token)


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
