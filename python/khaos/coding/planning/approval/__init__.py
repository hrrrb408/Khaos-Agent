"""Plan approval state machine and execution authorization gate.

M4 Batch 2 + Batch 2.1 (Broker Authenticity and Atomic Authorization Closure).

Public API:

* :class:`PlanApprovalStatus` — approval lifecycle enum.
* :class:`PlanApprovalRequest`, :class:`PlanApprovalDecision`,
  :class:`PlanExecutionAuthorization`, :class:`BrokerDecisionReceipt` —
  immutable records.
* :class:`PlanApprovalStore` — durable, CAS-backed persistence with atomic
  multi-row transitions.
* :class:`PlanApprovalService` — server-side approval state machine. Accepts
  ONLY authenticated :class:`BrokerDecisionReceipt` objects.
* :class:`PlanExecutionGate` — single authorization mint+consume point with
  server_epoch restart-invalidation.
* :class:`PlanLiveValidator` — shared live-plan validation used at four stages.
* :class:`PlanSnapshotStore` / :class:`PlanRepository` — authoritative plan
  snapshot source.
* :class:`PlannedExecutionGuard` / :class:`AuthorizedExecutionContext` —
  Batch 3 execution contract (failure-only stubs in this batch).
"""
from khaos.coding.planning.approval.execution_contract import (
    AuthorizedExecutionContext,
    PlannedExecutionGuard,
)
from khaos.coding.planning.approval.gate import (
    AuthorizationAlreadyConsumedError,
    AuthorizationError,
    AuthorizationExpiredError,
    AuthorizationMismatchError,
    AuthorizationRevokedError,
    GatePolicy,
    PlanExecutionGate,
)
from khaos.coding.planning.approval.models import (
    ALLOWED_APPROVAL_TRANSITIONS,
    AuthorizationStatus,
    BrokerDecisionReceipt,
    Clock,
    PlanApprovalAuditEvent,
    PlanApprovalDecision,
    PlanApprovalRequest,
    PlanApprovalStatus,
    PlanExecutionAuthorization,
    PlanValidationContext,
    compute_plan_binding_digest,
    compute_risk_digest,
    compute_verification_digest,
    generate_nonce,
    generate_receipt_token,
    hash_nonce,
    hash_receipt_token,
    verify_nonce,
    verify_receipt_token,
)
from khaos.coding.planning.approval.repository import (
    PlanRepository,
    PlanSnapshotStore,
)
from khaos.coding.planning.approval.requirement import (
    ApprovalRequirementOutcome,
    evaluate_approval_requirement,
)
from khaos.coding.planning.approval.service import (
    ApprovalConflictError,
    ApprovalPolicy,
    ContextProvider,
    CurrentRepositoryState,
    PlanApprovalError,
    PlanApprovalService,
    PlanNotRequestableError,
    PlanStaleError,
    UnauthenticatedReceiptError,
    UnknownBrokerRequestError,
)
from khaos.coding.planning.approval.store import (
    APPROVAL_SCHEMA,
    ApprovalTransitionResult,
    PlanApprovalStore,
)
from khaos.coding.planning.approval.validator import (
    PlanLiveValidator,
)

__all__ = [
    "ALLOWED_APPROVAL_TRANSITIONS",
    "APPROVAL_SCHEMA",
    "AuthorizedExecutionContext",
    "AuthorizationAlreadyConsumedError",
    "AuthorizationError",
    "AuthorizationExpiredError",
    "AuthorizationMismatchError",
    "AuthorizationRevokedError",
    "AuthorizationStatus",
    "ApprovalConflictError",
    "ApprovalPolicy",
    "ApprovalRequirementOutcome",
    "ApprovalTransitionResult",
    "BrokerDecisionReceipt",
    "Clock",
    "ContextProvider",
    "CurrentRepositoryState",
    "GatePolicy",
    "PlanApprovalAuditEvent",
    "PlanApprovalDecision",
    "PlanApprovalError",
    "PlanApprovalRequest",
    "PlanApprovalService",
    "PlanApprovalStatus",
    "PlanApprovalStore",
    "PlanExecutionAuthorization",
    "PlanExecutionGate",
    "PlanLiveValidator",
    "PlanNotRequestableError",
    "PlanRepository",
    "PlanSnapshotStore",
    "PlanStaleError",
    "PlanValidationContext",
    "PlannedExecutionGuard",
    "UnauthenticatedReceiptError",
    "UnknownBrokerRequestError",
    "compute_plan_binding_digest",
    "compute_risk_digest",
    "compute_verification_digest",
    "evaluate_approval_requirement",
    "generate_nonce",
    "generate_receipt_token",
    "hash_nonce",
    "hash_receipt_token",
    "verify_nonce",
    "verify_receipt_token",
]
