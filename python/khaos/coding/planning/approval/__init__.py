"""Plan approval state machine and execution authorization gate (M4 Batch 2).

Public API:

* :class:`PlanApprovalStatus` — approval lifecycle enum.
* :class:`PlanApprovalRequest`, :class:`PlanApprovalDecision`,
  :class:`PlanExecutionAuthorization` — immutable records.
* :class:`PlanApprovalStore` — durable, CAS-backed persistence.
* :class:`PlanApprovalService` — server-side approval state machine.
* :class:`PlanExecutionGate` — single authorization mint+consume point.
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
    PlanApprovalAuditEvent,
    PlanApprovalDecision,
    PlanApprovalRequest,
    PlanApprovalStatus,
    PlanExecutionAuthorization,
    compute_plan_binding_digest,
    compute_risk_digest,
    compute_verification_digest,
    generate_nonce,
    hash_nonce,
    verify_nonce,
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
    PlanValidationContext,
    UnknownBrokerRequestError,
)
from khaos.coding.planning.approval.store import (
    APPROVAL_SCHEMA,
    ApprovalTransitionResult,
    PlanApprovalStore,
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
    "PlanNotRequestableError",
    "PlanStaleError",
    "PlanValidationContext",
    "PlannedExecutionGuard",
    "UnknownBrokerRequestError",
    "compute_plan_binding_digest",
    "compute_risk_digest",
    "compute_verification_digest",
    "evaluate_approval_requirement",
    "generate_nonce",
    "hash_nonce",
    "verify_nonce",
]
