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
* :class:`PersistedPlanRepository` / :class:`PlanRepository` — authoritative
  plan snapshot source. ``PlanSnapshotStore`` (in-memory) is NOT exported
  as a production option; it is only importable from
  ``khaos.coding.planning.approval.repository`` for test use.
* :class:`ApprovalRuntime` / :class:`BootContext` — production bootstrap
  that self-wires the Broker → Receipt outbox and fences stale boots.
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
    ApprovalAuthenticator,
    AuthenticatedApprovalContext,
    AuthenticatedSession,
    AuthorizationStatus,
    BrokerDecisionReceipt,
    Clock,
    PlanApprovalAuditEvent,
    PlanApprovalDecision,
    PlanApprovalRequest,
    PlanApprovalStatus,
    PlanExecutionAuthorization,
    PlanValidationContext,
    ReceiptSigner,
    WorkspaceExecutionLease,
    compute_plan_binding_digest,
    compute_reason_digest,
    compute_risk_digest,
    compute_verification_digest,
    generate_nonce,
    generate_receipt_token,
    hash_nonce,
    hash_receipt_token,
    verify_nonce,
    verify_receipt_token,
)
from khaos.coding.planning.approval.mutation_fence import (
    PlannedHeadMutationAdapter,
    WorkspaceMutationFence,
    fenced_acquire_lease,
)
from khaos.coding.planning.approval.repository import (
    PersistedPlanRepository,
    PlanRepository,
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
from khaos.coding.planning.approval.runtime import ApprovalRuntime, BootContext, RuntimeState, WorkspaceExecutionLeaseCoordinator

__all__ = [
    "ALLOWED_APPROVAL_TRANSITIONS",
    "APPROVAL_SCHEMA",
    "ApprovalAuthenticator",
    "AuthenticatedApprovalContext",
    "AuthenticatedSession",
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
    "ApprovalRuntime",
    "ApprovalTransitionResult",
    "BrokerDecisionReceipt",
    "BootContext",
    "Clock",
    "ContextProvider",
    "CurrentRepositoryState",
    "GatePolicy",
    "PersistedPlanRepository",
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
    "PlanStaleError",
    "PlanValidationContext",
    "PlannedExecutionGuard",
    "PlannedHeadMutationAdapter",
    "ReceiptSigner",
    "RuntimeState",
    "UnauthenticatedReceiptError",
    "WorkspaceExecutionLease",
    "WorkspaceExecutionLeaseCoordinator",
    "WorkspaceMutationFence",
    "UnknownBrokerRequestError",
    "fenced_acquire_lease",
    "compute_plan_binding_digest",
    "compute_reason_digest",
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
