"""Plan approval state machine service.

Single server-side entry point that:

* Decides whether a plan needs human approval (server-authoritative — client
  ``approved`` / ``requires_approval`` / ``risk`` / ``status`` fields are
  IGNORED).
* Creates a broker request via the unified :class:`ApprovalBroker`
  (namespaced ``plan-execution:`` so it never collides with Task approvals or
  destructive-operation approvals) using a DURABLE registration flow:
  insert ``registering`` row → register broker → atomically flip to ``pending``.
* Binds every approval to the WHOLE plan + repository state via a SHA-256
  binding digest.
* Performs the same validation (via :class:`PlanLiveValidator`) at request
  creation and at decision time.
* Applies approve/reject ONLY via an authenticated :class:`BrokerDecisionReceipt`
  minted by the broker — never via a caller-supplied ``approved: bool``.
* Records decision + audit + receipt consumption in ONE atomic transaction.

This service is *not* reachable from the Agent loop. Approval decisions must
arrive through the broker callback (an authenticated human-in-the-loop path).
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any, Protocol, TYPE_CHECKING

from khaos.coding.planning.approval.models import (
    BrokerDecisionReceipt,
    PlanApprovalAuditEvent,
    PlanApprovalDecision,
    PlanApprovalRequest,
    PlanApprovalStatus,
    PlanValidationContext,
)
from khaos.coding.planning.approval.repository import PlanRepository, PlanSnapshotStore
from khaos.coding.planning.approval.validator import (
    PlanLiveValidator,
    PlanNotRequestableError as _ValidatorNotRequestable,
    PlanStaleError as _ValidatorStale,
)
from khaos.coding.planning.approval.store import (
    ApprovalTransitionResult,
    PlanApprovalStore,
    new_event_id,
    new_request_id,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from khaos.coding.planning.approval.models import Clock
    from khaos.coding.planning.contracts import ImplementationPlan

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class PlanApprovalError(Exception):
    """Base error for the plan approval subsystem."""


class PlanNotRequestableError(PlanApprovalError):
    """The plan cannot be approved right now (blocked/stale/task dead/...)."""


class PlanStaleError(PlanApprovalError):
    """The plan or repository state drifted between request and decision."""


class ApprovalConflictError(PlanApprovalError):
    """An opposite decision was already applied."""


class UnknownBrokerRequestError(PlanApprovalError):
    """The broker callback referenced an unknown request."""


class UnauthenticatedReceiptError(PlanApprovalError):
    """A decision was supplied without a valid broker receipt (§1)."""


# ---------------------------------------------------------------------------
# Context provider — abstracts Task / Workspace / Repository lookups
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CurrentRepositoryState:
    """Snapshot of the repository + task + workspace state at validation time."""

    repository_id: str
    task_id: str
    workspace_id: str
    head_sha: str
    repository_generation: int
    task_active: bool
    workspace_active: bool
    task_terminal: bool
    workspace_terminal: bool


class ContextProvider(Protocol):
    """Read-only accessor for live Task/Workspace/Repository state."""

    def current_state(
        self,
        *,
        repository_id: str,
        task_id: str,
        workspace_id: str,
    ) -> CurrentRepositoryState:  # pragma: no cover - protocol
        ...


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ApprovalPolicy:
    """Tunable knobs for the approval state machine."""

    pending_ttl_seconds: float = 3600.0  # 1h
    approved_ttl_seconds: float = 1800.0  # 30m
    max_scope_items: int = 500


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------


class PlanApprovalService:
    """Server-side plan approval state machine.

    Batch 2.1 hardening:

    * ``apply_broker_decision`` accepts ONLY a :class:`BrokerDecisionReceipt`
      (minted by ``ApprovalBroker.resolve_plan_approval``). The old
      ``(approved: bool, actor_id, actor_type)`` signature is GONE — a
      caller can no longer forge an approval by passing ``approved=True``.
    * Request creation uses a durable registration flow: the request row is
      inserted as ``registering`` BEFORE the broker is contacted, then
      atomically flipped to ``pending`` with the broker_request_id. A crash
      between the two leaves a recoverable ``registering`` row, not an orphan.
    * Validation is delegated to :class:`PlanLiveValidator`, shared with the
      execution gate, so the four validation stages cannot diverge.
    """

    def __init__(
        self,
        store: PlanApprovalStore,
        broker: Any,
        context_provider: ContextProvider,
        plan_repository: PlanRepository | None = None,
        planning_service: Any | None = None,
        policy: ApprovalPolicy | None = None,
        clock: Any = time.time,
    ) -> None:
        self._store = store
        self._broker = broker
        self._context_provider = context_provider
        self._plan_repository = plan_repository or PlanSnapshotStore()
        self._planning_service = planning_service
        self._policy = policy or ApprovalPolicy()
        self._clock = clock
        self._validator = PlanLiveValidator(
            plan_repository=self._plan_repository,
            context_provider=context_provider,
            planning_service=planning_service,
        )

    # ------------------------------------------------------------------
    # Expose the plan repository so callers can register authoritative snapshots
    # ------------------------------------------------------------------

    @property
    def plan_repository(self) -> PlanRepository:
        return self._plan_repository

    def register_plan(self, plan: "ImplementationPlan") -> bool:
        """Register the authoritative plan snapshot. Returns False if a
        snapshot with the same plan_id but different content_hash already
        exists (refused — use a new plan_id)."""
        result = self._plan_repository.register(plan)  # type: ignore[attr-defined]
        # In-memory PlanSnapshotStore.register returns None; treat as success.
        return True if result is None else bool(result)

    # ------------------------------------------------------------------
    # Validation (delegates to the shared PlanLiveValidator)
    # ------------------------------------------------------------------

    def _validate_for_approval(self, plan: "ImplementationPlan") -> PlanValidationContext:
        """Validate via the shared :class:`PlanLiveValidator`.

        Catches the validator's errors and re-raises them as the service-level
        error types so callers see a single hierarchy.
        """
        try:
            return self._validator.validate_plan(plan)
        except _ValidatorStale as exc:
            raise PlanStaleError(str(exc)) from exc
        except _ValidatorNotRequestable as exc:
            raise PlanNotRequestableError(str(exc)) from exc

    # ------------------------------------------------------------------
    # Step 2/3: create or fetch an approval request (durable registration)
    # ------------------------------------------------------------------

    def request_approval(
        self,
        plan: "ImplementationPlan",
        *,
        actor_id: str = "system",
        reason: str = "",
    ) -> PlanApprovalRequest:
        """Create (or return an existing) approval request for a plan.

        Durable registration flow (§7):

        1. Validate + compute binding digest.
        2. Register the authoritative plan snapshot.
        3. Insert the request row as ``registering`` (or ``not-required``)
           and COMMIT — so the row is durable before the broker is contacted.
        4. For approval-required plans: register the broker; on success
           atomically flip ``registering → pending`` + attach
           ``broker_request_id``; on failure flip to ``registration-failed``.
        """
        ctx = self._validate_for_approval(plan)
        # Register the authoritative snapshot so the gate can resolve it later.
        # Batch 2.3 §9: if the plan_id is already registered with DIFFERENT
        # content, refuse to create the request (no silent overwrite).
        if not self.register_plan(plan):
            raise PlanApprovalError(
                f"plan_id {plan.plan_id} is already registered with different "
                "content; use a new plan_id or explicit revision"
            )

        existing = self._store.find_request_by_plan_binding(plan.plan_id, ctx.binding_digest)
        if existing is not None and not existing.status.is_terminal:
            return existing
        if existing is not None and existing.status == PlanApprovalStatus.PENDING:
            return existing

        now = float(self._clock())
        approval_request_id = new_request_id()

        # ---- not-required path ----
        if not ctx.requires_approval:
            request = self._build_request(
                approval_request_id, plan, ctx, now,
                expires_at=now + self._policy.approved_ttl_seconds,
                status=PlanApprovalStatus.NOT_REQUIRED,
                broker_request_id="",
                reason=reason or "not-required:" + ",".join(ctx.reason_codes),
            )
            self._store.insert_request(request)
            self._record_audit(
                request=request, previous_status="(none)",
                new_status=PlanApprovalStatus.NOT_REQUIRED.value,
                actor_id=actor_id, actor_type="system",
                reason_code="not-required", correlation_id=approval_request_id,
            )
            logger.info("plan %s does not require approval (request %s)", plan.plan_id, approval_request_id)
            return request

        # ---- approval-required path: durable registration ----
        # Step 3: insert as registering first (durable).
        registering = self._build_request(
            approval_request_id, plan, ctx, now,
            expires_at=now + self._policy.pending_ttl_seconds,
            status=PlanApprovalStatus.REGISTERING,
            broker_request_id="",
            reason=reason or "registering:" + ",".join(ctx.reason_codes),
        )
        self._store.insert_request(registering)
        self._record_audit(
            request=registering, previous_status="(none)",
            new_status=PlanApprovalStatus.REGISTERING.value,
            actor_id=actor_id, actor_type="system",
            reason_code="registering", correlation_id=approval_request_id,
        )

        # Step 4: contact the broker.
        binding = self._broker_binding(ctx)
        summary = self._broker_summary(ctx)
        try:
            broker_request_id = self._broker_register(
                approval_request_id=approval_request_id,
                binding=binding, summary=summary,
                expires_at=now + self._policy.pending_ttl_seconds,
            )
        except Exception as exc:
            # Broker failed — mark registration-failed (durable, terminal).
            logger.error("broker registration failed for %s: %s", approval_request_id, exc)
            self._store.transition_request_status(
                approval_request_id,
                expected={PlanApprovalStatus.REGISTERING},
                target=PlanApprovalStatus.REGISTRATION_FAILED,
            )
            self._record_audit(
                request=registering, previous_status=PlanApprovalStatus.REGISTERING.value,
                new_status=PlanApprovalStatus.REGISTRATION_FAILED.value,
                actor_id=actor_id, actor_type="system",
                reason_code="registration-failed", correlation_id=approval_request_id,
            )
            raise PlanApprovalError(f"broker registration failed: {exc}") from exc

        # Atomically attach broker_request_id + flip to pending.
        self._store.set_request_broker(approval_request_id, broker_request_id, pending=True)
        request = self._build_request(
            approval_request_id, plan, ctx, now,
            expires_at=now + self._policy.pending_ttl_seconds,
            status=PlanApprovalStatus.PENDING,
            broker_request_id=broker_request_id,
            reason=reason or "pending:" + ",".join(ctx.reason_codes),
        )
        self._record_audit(
            request=request, previous_status=PlanApprovalStatus.REGISTERING.value,
            new_status=PlanApprovalStatus.PENDING.value,
            actor_id=actor_id, actor_type="system",
            reason_code="registered", correlation_id=approval_request_id,
        )
        logger.info(
            "plan %s requires approval; request %s pending (broker=%s)",
            plan.plan_id, approval_request_id, broker_request_id,
        )
        return request

    def _build_request(
        self,
        approval_request_id: str,
        plan: "ImplementationPlan",
        ctx: PlanValidationContext,
        now: float,
        *,
        expires_at: float,
        status: PlanApprovalStatus,
        broker_request_id: str,
        reason: str,
    ) -> PlanApprovalRequest:
        return PlanApprovalRequest(
            approval_request_id=approval_request_id,
            plan_id=plan.plan_id,
            plan_content_hash=plan.content_hash,
            repository_id=plan.repository_id,
            task_id=plan.task_id,
            workspace_id=plan.workspace_id,
            base_sha=plan.base_sha,
            repository_generation=int(plan.repository_generation),
            risk_level=ctx.risk_level,
            requested_operations=tuple(
                sorted({getattr(f.operation, "value", str(f.operation)) for f in plan.affected_files})
            ),
            affected_files=tuple(sorted({f.path for f in plan.affected_files})),
            affected_symbols=tuple(
                sorted({s.stable_symbol_id for s in plan.affected_symbols if s.stable_symbol_id})
            ),
            verification_digest=ctx.verification_digest,
            binding_digest=ctx.binding_digest,
            requested_at=now,
            expires_at=expires_at,
            status=status,
            broker_request_id=broker_request_id,
            reason=reason,
            metadata={"reason_codes": list(ctx.reason_codes)},
        )

    # ------------------------------------------------------------------
    # Step 5: broker approve/reject — receipt-based (§1)
    # ------------------------------------------------------------------

    def apply_broker_decision(
        self,
        receipt: BrokerDecisionReceipt,
    ) -> PlanApprovalRequest:
        """Apply a broker decision carried by an authenticated receipt.

        The receipt MUST be a :class:`BrokerDecisionReceipt` produced by
        :meth:`ApprovalBroker.resolve_plan_approval`. The old
        ``(approved: bool, actor_id, actor_type)`` signature is gone — a caller
        cannot forge an approval because the receipt carries a one-time token
        whose hash must match a row in the ``plan_approval_receipts`` outbox
        that only the broker can create.

        Batch 2.2: the ``current_plan`` parameter is GONE. The authoritative
        plan is resolved by ``request.plan_id`` from the persisted
        :class:`PlanRepository`, then validated via
        :meth:`PlanLiveValidator.validate(plan_id)`. A caller cannot influence
        validation by passing a forged plan.
        """
        # The receipt must be a real BrokerDecisionReceipt (not a dict / bool).
        if not isinstance(receipt, BrokerDecisionReceipt):
            raise UnauthenticatedReceiptError(
                "apply_broker_decision requires a BrokerDecisionReceipt; "
                "forged dataclasses or bool inputs are refused"
            )
        if receipt.namespace != "plan-execution":
            raise UnauthenticatedReceiptError(
                f"receipt namespace {receipt.namespace!r} is not plan-execution"
            )

        request = self._store.get_request_by_broker(receipt.broker_request_id)
        if request is None:
            raise UnknownBrokerRequestError(receipt.broker_request_id)
        if receipt.approval_request_id != request.approval_request_id:
            raise UnauthenticatedReceiptError("receipt approval_request_id mismatch")

        # Expiry check (pre-flight; the atomic method re-checks).
        now = float(self._clock())
        if now >= request.expires_at:
            self._store.mark_expired(request.approval_request_id, now=now)
            self._record_audit(
                request=request, previous_status=request.status.value,
                new_status=PlanApprovalStatus.EXPIRED.value,
                actor_id=receipt.authenticated_actor_id,
                actor_type=receipt.authenticated_actor_type,
                reason_code="expired", correlation_id=receipt.broker_request_id,
            )
            raise PlanNotRequestableError("request expired before decision")

        # Resolve the AUTHORITATIVE plan snapshot by plan_id (Batch 2.2 §4).
        # No caller-supplied plan object is accepted.
        try:
            ctx = self._validator.validate(request.plan_id)
        except _ValidatorStale as exc:
            self._transition(
                request=request, target=PlanApprovalStatus.STALE,
                expected={PlanApprovalStatus.PENDING, PlanApprovalStatus.APPROVED},
                actor_id=receipt.authenticated_actor_id,
                actor_type=receipt.authenticated_actor_type,
                reason_code="stale-on-decision", reason=str(exc),
                correlation_id=receipt.broker_request_id,
            )
            self._store.revoke_authorizations_for_request(request.approval_request_id)
            raise PlanStaleError(str(exc)) from exc
        except _ValidatorNotRequestable as exc:
            raise PlanNotRequestableError(str(exc)) from exc

        if ctx.binding_digest != request.binding_digest:
            self._transition(
                request=request, target=PlanApprovalStatus.STALE,
                expected={PlanApprovalStatus.PENDING, PlanApprovalStatus.APPROVED},
                actor_id=receipt.authenticated_actor_id,
                actor_type=receipt.authenticated_actor_type,
                reason_code="binding-drift-on-decision", reason="binding digest changed",
                correlation_id=receipt.broker_request_id,
            )
            self._store.revoke_authorizations_for_request(request.approval_request_id)
            raise PlanStaleError("binding digest changed between request and decision")

        # NOTE (Batch 2.2 §1.4): there is NO early idempotency return here.
        # The request-already-approved case is handled INSIDE the store's
        # apply_authenticated_decision, which verifies the receipt's token +
        # ALL authoritative fields BEFORE returning UNCHANGED. An early return
        # here would let a tampered receipt (same decision, different actor)
        # skip verification.

        # Build the decision + audit records.
        decision_record = PlanApprovalDecision(
            approval_request_id=request.approval_request_id,
            decision=receipt.decision,
            actor_id=receipt.authenticated_actor_id,
            actor_type=receipt.authenticated_actor_type,
            decided_at=now,
            reason=receipt.metadata.get("reason", ""),
            authenticated_context={
                "broker_request_id": receipt.broker_request_id,
                "receipt_id": receipt.receipt_id,
                "binding_digest": ctx.binding_digest,
                "authenticated_source": receipt.authenticated_source,
                "session_request_id": receipt.session_request_id,
            },
        )
        new_expiry = None
        if receipt.decision == PlanApprovalStatus.APPROVED:
            new_expiry = now + self._policy.approved_ttl_seconds
        audit_event = PlanApprovalAuditEvent(
            event_id=new_event_id(),
            event_type=f"plan-approval:{receipt.decision.value}",
            approval_request_id=request.approval_request_id,
            plan_id=request.plan_id,
            previous_status=request.status.value,
            new_status=receipt.decision.value,
            actor_id=receipt.authenticated_actor_id,
            actor_type=receipt.authenticated_actor_type,
            authenticated_source=receipt.authenticated_source,
            timestamp=now,
            reason_code=receipt.decision.value,
            task_id=request.task_id,
            workspace_id=request.workspace_id,
            repository_id=request.repository_id,
            correlation_id=receipt.broker_request_id,
        )

        # The atomic transaction: status + decision + audit + expiry + receipt
        # consumption all commit or all roll back (§2). The full receipt is
        # passed so every authoritative field is verified (Batch 2.2 §1).
        result = self._store.apply_authenticated_decision(
            approval_request_id=request.approval_request_id,
            receipt=receipt,
            decision_record=decision_record,
            audit_event=audit_event,
            new_expiry=new_expiry,
            now=now,
        )
        if result == ApprovalTransitionResult.UPDATED:
            logger.info(
                "applied %s to request %s (atomically: status+decision+audit+receipt)",
                receipt.decision.value, request.approval_request_id,
            )
        elif result == ApprovalTransitionResult.UNCHANGED:
            logger.info("idempotent %s on request %s", receipt.decision.value, request.approval_request_id)
        elif result == ApprovalTransitionResult.STALE:
            self._store.revoke_authorizations_for_request(request.approval_request_id)
            raise PlanStaleError("binding drift while applying decision")
        elif result == ApprovalTransitionResult.CONFLICT:
            raise ApprovalConflictError(
                f"cannot apply {receipt.decision.value}; receipt replay or state conflict"
            )
        elif result == ApprovalTransitionResult.NOT_FOUND:
            raise UnauthenticatedReceiptError(
                "receipt token not found in outbox (forged or unknown receipt)"
            )

        return self._store.get_request(request.approval_request_id)  # type: ignore[return-value]

    # ------------------------------------------------------------------
    # Reconciliation (§7) — recover registering/pending rows at startup
    # ------------------------------------------------------------------

    def reconcile(self, *, actor_id: str = "system", now: float | None = None) -> dict[str, int]:
        """Re-register any ``registering`` / ``pending`` rows with the broker.

        Called at process startup. ``registering`` rows that lost their broker
        registration to a crash are re-registered (or marked stale if their
        binding/plan is no longer valid). ``pending`` rows whose broker
        registration vanished (in-memory broker lost) are re-registered too.

        Returns a small summary ``{re-registered, staled, left-pending}``.
        """
        now = float(self._clock() if now is None else now)
        counts = {"re_registered": 0, "staled": 0, "left_pending": 0}
        for request in self._store.list_registering_or_pending():
            if request.status == PlanApprovalStatus.REGISTERING:
                # Attempt re-registration. We can't rebuild the original
                # binding/summary without the plan, so mark stale if the plan
                # snapshot is gone; otherwise re-register.
                plan = self._plan_repository.get(request.plan_id)
                if plan is None:
                    self._store.transition_request_status(
                        request.approval_request_id,
                        expected={PlanApprovalStatus.REGISTERING},
                        target=PlanApprovalStatus.STALE,
                    )
                    counts["staled"] += 1
                    continue
                try:
                    ctx = self._validator.validate_plan(plan)
                except Exception:
                    self._store.transition_request_status(
                        request.approval_request_id,
                        expected={PlanApprovalStatus.REGISTERING},
                        target=PlanApprovalStatus.STALE,
                    )
                    counts["staled"] += 1
                    continue
                binding = self._broker_binding(ctx)
                summary = self._broker_summary(ctx)
                try:
                    brid = self._broker_register(
                        approval_request_id=request.approval_request_id,
                        binding=binding, summary=summary,
                        expires_at=request.expires_at,
                    )
                    self._store.set_request_broker(request.approval_request_id, brid, pending=True)
                    counts["re_registered"] += 1
                except Exception:
                    self._store.transition_request_status(
                        request.approval_request_id,
                        expected={PlanApprovalStatus.REGISTERING},
                        target=PlanApprovalStatus.REGISTRATION_FAILED,
                    )
                    counts["staled"] += 1
            elif request.status == PlanApprovalStatus.PENDING:
                # Re-register with the broker (idempotent) so callbacks can
                # still resolve. If the broker has no memory of it, this
                # refreshes the registration.
                plan = self._plan_repository.get(request.plan_id)
                if plan is None:
                    self._store.transition_request_status(
                        request.approval_request_id,
                        expected={PlanApprovalStatus.PENDING},
                        target=PlanApprovalStatus.STALE,
                    )
                    counts["staled"] += 1
                    continue
                try:
                    ctx = self._validator.validate_plan(plan)
                except Exception:
                    self._store.transition_request_status(
                        request.approval_request_id,
                        expected={PlanApprovalStatus.PENDING},
                        target=PlanApprovalStatus.STALE,
                    )
                    counts["staled"] += 1
                    continue
                binding = self._broker_binding(ctx)
                summary = self._broker_summary(ctx)
                try:
                    self._broker_register(
                        approval_request_id=request.approval_request_id,
                        binding=binding, summary=summary,
                        expires_at=request.expires_at,
                    )
                    counts["left_pending"] += 1
                except Exception:
                    counts["left_pending"] += 1
        return counts

    # ------------------------------------------------------------------
    # Revocation / invalidation
    # ------------------------------------------------------------------

    def revoke(
        self,
        approval_request_id: str,
        *,
        actor_id: str = "system",
        actor_type: str = "system",
        reason: str = "",
    ) -> PlanApprovalRequest:
        """Atomically revoke a request AND all its active authorizations (§6).

        ONE ``BEGIN IMMEDIATE`` via
        :meth:`PlanApprovalStore.invalidate_request_and_authorizations` — no
        request=revoked + auth=active window.
        """
        request = self._store.get_request(approval_request_id)
        if request is None:
            raise PlanApprovalError(f"unknown approval request {approval_request_id}")
        now = float(self._clock())
        audit = PlanApprovalAuditEvent(
            event_id=new_event_id(),
            event_type="plan-approval:revoked",
            approval_request_id=request.approval_request_id,
            plan_id=request.plan_id,
            previous_status=request.status.value,
            new_status=PlanApprovalStatus.REVOKED.value,
            actor_id=actor_id, actor_type=actor_type,
            authenticated_source=actor_type,
            timestamp=now, reason_code="revoked",
            task_id=request.task_id, workspace_id=request.workspace_id,
            repository_id=request.repository_id,
            correlation_id=approval_request_id,
        )
        result = self._store.invalidate_request_and_authorizations(
            approval_request_id,
            target_status=PlanApprovalStatus.REVOKED,
            expected_statuses={
                PlanApprovalStatus.APPROVED, PlanApprovalStatus.PENDING,
                PlanApprovalStatus.REGISTERING, PlanApprovalStatus.NOT_REQUIRED,
            },
            audit_event=audit,
            now=now,
        )
        if result.value in ("conflict", "invalid_transition"):
            raise ApprovalConflictError(
                f"cannot revoke request in status {request.status.value}"
            )
        return self._store.get_request(approval_request_id)  # type: ignore[return-value]

    def invalidate_for_task(
        self, *, task_id: str, actor_id: str = "system", reason: str = "task terminal"
    ) -> int:
        """Atomically stale every active request for a task AND revoke their
        authorizations (§6). Each request+authorization pair is invalidated
        in one ``BEGIN IMMEDIATE`` transaction.
        """
        count = 0
        now = float(self._clock())
        for request in self._store.list_requests_for_task(task_id):
            if request.status in (PlanApprovalStatus.PENDING, PlanApprovalStatus.APPROVED, PlanApprovalStatus.REGISTERING, PlanApprovalStatus.NOT_REQUIRED):
                audit = PlanApprovalAuditEvent(
                    event_id=new_event_id(),
                    event_type="plan-approval:stale",
                    approval_request_id=request.approval_request_id,
                    plan_id=request.plan_id,
                    previous_status=request.status.value,
                    new_status=PlanApprovalStatus.STALE.value,
                    actor_id=actor_id, actor_type="system",
                    authenticated_source="system",
                    timestamp=now, reason_code="task-invalidation",
                    task_id=request.task_id, workspace_id=request.workspace_id,
                    repository_id=request.repository_id,
                    correlation_id=f"task:{task_id}",
                )
                result = self._store.invalidate_request_and_authorizations(
                    request.approval_request_id,
                    target_status=PlanApprovalStatus.STALE,
                    expected_statuses={
                        PlanApprovalStatus.PENDING, PlanApprovalStatus.APPROVED,
                        PlanApprovalStatus.REGISTERING, PlanApprovalStatus.NOT_REQUIRED,
                    },
                    audit_event=audit,
                    now=now,
                )
                if result.value == "updated":
                    count += 1
        return count

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _transition(
        self, *, request: PlanApprovalRequest, target: PlanApprovalStatus,
        expected: set[PlanApprovalStatus], actor_id: str, actor_type: str,
        reason_code: str, reason: str, correlation_id: str,
    ) -> None:
        previous = request.status
        audit = PlanApprovalAuditEvent(
            event_id=new_event_id(),
            event_type=f"plan-approval:{target.value}",
            approval_request_id=request.approval_request_id,
            plan_id=request.plan_id,
            previous_status=previous.value,
            new_status=target.value,
            actor_id=actor_id, actor_type=actor_type,
            authenticated_source=actor_type,
            timestamp=float(self._clock()),
            reason_code=reason_code,
            task_id=request.task_id, workspace_id=request.workspace_id,
            repository_id=request.repository_id, correlation_id=correlation_id,
        )
        result = self._store.transition_request_status(
            request.approval_request_id, expected=expected, target=target, audit_event=audit,
        )
        if result == ApprovalTransitionResult.UPDATED:
            return
        if result == ApprovalTransitionResult.UNCHANGED:
            return
        if result in (ApprovalTransitionResult.CONFLICT, ApprovalTransitionResult.INVALID_TRANSITION):
            raise ApprovalConflictError(
                f"cannot transition {previous.value} → {target.value} for {request.approval_request_id}"
            )
        if result == ApprovalTransitionResult.STALE:
            raise PlanStaleError(f"binding drift while transitioning {request.approval_request_id}")
        if result == ApprovalTransitionResult.NOT_FOUND:
            raise PlanApprovalError(f"unknown approval request {request.approval_request_id}")

    def _record_audit(
        self, *, request: PlanApprovalRequest, previous_status: str, new_status: str,
        actor_id: str, actor_type: str, reason_code: str, correlation_id: str,
        reason: str = "",
    ) -> None:
        event = PlanApprovalAuditEvent(
            event_id=new_event_id(), event_type=f"plan-approval:{new_status}",
            approval_request_id=request.approval_request_id, plan_id=request.plan_id,
            previous_status=previous_status, new_status=new_status,
            actor_id=actor_id, actor_type=actor_type,
            authenticated_source=actor_type, timestamp=float(self._clock()),
            reason_code=reason_code, task_id=request.task_id,
            workspace_id=request.workspace_id, repository_id=request.repository_id,
            correlation_id=correlation_id,
        )
        self._store.insert_audit_event(event)

    @staticmethod
    def _broker_binding(ctx: PlanValidationContext) -> dict:
        return {
            "plan_id": ctx.plan.plan_id,
            "plan_content_hash": ctx.plan.content_hash,
            "binding_digest": ctx.binding_digest,
            "repository_id": ctx.plan.repository_id,
            "task_id": ctx.plan.task_id,
            "workspace_id": ctx.plan.workspace_id,
            "base_sha": ctx.plan.base_sha,
            "repository_generation": int(ctx.plan.repository_generation),
        }

    @staticmethod
    def _broker_summary(ctx: PlanValidationContext) -> dict:
        return {
            "plan_id": ctx.plan.plan_id,
            "summary": ctx.plan.summary[:500],
            "risk_level": ctx.risk_level,
            "requires_approval": ctx.requires_approval,
            "reason_codes": list(ctx.reason_codes),
            "affected_files_count": len(ctx.plan.affected_files),
            "affected_symbols_count": len(ctx.plan.affected_symbols),
            "verification_digest": ctx.verification_digest,
            "base_sha": ctx.plan.base_sha,
            "repository_generation": int(ctx.plan.repository_generation),
        }

    def _broker_register(
        self, *, approval_request_id: str, binding: dict, summary: dict, expires_at: float
    ) -> str:
        """Register with the broker, awaiting async brokers via a private loop."""
        result = self._broker.register_plan_approval(
            approval_request_id=approval_request_id, binding=binding,
            summary=summary, expires_at=expires_at,
        )
        if hasattr(result, "__await__"):
            return _run(result)
        return result


def _run(coro: Any) -> Any:
    """Await a coroutine from a sync context."""
    import asyncio

    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                return pool.submit(asyncio.run, coro).result()
    except RuntimeError:
        pass
    return asyncio.run(coro)
