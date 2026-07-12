"""Plan approval state machine service.

Single server-side entry point that:

* Decides whether a plan needs human approval (server-authoritative — client
  ``approved`` / ``requires_approval`` / ``risk`` / ``status`` fields are
  IGNORED).
* Creates a broker request via the unified :class:`ApprovalBroker`
  (namespaced ``plan-execution:`` so it never collides with Task approvals or
  destructive-operation approvals).
* Binds every approval to the WHOLE plan + repository state via a SHA-256
  binding digest.
* Performs the same validation TWICE: once before creating the request, and
  once inside the approve callback (catching drift between request and
  decision).
* Applies approve/reject via atomic Compare-And-Swap, with idempotency for
  repeat decisions and conflicts for opposite decisions.
* Records a structured audit event for every transition.

This service is *not* reachable from the Agent loop. Approval decisions must
arrive through the broker callback (an authenticated human-in-the-loop path).
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any, Protocol, TYPE_CHECKING

from khaos.coding.planning.approval.models import (
    PlanApprovalAuditEvent,
    PlanApprovalDecision,
    PlanApprovalRequest,
    PlanApprovalStatus,
    PlanExecutionAuthorization,
    compute_plan_binding_digest,
    compute_verification_digest,
)
from khaos.coding.planning.approval.requirement import evaluate_approval_requirement
from khaos.coding.planning.approval.store import (
    ApprovalTransitionResult,
    PlanApprovalStore,
    new_event_id,
    new_request_id,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
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
    """Read-only accessor for live Task/Workspace/Repository state.

    Implementations may query :class:`TaskManager`, :class:`WorkspaceManager`
    and the repository index. The service never writes through this provider.
    """

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

    #: Seconds before a pending request expires.
    pending_ttl_seconds: float = 3600.0  # 1h
    #: Seconds before an approved request expires.
    approved_ttl_seconds: float = 1800.0  # 30m
    #: Hard ceiling on requested_operations / files / symbols we accept.
    max_scope_items: int = 500


# ---------------------------------------------------------------------------
# Result of a successful pre-validation (used both at request time and at
# approve-callback time, with the binding digest recomputed each call).
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PlanValidationContext:
    """The frozen view of a plan + repository used to create an approval."""

    plan: "ImplementationPlan"
    state: CurrentRepositoryState
    binding_digest: str
    verification_digest: str
    risk_level: str
    requires_approval: bool
    reason_codes: tuple[str, ...]


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------


class PlanApprovalService:
    """Server-side plan approval state machine.

    Construction takes the durable :class:`PlanApprovalStore`, the in-memory
    unified :class:`ApprovalBroker`, a :class:`ContextProvider` for live
    repository state, and an :class:`ApprovalPolicy`.

    The service does NOT execute plans, does NOT call tools, does NOT write
    repository files, and does NOT create or apply ChangeSets. It only
    manages approval state and emits authorizations (via the separate
    :class:`PlanExecutionGate`).
    """

    def __init__(
        self,
        store: PlanApprovalStore,
        broker: Any,
        context_provider: ContextProvider,
        planning_service: Any | None = None,
        policy: ApprovalPolicy | None = None,
        clock: Any = time.time,
    ) -> None:
        self._store = store
        self._broker = broker
        self._context_provider = context_provider
        self._planning_service = planning_service
        self._policy = policy or ApprovalPolicy()
        self._clock = clock

    # ------------------------------------------------------------------
    # Step 1 + 7: pre-validation (and re-validation helper)
    # ------------------------------------------------------------------

    def _validate_for_approval(
        self,
        plan: "ImplementationPlan",
        *,
        recompute_risk: bool = True,
    ) -> PlanValidationContext:
        """Run every pre-condition from spec §7 against the live state.

        Raises :class:`PlanNotRequestableError` (with a specific reason) on
        any failure. Returns the frozen validation context (including the
        freshly recomputed binding digest) on success.
        """
        # 2 — plan must not be blocked/stale itself.
        status = plan.status
        status_value = getattr(status, "value", str(status))
        if status_value in {"blocked", "stale"}:
            raise PlanNotRequestableError(f"plan status is {status_value}")

        # 3/4/5 — repository, task, workspace must be active and consistent.
        state = self._context_provider.current_state(
            repository_id=plan.repository_id,
            task_id=plan.task_id,
            workspace_id=plan.workspace_id,
        )
        if state.repository_id != plan.repository_id:
            raise PlanNotRequestableError("repository id mismatch")
        if state.task_id != plan.task_id:
            raise PlanNotRequestableError("task id mismatch")
        if state.workspace_id != plan.workspace_id:
            raise PlanNotRequestableError("workspace id mismatch")
        if state.task_terminal:
            raise PlanNotRequestableError("task is terminal")
        if state.workspace_terminal:
            raise PlanNotRequestableError("workspace is terminal")

        # 6/7 — HEAD + repository generation must match the plan.
        if state.head_sha != plan.base_sha:
            raise PlanStaleError(
                f"head drift: plan={plan.base_sha} current={state.head_sha}"
            )
        if int(state.repository_generation) != int(plan.repository_generation):
            raise PlanStaleError(
                f"generation drift: plan={plan.repository_generation} "
                f"current={state.repository_generation}"
            )

        # 8 — if a PlanningService is wired in, run its validate_plan() too.
        if self._planning_service is not None:
            try:
                result = self._planning_service.validate_plan(
                    plan,
                    current_head=state.head_sha,
                    current_repository_generation=state.repository_generation,
                )
                if not result.valid:
                    raise PlanStaleError(
                        "planner validation failed: "
                        + ",".join(d.code for d in result.diagnostics)
                    )
            except PlanStaleError:
                raise
            except Exception as exc:  # defensive: planner errors fail closed
                logger.warning("planner validate_plan raised: %s", exc)
                raise PlanNotRequestableError(f"planner validation error: {exc}")

        # 9 — server-authoritative approval requirement (IGNORES client fields).
        outcome = evaluate_approval_requirement(plan)

        # 10 — binding digest.
        binding_digest = compute_plan_binding_digest(plan)
        verification_digest = compute_verification_digest(plan.verification_requirements)

        return PlanValidationContext(
            plan=plan,
            state=state,
            binding_digest=binding_digest,
            verification_digest=verification_digest,
            risk_level=outcome.risk_level,
            requires_approval=outcome.requires_approval,
            reason_codes=outcome.reason_codes,
        )

    # ------------------------------------------------------------------
    # Step 2/3: create or fetch an approval request
    # ------------------------------------------------------------------

    def request_approval(
        self,
        plan: "ImplementationPlan",
        *,
        actor_id: str = "system",
        reason: str = "",
    ) -> PlanApprovalRequest:
        """Create (or return an existing) approval request for a plan.

        Decision flow:

        * Recompute the approval requirement from the final plan.
        * If approval is NOT required → persist a ``not-required`` request and
          return it. No broker request is created; the caller can proceed to
          :meth:`PlanExecutionGate.authorize_execution` immediately.
        * If approval IS required → validate state, compute binding digest,
          register a namespaced broker request, and persist a ``pending``
          request.

        The client cannot influence this path: any ``approved`` /
        ``requires_approval`` / ``risk`` / ``status`` fields carried on or
        alongside the plan are ignored by :func:`evaluate_approval_requirement`.
        """
        ctx = self._validate_for_approval(plan)

        # Idempotent: if a request already exists for this plan + binding,
        # return it. This makes repeated request_approval() calls safe.
        existing = self._find_existing_request(ctx)
        if existing is not None:
            return existing

        now = float(self._clock())
        approval_request_id = new_request_id()

        if not ctx.requires_approval:
            # No human approval needed; still record a not-required request so
            # the gate can bind an authorization to it.
            request = PlanApprovalRequest(
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
                expires_at=now + self._policy.approved_ttl_seconds,
                status=PlanApprovalStatus.NOT_REQUIRED,
                broker_request_id="",
                reason=reason or "not-required:" + ",".join(ctx.reason_codes),
                metadata={"reason_codes": list(ctx.reason_codes)},
            )
            self._store.insert_request(request)
            self._record_audit(
                request=request,
                previous_status="(none)",
                new_status=PlanApprovalStatus.NOT_REQUIRED.value,
                actor_id=actor_id,
                actor_type="system",
                reason_code="not-required",
                correlation_id=approval_request_id,
            )
            logger.info(
                "plan %s does not require approval (request %s)",
                plan.plan_id, approval_request_id,
            )
            return request

        # Approval required → register a broker request (namespaced).
        expires_at = now + self._policy.pending_ttl_seconds
        binding = self._broker_binding(ctx)
        summary = self._broker_summary(ctx)
        broker_request_id = self._broker_sync_register_plan_approval(
            approval_request_id=approval_request_id,
            binding=binding,
            summary=summary,
            expires_at=expires_at,
        )
        request = PlanApprovalRequest(
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
            status=PlanApprovalStatus.PENDING,
            broker_request_id=broker_request_id,
            reason=reason or "pending:" + ",".join(ctx.reason_codes),
            metadata={"reason_codes": list(ctx.reason_codes)},
        )
        self._store.insert_request(request)
        self._record_audit(
            request=request,
            previous_status="(none)",
            new_status=PlanApprovalStatus.PENDING.value,
            actor_id=actor_id,
            actor_type="system",
            reason_code="requested",
            correlation_id=approval_request_id,
        )
        logger.info(
            "plan %s requires approval; request %s pending (broker=%s)",
            plan.plan_id, approval_request_id, broker_request_id,
        )
        return request

    def _find_existing_request(self, ctx: PlanValidationContext) -> PlanApprovalRequest | None:
        """Return a non-terminal request for the same plan + binding if any."""
        # Walk recent requests for this plan. We don't have a direct index by
        # binding_digest, but the audit log + plan index give us the set.
        # For correctness we look up by broker records is not feasible here;
        # instead we scan via the store helper below.
        return self._store_find_by_plan_binding(ctx.plan.plan_id, ctx.binding_digest)

    # ------------------------------------------------------------------
    # Step 5: broker approve/reject callback
    # ------------------------------------------------------------------

    def apply_broker_decision(
        self,
        *,
        broker_request_id: str,
        approved: bool,
        actor_id: str,
        actor_type: str = "user",
        reason: str = "",
        current_plan: "ImplementationPlan | None" = None,
    ) -> PlanApprovalRequest:
        """Apply a broker decision callback to the matching request.

        Re-runs the FULL pre-validation (spec §7) before persisting. If the
        plan/repository drifted between request and decision, the request is
        moved to ``stale`` and a :class:`PlanStaleError` is raised.

        ``current_plan`` MUST be supplied by the caller (the broker callback
        path always re-reads the current plan). Without it we cannot
        re-validate.
        """
        request = self._store.get_request_by_broker(broker_request_id)
        if request is None:
            raise UnknownBrokerRequestError(broker_request_id)

        # Terminal states other than approved/rejected cannot be decided.
        if request.status.is_terminal and request.status not in (PlanApprovalStatus.APPROVED, PlanApprovalStatus.REJECTED):
            raise ApprovalConflictError(
                f"request is already {request.status.value}; cannot decide"
            )

        # Expiry check.
        if time.time() >= request.expires_at:
            self._store.mark_expired(request.approval_request_id)
            self._record_audit(
                request=request,
                previous_status=request.status.value,
                new_status=PlanApprovalStatus.EXPIRED.value,
                actor_id=actor_id,
                actor_type=actor_type,
                reason_code="expired",
                correlation_id=broker_request_id,
            )
            raise PlanNotRequestableError("request expired before decision")

        if current_plan is None:
            raise PlanApprovalError(
                "apply_broker_decision requires current_plan for re-validation"
            )

        # Re-validate the plan against live state — this is the second of the
        # two validations required by spec §7. Drift → stale. This runs BEFORE
        # the idempotency check so that drift is always detected, even on a
        # repeated callback for an already-approved request.
        try:
            ctx = self._validate_for_approval(current_plan)
        except PlanStaleError as exc:
            self._transition(
                request=request,
                target=PlanApprovalStatus.STALE,
                expected={PlanApprovalStatus.PENDING, PlanApprovalStatus.APPROVED},
                actor_id=actor_id,
                actor_type=actor_type,
                reason_code="stale-on-decision",
                reason=str(exc),
                correlation_id=broker_request_id,
                binding_digest=None,
            )
            self._store.revoke_authorizations_for_request(request.approval_request_id)
            raise

        # The plan digest must match what was requested. Drift detection takes
        # priority over idempotency: a changed plan MUST invalidate even an
        # already-approved request.
        if ctx.binding_digest != request.binding_digest:
            self._transition(
                request=request,
                target=PlanApprovalStatus.STALE,
                expected={PlanApprovalStatus.PENDING, PlanApprovalStatus.APPROVED},
                actor_id=actor_id,
                actor_type=actor_type,
                reason_code="binding-drift-on-decision",
                reason="binding digest changed",
                correlation_id=broker_request_id,
                binding_digest=None,
            )
            self._store.revoke_authorizations_for_request(request.approval_request_id)
            raise PlanStaleError("binding digest changed between request and decision")

        # Idempotency: only AFTER drift detection passes. A repeated identical
        # decision for an unchanged plan is a no-op success.
        if request.status == PlanApprovalStatus.APPROVED and approved:
            return request
        if request.status == PlanApprovalStatus.REJECTED and not approved:
            return request

        target = PlanApprovalStatus.APPROVED if approved else PlanApprovalStatus.REJECTED
        self._transition(
            request=request,
            target=target,
            expected={PlanApprovalStatus.PENDING},
            actor_id=actor_id,
            actor_type=actor_type,
            reason_code=target.value,
            reason=reason,
            correlation_id=broker_request_id,
            binding_digest=ctx.binding_digest,
        )

        # Persist the authenticated decision record.
        self._store.insert_decision(
            PlanApprovalDecision(
                approval_request_id=request.approval_request_id,
                decision=target,
                actor_id=actor_id,
                actor_type=actor_type,
                decided_at=float(self._clock()),
                reason=reason,
                authenticated_context={
                    "broker_request_id": broker_request_id,
                    "binding_digest": ctx.binding_digest,
                },
            )
        )

        if approved:
            # Promote expiry to the approved TTL window.
            self._refresh_expiry(request.approval_request_id, approved=True)
        return self._store.get_request(request.approval_request_id)  # type: ignore[return-value]

    # ------------------------------------------------------------------
    # Step 13: revocation / expiry / external invalidation
    # ------------------------------------------------------------------

    def revoke(
        self,
        approval_request_id: str,
        *,
        actor_id: str = "system",
        actor_type: str = "system",
        reason: str = "",
    ) -> PlanApprovalRequest:
        """Revoke an approved request (user / admin / policy / drift)."""
        request = self._store.get_request(approval_request_id)
        if request is None:
            raise PlanApprovalError(f"unknown approval request {approval_request_id}")
        self._transition(
            request=request,
            target=PlanApprovalStatus.REVOKED,
            expected={PlanApprovalStatus.APPROVED, PlanApprovalStatus.PENDING},
            actor_id=actor_id,
            actor_type=actor_type,
            reason_code="revoked",
            reason=reason,
            correlation_id=approval_request_id,
            binding_digest=None,
        )
        # Any outstanding authorizations for this request are dead.
        self._store.revoke_authorizations_for_request(approval_request_id)
        return self._store.get_request(approval_request_id)  # type: ignore[return-value]

    def invalidate_for_task(
        self,
        *,
        task_id: str,
        actor_id: str = "system",
        reason: str = "task terminal",
    ) -> int:
        """Move every still-decidable request for a task to a terminal state.

        Called when a Task is cancelled/terminated or a Workspace is cleaned
        up. Returns the number of requests invalidated.
        """
        count = 0
        for request in self._store_list_requests_for_task(task_id):
            if request.status in (PlanApprovalStatus.PENDING, PlanApprovalStatus.APPROVED):
                target = PlanApprovalStatus.STALE
                try:
                    self._transition(
                        request=request,
                        target=target,
                        expected={PlanApprovalStatus.PENDING, PlanApprovalStatus.APPROVED},
                        actor_id=actor_id,
                        actor_type="system",
                        reason_code="task-invalidation",
                        reason=reason,
                        correlation_id=f"task:{task_id}",
                        binding_digest=None,
                    )
                    self._store.revoke_authorizations_for_request(request.approval_request_id)
                    count += 1
                except ApprovalConflictError:
                    continue
        return count

    # ------------------------------------------------------------------
    # Internal: atomic CAS transition wrapper
    # ------------------------------------------------------------------

    def _transition(
        self,
        *,
        request: PlanApprovalRequest,
        target: PlanApprovalStatus,
        expected: set[PlanApprovalStatus],
        actor_id: str,
        actor_type: str,
        reason_code: str,
        reason: str,
        correlation_id: str,
        binding_digest: str | None,
    ) -> None:
        previous = request.status
        result = self._store.compare_and_set_status(
            request.approval_request_id,
            expected=expected,
            target=target,
            current_binding_digest=binding_digest,
        )
        if result == ApprovalTransitionResult.UPDATED:
            self._record_audit(
                request=request,
                previous_status=previous.value,
                new_status=target.value,
                actor_id=actor_id,
                actor_type=actor_type,
                reason_code=reason_code,
                correlation_id=correlation_id,
                reason=reason,
            )
            return
        if result == ApprovalTransitionResult.UNCHANGED:
            # Idempotent — already in target. Still audit for traceability.
            self._record_audit(
                request=request,
                previous_status=target.value,
                new_status=target.value,
                actor_id=actor_id,
                actor_type=actor_type,
                reason_code=f"idempotent:{reason_code}",
                correlation_id=correlation_id,
                reason=reason,
            )
            return
        if result == ApprovalTransitionResult.CONFLICT:
            raise ApprovalConflictError(
                f"cannot transition {previous.value} → {target.value} "
                f"for {request.approval_request_id}"
            )
        if result == ApprovalTransitionResult.STALE:
            raise PlanStaleError(
                f"binding drift while transitioning {request.approval_request_id}"
            )
        if result == ApprovalTransitionResult.NOT_FOUND:
            raise PlanApprovalError(f"unknown approval request {request.approval_request_id}")
        # INVALID_TRANSITION — fall through as a conflict for caller clarity.
        raise ApprovalConflictError(
            f"invalid transition {previous.value} → {target.value}"
        )

    def _record_audit(
        self,
        *,
        request: PlanApprovalRequest,
        previous_status: str,
        new_status: str,
        actor_id: str,
        actor_type: str,
        reason_code: str,
        correlation_id: str,
        reason: str = "",
    ) -> None:
        event = PlanApprovalAuditEvent(
            event_id=new_event_id(),
            event_type=f"plan-approval:{new_status}",
            approval_request_id=request.approval_request_id,
            plan_id=request.plan_id,
            previous_status=previous_status,
            new_status=new_status,
            actor_id=actor_id,
            actor_type=actor_type,
            authenticated_source=actor_type,
            timestamp=float(self._clock()),
            reason_code=reason_code,
            task_id=request.task_id,
            workspace_id=request.workspace_id,
            repository_id=request.repository_id,
            correlation_id=correlation_id,
        )
        self._store.insert_audit_event(event)

    # ------------------------------------------------------------------
    # Broker integration helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _broker_binding(ctx: PlanValidationContext) -> dict:
        """Build the immutable broker binding for a request.

        NEVER includes source code, credentials, or host absolute paths. The
        path strings here are repository-relative paths, which are safe.
        """
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
        """Human-facing summary shown to the approver.

        Includes risk + scope + verification plan, but NEVER source code,
        credentials or absolute paths.
        """
        return {
            "plan_id": ctx.plan.plan_id,
            "summary": ctx.plan.summary[:500],
            "risk_level": ctx.risk_level,
            "requires_approval": ctx.requires_approval,
            "reason_codes": list(ctx.reason_codes),
            "affected_files": list(ctx.plan.affected_files)[:50],
            "affected_symbols_count": len(ctx.plan.affected_symbols),
            "verification_digest": ctx.verification_digest,
            "base_sha": ctx.plan.base_sha,
            "repository_generation": int(ctx.plan.repository_generation),
        }

    def _broker_sync_register_plan_approval(
        self,
        *,
        approval_request_id: str,
        binding: dict,
        summary: dict,
        expires_at: float,
    ) -> str:
        """Register with the broker, tolerating sync vs async brokers.

        Tests sometimes pass a synchronous fake broker. Production brokers are
        async; we detect and await via :func:`_run`.
        """
        result = self._broker.register_plan_approval(
            approval_request_id=approval_request_id,
            binding=binding,
            summary=summary,
            expires_at=expires_at,
        )
        if hasattr(result, "__await__"):
            return _run(result)
        return result

    def _refresh_expiry(self, approval_request_id: str, *, approved: bool) -> None:
        """Extend (or shorten) a request's expiry when it is approved."""
        ttl = self._policy.approved_ttl_seconds if approved else self._policy.pending_ttl_seconds
        new_expiry = float(self._clock()) + ttl
        self._store_refresh_expiry(approval_request_id, new_expiry)

    # ------------------------------------------------------------------
    # Store wrappers that don't exist yet on PlanApprovalStore (small helpers
    # kept here so the store stays focused on single-row CRUD + CAS).
    # ------------------------------------------------------------------

    def _store_find_by_plan_binding(self, plan_id: str, binding_digest: str) -> PlanApprovalRequest | None:
        import sqlite3

        conn = self._store._conn  # noqa: SLF001 — same package-level access
        row = conn.execute(
            "SELECT * FROM plan_approval_requests WHERE plan_id = ? AND binding_digest = ? "
            "ORDER BY requested_at DESC LIMIT 1",
            (plan_id, binding_digest),
        ).fetchone()
        if row is None:
            return None
        return self._store._row_to_request(row)  # noqa: SLF001

    def _store_list_requests_for_task(self, task_id: str) -> list[PlanApprovalRequest]:
        conn = self._store._conn  # noqa: SLF001
        rows = conn.execute(
            "SELECT * FROM plan_approval_requests WHERE task_id = ? "
            "ORDER BY requested_at ASC",
            (task_id,),
        ).fetchall()
        return [self._store._row_to_request(r) for r in rows]  # noqa: SLF001

    def _store_refresh_expiry(self, approval_request_id: str, new_expiry: float) -> None:
        conn = self._store._conn  # noqa: SLF001
        conn.execute(
            "UPDATE plan_approval_requests SET expires_at = ? WHERE approval_request_id = ?",
            (float(new_expiry), approval_request_id),
        )
        conn.commit()


# ---------------------------------------------------------------------------
# Helper: run an awaitable from a sync context (tests use sync brokers).
# ---------------------------------------------------------------------------


def _run(coro: Any) -> Any:
    """Await a coroutine regardless of whether a loop is running.

    The approval service methods are sync so they can be called from the
    synchronous CAS code path. When the broker is the real async broker we
    still need to drive the coroutine to completion. We do so by creating a
    private event loop (never the running one) so this is safe to call from
    within an existing loop in tests too.
    """
    import asyncio

    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # We're inside a running loop — schedule on a fresh loop in a
            # thread to avoid the "loop already running" error.
            import concurrent.futures

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                return pool.submit(asyncio.run, coro).result()
    except RuntimeError:
        pass
    return asyncio.run(coro)
