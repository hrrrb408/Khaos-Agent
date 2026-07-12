"""Shared approval broker for tool permissions and task APIs."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field


#: Namespace prefix reserved for plan-execution approval requests. This keeps
#: plan approvals disjoint from Task approvals (keyed by tool_call_id) and
#: from destructive-operation approvals (keyed by ChangeSet approval keys).
PLAN_APPROVAL_NAMESPACE = "plan-execution"


@dataclass(frozen=True)
class ApprovalDecision:
    approved: bool
    remember: bool = False


@dataclass
class PlanApprovalRecord:
    """In-memory state for one plan-execution approval request.

    Lives only inside the broker; durable state is owned by
    :class:`PlanApprovalStore`. The ``binding`` dict mirrors the request's
    binding digest + scope so that callbacks can be validated atomically.
    """

    broker_request_id: str
    approval_request_id: str
    binding: dict
    summary: dict
    expires_at: float
    decision: str | None = None  # None=pending, "approved", "rejected"
    decide_count: int = 0


@dataclass(frozen=True)
class PlanApprovalOutcome:
    """Result of a plan-approval broker decision callback."""

    ok: bool
    decision: str | None  # "approved" | "rejected" | None
    reason: str


class ApprovalBroker:
    """One await/resolve channel keyed by tool call id."""

    def __init__(self) -> None:
        self._pending: dict[str, asyncio.Future[ApprovalDecision]] = {}
        self._decisions: dict[str, ApprovalDecision] = {}
        self._bindings: dict[str, tuple[str, float | None]] = {}
        self._operation_approvals: dict[str, dict] = {}
        # Namespaced plan-execution approvals (disjoint key space).
        self._plan_approvals: dict[str, PlanApprovalRecord] = {}
        self._lock = asyncio.Lock()

    async def bind(self, tool_call_id: str, approval_key: str, expiry: float | None = None) -> None:
        """Bind a pending approval to an immutable ChangeSet operation."""
        async with self._lock:
            self._bindings[tool_call_id] = (approval_key, expiry)

    async def wait(self, tool_call_id: str, timeout: float | None = None) -> dict:
        async with self._lock:
            future = self._pending.get(tool_call_id)
            if future is None:
                decision = self._decisions.pop(tool_call_id, None)
                if decision is not None:
                    self._bindings.pop(tool_call_id, None)
                    return {"approved": decision.approved, "remember": decision.remember}
                future = asyncio.get_running_loop().create_future()
                self._pending[tool_call_id] = future
        try:
            decision = await asyncio.wait_for(asyncio.shield(future), timeout) if timeout else await future
            return {"approved": decision.approved, "remember": decision.remember}
        except asyncio.TimeoutError:
            return {"approved": False, "remember": False}
        finally:
            async with self._lock:
                self._pending.pop(tool_call_id, None)

    async def resolve(
        self,
        tool_call_id: str,
        approved: bool,
        remember: bool = False,
        approval_key: str | None = None,
    ) -> bool:
        async with self._lock:
            binding = self._bindings.get(tool_call_id)
            if binding is not None and (binding[0] != approval_key or binding[1] is not None and time.time() >= binding[1]):
                return False
            future = self._pending.get(tool_call_id)
            if future is None:
                self._decisions[tool_call_id] = ApprovalDecision(approved, remember)
                return True
            if future.done():
                return False
            future.set_result(ApprovalDecision(approved, remember))
            self._bindings.pop(tool_call_id, None)
            return True

    async def register_operation(
        self, approval_id: str, binding: dict, expiry: float
    ) -> None:
        """Register immutable destructive-operation state before prompting."""
        async with self._lock:
            self._operation_approvals[approval_id] = {
                "binding": dict(binding),
                "expiry": expiry,
                "approved": False,
                "used": False,
            }

    async def approve_operation(self, approval_id: str, requester: str) -> bool:
        """Mark a registered operation approved by its bound requester."""
        async with self._lock:
            record = self._operation_approvals.get(approval_id)
            if (
                record is None
                or record["used"]
                or time.time() >= record["expiry"]
                or record["binding"].get("requester") != requester
            ):
                return False
            record["approved"] = True
            return True

    async def consume_operation(self, approval_id: str, binding: dict) -> bool:
        """Atomically consume an approved operation; every attempt is one-shot."""
        async with self._lock:
            record = self._operation_approvals.get(approval_id)
            if record is None or record["used"]:
                return False
            record["used"] = True
            return bool(
                record["approved"]
                and time.time() < record["expiry"]
                and record["binding"] == binding
            )

    async def cancel_operation(self, approval_id: str) -> None:
        """Make a denied or cancelled destructive approval non-replayable."""
        async with self._lock:
            record = self._operation_approvals.get(approval_id)
            if record is not None:
                record["used"] = True

    # ------------------------------------------------------------------
    # Plan-execution approvals (namespaced, disjoint from Task / operation)
    # ------------------------------------------------------------------

    @staticmethod
    def _plan_broker_request_id(approval_request_id: str) -> str:
        """Return the namespaced broker key for a plan approval request.

        The ``plan-execution:`` prefix keeps plan approvals disjoint from
        Task approvals (raw tool_call_id) and destructive-operation approvals
        (ChangeSet approval keys). It is impossible for a Task approve/reject
        or a ChangeSet consume to accidentally resolve a plan approval.
        """
        return f"{PLAN_APPROVAL_NAMESPACE}:{approval_request_id}"

    async def register_plan_approval(
        self,
        *,
        approval_request_id: str,
        binding: dict,
        summary: dict,
        expires_at: float,
    ) -> str:
        """Register a pending plan-execution approval request.

        Returns the namespaced ``broker_request_id`` that callers should use
        when presenting the approval to a user. The ``binding`` must include
        the plan binding digest and scope (plan/task/workspace/repository ids)
        so that callbacks can be validated.
        """
        broker_request_id = self._plan_broker_request_id(approval_request_id)
        async with self._lock:
            existing = self._plan_approvals.get(broker_request_id)
            # Idempotent re-registration: keep the original expiry/decision,
            # refresh the mutable summary if the caller passed new data.
            if existing is not None:
                return broker_request_id
            self._plan_approvals[broker_request_id] = PlanApprovalRecord(
                broker_request_id=broker_request_id,
                approval_request_id=approval_request_id,
                binding=dict(binding),
                summary=dict(summary),
                expires_at=float(expires_at),
            )
        return broker_request_id

    async def resolve_plan_approval(
        self,
        *,
        broker_request_id: str,
        approved: bool,
        actor_id: str,
        actor_type: str = "user",
        reason: str = "",
    ) -> PlanApprovalOutcome:
        """Apply an approve/reject decision to a plan-execution request.

        Returns a :class:`PlanApprovalOutcome` describing the result:

        * Unknown broker request → ``ok=False``, ``decision=None``.
        * Expired request → ``ok=False``, ``decision=None``.
        * Duplicate identical decision → ``ok=True``, idempotent
          (``decision`` reflects the prior decision, ``decide_count>1``).
        * Conflicting decision (approve after reject or vice versa) →
          ``ok=False``, ``decision`` reflects the ORIGINAL decision. The
          caller surfaces this as a conflict; the state machine never flips.
        * First decision → ``ok=True``, ``decision`` set accordingly.

        The broker does NOT decide whether the approval is *valid* against the
        current plan/repository state — that re-validation happens in
        :class:`PlanApprovalService` before persisting the decision. The
        broker only serializes concurrent callbacks so that exactly one
        wins.
        """
        decision_value = "approved" if approved else "rejected"
        async with self._lock:
            record = self._plan_approvals.get(broker_request_id)
            if record is None:
                return PlanApprovalOutcome(ok=False, decision=None, reason="unknown-broker-request")
            if time.time() >= record.expires_at:
                return PlanApprovalOutcome(ok=False, decision=None, reason="expired")
            record.decide_count += 1
            if record.decision is None:
                record.decision = decision_value
                return PlanApprovalOutcome(
                    ok=True,
                    decision=decision_value,
                    reason=reason or f"{decision_value}-by-{actor_type}:{actor_id}",
                )
            # A decision was already recorded for this broker request.
            if record.decision == decision_value:
                # Idempotent repeat of the SAME decision — succeed silently.
                return PlanApprovalOutcome(
                    ok=True,
                    decision=record.decision,
                    reason=f"idempotent:{record.decision}",
                )
            # Opposite decision after a prior one — conflict, original wins.
            return PlanApprovalOutcome(
                ok=False,
                decision=record.decision,
                reason=f"conflict:already-{record.decision}",
            )

    async def get_plan_approval(self, broker_request_id: str) -> PlanApprovalRecord | None:
        async with self._lock:
            return self._plan_approvals.get(broker_request_id)

    async def cancel_plan_approval(self, broker_request_id: str) -> bool:
        """Mark a plan approval non-resolvable (e.g. on stale/expiry)."""
        async with self._lock:
            record = self._plan_approvals.get(broker_request_id)
            if record is None:
                return False
            # Pin the decision so any later callback is treated as a no-op.
            if record.decision is None:
                record.decision = "rejected"
            record.decide_count += 1
            return True
