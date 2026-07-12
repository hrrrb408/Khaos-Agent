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

    def __init__(self, authenticator=None) -> None:
        self._pending: dict[str, asyncio.Future[ApprovalDecision]] = {}
        self._decisions: dict[str, ApprovalDecision] = {}
        self._bindings: dict[str, tuple[str, float | None]] = {}
        self._operation_approvals: dict[str, dict] = {}
        # Namespaced plan-execution approvals (disjoint key space).
        self._plan_approvals: dict[str, PlanApprovalRecord] = {}
        self._lock = asyncio.Lock()
        # Batch 2.3 §5: server-owned authenticator for HMAC-verifying
        # AuthenticatedApprovalContext signatures. If None, the broker
        # refuses all plan-approval decisions (fail closed).
        self._authenticator = authenticator
        # Broker-private Ed25519 authority for durable decision receipts.
        # Only its public verifier is persisted by the runtime.
        from khaos.coding.planning.approval.receipt_crypto import _ReceiptSigningAuthority
        self.__receipt_signing_authority = _ReceiptSigningAuthority()
        # Batch 2.6 §1: the durable receipt writer is stored name-mangled so
        # ordinary code and tests cannot read or replace it. Only the runtime
        # can install it via _install_runtime_receipt_writer with the
        # runtime-internal token. Replaces the old _register_runtime_receipt_sink.
        self.__runtime_receipt_writer = None  # type: ignore[assignment]
        self.__runtime_receipt_token = None  # type: ignore[assignment]

    def _receipt_public_verifier(self):
        return self.__receipt_signing_authority.verifier

    def _rotate_receipt_signing_authority(self, boot_epoch: int, boot_id: str) -> None:
        from khaos.coding.planning.approval.receipt_crypto import _ReceiptSigningAuthority
        self.__receipt_signing_authority = _ReceiptSigningAuthority(
            boot_epoch=boot_epoch, boot_id=boot_id
        )

    def _install_runtime_receipt_writer(
        self, writer, *, runtime_token: object, runtime_capability=None
    ) -> None:
        """Install the durable receipt writer produced by ApprovalRuntime.

        Batch 2.6 §1: replaces the old ``_register_runtime_receipt_sink``.
        The ``runtime_token`` is an opaque object that only
        :class:`ApprovalRuntime` possesses. A forged token (or a call
        without one) is silently ignored — the writer stays ``None`` and
        receipt persistence is refused (fail-closed).
        """
        from khaos.coding.planning.approval.runtime import _consume_runtime_capability

        try:
            _consume_runtime_capability(runtime_capability, "receipt-broker")
        except PermissionError as exc:
            raise PermissionError("runtime receipt authority required") from exc
        if runtime_token is None:
            raise PermissionError("runtime receipt token required")
        self.__runtime_receipt_token = runtime_token  # type: ignore[assignment]
        self.__runtime_receipt_writer = writer  # type: ignore[assignment]

    def _reset_runtime_receipt_writer(self) -> None:
        """Clear the runtime receipt writer (used by runtime rollback)."""
        self.__runtime_receipt_writer = None  # type: ignore[assignment]
        self.__runtime_receipt_token = None  # type: ignore[assignment]

    def _has_runtime_receipt_writer(self) -> bool:
        """Test-only introspection: does a writer exist?"""
        return self.__runtime_receipt_writer is not None  # type: ignore[attr-defined]

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
        context,
        reason: str = "",
        binding_digest: str = "",
        receipt_sink=None,  # DEPRECATED — ignored. See Batch 2.6 §1.
        clock=None,
    ):
        """Apply an approve/reject decision and mint an authenticated receipt.

        This is the ONLY method that creates a :class:`BrokerDecisionReceipt`.
        Actor identity comes from ``context`` — an
        :class:`AuthenticatedApprovalContext` that ONLY the authenticated
        API/session layer may construct. Bare actor strings are NOT accepted,
        so a caller cannot self-assert an authenticated identity.

        Batch 2.7: the receipt is signed by the broker's private Ed25519
        authority over the canonical payload digest. The
        ``receipt_sink`` parameter is DEPRECATED and silently ignored —
        the runtime-installed name-mangled writer is the ONLY path to the
        durable outbox. An ordinary caller cannot inject a sink.

        Returns a :class:`BrokerDecisionReceipt` on success, or ``None`` if
        the broker request is unknown, expired, or conflicts with a prior
        opposite decision. Idempotent repeats of the SAME decision re-mint a
        fresh receipt (the store dedups on token hash).
        """
        import time as _time
        import uuid as _uuid

        # Lazy import to avoid a circular dependency at module load time.
        from khaos.coding.planning.approval.models import (
            AuthenticatedApprovalContext,
            BrokerDecisionReceipt,
            PlanApprovalStatus,
            compute_reason_digest,
            generate_receipt_token,
            hash_receipt_token,
        )

        # The context MUST be a real AuthenticatedApprovalContext — refuse
        # bare strings/dicts that a caller might try to smuggle through.
        if not isinstance(context, AuthenticatedApprovalContext):
            raise TypeError(
                "resolve_plan_approval requires an AuthenticatedApprovalContext; "
                "bare actor strings are not accepted"
            )
        # Verify the server-owned authenticated-session HMAC. A
        # hand-constructed context has signature="" → rejected. An
        # authenticator MUST be wired or all decisions fail closed.
        if self._authenticator is None:
            raise PermissionError(
                "broker has no ApprovalAuthenticator; plan-approval decisions are refused"
            )
        now = (clock or _time.time)()
        decision_status = PlanApprovalStatus.APPROVED if approved else PlanApprovalStatus.REJECTED
        decision_value = decision_status.value
        reason_text = reason or f"{decision_value}-by-{context.actor_type}:{context.actor_id}"
        reason_digest = compute_reason_digest(reason_text)

        async with self._lock:
            record = self._plan_approvals.get(broker_request_id)
            if record is None:
                return None
            if not self._authenticator.verify_context(
                context, expected_approval_request_id=record.approval_request_id,
                now=now, consume=True,
            ):
                raise PermissionError(
                    "AuthenticatedApprovalContext verification failed "
                    "(session, request binding, expiry, capability, or replay)"
                )
            if now >= record.expires_at:
                return None
            record.decide_count += 1
            if record.decision is None:
                record.decision = decision_value
            elif record.decision != decision_value:
                # Opposite decision after a prior one — conflict, no receipt.
                return None
            # Same decision (first or idempotent repeat) → mint a receipt.

            token = generate_receipt_token()
            token_hash = hash_receipt_token(token)
            receipt = BrokerDecisionReceipt(
                receipt_id=f"rec_{_uuid.uuid4().hex}",
                namespace=PLAN_APPROVAL_NAMESPACE,
                broker_request_id=broker_request_id,
                approval_request_id=record.approval_request_id,
                decision=decision_status,
                authenticated_actor_id=context.actor_id,
                authenticated_actor_type=context.actor_type,
                authenticated_source=context.authenticated_source,
                session_request_id=context.session_request_id,
                server_capability=context.server_capability,
                binding_digest=binding_digest or record.binding.get("binding_digest", ""),
                decided_at=now,
                expires_at=record.expires_at,
                reason_digest=reason_digest,
                one_time_token=token,
                token_hash=token_hash,
                signer_epoch=self.__receipt_signing_authority.verifier.boot_epoch,
                signer_boot_id=self.__receipt_signing_authority.verifier.boot_id,
                issued_at=now,
                metadata={"reason": reason_text},
            )
        # Batch 2.7: sign with the broker-private Ed25519 authority. The key
        # is never exposed or persisted. The signature
            # is bound to every authoritative field + token_hash.
            payload_digest = receipt.compute_canonical_payload_digest()
            signature = self.__receipt_signing_authority._sign_payload_digest(payload_digest)
            # frozen dataclass — use object.__setattr__ to set the signature fields.
            object.__setattr__(receipt, "canonical_payload_digest", payload_digest)
            object.__setattr__(receipt, "broker_signature", signature)
            object.__setattr__(receipt, "signer_key_id", self.__receipt_signing_authority.verifier.key_id)

        # Persist the receipt outbox row outside the broker lock. The
        # name-mangled runtime writer is the ONLY path — the deprecated
        # receipt_sink parameter is silently ignored. An ordinary caller
        # cannot inject a writer because it is installed by the runtime via
        # _install_runtime_receipt_writer with a runtime-internal token.
        writer = self.__runtime_receipt_writer  # type: ignore[attr-defined]
        if writer is not None:
            writer(
                receipt_id=receipt.receipt_id,
                token_hash=receipt.token_hash,
                approval_request_id=receipt.approval_request_id,
                broker_request_id=receipt.broker_request_id,
                binding_digest=receipt.binding_digest,
                decision=receipt.decision.value,
                namespace=receipt.namespace,
                authenticated_actor_id=receipt.authenticated_actor_id,
                authenticated_actor_type=receipt.authenticated_actor_type,
                authenticated_source=receipt.authenticated_source,
                session_request_id=receipt.session_request_id,
                server_capability=receipt.server_capability,
                decided_at=receipt.decided_at,
                reason_digest=receipt.reason_digest,
                expires_at=receipt.expires_at,
                canonical_payload_digest=receipt.canonical_payload_digest,
                broker_signature=receipt.broker_signature,
                signer_key_id=receipt.signer_key_id,
                signer_epoch=receipt.signer_epoch,
                signer_boot_id=receipt.signer_boot_id,
                issued_at=receipt.issued_at,
                created_at=now,
            )
        return receipt

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
