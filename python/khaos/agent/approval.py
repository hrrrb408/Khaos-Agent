"""Shared approval broker for tool permissions and task APIs."""

from __future__ import annotations

import asyncio
import hashlib
import json
import secrets
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Self

#: Namespace prefix reserved for plan-execution approval requests. This keeps
#: plan approvals disjoint from Task approvals (keyed by tool_call_id) and
#: from destructive-operation approvals (keyed by ChangeSet approval keys).
PLAN_APPROVAL_NAMESPACE = "plan-execution"


@dataclass(frozen=True)
class ApprovalDecision:
    approved: bool
    remember: bool = False


@dataclass(frozen=True)
class StepExecutionAuthority:
    """Immutable authority snapshot for one executable tool step.

    Turn-level context may evolve while an approval is pending.  This object
    is the boundary between approval and execution: both sides bind to the
    same identity, workspace, cwd, environment, concrete sandbox decision,
    executable identity, backend, policy, resource,
    tool, and argument scope.  Environment values are deliberately excluded;
    only non-secret allowlisted environment values are fingerprinted; secret
    values are never copied into the authority.
    """

    principal_id: str
    project_id: str
    session_id: str
    task_id: str
    turn_id: str
    step_id: str
    tool_call_id: str
    tool_name: str
    workspace_id: str
    workspace_generation: int
    cwd_identity: str
    permission_profile_digest: str
    environment_keys: tuple[str, ...]
    environment_digest: str
    sandbox_backend: str
    sandbox_decision_digest: str
    executable_identity: str
    network_authority: str
    target: str
    approval_target: str
    arguments_digest: str
    authorization_resource_digest: str
    authorization_epoch: int
    policy_digest: str
    tool_schema_digest: str
    tool_security_digest: str
    spawn_plan_digest: str = ""
    approval_receipt_digest: str = ""
    principal_kind: str = ""
    parent_principal_id: str = ""
    delegation_digest: str = ""
    # Transport provenance for the delegation digest: the authority
    # recomputes the transport-root commitment from it, so the grant
    # caller must present the same transport the context was built from.
    source_transport: str = ""

    def __post_init__(self) -> None:
        required = (
            self.principal_id,
            self.project_id,
            self.session_id,
            self.task_id,
            self.turn_id,
            self.step_id,
            self.tool_call_id,
            self.tool_name,
            self.workspace_id,
            self.cwd_identity,
            self.permission_profile_digest,
            self.environment_digest,
            self.sandbox_backend,
            self.sandbox_decision_digest,
            self.executable_identity,
            self.network_authority,
            self.target,
            self.approval_target,
            self.arguments_digest,
            self.policy_digest,
            self.tool_schema_digest,
            self.tool_security_digest,
        )
        if any(not value for value in required):
            raise ValueError("step execution authority fields must not be empty")
        if self.workspace_generation < 0 or self.authorization_epoch < 0:
            raise ValueError("step execution authority generations must be non-negative")
        if any(not isinstance(key, str) or not key for key in self.environment_keys):
            raise ValueError("step execution environment keys must be non-empty strings")
        if tuple(sorted(set(self.environment_keys))) != self.environment_keys:
            raise ValueError("step execution environment keys must be sorted and unique")
        if self.spawn_plan_digest and not isinstance(self.spawn_plan_digest, str):
            raise ValueError("step execution spawn plan digest must be a string")
        typed = (self.principal_kind, self.parent_principal_id, self.delegation_digest)
        if any(typed) and not all(typed):
            raise ValueError("step execution typed principal binding is incomplete")
        if self.principal_kind and self.principal_kind not in {
            "human", "gateway", "channel", "automation", "subagent", "browser"
        }:
            raise ValueError("step execution principal kind is invalid")
        if self.delegation_digest and (
            len(self.delegation_digest) != 64
            or any(c not in "0123456789abcdef" for c in self.delegation_digest)
        ):
            raise ValueError("step execution delegation digest is invalid")

    def _payload(self, *, include_receipt: bool) -> dict[str, object]:
        payload: dict[str, object] = {
            "principal_id": self.principal_id,
            "project_id": self.project_id,
            "session_id": self.session_id,
            "task_id": self.task_id,
            "turn_id": self.turn_id,
            "step_id": self.step_id,
            "tool_call_id": self.tool_call_id,
            "tool_name": self.tool_name,
            "workspace_id": self.workspace_id,
            "workspace_generation": self.workspace_generation,
            "cwd_identity": self.cwd_identity,
            "permission_profile_digest": self.permission_profile_digest,
            "environment_keys": self.environment_keys,
            "environment_digest": self.environment_digest,
            "sandbox_backend": self.sandbox_backend,
            "sandbox_decision_digest": self.sandbox_decision_digest,
            "executable_identity": self.executable_identity,
            "network_authority": self.network_authority,
            "target": self.target,
            "approval_target": self.approval_target,
            "arguments_digest": self.arguments_digest,
            "authorization_resource_digest": self.authorization_resource_digest,
            "authorization_epoch": self.authorization_epoch,
            "policy_digest": self.policy_digest,
            "tool_schema_digest": self.tool_schema_digest,
            "tool_security_digest": self.tool_security_digest,
            "spawn_plan_digest": self.spawn_plan_digest,
            "principal_kind": self.principal_kind,
            "parent_principal_id": self.parent_principal_id,
            "delegation_digest": self.delegation_digest,
            "source_transport": self.source_transport,
        }
        if include_receipt:
            payload["approval_receipt_digest"] = self.approval_receipt_digest
        return payload

    def scope_digest(self) -> str:
        """Digest the authority scope before an approval receipt is attached."""
        return _canonical_digest(self._payload(include_receipt=False))

    def digest(self) -> str:
        """Digest the final step authority including its approval receipt."""
        return _canonical_digest(self._payload(include_receipt=True))

    @property
    def step_execution_digest(self) -> str:
        """Stable public spelling for the final step authority digest."""
        return self.digest()


@dataclass(frozen=True)
class ApprovalBinding:
    """Immutable authority scope for one ordinary tool approval."""

    principal_id: str
    session_id: str
    task_id: str
    turn_id: str
    tool_call_id: str
    tool_name: str
    arguments_digest: str
    workspace_id: str
    profile_digest: str
    expires_at: float
    nonce: str = field(default_factory=lambda: secrets.token_hex(32))
    project_id: str = ""
    workspace_generation: int = 0
    authorization_resource_digest: str = ""
    authorization_epoch: int = 0
    policy_digest: str = ""
    tool_schema_digest: str = ""
    # Batch 15.6: the COMPLETE tool security contract digest (covers
    # capabilities, permission_level, resource_resolver, effect_status,
    # modes, parallel, timeout, reconciliation_hint — not just
    # name + parameters).  When non-empty, the scheduler's dispatch
    # drift check verifies the live ``ToolDefinition.security_digest``
    # matches this value, so any post-approval mutation to a security
    # field is detected and refused.
    tool_security_digest: str = ""
    # Scope digest of the immutable StepExecutionAuthority reviewed for this
    # approval.  The final authority adds the broker binding digest as its
    # approval receipt.
    step_authority_digest: str = ""

    def __post_init__(self) -> None:
        required = (
            self.principal_id,
            self.session_id,
            self.task_id,
            self.turn_id,
            self.tool_call_id,
            self.tool_name,
            self.arguments_digest,
            self.workspace_id,
            self.profile_digest,
            self.nonce,
        )
        if any(not value for value in required):
            raise ValueError("approval binding fields must not be empty")
        if self.expires_at <= 0:
            raise ValueError("approval binding expiry must be positive")

    def digest(self) -> str:
        payload = {
            "principal_id": self.principal_id,
            "session_id": self.session_id,
            "task_id": self.task_id,
            "turn_id": self.turn_id,
            "tool_call_id": self.tool_call_id,
            "tool_name": self.tool_name,
            "arguments_digest": self.arguments_digest,
            "workspace_id": self.workspace_id,
            "profile_digest": self.profile_digest,
            "expires_at": self.expires_at,
            "nonce": self.nonce,
            "project_id": self.project_id,
            "workspace_generation": self.workspace_generation,
            "authorization_resource_digest": self.authorization_resource_digest,
            "authorization_epoch": self.authorization_epoch,
            "policy_digest": self.policy_digest,
            "tool_schema_digest": self.tool_schema_digest,
            "tool_security_digest": self.tool_security_digest,
            "step_authority_digest": self.step_authority_digest,
        }
        canonical = json.dumps(
            payload, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()


def _canonical_digest(value: object) -> str:
    """Return the canonical digest used by immutable step authorities."""
    canonical = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


@dataclass
class _ToolApprovalRecord:
    binding: ApprovalBinding
    binding_digest: str
    approval_id: str
    decision: ApprovalDecision | None = None
    used: bool = False
    dispatched: bool = False
    # Round-4 review Batch 4 (§13.1): timestamp for TTL-based eviction.
    created_at: float = field(default_factory=time.time)


class ToolApprovalHandle(str):
    """Server-generated approval identity with legacy digest compatibility.

    The string value remains the binding digest for existing callers that
    persist/pass ``binding_digest``. ``approval_id`` is a separate random
    server identity and is the Broker's internal primary key.
    """

    # Batch 15.7: declare instance attributes so pyright recognises them
    # (``str`` subclasses don't carry these by default; ``__new__`` sets
    # them but pyright cannot infer that without class-level annotations).
    approval_id: str
    binding_digest: str

    def __new__(
        cls, binding_digest: str, approval_id: str
    ) -> Self:
        instance = super().__new__(cls, binding_digest)
        instance.approval_id = approval_id
        instance.binding_digest = binding_digest
        return instance


class _ToolApprovalStore(dict[str, _ToolApprovalRecord]):
    """Primary approval-id store with a read-only legacy call-id view.

    Existing diagnostics/tests may inspect ``broker._tool_approvals[call_id]``.
    That compatibility lookup is intentionally ambiguous-safe and is never
    used by authorization methods; the real store keys remain server IDs.
    """

    def _legacy_lookup(self, key: object) -> _ToolApprovalRecord | None:
        matches = [
            record
            for record in dict.values(self)
            if record.binding.tool_call_id == key
        ]
        return matches[0] if len(matches) == 1 else None

    def __contains__(self, key: object) -> bool:
        return dict.__contains__(self, key) or self._legacy_lookup(key) is not None

    def __getitem__(self, key: str) -> _ToolApprovalRecord:
        try:
            return dict.__getitem__(self, key)
        except KeyError:
            record = self._legacy_lookup(key)
            if record is None:
                raise
            return record

    def get(  # type: ignore[override]
        self, key: str, default: _ToolApprovalRecord | None = None
    ) -> _ToolApprovalRecord | None:
        record = dict.get(self, key)
        if record is not None:
            return record
        return self._legacy_lookup(key) or default


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
    """Approval channels keyed internally by server-generated approval IDs."""

    def __init__(
        self,
        authenticator=None,
        db=None,
        *,
        max_pending_per_principal_session: int = 128,
        max_pending_per_turn: int = 16,
    ) -> None:
        if max_pending_per_principal_session <= 0 or max_pending_per_turn <= 0:
            raise ValueError("approval pending quotas must be positive")
        self._pending: dict[str, asyncio.Future[ApprovalDecision]] = {}
        # P1-3: model/tool call IDs are not global identities. The server
        # generates a fresh approval_id for every immutable binding, so two
        # sessions may legitimately reuse the same model call ID.
        self._tool_approvals: _ToolApprovalStore = _ToolApprovalStore()
        self._operation_approvals: dict[str, dict] = {}
        # Bound attacker-controlled approval fan-out before a user can be
        # asked to resolve an unbounded number of challenges. These quotas
        # are scoped by the server-verified principal/session and turn, not
        # by the model-provided tool_call_id.
        self._max_pending_per_principal_session = max_pending_per_principal_session
        self._max_pending_per_turn = max_pending_per_turn
        # Namespaced plan-execution approvals (disjoint key space).
        self._plan_approvals: dict[str, PlanApprovalRecord] = {}
        self._lock = asyncio.Lock()
        # Batch 2.3 §5: server-owned authenticator for HMAC-verifying
        # AuthenticatedApprovalContext signatures. If None, the broker
        # refuses all plan-approval decisions (fail closed).
        self._authenticator = authenticator
        self._db = db
        # Broker-private Ed25519 authority for durable decision receipts.
        # Only its public verifier is persisted by the runtime.
        from khaos.coding.planning.approval.receipt_crypto import (
            _ReceiptSigningAuthority,
        )
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
        from khaos.coding.planning.approval.receipt_crypto import (
            _ReceiptSigningAuthority,
        )
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

    async def sweep_expired(self, *, ttl_seconds: float = 3600.0) -> dict[str, int]:
        """Round-4 review Batch 4 (§13.1): evict consumed and expired records.

        The broker previously kept every ``_tool_approvals`` /
        ``_operation_approvals`` / ``_plan_approvals`` record forever —
        consumed records were marked ``used``/``dispatched`` but never
        deleted, causing unbounded growth in long-running processes.

        This method evicts:
          - Tool approvals where ``used=True`` (consumed).
          - Tool approvals older than ``ttl_seconds``.
          - Plan approvals past their ``expires_at``.
          - Operation approvals where ``used=True`` or past ``expiry``
            (H-10, round-5 Batch 5.4 — previously ``_operation_approvals``
            was never swept, causing unbounded growth).

        Round-5 Batch 5.4 (Future expiry resolution): before removing a
        tool approval's entry from ``_pending``, any unresolved Future
        is resolved with a denied ``ApprovalDecision`` so the task
        blocked in :meth:`wait` wakes immediately instead of hanging
        forever (a Future removed from ``_pending`` without being
        resolved is never awaited again — ``asyncio.shield`` would
        block indefinitely when no ``timeout`` was passed).

        Returns a summary dict ``{"tool": N, "plan": N, "operation": N}``.
        """
        now = time.time()
        counts = {"tool": 0, "plan": 0, "operation": 0}
        denied = ApprovalDecision(approved=False, remember=False)
        async with self._lock:
            # Tool approvals: evict consumed or expired.
            stale_tool = [
                key for key, rec in self._tool_approvals.items()
                if rec.used or (now - rec.created_at) > ttl_seconds
            ]
            for key in stale_tool:
                self._tool_approvals.pop(key, None)
                # H-05/Future-expiry: wake any waiter before dropping the
                # Future so it does not block on a shielded, never-resolved
                # Future when ``wait()`` was called without a timeout.
                future = self._pending.pop(key, None)
                if future is not None and not future.done():
                    future.set_result(denied)
                counts["tool"] += 1
            # Plan approvals: evict expired.
            stale_plan = [
                key for key, rec in self._plan_approvals.items()
                if rec.expires_at <= now
            ]
            for key in stale_plan:
                self._plan_approvals.pop(key, None)
                counts["plan"] += 1
            # H-10 (round-5 Batch 5.4): operation approvals — evict
            # consumed (``used=True``) or past ``expiry``.  These were
            # previously never swept, so a long-running process
            # accumulated every destructive-operation approval record
            # forever.
            stale_op = [
                key for key, rec in self._operation_approvals.items()
                if rec.get("used") or now >= float(rec.get("expiry", 0))
            ]
            for key in stale_op:
                self._operation_approvals.pop(key, None)
                counts["operation"] += 1
        return counts

    async def register_tool_approval(
        self, binding: ApprovalBinding
    ) -> ToolApprovalHandle:
        """Register one immutable, principal-bound tool challenge.

        Registration is idempotent for the exact binding digest. A repeated
        model ``tool_call_id`` with a different binding creates a separate
        server approval rather than colliding with an existing session.
        """
        digest = binding.digest()
        async with self._lock:
            for existing in self._tool_approvals.values():
                if existing.binding_digest == digest:
                    return ToolApprovalHandle(digest, existing.approval_id)
            now = time.time()
            active = [
                existing
                for existing in self._tool_approvals.values()
                if not existing.used and existing.binding.expires_at > now
            ]
            principal_session_count = sum(
                1
                for existing in active
                if existing.binding.principal_id == binding.principal_id
                and existing.binding.session_id == binding.session_id
            )
            if principal_session_count >= self._max_pending_per_principal_session:
                raise PermissionError(
                    "approval pending quota exceeded for principal/session"
                )
            turn_count = sum(
                1
                for existing in active
                if existing.binding.principal_id == binding.principal_id
                and existing.binding.session_id == binding.session_id
                and existing.binding.turn_id == binding.turn_id
            )
            if turn_count >= self._max_pending_per_turn:
                raise PermissionError("approval pending quota exceeded for turn")
            approval_id = f"approval_{secrets.token_urlsafe(24)}"
            while dict.__contains__(self._tool_approvals, approval_id):
                approval_id = f"approval_{secrets.token_urlsafe(24)}"
            self._tool_approvals[approval_id] = _ToolApprovalRecord(
                binding=binding,
                binding_digest=digest,
                approval_id=approval_id,
            )
        return ToolApprovalHandle(digest, approval_id)

    def _find_tool_approval_locked(
        self,
        tool_call_id: str,
        binding_digest: str,
        *,
        principal_id: str | None = None,
        session_id: str | None = None,
    ) -> _ToolApprovalRecord | None:
        """Find a record by its server-bound digest and authority scope."""
        matches = [
            record
            for record in self._tool_approvals.values()
            if record.binding_digest == str(binding_digest)
            and record.binding.tool_call_id == tool_call_id
            and (
                principal_id is None
                or record.binding.principal_id == principal_id
            )
            and (
                session_id is None or record.binding.session_id == session_id
            )
        ]
        return matches[0] if len(matches) == 1 else None

    async def wait(
        self,
        tool_call_id: str,
        timeout: float | None = None,
        *,
        binding_digest: str,
    ) -> dict:
        async with self._lock:
            record = self._find_tool_approval_locked(
                tool_call_id, binding_digest
            )
            if (
                record is None
                or record.used
                or record.binding_digest != binding_digest
                or time.time() >= record.binding.expires_at
            ):
                return {"approved": False, "remember": False}
            future = self._pending.get(record.approval_id)
            if record.decision is not None:
                record.used = True
                return {
                    "approved": record.decision.approved,
                    "remember": record.decision.remember,
                }
            if future is None:
                future = asyncio.get_running_loop().create_future()
                self._pending[record.approval_id] = future
        try:
            decision = await asyncio.wait_for(asyncio.shield(future), timeout) if timeout else await future
            return {"approved": decision.approved, "remember": decision.remember}
        except TimeoutError:
            async with self._lock:
                record = self._find_tool_approval_locked(
                    tool_call_id, binding_digest
                )
                if record is not None:
                    record.used = True
            return {"approved": False, "remember": False}
        finally:
            async with self._lock:
                record = self._find_tool_approval_locked(
                    tool_call_id, binding_digest
                )
                if record is not None:
                    self._pending.pop(record.approval_id, None)
                    record.used = True

    async def resolve(
        self,
        tool_call_id: str,
        approved: bool,
        remember: bool = False,
        *,
        principal_id: str,
        session_id: str,
        binding_digest: str,
    ) -> bool:
        async with self._lock:
            record = self._find_tool_approval_locked(
                tool_call_id,
                binding_digest,
                principal_id=principal_id,
                session_id=session_id,
            )
            if (
                record is None
                or record.used
                or record.decision is not None
                or record.binding_digest != binding_digest
                or record.binding.principal_id != principal_id
                or record.binding.session_id != session_id
                or time.time() >= record.binding.expires_at
            ):
                return False
            decision = ApprovalDecision(approved, remember)
            record.decision = decision
            future = self._pending.get(record.approval_id)
            if future is None:
                return True
            if future.done():
                return False
            future.set_result(decision)
            return True

    async def consume_for_dispatch(
        self,
        tool_call_id: str,
        approved: bool,
        remember: bool = False,
        *,
        principal_id: str,
        session_id: str,
        binding_digest: str,
    ) -> dict:
        """Validate UI intent and authorize at most one scheduler dispatch.

        A remote callback may already have called :meth:`resolve` and
        :meth:`wait`; a local callback has not. Both paths converge here and
        are checked against the server-held immutable binding.
        """
        async with self._lock:
            record = self._find_tool_approval_locked(
                tool_call_id,
                binding_digest,
                principal_id=principal_id,
                session_id=session_id,
            )
            if (
                record is None
                or record.dispatched
                or record.binding_digest != binding_digest
                or record.binding.principal_id != principal_id
                or record.binding.session_id != session_id
                or time.time() >= record.binding.expires_at
            ):
                return {"approved": False, "remember": False}
            callback_decision = ApprovalDecision(approved, remember)
            if record.decision is not None and record.decision != callback_decision:
                record.used = True
                return {"approved": False, "remember": False}
            if record.decision is None:
                record.decision = callback_decision
            record.used = True
            record.dispatched = True
            return {
                "approved": record.decision.approved,
                "remember": record.decision.remember,
            }

    async def consume_task_decision_and_commit(
        self,
        tool_call_id: str,
        approved: bool,
        *,
        principal_id: str,
        session_id: str,
        binding_digest: str,
        commit: Callable[[], Awaitable[bool]],
    ) -> bool:
        """Consume a task approval before publishing its state transition.

        Broker validation, one-shot consumption, task CAS/persistence and
        waiter notification execute under one authority critical section.
        A failed task CAS leaves the capability consumed and never exposes a
        RUNNING task without a consumed approval.
        """
        async with self._lock:
            record = self._find_tool_approval_locked(
                tool_call_id,
                binding_digest,
                principal_id=principal_id,
                session_id=session_id,
            )
            if (
                record is None
                or record.used
                or record.dispatched
                or record.decision is not None
                or record.binding_digest != binding_digest
                or record.binding.principal_id != principal_id
                or record.binding.session_id != session_id
                or time.time() >= record.binding.expires_at
            ):
                return False
            decision = ApprovalDecision(approved, False)
            record.decision = decision
            record.used = True
            record.dispatched = True
            if not await commit():
                return False
            future = self._pending.get(record.approval_id)
            if future is not None and not future.done():
                future.set_result(decision)
            return True

    async def register_operation(
        self, approval_id: str, binding: dict, expiry: float
    ) -> None:
        """Register immutable destructive-operation state before prompting."""
        normalized = _normalize_operation_binding(binding, expiry)
        binding_digest = _canonical_digest(normalized)
        async with self._lock:
            self._operation_approvals[approval_id] = {
                "binding": normalized,
                "binding_digest": binding_digest,
                "expiry": expiry,
                "approved": False,
                "used": False,
            }
        if self._db is not None:
            nonce = secrets.token_bytes(32)
            await self._db.register_operation_approval(
                approval_id=approval_id,
                binding_digest=binding_digest,
                binding_json=json.dumps(
                    normalized, sort_keys=True, separators=(",", ":")
                ),
                principal_id=normalized["principal_id"],
                session_id=normalized["session_id"],
                task_id=normalized["task_id"],
                workspace_id=normalized["workspace_id"],
                operation=normalized["operation"],
                nonce_hash=hashlib.sha256(nonce).hexdigest(),
                expires_at=float(expiry),
                created_at=time.time(),
            )

    async def approve_operation(
        self,
        approval_id: str,
        requester: str,
        *,
        principal_id: str | None = None,
    ) -> bool:
        """Mark a registered operation approved by its bound requester."""
        principal = principal_id or requester
        if self._db is not None:
            approved = await self._db.approve_operation_approval(
                approval_id,
                principal_id=principal,
                session_id=requester,
                now=time.time(),
            )
            if approved:
                async with self._lock:
                    record = self._operation_approvals.get(approval_id)
                    if record is not None:
                        record["approved"] = True
            return approved
        async with self._lock:
            record = self._operation_approvals.get(approval_id)
            if (
                record is None
                or record["used"]
                or time.time() >= record["expiry"]
                or record["binding"].get("session_id") != requester
                or record["binding"].get("principal_id") != principal
            ):
                return False
            record["approved"] = True
            return True

    async def consume_operation(self, approval_id: str, binding: dict) -> bool:
        """Atomically consume an approved operation; every attempt is one-shot."""
        expiry = float(binding.get("expiry") or 0)
        normalized = _normalize_operation_binding(binding, expiry)
        binding_digest = _canonical_digest(normalized)
        if self._db is not None:
            return await self._db.consume_operation_approval(
                approval_id,
                binding_digest=binding_digest,
                principal_id=normalized["principal_id"],
                session_id=normalized["session_id"],
                now=time.time(),
            )
        async with self._lock:
            record = self._operation_approvals.get(approval_id)
            if record is None or record["used"]:
                return False
            record["used"] = True
            return bool(
                record["approved"]
                and time.time() < record["expiry"]
                and record["binding_digest"] == binding_digest
            )

    async def cancel_operation(self, approval_id: str) -> None:
        """Make a denied or cancelled destructive approval non-replayable."""
        async with self._lock:
            record = self._operation_approvals.get(approval_id)
            if record is not None:
                record["used"] = True
        if self._db is not None:
            await self._db.cancel_operation_approval(
                approval_id, now=time.time()
            )

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


def _normalize_operation_binding(binding: dict, expiry: float) -> dict:
    normalized = dict(binding)
    requester = str(normalized.get("requester") or normalized.get("session_id") or "")
    normalized["requester"] = requester
    normalized["session_id"] = str(normalized.get("session_id") or requester)
    normalized["principal_id"] = str(
        normalized.get("principal_id") or normalized["session_id"]
    )
    # Expiry is an authoritative ledger column and is deliberately excluded
    # from caller-recomputed binding JSON so restart consumers need not echo it.
    normalized.pop("expiry", None)
    for key in (
        "principal_id", "session_id", "task_id", "workspace_id", "operation"
    ):
        if not str(normalized.get(key) or ""):
            raise ValueError(f"operation approval binding requires {key}")
    normalized.setdefault(
        "arguments_digest",
        _canonical_digest(
            {
                "operation": normalized["operation"],
                "target": normalized.get("target"),
                "changeset_id": normalized.get("changeset_id"),
                "payload_hash": normalized.get("payload_hash"),
            }
        ),
    )
    normalized.setdefault(
        "profile_digest",
        _canonical_digest(
            {
                "network_policy": normalized.get("network_policy", "none"),
                "credential_scope": normalized.get("credential_scope", ""),
                "operation": normalized["operation"],
            }
        ),
    )
    return normalized
