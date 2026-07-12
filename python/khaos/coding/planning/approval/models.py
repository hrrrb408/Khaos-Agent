"""Server-side plan approval state machine and execution authorization models.

This module is the single source of truth for the *approval* layer that sits
between :class:`ImplementationPlan` (read-only planning output) and the future
Batch 3 execution engine. It defines:

* :class:`PlanApprovalStatus` — the eight-state approval lifecycle.
* :class:`PlanApprovalRequest` — a server-issued, content-bound approval
  request. Its :attr:`binding_digest` freezes the exact plan, repository,
  task, workspace, files, symbols, risks, verification plan and trusted
  configuration fingerprint that were verified at request time.
* :class:`PlanApprovalDecision` — an authenticated approve/reject decision.
* :class:`PlanExecutionAuthorization` — a short-lived, single-use, opaque
  authorization object emitted by :class:`PlanExecutionGate`. Only its opaque
  :attr:`authorization_id` ever leaves the server; the nonce is stored only
  as a hash.

Design rules enforced here and by the surrounding services:

* Approval is bound to the WHOLE plan + repository state, never to ``plan_id``
  alone. Any drift invalidates the approval (→ ``stale``).
* The client can NEVER self-approve. Fields such as ``approved``,
  ``requires_approval``, ``risk`` and ``status`` supplied by the client are
  ignored; the server recomputes approval requirement from the final plan.
* Authorizations are unforgeable and non-replayable: high-entropy nonce,
  stored as hash, short TTL, single consume via atomic CAS, bound to a single
  plan/task/workspace/repository tuple.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - typing only
    from khaos.coding.planning.contracts import ImplementationPlan


# ---------------------------------------------------------------------------
# Unified clock (§9)
# ---------------------------------------------------------------------------

#: Authoritative time source injected into every service/store/gate. Business
#: logic must NEVER call ``time.time()`` directly — it reads ``clock()`` so
#: tests can control expiry deterministically via a FakeClock.
Clock = Callable[[], float]


# ---------------------------------------------------------------------------
# Status enum
# ---------------------------------------------------------------------------


class PlanApprovalStatus(str, Enum):
    """Lifecycle of a plan approval request.

    Transitions (enforced by :class:`PlanApprovalService`):

    * ``registering``      → ``pending`` | ``registration-failed``
    * ``not-required``     → ``consumed`` | ``expired``
    * ``pending``          → ``approved`` | ``rejected`` | ``stale`` | ``expired``
    * ``approved``         → ``consumed`` | ``revoked`` | ``stale`` | ``expired``

    ``rejected``, ``revoked``, ``stale``, ``expired``, ``consumed`` and
    ``registration-failed`` are terminal. Recovery requires a brand new plan
    and a brand new request.
    """

    REGISTERING = "registering"
    REGISTRATION_FAILED = "registration-failed"
    NOT_REQUIRED = "not-required"
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    REVOKED = "revoked"
    STALE = "stale"
    EXPIRED = "expired"
    CONSUMED = "consumed"

    @property
    def is_terminal(self) -> bool:
        return self in (
            PlanApprovalStatus.REJECTED,
            PlanApprovalStatus.REVOKED,
            PlanApprovalStatus.STALE,
            PlanApprovalStatus.EXPIRED,
            PlanApprovalStatus.CONSUMED,
            PlanApprovalStatus.REGISTRATION_FAILED,
        )


# Allowed forward transitions (source → {targets}). Everything else is invalid.
ALLOWED_APPROVAL_TRANSITIONS: dict[PlanApprovalStatus, frozenset[PlanApprovalStatus]] = {
    PlanApprovalStatus.REGISTERING: frozenset({
        PlanApprovalStatus.PENDING,
        PlanApprovalStatus.REGISTRATION_FAILED,
        PlanApprovalStatus.STALE,
        PlanApprovalStatus.EXPIRED,
    }),
    PlanApprovalStatus.NOT_REQUIRED: frozenset({PlanApprovalStatus.CONSUMED, PlanApprovalStatus.EXPIRED}),
    PlanApprovalStatus.PENDING: frozenset({
        PlanApprovalStatus.APPROVED,
        PlanApprovalStatus.REJECTED,
        PlanApprovalStatus.STALE,
        PlanApprovalStatus.EXPIRED,
    }),
    PlanApprovalStatus.APPROVED: frozenset({
        PlanApprovalStatus.CONSUMED,
        PlanApprovalStatus.REVOKED,
        PlanApprovalStatus.STALE,
        PlanApprovalStatus.EXPIRED,
    }),
}


class AuthorizationStatus(str, Enum):
    """Lifecycle of a :class:`PlanExecutionAuthorization`."""

    ACTIVE = "active"
    CONSUMED = "consumed"
    EXPIRED = "expired"
    REVOKED = "revoked"

    @property
    def is_terminal(self) -> bool:
        return self != AuthorizationStatus.ACTIVE


# ---------------------------------------------------------------------------
# Binding digest
# ---------------------------------------------------------------------------

#: Tunable: number of hex chars retained from each evidence hash in the binding
#: digest. Full 64-char hashes are used; this documents intent only.
_BINDING_HASH_LEN = 64


def compute_risk_digest(risks: tuple[Any, ...]) -> str:
    """Hash the tuple of :class:`RiskAssessment` into a stable digest.

    Only the semantically meaningful fields participate; ``description`` text
    is excluded so that cosmetic wording changes do not invalidate approvals,
    while the risk ``level``, ``category`` and ``requires_approval`` flag do.
    """
    payload = sorted(
        (
            {
                "level": r.level,
                "category": r.category,
                "requires_approval": bool(r.requires_approval),
                "scope": tuple(sorted(r.affected_scope)),
            }
            for r in risks
        ),
        key=lambda x: (x["level"], x["category"]),
    )
    return _digest({"risks": payload})


def compute_verification_digest(requirements: tuple[Any, ...]) -> str:
    """Hash the verification plan (commands + types + risk) into a digest."""
    payload = sorted(
        (
            {
                "type": v.verification_type,
                "scope": v.scope,
                "expected": v.expected_result,
                "required": bool(v.required),
                "risk": v.risk_level,
                "command": tuple(v.command) if v.command else (),
            }
            for v in requirements
        ),
        key=lambda x: (x["type"], x["scope"], x["risk"]),
    )
    return _digest({"verification": payload})


def _extract_config_fingerprint(evidence: tuple[Any, ...]) -> str:
    """Return the trusted verification config hash recorded in plan evidence."""
    for ev in evidence:
        if getattr(ev, "source", None) == "verification-config":
            meta = getattr(ev, "metadata", {}) or {}
            ch = meta.get("config_hash")
            if ch:
                return str(ch)
    return ""


def compute_plan_binding_digest(plan: "ImplementationPlan") -> str:
    """Freeze the full plan + repository binding into one SHA-256 digest.

    Every field listed in the design spec §6 (plan id, content hash,
    repository/task/workspace ids, base sha, repository generation, affected
    file paths/operations/destinations, affected stable symbol ids, risk
    digest, verification digest, trusted config fingerprint) is hashed.

    If ANY of these changes between request creation and the approve callback
    (or at authorize time), the recomputed digest will differ and the
    approval MUST be moved to ``stale``.
    """
    affected_files = sorted(
        (
            {
                "path": f.path,
                "operation": f.operation.value,
                "destination": f.destination_path,
            }
            for f in plan.affected_files
        ),
        key=lambda x: (x["path"], x["operation"]),
    )
    affected_symbols = sorted(
        s.stable_symbol_id for s in plan.affected_symbols if s.stable_symbol_id
    )
    # Evidence-level file/symbol hashes: these catch in-file drift even when
    # the affected-file manifest is unchanged.
    file_evidence = sorted(
        (
            {"path": ev.path, "content_hash": ev.content_hash, "generation": ev.generation}
            for ev in plan.evidence
            if getattr(ev, "path", None) and getattr(ev, "content_hash", None)
        ),
        key=lambda x: x["path"],
    )
    symbol_evidence = sorted(
        (
            {
                "stable_symbol_id": ev.symbol_id,
                "qualified_name": (ev.metadata or {}).get("qualified_name", ""),
                "kind": (ev.metadata or {}).get("kind", ""),
                "generation": ev.generation,
            }
            for ev in plan.evidence
            if getattr(ev, "symbol_id", None)
        ),
        key=lambda x: x["stable_symbol_id"],
    )
    payload = {
        "plan_id": plan.plan_id,
        "content_hash": plan.content_hash,
        "repository_id": plan.repository_id,
        "task_id": plan.task_id,
        "workspace_id": plan.workspace_id,
        "base_sha": plan.base_sha,
        "repository_generation": int(plan.repository_generation),
        "planner_schema": "khaos.planning.v1",
        "affected_files": affected_files,
        "affected_symbols": affected_symbols,
        "file_evidence": file_evidence,
        "symbol_evidence": symbol_evidence,
        "risk_digest": compute_risk_digest(plan.risks),
        "verification_digest": compute_verification_digest(plan.verification_requirements),
        "config_fingerprint": _extract_config_fingerprint(plan.evidence),
    }
    return _digest(payload)


def _digest(payload: dict[str, Any]) -> str:
    """Stable SHA-256 over a JSON-normalized payload (matches ImplementationPlan.digest)."""
    import json

    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Nonce helpers (constant-time, hash-only storage)
# ---------------------------------------------------------------------------

#: Length of the raw nonce in bytes (256 bits of entropy).
NONCE_BYTES = 32


def generate_nonce() -> str:
    """Return a high-entropy opaque nonce (64 hex chars)."""
    return secrets.token_hex(NONCE_BYTES)


def hash_nonce(nonce: str) -> str:
    """Hash a nonce for storage. Only the hash is ever persisted.

    Uses a plain SHA-256 (the nonce already carries 256 bits of entropy so a
    slow KDF is unnecessary) and returns a hex digest.
    """
    return hashlib.sha256(nonce.encode("utf-8")).hexdigest()


def verify_nonce(nonce: str, expected_hash: str) -> bool:
    """Constant-time nonce verification against a stored hash."""
    return hmac.compare_digest(hash_nonce(nonce), expected_hash)


# ---------------------------------------------------------------------------
# Broker decision receipt helpers (§1)
# ---------------------------------------------------------------------------

#: Length of the receipt one-time-token in bytes (256 bits of entropy). The
#: plaintext token travels only inside the in-memory receipt returned by
#: ``ApprovalBroker.resolve_plan_approval``; only its hash is persisted in the
#: ``plan_approval_receipts`` outbox table. A forged dataclass receipt fails
#: because the store compares the token hash against a row that only the
#: broker could have created.
RECEIPT_TOKEN_BYTES = 32


def generate_receipt_token() -> str:
    """Return a high-entropy one-time token for a broker decision receipt."""
    return secrets.token_hex(RECEIPT_TOKEN_BYTES)


def hash_receipt_token(token: str) -> str:
    """Hash a receipt token for storage (only the hash is persisted)."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def verify_receipt_token(token: str, expected_hash: str) -> bool:
    """Constant-time receipt-token verification against a stored hash."""
    return hmac.compare_digest(hash_receipt_token(token), expected_hash)


def compute_reason_digest(reason: str) -> str:
    """Stable SHA-256 over a decision's free-text reason.

    Bound into the durable receipt so tampering with the reason text (which
    could carry authorization-relevant semantics) is detected at apply time.
    """
    return hashlib.sha256(reason.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Authenticated approval context (§1)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AuthenticatedApprovalContext:
    """The ONLY sanctioned carrier of actor identity into the broker.

    Batch 2.3 §5: a plain dataclass construction does NOT produce a valid
    context — the ``signature`` field must be a server-owned HMAC computed by
    :class:`ApprovalAuthenticator.issue_context`. A hand-constructed context
    has an empty/invalid signature and is rejected by the broker's
    ``verify_context`` check.

    Fields:
    * ``actor_id`` — the authenticated principal.
    * ``actor_type`` — "user" / "admin" / "system-service".
    * ``session_request_id`` — the authenticating session or request id.
    * ``authenticated_source`` — the mechanism ("api", "rpc", "session").
    * ``authentication_time`` — when the session authenticated (epoch seconds).
    * ``server_capability`` — the capability granting approval rights.
    * ``context_nonce`` — random nonce unique to this context (anti-replay).
    * ``issued_at`` / ``expires_at`` — context validity window.
    * ``signature`` — server-owned HMAC over all the above. Empty by default;
      only ``ApprovalAuthenticator.issue_context`` can compute a valid one.
    """

    actor_id: str
    actor_type: str
    session_request_id: str
    authenticated_source: str
    authentication_time: float
    server_capability: str
    context_nonce: str
    issued_at: float
    expires_at: float
    approval_request_id: str = ""
    session_generation: int = 0
    signature: str = ""  # empty unless minted by ApprovalAuthenticator

    def __post_init__(self) -> None:
        for field_name in ("actor_id", "actor_type", "session_request_id", "authenticated_source", "server_capability", "context_nonce"):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"AuthenticatedApprovalContext.{field_name} must be a non-empty string")

    def signing_payload(self) -> str:
        """The canonical payload over which the HMAC signature is computed."""
        return "|".join([
            self.actor_id, self.actor_type, self.session_request_id,
            self.authenticated_source, self.server_capability,
            self.context_nonce,
            f"{self.authentication_time:.6f}",
            f"{self.issued_at:.6f}",
            f"{self.expires_at:.6f}",
            self.approval_request_id, str(self.session_generation),
        ])

@dataclass(frozen=True)
class AuthenticatedSession:
    session_id: str
    principal_id: str
    principal_type: str
    authenticated_at: float
    session_expiry: float
    granted_capabilities: tuple[str, ...]
    generation: int = 1
    revoked: bool = False


class ApprovalAuthenticator:
    """Server-owned HMAC signer for :class:`AuthenticatedApprovalContext`.

    Holds a secret key generated at construction (or supplied for test
    reproducibility). ``issue_context`` is the ONLY way to produce a context
    with a valid signature. The broker holds a reference to the authenticator
    and calls ``verify_context`` before accepting any decision.

    A caller who constructs ``AuthenticatedApprovalContext(actor_id="admin",
    ...)`` directly gets ``signature=""`` which fails verification — there is
    no way to compute a valid HMAC without the server's key.
    """

    CAPABILITY_PLAN_APPROVAL = "plan-execution-approve"

    def __init__(self, secret_key: str | None = None) -> None:
        self._key = secret_key or secrets.token_hex(32)
        self._sessions: dict[str, AuthenticatedSession] = {}
        self._consumed_context_nonces: set[str] = set()

    def register_session(self, session: AuthenticatedSession) -> None:
        self._sessions[session.session_id] = session

    def revoke_session(self, session_id: str) -> None:
        session = self._sessions.get(session_id)
        if session is not None:
            self._sessions[session_id] = AuthenticatedSession(
                session.session_id, session.principal_id, session.principal_type,
                session.authenticated_at, session.session_expiry,
                session.granted_capabilities, session.generation + 1, True,
            )

    def issue_context(
        self,
        *,
        session: AuthenticatedSession,
        approval_request_id: str,
        authenticated_source: str = "api",
        capability: str = CAPABILITY_PLAN_APPROVAL,
        ttl_seconds: float = 300.0,
        now: float | None = None,
    ) -> AuthenticatedApprovalContext:
        """Mint a signed AuthenticatedApprovalContext.

        The caller supplies the authenticated session identity (which a real
        API/session layer has already verified). This method adds the
        server-owned HMAC signature that prevents forgery.
        """
        import time as _time

        now = _time.time() if now is None else now
        current = self._sessions.get(session.session_id)
        if current != session or session.revoked or now >= session.session_expiry:
            raise PermissionError("session is not active in the server registry")
        if capability not in session.granted_capabilities:
            raise PermissionError("session lacks plan approval capability")
        if not approval_request_id:
            raise ValueError("approval_request_id is required")
        ctx = AuthenticatedApprovalContext(
            actor_id=session.principal_id,
            actor_type=session.principal_type,
            session_request_id=session.session_id,
            authenticated_source=authenticated_source,
            authentication_time=session.authenticated_at,
            server_capability=capability,
            context_nonce=secrets.token_hex(16),
            issued_at=now,
            expires_at=min(now + ttl_seconds, session.session_expiry),
            approval_request_id=approval_request_id,
            session_generation=session.generation,
        )
        sig = self._sign(ctx.signing_payload())
        # frozen dataclass — use object.__setattr__ to set the signature.
        object.__setattr__(ctx, "signature", sig)
        return ctx

    def verify_context(
        self,
        ctx: AuthenticatedApprovalContext,
        *,
        expected_capability: str = CAPABILITY_PLAN_APPROVAL,
        expected_approval_request_id: str | None = None,
        consume: bool = False,
        now: float | None = None,
    ) -> bool:
        """Verify a context's signature, capability, and expiry.

        Returns True only if:
        * The HMAC signature matches (constant-time).
        * The capability matches ``expected_capability``.
        * The context has not expired.
        * The signature is non-empty (a hand-constructed context has "").
        """
        import time as _time

        if not ctx.signature:
            return False
        now = _time.time() if now is None else now
        if now >= ctx.expires_at:
            return False
        if ctx.server_capability != expected_capability:
            return False
        session = self._sessions.get(ctx.session_request_id)
        if session is None or session.revoked or session.generation != ctx.session_generation:
            return False
        if session.principal_id != ctx.actor_id or session.principal_type != ctx.actor_type or now >= session.session_expiry:
            return False
        if expected_approval_request_id is not None and ctx.approval_request_id != expected_approval_request_id:
            return False
        if ctx.context_nonce in self._consumed_context_nonces:
            return False
        expected_sig = self._sign(ctx.signing_payload())
        valid = hmac.compare_digest(ctx.signature, expected_sig)
        if valid and consume:
            self._consumed_context_nonces.add(ctx.context_nonce)
        return valid

    def _sign(self, payload: str) -> str:
        import hmac as _hmac

        return _hmac.new(
            self._key.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256
        ).hexdigest()


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PlanApprovalRequest:
    """A server-issued, content-bound plan approval request.

    Immutable by construction. The :attr:`binding_digest` freezes the whole
    plan + repository state at request time; it is recomputed and compared at
    every decision callback and at authorize time.
    """

    approval_request_id: str
    plan_id: str
    plan_content_hash: str
    repository_id: str
    task_id: str
    workspace_id: str
    base_sha: str
    repository_generation: int
    risk_level: str
    requested_operations: tuple[str, ...]
    affected_files: tuple[str, ...]
    affected_symbols: tuple[str, ...]
    verification_digest: str
    binding_digest: str
    requested_at: float
    expires_at: float
    status: PlanApprovalStatus
    broker_request_id: str
    reason: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PlanApprovalDecision:
    """An authenticated approve/reject decision applied to a request."""

    approval_request_id: str
    decision: PlanApprovalStatus  # APPROVED or REJECTED
    actor_id: str
    actor_type: str
    decided_at: float
    reason: str = ""
    authenticated_context: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PlanExecutionAuthorization:
    """Short-lived, single-use, opaque authorization to execute one plan.

    The plaintext :attr:`nonce` lives ONLY in the in-memory object returned by
    the gate. The persistent store keeps :attr:`nonce_hash` alone. Callers
    outside the server process receive only the opaque
    :attr:`authorization_id`.
    """

    authorization_id: str
    approval_request_id: str
    plan_id: str
    plan_content_hash: str
    repository_id: str
    task_id: str
    workspace_id: str
    base_sha: str
    repository_generation: int
    issued_at: float
    expires_at: float
    nonce: str  # plaintext; never persisted, never logged
    nonce_hash: str  # persisted surrogate
    status: AuthorizationStatus
    binding_digest: str


@dataclass(frozen=True)
class ApprovalRequirementOutcome:
    """Result of server-side approval-requirement evaluation.

    ``requires_approval`` is authoritative: it is recomputed from the final
    plan and IGNORES any client-supplied ``approved`` / ``requires_approval``
    / ``risk`` / ``status`` fields.
    """

    requires_approval: bool
    risk_level: str
    reason_codes: tuple[str, ...]
    requested_operations: tuple[str, ...]


@dataclass(frozen=True)
class PlanApprovalAuditEvent:
    """Structured audit record for one approval transition.

    Never contains source code, nonce plaintext, credentials, host absolute
    paths, or un-sanitized environment variables.
    """

    event_id: str
    event_type: str
    approval_request_id: str
    plan_id: str
    previous_status: str
    new_status: str
    actor_id: str
    actor_type: str
    authenticated_source: str
    timestamp: float
    reason_code: str
    task_id: str
    workspace_id: str
    repository_id: str
    correlation_id: str


@dataclass(frozen=True)
class BrokerDecisionReceipt:
    """Authenticated, one-time decision receipt minted by the ApprovalBroker.

    This is the ONLY authority that :meth:`PlanApprovalService.apply_broker_decision`
    accepts. It cannot be forged by callers because:

    * The ``one_time_token`` plaintext lives only inside this in-memory object
      (returned by ``ApprovalBroker.resolve_plan_approval``).
    * The store persists only ``hash_receipt_token(one_time_token)`` in the
      ``plan_approval_receipts`` outbox — a row the broker creates at resolve
      time — alongside EVERY authoritative field (namespace, actor identity,
      source, session, capability, decided_at, reason_digest, binding_digest,
      decision).
    * :meth:`PlanApprovalStore.apply_authenticated_decision` verifies the
      token hash AND compares EVERY authoritative field against the outbox row
      inside the same ``BEGIN IMMEDIATE`` transaction that applies the decision.
      Tampering ANY field (actor_id, source, decided_at, reason_digest, …) on
      a real receipt is detected and refused as CONFLICT.
    * Actor identity originates from :class:`AuthenticatedApprovalContext`,
      which only the authenticated API/session layer may construct — never
      from caller args to ``apply_broker_decision``.

    The receipt is namespaced (``namespace == "plan-execution"``) so it can
    never be confused with a Task or ChangeSet approval.
    """

    receipt_id: str
    namespace: str
    broker_request_id: str
    approval_request_id: str
    decision: PlanApprovalStatus  # APPROVED or REJECTED
    authenticated_actor_id: str
    authenticated_actor_type: str
    authenticated_source: str
    session_request_id: str
    server_capability: str
    binding_digest: str
    decided_at: float
    expires_at: float
    reason_digest: str  # SHA-256 of the decision reason; bound into the durable row
    one_time_token: str  # plaintext; never persisted, never logged
    token_hash: str  # persisted surrogate (hash of one_time_token)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PlanValidationContext:
    """Frozen view of a plan + repository produced by :class:`PlanLiveValidator`.

    Used at four identical validation stages (request creation, broker
    decision, authorization mint, authorization consume) so they cannot
    diverge.
    """

    plan: Any  # ImplementationPlan (typed loosely to avoid a runtime import cycle)
    state: Any  # CurrentRepositoryState
    binding_digest: str
    verification_digest: str
    risk_level: str
    requires_approval: bool
    reason_codes: tuple[str, ...]


@dataclass(frozen=True)
class WorkspaceExecutionLease:
    """Exclusive short-lived workspace execution lease (Batch 2.2 §7).

    Closes the TOCTOU between live validation and consume: the lease holds
    HEAD + generation + evidence digest at acquire time, and any concurrent
    HEAD/generation/workspace change is mutually exclusive with the lease
    (enforced by the ``uq_plan_execution_leases_active_workspace`` partial
    unique index — at most one ACTIVE lease per workspace).

    The lease is bound to a single consumed authorization; it cannot be
    replayed across workspaces or tasks.
    """

    lease_id: str
    task_id: str
    workspace_id: str
    repository_id: str
    plan_id: str
    head_sha: str
    repository_generation: int
    evidence_digest: str
    binding_digest: str
    authorization_id: str
    expiry: float
    owner_execution_id: str
    status: str  # "active" / "released" / "expired"
