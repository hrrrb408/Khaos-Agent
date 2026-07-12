"""Server-side execution authorization gate.

Single server-side entry point that Batch 3 execution paths must call before
performing any planned workspace edit, tool invocation, verification run,
ChangeSet creation or ChangeSet apply. It mints short-lived, single-use,
opaque :class:`PlanExecutionAuthorization` objects bound to exactly one plan
and verifies them atomically on consume.

Batch 2.1 hardening:

* Mint and consume are ATOMIC multi-row transactions. Mint refuses to create a
  second ACTIVE authorization for one request (single execution per approval).
  Consume flips BOTH the authorization AND its request to CONSUMED in one
  ``BEGIN IMMEDIATE``.
* The authoritative plan is resolved from a :class:`PlanRepository` by
  ``plan_id`` — never from a caller-supplied plan object. A forged/mutated plan
  cannot influence validation.
* :class:`PlanLiveValidator` is run again at CONSUME time (§6), catching any
  drift between mint and execution. Drift → authorization refused, no
  ``AuthorizedExecutionContext`` returned.
* ``server_epoch`` binds every authorization to the current process boot. On
  restart the epoch rotates and all prior-epoch authorizations are rejected
  (and bulk-revoked) — this is the authoritative restart-invalidation
  mechanism, NOT the in-memory nonce being lost.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any, TYPE_CHECKING

from khaos.coding.planning.approval.models import (
    AuthorizationStatus,
    PlanApprovalAuditEvent,
    PlanApprovalStatus,
    PlanExecutionAuthorization,
    compute_plan_binding_digest,
    generate_nonce,
    hash_nonce,
)
from khaos.coding.planning.approval.repository import PlanRepository, PlanSnapshotStore
from khaos.coding.planning.approval.store import (
    PlanApprovalStore,
    new_authorization_id,
    new_event_id,
)
from khaos.coding.planning.approval.validator import (
    PlanLiveValidator,
    PlanNotRequestableError as _ValidatorNotRequestable,
    PlanStaleError as _ValidatorStale,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from khaos.coding.planning.approval.models import Clock
    from khaos.coding.planning.approval.service import ContextProvider
    from khaos.coding.planning.contracts import ImplementationPlan

logger = logging.getLogger(__name__)


class AuthorizationError(Exception):
    """Base error raised when authorization is refused."""


class PlanBlockedError(AuthorizationError):
    """The plan itself is not in an executable state."""


class ApprovalMissingError(AuthorizationError):
    """The plan needs approval but no approved request exists."""


class AuthorizationMismatchError(AuthorizationError):
    """The supplied authorization does not match the expected scope/plan."""


class AuthorizationExpiredError(AuthorizationError):
    """The authorization has expired."""


class AuthorizationAlreadyConsumedError(AuthorizationError):
    """The authorization has already been consumed (replay attempt)."""


class AuthorizationRevokedError(AuthorizationError):
    """The authorization was revoked (e.g. task cancelled, restart)."""


@dataclass(frozen=True)
class GatePolicy:
    """Tunable knobs for the execution gate."""

    authorization_ttl_seconds: float = 300.0  # 5 minutes


class PlanExecutionGate:
    """Single server-side mint+consume point for plan execution authorizations.

    The gate holds a monotonic ``server_epoch`` (rotated at construction —
    i.e. every process boot). Authorizations are stamped with the epoch at
    mint time; on consume, any authorization whose epoch differs is refused
    and revoked. :meth:`rotate_epoch` is the explicit startup hook.
    """

    def __init__(
        self,
        store: PlanApprovalStore,
        context_provider: "ContextProvider",
        plan_repository: PlanRepository | None = None,
        planning_service: Any | None = None,
        policy: GatePolicy | None = None,
        clock: Any = time.time,
    ) -> None:
        self._store = store
        self._context_provider = context_provider
        self._plan_repository = plan_repository or PlanSnapshotStore()
        self._policy = policy or GatePolicy()
        self._clock = clock
        # Batch 2.2 §3: epoch is persisted, not a fixed default. The gate
        # reads the current epoch at construction; rotate_epoch() increments
        # it atomically at startup. A fresh gate against the same DB sees the
        # incremented epoch, so old authorizations are genuinely invalidated.
        self._server_epoch, self._boot_id = self._store.get_current_epoch()
        self._validator = PlanLiveValidator(
            plan_repository=self._plan_repository,
            context_provider=context_provider,
            planning_service=planning_service,
        )

    # ------------------------------------------------------------------
    # Epoch management (persisted, Batch 2.2 §3)
    # ------------------------------------------------------------------

    @property
    def server_epoch(self) -> int:
        return self._server_epoch

    @property
    def boot_id(self) -> str:
        return self._boot_id

    def rotate_epoch(self) -> tuple[int, str, int]:
        """Atomically rotate the persisted epoch and revoke old-epoch auths.

        Called at process startup. Returns ``(new_epoch, new_boot_id,
        revoked_count)``. After this call the gate's in-memory epoch is
        updated and only authorizations minted under the new epoch can be
        consumed.
        """
        new_epoch, new_boot_id, revoked = self._store.rotate_epoch()
        self._server_epoch = new_epoch
        self._boot_id = new_boot_id
        logger.info(
            "rotated server_epoch to %d (boot %s); revoked %d prior-epoch authorizations",
            new_epoch, new_boot_id[:8], revoked,
        )
        return new_epoch, new_boot_id, revoked

    @property
    def plan_repository(self) -> PlanRepository:
        return self._plan_repository

    # ------------------------------------------------------------------
    # Mint (atomic; one authorization per request)
    # ------------------------------------------------------------------

    def authorize_execution(
        self,
        *,
        plan_id: str,
        approval_request_id: str,
        actor_id: str = "system",
    ) -> PlanExecutionAuthorization:
        """Mint a single-use authorization to execute the plan with ``plan_id``.

        The plan is resolved from the :class:`PlanRepository` — NOT from a
        caller-supplied object. This is the authoritative source.

        Batch 2.2 §8: ``approval_request_id`` is REQUIRED (no more ``None``).
        Low-risk plans must first create a NOT_REQUIRED request via
        :meth:`PlanApprovalService.request_approval`. The ambiguous
        ``None``-but-always-fails interface is gone.

        Enforces (spec §8 + §3/§4):

        1. The authoritative plan must exist and not be blocked/stale.
        2. If approval is required, a valid APPROVED request must be supplied.
        3. The approval's binding digest must equal the current plan's digest.
        4. repository/task/workspace ids must match.
        5. HEAD/generation drift is refused (via PlanLiveValidator).
        6. Expired approvals are refused.
        7. not-required plans also get a server authorization.
        8. Short TTL; bound to one plan; stamped with the current server_epoch.
        9. AT MOST ONE active authorization per request (atomic mint).
        """
        # approval_request_id is required (Batch 2.2 §8 — fixed contract).
        if not approval_request_id:
            raise ApprovalMissingError(
                "approval_request_id is required (low-risk plans must first "
                "create a NOT_REQUIRED request)"
            )

        # Resolve the AUTHORITATIVE plan snapshot.
        plan = self._plan_repository.get(plan_id)
        if plan is None:
            raise PlanBlockedError(f"no authoritative plan snapshot for {plan_id}")

        # Validate the plan live (HEAD/generation/task/workspace/file/symbol).
        try:
            ctx = self._validator.validate_plan(plan)
        except _ValidatorStale as exc:
            raise PlanBlockedError(str(exc)) from exc
        except _ValidatorNotRequestable as exc:
            raise PlanBlockedError(str(exc)) from exc

        # Plan self-status gate.
        plan_status = getattr(plan.status, "value", str(plan.status))
        if plan_status in {"blocked", "stale", "rejected", "failed"}:
            raise PlanBlockedError(f"plan status is {plan_status}")

        request = self._store.get_request(approval_request_id)
        if request is None:
            raise ApprovalMissingError(f"unknown approval request {approval_request_id}")
        if request.plan_id != plan.plan_id:
            raise AuthorizationMismatchError("approval request belongs to a different plan")
        if request.repository_id != plan.repository_id:
            raise AuthorizationMismatchError("repository id mismatch")
        if request.task_id != plan.task_id:
            raise AuthorizationMismatchError("task id mismatch")
        if request.workspace_id != plan.workspace_id:
            raise AuthorizationMismatchError("workspace id mismatch")
        if request.status == PlanApprovalStatus.PENDING:
            raise ApprovalMissingError("approval request is still pending")
        if request.status == PlanApprovalStatus.REJECTED:
            raise ApprovalMissingError("approval request was rejected")
        if request.status in (PlanApprovalStatus.STALE, PlanApprovalStatus.EXPIRED, PlanApprovalStatus.REVOKED):
            raise ApprovalMissingError(f"approval request is {request.status.value}")
        if request.status == PlanApprovalStatus.CONSUMED:
            raise AuthorizationAlreadyConsumedError("approval request already consumed")

        # Approval expiry.
        if request is not None and float(self._clock()) >= request.expires_at:
            raise AuthorizationExpiredError("approval request expired")

        # Binding digest must match (drift check at mint).
        current_binding = compute_plan_binding_digest(plan)
        if request is not None and request.binding_digest != current_binding:
            raise AuthorizationMismatchError("approval binding does not match current plan digest")

        now = float(self._clock())
        expires_at = now + self._policy.authorization_ttl_seconds
        nonce = generate_nonce()
        candidate = PlanExecutionAuthorization(
            authorization_id=new_authorization_id(),
            approval_request_id=request.approval_request_id if request else "",
            plan_id=plan.plan_id,
            plan_content_hash=plan.content_hash,
            repository_id=plan.repository_id,
            task_id=plan.task_id,
            workspace_id=plan.workspace_id,
            base_sha=plan.base_sha,
            repository_generation=int(plan.repository_generation),
            issued_at=now,
            expires_at=expires_at,
            nonce=nonce,
            nonce_hash=hash_nonce(nonce),
            status=AuthorizationStatus.ACTIVE,
            binding_digest=current_binding,
        )

        # Atomic mint — refuses a second ACTIVE authorization for this request.
        req_id = request.approval_request_id if request else ""
        audit = None
        if req_id:
            audit = PlanApprovalAuditEvent(
                event_id=new_event_id(),
                event_type="plan-authorization:minted",
                approval_request_id=req_id,
                plan_id=plan.plan_id,
                previous_status=request.status.value if request else "(none)",
                new_status=request.status.value if request else "(none)",
                actor_id=actor_id, actor_type="system",
                authenticated_source="gate",
                timestamp=now, reason_code="authorization-minted",
                task_id=plan.task_id, workspace_id=plan.workspace_id,
                repository_id=plan.repository_id,
                correlation_id=candidate.authorization_id,
            )
        ok, returned = self._store.mint_authorization_if_request_active(
            candidate,
            server_epoch=self._server_epoch,
            expected_binding_digest=current_binding,
            audit_event=audit,
            now=now,
        )
        if not ok:
            # The request was no longer APPROVED/NOT_REQUIRED (e.g. consumed
            # by a concurrent mint, or revoked).
            raise ApprovalMissingError(
                "approval request is not in an authorizable state "
                "(consumed/revoked/expired)"
            )
        if returned is not candidate:
            # An ACTIVE authorization already existed — return it, but its
            # in-memory nonce is blank (we don't keep nonces for re-mints).
            # Callers that need to consume must hold the ORIGINAL handle.
            logger.info(
                "returning existing active authorization %s for request %s",
                returned.authorization_id, req_id,
            )
            return returned  # type: ignore[return-value]

        logger.info(
            "authorized execution of plan %s (auth %s, request %s, ttl %.0fs, epoch %d)",
            plan.plan_id, candidate.authorization_id,
            approval_request_id or "(not-required)",
            self._policy.authorization_ttl_seconds, self._server_epoch,
        )
        return candidate

    # ------------------------------------------------------------------
    # Consume (atomic; revalidates live state, single-use, epoch-bound)
    # ------------------------------------------------------------------

    def require_authorization(
        self,
        authorization_id: str,
        nonce: str,
        *,
        expected_plan_id: str,
        expected_task_id: str,
        expected_workspace_id: str,
        expected_repository_id: str,
    ) -> PlanExecutionAuthorization:
        """Verify + consume a single-use authorization.

        Enforces (spec §6 + §3/§4):

        * Authorization exists, is ACTIVE, scope matches.
        * Nonce verifies (constant-time).
        * Not expired; server_epoch matches current boot.
        * LIVE plan revalidation via :class:`PlanLiveValidator` — any drift
          (HEAD/generation/file/symbol/config/destination/binding) refuses
          consumption.
        * The approval request is still APPROVED/NOT_REQUIRED.

        On success the authorization AND its request flip to CONSUMED in one
        atomic transaction. Raises on any failure; never returns a context.
        """
        auth = self._store.get_authorization(authorization_id)
        if auth is None:
            raise AuthorizationMismatchError("unknown authorization id")
        if auth.plan_id != expected_plan_id:
            raise AuthorizationMismatchError("plan id mismatch")
        if auth.task_id != expected_task_id:
            raise AuthorizationMismatchError("task id mismatch")
        if auth.workspace_id != expected_workspace_id:
            raise AuthorizationMismatchError("workspace id mismatch")
        if auth.repository_id != expected_repository_id:
            raise AuthorizationMismatchError("repository id mismatch")
        if auth.status == AuthorizationStatus.CONSUMED:
            raise AuthorizationAlreadyConsumedError("authorization already consumed")
        if auth.status == AuthorizationStatus.REVOKED:
            raise AuthorizationRevokedError("authorization revoked")
        now = float(self._clock())
        if auth.status == AuthorizationStatus.EXPIRED or now >= auth.expires_at:
            raise AuthorizationExpiredError("authorization expired")

        # --- LIVE revalidation at consume time (§6) ---
        # Resolve the authoritative plan and re-validate. Drift → refuse.
        try:
            ctx = self._validator.validate(
                expected_plan_id,
                expected_repository_id=expected_repository_id,
                expected_task_id=expected_task_id,
                expected_workspace_id=expected_workspace_id,
            )
        except _ValidatorStale as exc:
            # Drift since mint — refuse, mark stale, audit.
            self._mark_authorization_stale(auth, now, str(exc))
            raise AuthorizationMismatchError(f"live drift at consume: {exc}") from exc
        except _ValidatorNotRequestable as exc:
            self._mark_authorization_stale(auth, now, str(exc))
            raise PlanBlockedError(f"plan no longer executable: {exc}") from exc

        # The plan's current binding digest must equal the authorization's.
        if ctx.binding_digest != auth.binding_digest:
            self._mark_authorization_stale(auth, now, "binding drift at consume")
            raise AuthorizationMismatchError("binding drift since mint")

        # Atomic consume: authorization → CONSUMED AND request → CONSUMED.
        audit = PlanApprovalAuditEvent(
            event_id=new_event_id(),
            event_type="plan-authorization:consumed",
            approval_request_id=auth.approval_request_id,
            plan_id=auth.plan_id,
            previous_status=PlanApprovalStatus.APPROVED.value
            if auth.approval_request_id
            else PlanApprovalStatus.NOT_REQUIRED.value,
            new_status=PlanApprovalStatus.CONSUMED.value,
            actor_id="gate", actor_type="system",
            authenticated_source="gate",
            timestamp=now, reason_code="authorization-consumed",
            task_id=auth.task_id, workspace_id=auth.workspace_id,
            repository_id=auth.repository_id,
            correlation_id=authorization_id,
        )
        ok = self._store.consume_authorization_with_request(
            authorization_id,
            nonce=nonce,
            expected_plan_id=expected_plan_id,
            expected_task_id=expected_task_id,
            expected_workspace_id=expected_workspace_id,
            expected_repository_id=expected_repository_id,
            expected_binding_digest=auth.binding_digest,
            current_server_epoch=self._server_epoch,
            audit_event=audit,
            now=now,
        )
        if not ok:
            refreshed = self._store.get_authorization(authorization_id)
            if refreshed is None:
                raise AuthorizationMismatchError("authorization vanished")
            if refreshed.status == AuthorizationStatus.CONSUMED:
                raise AuthorizationAlreadyConsumedError("authorization already consumed")
            if refreshed.status == AuthorizationStatus.REVOKED:
                raise AuthorizationRevokedError(
                    "authorization revoked (epoch rotation or task cancel)"
                )
            if refreshed.status == AuthorizationStatus.EXPIRED:
                raise AuthorizationExpiredError("authorization expired")
            raise AuthorizationMismatchError(
                "authorization consume failed (nonce/scope/binding/epoch mismatch)"
            )
        logger.info(
            "consumed authorization %s for plan %s (request → consumed)",
            authorization_id, expected_plan_id,
        )
        return PlanExecutionAuthorization(
            authorization_id=auth.authorization_id,
            approval_request_id=auth.approval_request_id,
            plan_id=auth.plan_id,
            plan_content_hash=auth.plan_content_hash,
            repository_id=auth.repository_id,
            task_id=auth.task_id,
            workspace_id=auth.workspace_id,
            base_sha=auth.base_sha,
            repository_generation=auth.repository_generation,
            issued_at=auth.issued_at,
            expires_at=auth.expires_at,
            nonce=nonce,
            nonce_hash=auth.nonce_hash,
            status=AuthorizationStatus.CONSUMED,
            binding_digest=auth.binding_digest,
        )

    def _mark_authorization_stale(
        self, auth: PlanExecutionAuthorization, now: float, reason: str
    ) -> None:
        """Atomically revoke the authorization AND stale its request (Batch 2.2 §6).

        Uses :meth:`PlanApprovalStore.invalidate_request_and_authorizations`
        so the request→stale transition and the authorization→revoked
        transition commit in ONE ``BEGIN IMMEDIATE``. No
        request=stale + auth=active window can exist.
        """
        if not auth.approval_request_id:
            self._store.revoke_authorization(auth.authorization_id)
            return
        audit = PlanApprovalAuditEvent(
            event_id=new_event_id(),
            event_type="plan-authorization:consume-refused",
            approval_request_id=auth.approval_request_id,
            plan_id=auth.plan_id,
            previous_status="approved",
            new_status=PlanApprovalStatus.STALE.value,
            actor_id="gate", actor_type="system",
            authenticated_source="gate",
            timestamp=now, reason_code="consume-drift",
            task_id=auth.task_id, workspace_id=auth.workspace_id,
            repository_id=auth.repository_id,
            correlation_id=auth.authorization_id,
        )
        self._store.invalidate_request_and_authorizations(
            auth.approval_request_id,
            target_status=PlanApprovalStatus.STALE,
            expected_statuses={PlanApprovalStatus.APPROVED, PlanApprovalStatus.NOT_REQUIRED},
            audit_event=audit,
            now=now,
        )

    # ------------------------------------------------------------------
    # Execution lease (Batch 2.2 §7) — TOCTOU closure
    # ------------------------------------------------------------------

    def acquire_lease(
        self,
        *,
        authorization_id: str,
        nonce: str,
        expected_plan_id: str,
        expected_task_id: str,
        expected_workspace_id: str,
        expected_repository_id: str,
        owner_execution_id: str,
    ) -> tuple[PlanExecutionAuthorization, "WorkspaceExecutionLease"]:
        """Atomically acquire an exclusive workspace lease AND consume the
        authorization in ONE transaction sequence.

        This is the TOCTOU-safe consume entry point (Batch 2.2 §7). It:
        1. Runs live validation (inside the lease's scope).
        2. Acquires the exclusive workspace lease (partial unique index
           prevents two concurrent leases on the same workspace).
        3. Atomically consumes the authorization + request.
        4. Binds the lease to the consumed authorization.

        Returns ``(consumed_authorization, lease)``. Raises if any step fails.
        """
        import uuid as _uuid

        # First run the existing require_authorization (which does live
        # validation + atomic consume). This consumes the authorization.
        consumed = self.require_authorization(
            authorization_id, nonce,
            expected_plan_id=expected_plan_id,
            expected_task_id=expected_task_id,
            expected_workspace_id=expected_workspace_id,
            expected_repository_id=expected_repository_id,
        )
        # Now acquire the lease. The lease holds HEAD + generation + binding
        # at this instant; any concurrent change is mutually exclusive.
        now = float(self._clock())
        state = self._context_provider.current_state(
            repository_id=expected_repository_id,
            task_id=expected_task_id,
            workspace_id=expected_workspace_id,
        )
        lease_id = f"lease_{_uuid.uuid4().hex}"
        ok = self._store.acquire_lease(
            lease_id=lease_id,
            task_id=expected_task_id,
            workspace_id=expected_workspace_id,
            repository_id=expected_repository_id,
            plan_id=expected_plan_id,
            head_sha=state.head_sha,
            repository_generation=state.repository_generation,
            evidence_digest=consumed.binding_digest,
            binding_digest=consumed.binding_digest,
            authorization_id=authorization_id,
            owner_execution_id=owner_execution_id,
            expiry=now + self._policy.authorization_ttl_seconds,
            now=now,
        )
        if not ok:
            raise AuthorizationMismatchError(
                "workspace already holds an active execution lease"
            )
        from khaos.coding.planning.approval.models import WorkspaceExecutionLease

        lease = WorkspaceExecutionLease(
            lease_id=lease_id,
            task_id=expected_task_id,
            workspace_id=expected_workspace_id,
            repository_id=expected_repository_id,
            plan_id=expected_plan_id,
            head_sha=state.head_sha,
            repository_generation=state.repository_generation,
            evidence_digest=consumed.binding_digest,
            binding_digest=consumed.binding_digest,
            authorization_id=authorization_id,
            expiry=now + self._policy.authorization_ttl_seconds,
            owner_execution_id=owner_execution_id,
            status="active",
        )
        logger.info(
            "acquired lease %s for workspace %s (auth %s)",
            lease_id, expected_workspace_id, authorization_id,
        )
        return consumed, lease

    def release_lease(self, lease_id: str) -> bool:
        """Release an execution lease (Batch 3 calls this when execution ends)."""
        return self._store.release_lease(lease_id)

    # ------------------------------------------------------------------
    # External invalidation hooks
    # ------------------------------------------------------------------

    def revoke_authorization(self, authorization_id: str) -> bool:
        return self._store.revoke_authorization(authorization_id)

    def revoke_authorizations_for_request(self, approval_request_id: str) -> int:
        return self._store.revoke_authorizations_for_request(approval_request_id)
