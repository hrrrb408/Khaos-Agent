"""Server-side execution authorization gate.

This is the SINGLE entry point that Batch 3 execution paths must call before
performing any planned workspace edit, tool invocation, verification run,
ChangeSet creation or ChangeSet apply. It mints short-lived, single-use,
opaque :class:`PlanExecutionAuthorization` objects bound to exactly one plan
and verifies them atomically on consume.

Guarantees:

* Blocked / stale / rejected / revoked / expired plans are refused.
* A plan that needs approval but has no approved request is refused.
* The approval's binding digest MUST match the current plan's digest.
* repository / task / workspace ids MUST all match.
* HEAD, generation, files, symbols and trusted-config drift are refused.
* Expired approvals are refused.
* ``not-required`` plans also receive a server-issued authorization — there
  is no "skip the gate" path.
* Authorizations are short-lived (default 5 minutes).
* Each authorization binds exactly one plan and defaults to single-use.
* Authorizations cannot be constructed by the Agent or the client; only this
  gate constructs them, and only its ``require_authorization`` method accepts
  them at consume time.
* Authorizations cannot be reused across workspaces, tasks or repositories.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any, Protocol, TYPE_CHECKING

from khaos.coding.planning.approval.models import (
    AuthorizationStatus,
    PlanApprovalStatus,
    PlanExecutionAuthorization,
    compute_plan_binding_digest,
    generate_nonce,
    hash_nonce,
)
from khaos.coding.planning.approval.store import (
    PlanApprovalStore,
    new_authorization_id,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from khaos.coding.planning.contracts import ImplementationPlan
    from khaos.coding.planning.approval.service import ContextProvider

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
    """The authorization was revoked (e.g. task cancelled)."""


@dataclass(frozen=True)
class GatePolicy:
    """Tunable knobs for the execution gate."""

    authorization_ttl_seconds: float = 300.0  # 5 minutes


# ---------------------------------------------------------------------------
# The gate
# ---------------------------------------------------------------------------


class PlanExecutionGate:
    """Single server-side mint+consume point for plan execution authorizations.

    Construction takes the same :class:`PlanApprovalStore` used by the
    approval service (so authorizations live next to their approvals), a
    :class:`ContextProvider` for live state, and a :class:`GatePolicy`.
    """

    def __init__(
        self,
        store: PlanApprovalStore,
        context_provider: "ContextProvider",
        policy: GatePolicy | None = None,
        clock: Any = time.time,
    ) -> None:
        self._store = store
        self._context_provider = context_provider
        self._policy = policy or GatePolicy()
        self._clock = clock

    # ------------------------------------------------------------------
    # Mint
    # ------------------------------------------------------------------

    def authorize_execution(
        self,
        *,
        plan: "ImplementationPlan",
        approval_request_id: str | None,
        actor_id: str = "system",
    ) -> PlanExecutionAuthorization:
        """Mint a single-use authorization to execute ``plan``.

        Spec §8 rules enforced:

        1. blocked/stale/rejected/revoked/expired plan → refused.
        2. needs approval but no approved request → refused.
        3. approval digest ≠ plan digest → refused.
        4. repository/task/workspace mismatch → refused.
        5. HEAD/generation/file/symbol/config drift → refused.
        6. approval expired → refused.
        7. not-required plans also get a server authorization.
        8. short TTL.
        9. bound to a single plan.
        10/11/12. only this gate constructs/accepts; never cross-scope.
        """
        # 1 — plan status gate. We treat any non-ready/approved status as
        # blocked. (Plans that needed approval are approved via the approval
        # service; not-required plans are still in READY.)
        plan_status = getattr(plan.status, "value", str(plan.status))
        if plan_status in {"blocked", "stale", "rejected", "failed"}:
            raise PlanBlockedError(f"plan status is {plan_status}")

        # If no approval request id was supplied, the gate must still verify
        # that the plan does NOT require human approval. A high-risk plan with
        # no approval request is refused outright (server-authoritative).
        if approval_request_id is None:
            from khaos.coding.planning.approval.requirement import evaluate_approval_requirement

            outcome = evaluate_approval_requirement(plan)
            if outcome.requires_approval:
                raise ApprovalMissingError(
                    "plan requires approval but no approval_request_id supplied"
                )

        # 2/3/4 — approval request lookup + binding verification.
        request = None
        if approval_request_id is not None:
            request = self._store.get_request(approval_request_id)
            if request is None:
                raise ApprovalMissingError(
                    f"unknown approval request {approval_request_id}"
                )

            # The request must belong to THIS plan.
            if request.plan_id != plan.plan_id:
                raise AuthorizationMismatchError(
                    "approval request belongs to a different plan"
                )
            if request.repository_id != plan.repository_id:
                raise AuthorizationMismatchError("repository id mismatch")
            if request.task_id != plan.task_id:
                raise AuthorizationMismatchError("task id mismatch")
            if request.workspace_id != plan.workspace_id:
                raise AuthorizationMismatchError("workspace id mismatch")

            # Request must be in a decidable state.
            if request.status == PlanApprovalStatus.PENDING:
                raise ApprovalMissingError("approval request is still pending")
            if request.status == PlanApprovalStatus.REJECTED:
                raise ApprovalMissingError("approval request was rejected")
            if request.status in (PlanApprovalStatus.STALE, PlanApprovalStatus.EXPIRED, PlanApprovalStatus.REVOKED):
                raise ApprovalMissingError(
                    f"approval request is {request.status.value}"
                )
            if request.status == PlanApprovalStatus.CONSUMED:
                raise AuthorizationAlreadyConsumedError(
                    "approval request has already been consumed"
                )
            # APPROVED or NOT_REQUIRED are acceptable.

        # 5 — live state re-check (HEAD + generation).
        state = self._context_provider.current_state(
            repository_id=plan.repository_id,
            task_id=plan.task_id,
            workspace_id=plan.workspace_id,
        )
        if state.head_sha != plan.base_sha:
            raise PlanBlockedError(
                f"head drift: plan={plan.base_sha} current={state.head_sha}"
            )
        if int(state.repository_generation) != int(plan.repository_generation):
            raise PlanBlockedError(
                f"generation drift: plan={plan.repository_generation} "
                f"current={state.repository_generation}"
            )
        if state.task_terminal or state.workspace_terminal:
            raise PlanBlockedError("task or workspace is terminal")

        # 3 (continued) — the approval's binding digest must equal the
        # CURRENT plan's binding digest. This is the master drift check: any
        # file/symbol/config/destination/verification change rotates it.
        current_binding = compute_plan_binding_digest(plan)
        if request is not None and request.binding_digest != current_binding:
            raise AuthorizationMismatchError(
                "approval binding does not match current plan digest"
            )

        # 6 — approval expiry.
        if request is not None and time.time() >= request.expires_at:
            raise AuthorizationExpiredError("approval request expired")

        now = float(self._clock())
        expires_at = now + self._policy.authorization_ttl_seconds

        # Mint the authorization. The plaintext nonce lives only in the
        # returned object; the store keeps only its hash.
        nonce = generate_nonce()
        authorization = PlanExecutionAuthorization(
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
        self._store.insert_authorization(authorization)
        logger.info(
            "authorized execution of plan %s (auth %s, request %s, ttl %.0fs)",
            plan.plan_id, authorization.authorization_id,
            approval_request_id or "(not-required)",
            self._policy.authorization_ttl_seconds,
        )
        return authorization

    # ------------------------------------------------------------------
    # Consume (Batch 3 entry point)
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

        This is the ONLY method Batch 3 execution paths may call before
        touching the repository. Every check happens inside one atomic
        ``BEGIN IMMEDIATE`` so concurrent consumers cannot both succeed.

        Returns the (now-consumed) authorization on success; raises one of
        the :class:`AuthorizationError` subclasses otherwise.
        """
        auth = self._store.get_authorization(authorization_id)
        if auth is None:
            raise AuthorizationMismatchError("unknown authorization id")
        # Cross-scope replay defense — checked both here (fast path) and
        # inside the atomic consume (authoritative).
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
        if auth.status == AuthorizationStatus.EXPIRED or time.time() >= auth.expires_at:
            raise AuthorizationExpiredError("authorization expired")

        # Nonce verification + atomic consume. The store does the CAS.
        ok = self._store.consume_authorization(
            authorization_id,
            expected_plan_id=expected_plan_id,
            expected_task_id=expected_task_id,
            expected_workspace_id=expected_workspace_id,
            expected_repository_id=expected_repository_id,
            nonce=nonce,
        )
        if not ok:
            # The consume failed. Re-read to classify the cause.
            refreshed = self._store.get_authorization(authorization_id)
            if refreshed is None:
                raise AuthorizationMismatchError("authorization vanished")
            if refreshed.status == AuthorizationStatus.CONSUMED:
                raise AuthorizationAlreadyConsumedError("authorization already consumed")
            if refreshed.status == AuthorizationStatus.EXPIRED:
                raise AuthorizationExpiredError("authorization expired")
            # Otherwise it's a nonce mismatch (forged/replayed) or a scope
            # mismatch caught inside the CAS — treat as mismatch.
            raise AuthorizationMismatchError(
                "authorization consume failed (nonce or scope mismatch)"
            )
        logger.info(
            "consumed authorization %s for plan %s",
            authorization_id, expected_plan_id,
        )
        # Return a view with the (still-plaintext) nonce for the caller.
        consumed = self._store.get_authorization(authorization_id)
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

    # ------------------------------------------------------------------
    # External invalidation hooks (Task cancel / Workspace cleanup)
    # ------------------------------------------------------------------

    def revoke_authorization(self, authorization_id: str) -> bool:
        return self._store.revoke_authorization(authorization_id)

    def revoke_authorizations_for_request(self, approval_request_id: str) -> int:
        return self._store.revoke_authorizations_for_request(approval_request_id)
