"""Independent authority daemon for signed execution receipts.

This service is intentionally a small control-plane reference implementation.
Production deployment must run it under a dedicated OS identity and connect
an append-only/WORM ``AuditWriter``; the daemon refuses to start without both
requirements.  The local process broker is only the explicitly selected test
profile and is never a production fallback.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import secrets
import socket
import stat
import sys
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from khaos.security.authorityd_protocol import (
    AUTHORITYD_PROTOCOL,
    MAX_GRANT_TTL_SECONDS,
    MAX_MESSAGE_BYTES,
    AuditWriter,
    AuthorityControlPlaneError,
    AuthorizationIntent,
    Ed25519KeyStore,
    RemoteAuditUnavailableError,
    SignedAuthorizationReceipt,
    _canonical,
    _digest,
    _encode_receipt_timestamp,
    _required_text,
    derive_resource_digest,
)
from khaos.security.identity_isolation import (
    IdentityIsolationError,
    peer_uid,
    peer_uid_platform,
    read_contract_from_environment,
    validate_private_unix_socket,
)
from khaos.security.principals import (
    DelegationAuthority,
    DelegationScope,
    PrincipalDelegationError,
    principal_from_kind,
)
from khaos.security.protocol_boundary import (
    ProtocolBoundaryError,
    read_bounded_line,
    require_receipt_transition,
)
from khaos.security.resource_scope import (
    ResourceScopeError,
    TypedResourcePartialOrder,
)

logger = logging.getLogger(__name__)

_NATIVE_EXECUTION_OPERATION = "exec.host"
_HEX_DIGITS = frozenset("0123456789abcdef")

_RECEIPT_PREPARED = "prepared"
_RECEIPT_PREPARING = "preparing"
_RECEIPT_CLAIMED = "claimed"
_RECEIPT_CLAIMING = "claiming"
_RECEIPT_NARROWING = "narrowing"
_RECEIPT_COMPLETING = "completing"
_RECEIPT_REVOKING = "revoking"
_RECEIPT_TERMINAL = "terminal"
_RECEIPT_REVOKED_BY_GRANT = "revoked-by-grant"

_NARROW_RESERVED = "reserved"
_NARROW_CHILD_PREPARING = "child-preparing"
_NARROW_CHILD_PREPARED = "child-prepared"
_NARROW_COMMITTING = "committing"
_NARROW_COMMITTED = "committed"
_NARROW_ABORTING = "aborting"
_NARROW_ABORTED = "aborted"


@dataclass
class _ReceiptRecord:
    receipt: SignedAuthorizationReceipt
    state: str = _RECEIPT_PREPARED


def _set_receipt_state(record: _ReceiptRecord, next_state: str) -> None:
    """Apply one pure, auditable authority state-machine transition."""
    try:
        require_receipt_transition(record.state, next_state)
    except ProtocolBoundaryError as exc:
        raise AuthorityControlPlaneError(str(exc)) from exc
    record.state = next_state


def _same_receipt(
    left: SignedAuthorizationReceipt, right: SignedAuthorizationReceipt
) -> bool:
    """Compare receipts by their exact signed wire representation.

    The daemon stores the in-process receipt with Python seconds-based
    floats, while a client crossing the JSON socket reconstructs it from the
    integer-millisecond wire representation.  Dataclass equality would treat
    those two equivalent receipts as different objects and incorrectly make a
    valid claim or completion look unknown.  Comparing the canonical wire
    dictionaries preserves the nonce/signature binding without trusting the
    transport's in-memory object identity.
    """
    return left.to_dict() == right.to_dict()


@dataclass
class _GrantRecord:
    principal_id: str
    project_id: str
    runtime_id: str
    task_id: str
    workspace_id: str
    workspace_generation: int
    policy_digest: str
    resource_digest: str
    operation_family: str
    authorization_epoch: int
    context_digest: str
    issued_at: float
    expires_at: float
    principal_kind: str = ""
    parent_principal_id: str = ""
    session_id: str = ""
    delegation_digest: str = ""


@dataclass
class _NarrowTransaction:
    """Own every resource reserved by one parent-to-child transition.

    Narrowing runs child preparation outside the daemon lock so the audit
    writer cannot block unrelated authority decisions.  The transaction
    record is the compensating owner for that interval: a grant invalidation
    can atomically move it to ``ABORTED`` and transfer its anonymous audit
    reservation to a stable abort event before the grant is forgotten.
    """

    transaction_id: str
    parent_receipt: SignedAuthorizationReceipt
    child_intent_nonce: str
    grant_id: str | None
    descendant_key: tuple[str, str] | None
    audit_token: str
    state: str = _NARROW_RESERVED
    child_receipt: SignedAuthorizationReceipt | None = None
    abort_event: dict[str, Any] | None = None
    abort_evidence_owner: str | None = None


class _ExpiredGrant(AuthorityControlPlaneError):
    """Internal rejection carrying the audit event for an expired grant."""

    def __init__(self, event: dict[str, Any], *, events: list[dict[str, Any]] | None = None) -> None:
        super().__init__("authority grant has expired")
        self.event = event
        self.events = events or [event]


class AuthorityDaemon:
    """Policy-enforcing signer and two-phase audit coordinator."""

    def __init__(
        self,
        *,
        socket_path: Path,
        signing_key: Ed25519PrivateKey,
        audit_writer: AuditWriter | None,
        issuer_id: str,
        policy: Callable[[AuthorizationIntent], None],
        max_pending_receipts: int = 1024,
        max_pending_per_principal: int = 256,
        terminal_tombstone_limit: int = 4096,
        max_audit_obligations: int | None = None,
        require_live_grants: bool = False,
        require_typed_principals: bool = False,
    ) -> None:
        if not socket_path.is_absolute() or audit_writer is None:
            raise AuthorityControlPlaneError(
                "authorityd requires an absolute socket and independent audit writer"
            )
        if (
            max_pending_receipts <= 0
            or max_pending_per_principal <= 0
            or terminal_tombstone_limit <= 0
            or (
                max_audit_obligations is not None
                and max_audit_obligations <= 0
            )
        ):
            raise ValueError("authorityd receipt quotas must be positive")
        self.socket_path = socket_path
        self.signing_key = signing_key
        self.audit_writer = audit_writer
        self.issuer_id = issuer_id
        self.policy = policy
        self._lock = threading.RLock()
        self._audit_lock = threading.Lock()
        self._pending: dict[str, SignedAuthorizationReceipt] = {}
        self._states: dict[str, _ReceiptRecord] = {}
        self._terminal: dict[str, str] = {}
        self._grants: dict[str, _GrantRecord] = {}
        self._grant_terminal: dict[str, str] = {}
        # A live grant may issue typed descendants through one-shot
        # narrowing receipts.  Keep the issued (resource, operation) pairs
        # independently from receipt state so a short-lived child can be
        # renewed after its receipt TTL, while an arbitrary scope/action can
        # never be smuggled in through a direct prepare.  Reservations close
        # the small gap while a child prepare is in flight.
        self._grant_descendants: dict[str, set[tuple[str, str]]] = {}
        self._grant_descendant_reservations: dict[str, set[tuple[str, str]]] = {}
        # A narrow transaction owns the parent receipt, child preparation,
        # descendant reservation, and audit reservation as one unit.  Grant
        # revoke/expiry/rotation must abort these records before forgetting
        # the grant, otherwise the in-flight caller would retain an anonymous
        # audit reservation forever.
        self._narrow_transactions: dict[str, _NarrowTransaction] = {}
        self.max_pending_receipts = max_pending_receipts
        self.max_pending_per_principal = max_pending_per_principal
        self.terminal_tombstone_limit = terminal_tombstone_limit
        self.max_audit_obligations = (
            max_audit_obligations
            if max_audit_obligations is not None
            else terminal_tombstone_limit
        )
        # Terminal state is independent from audit delivery. A lost WORM
        # response must never put an already-consumed receipt back into an
        # executable transition.
        self._audit_obligations: dict[str, dict[str, Any]] = {}
        self._audit_reservations: set[str] = set()
        self._audit_quarantined = False
        self.require_live_grants = require_live_grants
        self.require_typed_principals = require_typed_principals
        # Typed principal delegation state is owned by the authority daemon,
        # never by the Python caller: roots are registered here, children are
        # issued here (narrow-only, unique nonce), consumption is one-shot
        # here, and revocation cascades to unclaimed descendants here.
        self._delegations = DelegationAuthority()
        self._closed = False

    def _remember_grant_terminal_locked(self, grant_id: str, state: str) -> None:
        """Retain a bounded grant tombstone for stale receipt rejection."""
        self._grant_terminal[grant_id] = state
        while len(self._grant_terminal) > self.terminal_tombstone_limit:
            self._grant_terminal.pop(next(iter(self._grant_terminal)))

    def _reserve_grant_descendant_locked(
        self,
        grant_id: str,
        resource_digest: str,
        operation: str,
    ) -> tuple[str, str] | None:
        """Reserve one issued child scope before its receipt is prepared."""
        key = (resource_digest, operation)
        descendants = self._grant_descendants.setdefault(grant_id, set())
        reservations = self._grant_descendant_reservations.setdefault(
            grant_id, set()
        )
        if key in descendants:
            return None
        if key in reservations:
            raise AuthorityControlPlaneError(
                "authority grant descendant scope is already being issued"
            )
        if len(descendants) + len(reservations) >= self.max_pending_receipts:
            raise AuthorityControlPlaneError(
                "authority grant descendant scope quota is exhausted"
            )
        reservations.add(key)
        return key

    def _commit_grant_descendant_locked(
        self, grant_id: str, key: tuple[str, str]
    ) -> None:
        """Make a successfully prepared child scope renewable."""
        reservations = self._grant_descendant_reservations.get(grant_id)
        if reservations is None or key not in reservations:
            raise AuthorityControlPlaneError(
                "authority grant descendant reservation disappeared"
            )
        reservations.remove(key)
        self._grant_descendants.setdefault(grant_id, set()).add(key)
        if not reservations:
            self._grant_descendant_reservations.pop(grant_id, None)

    def _release_grant_descendant_reservation_locked(
        self, grant_id: str, key: tuple[str, str]
    ) -> None:
        """Release a child reservation when its prepare did not commit."""
        reservations = self._grant_descendant_reservations.get(grant_id)
        if reservations is None:
            return
        reservations.discard(key)
        if not reservations:
            self._grant_descendant_reservations.pop(grant_id, None)

    def _narrow_abort_event_locked(
        self,
        transaction: _NarrowTransaction,
        *,
        reason: str,
    ) -> dict[str, Any]:
        """Build the durable event that takes ownership of a narrow token."""
        if transaction.abort_event is not None:
            return transaction.abort_event
        child = transaction.child_receipt
        return self._audit_event(
            {
                # The token already owns one bounded audit slot.  Reusing it
                # as the stable event id transfers ownership without briefly
                # consuming a second slot or leaving an anonymous key behind.
                "event_id": transaction.audit_token,
                "kind": "execution.narrow-aborted-by-grant",
                "transaction_id": transaction.transaction_id,
                "grant_id": transaction.grant_id,
                "parent_nonce": transaction.parent_receipt.nonce,
                "parent_receipt_digest": transaction.parent_receipt.digest,
                "child_nonce": child.nonce if child is not None else None,
                "child_receipt_digest": child.digest if child is not None else None,
                "child_intent_nonce": transaction.child_intent_nonce,
                "reason": reason,
                "issuer_id": self.issuer_id,
            }
        )

    def _commit_narrow_abort_locked(
        self,
        transaction: _NarrowTransaction,
        *,
        planned_event: dict[str, Any] | None = None,
        reason: str | None = None,
        evidence_owner: str,
    ) -> dict[str, Any]:
        """Atomically abort a narrow and bind its token to abort evidence."""
        if (planned_event is None) == (reason is None):
            raise AuthorityControlPlaneError(
                "narrow abort commit requires exactly one event plan or reason"
            )
        event = self._narrow_abort_event_locked(
            transaction,
            reason=(
                str(planned_event.get("reason"))
                if planned_event is not None
                else str(reason)
            ),
        )
        if planned_event is not None:
            normalized_plan = self._audit_event(planned_event)
            if event != normalized_plan:
                raise AuthorityControlPlaneError(
                    "narrow abort event changed between planning and commit"
                )
        if transaction.state in {_NARROW_ABORTING, _NARROW_ABORTED}:
            if transaction.abort_event is not None and transaction.abort_event != event:
                raise AuthorityControlPlaneError(
                    "terminal narrow abort evidence does not match its plan"
                )
            return event
        if transaction.audit_token not in self._audit_reservations:
            raise AuthorityControlPlaneError(
                "authorityd narrow audit reservation disappeared before abort"
            )
        transaction.state = _NARROW_ABORTING
        transaction.abort_event = event
        transaction.abort_evidence_owner = evidence_owner
        if transaction.grant_id is not None and transaction.descendant_key is not None:
            self._release_grant_descendant_reservation_locked(
                transaction.grant_id,
                transaction.descendant_key,
            )
        transaction.state = _NARROW_ABORTED
        return event

    def _remove_narrow_receipts_locked(
        self,
        transaction: _NarrowTransaction,
        *,
        terminal_state: str = _RECEIPT_REVOKED_BY_GRANT,
    ) -> None:
        """Remove any still-launchable parent/child records after an abort."""
        receipts = [transaction.parent_receipt]
        if transaction.child_receipt is not None:
            receipts.append(transaction.child_receipt)
        for receipt in receipts:
            current = self._states.get(receipt.nonce)
            if current is None or not _same_receipt(current.receipt, receipt):
                continue
            self._pending.pop(receipt.nonce, None)
            self._states.pop(receipt.nonce, None)
            self._remember_terminal_locked(receipt.nonce, terminal_state)

    def _active_narrow_abort_plans_locked(
        self,
        grant_id: str,
        *,
        reason: str,
    ) -> list[tuple[_NarrowTransaction, dict[str, Any]]]:
        """Plan abort evidence without mutating transactions or quotas."""
        plans: list[tuple[_NarrowTransaction, dict[str, Any]]] = []
        for transaction in tuple(self._narrow_transactions.values()):
            if transaction.grant_id != grant_id:
                continue
            if transaction.state in {
                _NARROW_ABORTING,
                _NARROW_ABORTED,
                _NARROW_COMMITTING,
                _NARROW_COMMITTED,
            }:
                continue
            plans.append(
                (
                    transaction,
                    self._narrow_abort_event_locked(transaction, reason=reason),
                )
            )
        return plans

    def _forget_grant_descendants_locked(self, grant_id: str) -> None:
        """Drop descendant authority together with a terminal grant."""
        self._grant_descendants.pop(grant_id, None)
        self._grant_descendant_reservations.pop(grant_id, None)

    def _grant_revocation_events_locked(
        self,
        grant_id: str,
        record: _GrantRecord,
        *,
        reason: str,
        authorization_epoch: int | None = None,
        workspace_generation: int | None = None,
        grant_event_kind: str = "authority.grant.revoked",
    ) -> tuple[
        list[dict[str, Any]],
        list[str],
        list[tuple[_NarrowTransaction, dict[str, Any]]],
    ]:
        """Build grant and PREPARED-descendant terminal evidence."""
        events: list[dict[str, Any]] = [
            self._audit_event(
                {
                    "kind": grant_event_kind,
                    "grant_id": grant_id,
                    "context_digest": record.context_digest,
                    "operation_family": record.operation_family,
                    "reason": reason,
                    **(
                        {"authorization_epoch": authorization_epoch}
                        if authorization_epoch is not None else {}
                    ),
                    **(
                        {"workspace_generation": workspace_generation}
                        if workspace_generation is not None else {}
                    ),
                    "issuer_id": self.issuer_id,
                }
            )
        ]
        revoked_nonces: list[str] = []
        narrow_abort_plans = self._active_narrow_abort_plans_locked(
            grant_id,
            reason=reason,
        )
        events.extend(event for _transaction, event in narrow_abort_plans)
        # PREPARING is included to close the window between receipt insertion
        # and the prepare audit append.  NARROWING is also non-claimable; it
        # must not roll back into a live PREPARED parent after revocation.
        revocable_states = {
            _RECEIPT_PREPARING,
            _RECEIPT_PREPARED,
            _RECEIPT_NARROWING,
        }
        for nonce, receipt_record in tuple(self._states.items()):
            receipt = receipt_record.receipt
            if receipt.grant_id != grant_id or receipt_record.state not in revocable_states:
                continue
            revoked_nonces.append(nonce)
            events.append(
                self._audit_event(
                    {
                        "kind": "execution.revoked-by-grant",
                        "grant_id": grant_id,
                        "receipt_nonce": nonce,
                        "receipt_digest": receipt.digest,
                        "audit_intent_digest": receipt.audit_intent_digest,
                        "reason": reason,
                        "issuer_id": self.issuer_id,
                    }
                )
            )
        return events, revoked_nonces, narrow_abort_plans

    def _commit_grant_revocation_locked(
        self,
        grant_id: str,
        record: _GrantRecord,
        *,
        reason: str,
        authorization_epoch: int | None = None,
        workspace_generation: int | None = None,
    ) -> list[dict[str, Any]]:
        """Atomically reserve evidence and invalidate launchable descendants."""
        return self._commit_grant_revocations_locked(
            ((
                grant_id,
                record,
                reason,
                authorization_epoch,
                workspace_generation,
            ),)
        )

    def _commit_grant_revocations_locked(
        self,
        revocations: tuple[
            tuple[str, _GrantRecord, str, int | None, int | None],
            ...
        ],
    ) -> list[dict[str, Any]]:
        """Commit several grant invalidations under one daemon lock."""
        plans: list[
            tuple[
                str,
                list[dict[str, Any]],
                list[str],
                list[tuple[_NarrowTransaction, dict[str, Any]]],
            ]
        ] = []
        events: list[dict[str, Any]] = []
        for (
            grant_id,
            record,
            reason,
            authorization_epoch,
            workspace_generation,
        ) in revocations:
            grant_events, revoked_nonces, narrow_abort_plans = self._grant_revocation_events_locked(
                grant_id,
                record,
                reason=reason,
                authorization_epoch=authorization_epoch,
                workspace_generation=workspace_generation,
            )
            plans.append((grant_id, grant_events, revoked_nonces, narrow_abort_plans))
            events.extend(grant_events)
        new_event_ids = {
            str(event["event_id"])
            for event in events
            if str(event["event_id"]) not in self._audit_obligations
            and str(event["event_id"]) not in self._audit_reservations
        }
        available = (
            self.max_audit_obligations
            - len(self._audit_obligations)
            - len(self._audit_reservations)
        )
        if len(new_event_ids) > available:
            self._audit_quarantined = True
            raise AuthorityControlPlaneError(
                "authorityd audit reconciliation quota is exhausted"
            )
        for event in events:
            self._reserve_audit_event_locked(event)
        for (
            grant_id,
            _grant_events,
            revoked_nonces,
            narrow_abort_plans,
        ) in plans:
            for transaction, planned_event in narrow_abort_plans:
                self._commit_narrow_abort_locked(
                    transaction,
                    planned_event=planned_event,
                    evidence_owner="grant-revocation",
                )
            self._grants.pop(grant_id, None)
            self._forget_grant_descendants_locked(grant_id)
            self._remember_grant_terminal_locked(grant_id, "revoked")
            for nonce in revoked_nonces:
                self._pending.pop(nonce, None)
                self._states.pop(nonce, None)
                self._remember_terminal_locked(nonce, _RECEIPT_REVOKED_BY_GRANT)
        return events

    @property
    def public_key_bytes(self) -> bytes:
        return self.signing_key.public_key().public_bytes_raw()

    @property
    def pending_count(self) -> int:
        self._expire_grants()
        self._expire_pending()
        with self._lock:
            return len(self._pending)

    @property
    def audit_obligation_count(self) -> int:
        """Return terminal audit events waiting for a WORM retry."""
        with self._lock:
            return len(self._audit_obligations)

    def _expire_grants(self) -> None:
        """Retire expired live grants while retaining bounded audit ownership."""
        with self._lock:
            now = time.time()
            events: list[dict[str, Any]] = []
            for grant_id, record in tuple(self._grants.items()):
                if now < record.expires_at:
                    continue
                (
                    grant_events,
                    revoked_nonces,
                    narrow_abort_plans,
                ) = self._grant_revocation_events_locked(
                    grant_id,
                    record,
                    reason="expired",
                    grant_event_kind="authority.grant.expired",
                )
                new_event_ids = {
                    str(event["event_id"])
                    for event in grant_events
                    if str(event["event_id"]) not in self._audit_obligations
                    and str(event["event_id"]) not in self._audit_reservations
                }
                available = (
                    self.max_audit_obligations
                    - len(self._audit_obligations)
                    - len(self._audit_reservations)
                )
                if len(new_event_ids) > available:
                    self._audit_quarantined = True
                    break
                for event in grant_events:
                    self._reserve_audit_event_locked(event)
                for transaction, planned_event in narrow_abort_plans:
                    self._commit_narrow_abort_locked(
                        transaction,
                        planned_event=planned_event,
                        evidence_owner="grant-revocation",
                    )
                self._grants.pop(grant_id, None)
                self._forget_grant_descendants_locked(grant_id)
                self._remember_grant_terminal_locked(grant_id, "expired")
                for nonce in revoked_nonces:
                    self._pending.pop(nonce, None)
                    self._states.pop(nonce, None)
                    self._remember_terminal_locked(nonce, "expired-grant")
                events.extend(grant_events)
        for event in events:
            try:
                self._append_or_queue_audit(event)
            except BaseException:
                logger.exception("authorityd grant expiry evidence is pending")

    def _audit_event(self, event: dict[str, Any]) -> dict[str, Any]:
        """Attach a stable id so a WORM retry can be made idempotent."""
        normalized = dict(event)
        normalized.setdefault("event_id", _digest(normalized))
        return normalized

    def _reserve_audit_event_locked(self, event: dict[str, Any]) -> str:
        """Reserve bounded audit capacity before a state transition commits."""
        normalized = self._audit_event(event)
        key = str(normalized["event_id"])
        if key in self._audit_obligations or key in self._audit_reservations:
            return key
        if (
            len(self._audit_obligations) + len(self._audit_reservations)
            >= self.max_audit_obligations
        ):
            self._audit_quarantined = True
            raise AuthorityControlPlaneError(
                "authorityd audit reconciliation quota is exhausted"
            )
        self._audit_reservations.add(key)
        return key

    def _reserve_audit_token_locked(self, token: str) -> str:
        """Reserve one audit slot for a multi-event transition."""
        if not token or token in self._audit_obligations:
            raise AuthorityControlPlaneError("authorityd audit reservation is invalid")
        if token in self._audit_reservations:
            return token
        if (
            len(self._audit_obligations) + len(self._audit_reservations)
            >= self.max_audit_obligations
        ):
            self._audit_quarantined = True
            raise AuthorityControlPlaneError(
                "authorityd audit reconciliation quota is exhausted"
            )
        self._audit_reservations.add(token)
        return token

    def _bind_audit_reservation_locked(
        self, token: str, event: dict[str, Any]
    ) -> str:
        """Bind a reserved multi-event slot to its final stable event id."""
        normalized = self._audit_event(event)
        key = str(normalized["event_id"])
        if token not in self._audit_reservations:
            raise AuthorityControlPlaneError("authorityd audit reservation disappeared")
        if key in self._audit_obligations or (
            key in self._audit_reservations and key != token
        ):
            raise AuthorityControlPlaneError("authorityd audit event id collided")
        self._audit_reservations.remove(token)
        self._audit_reservations.add(key)
        return key

    def _release_audit_reservation_locked(self, key: str) -> None:
        """Release a reservation while the authority state lock is held."""
        self._audit_reservations.discard(key)
        if not self._audit_obligations and not self._audit_reservations:
            self._audit_quarantined = False

    def _release_audit_reservation(self, key: str) -> None:
        with self._lock:
            self._release_audit_reservation_locked(key)

    def _queue_audit_obligation(
        self, event: dict[str, Any], *, key: str | None = None
    ) -> None:
        """Retain an uncertain audit append without retaining authority."""
        normalized = self._audit_event(event)
        obligation_key = key or str(normalized["event_id"])
        with self._lock:
            if obligation_key in self._audit_obligations:
                return
            # A failed append normally arrives with a reservation for this
            # exact event.  Keep that reservation until the obligation is
            # installed; otherwise a quota race could discard the only
            # durable ownership marker before raising and silently lose the
            # evidence that the state transition already happened.
            reserved = obligation_key in self._audit_reservations
            if (
                not reserved
                and len(self._audit_obligations) >= self.max_audit_obligations
            ):
                self._audit_quarantined = True
                raise AuthorityControlPlaneError(
                    "authorityd audit reconciliation quota is exhausted"
                )
            self._audit_reservations.discard(obligation_key)
            self._audit_obligations[obligation_key] = normalized

    def reconcile_audit_obligations(self) -> int:
        """Retry retained audit events and return the remaining backlog."""
        with self._lock:
            obligations = tuple(self._audit_obligations.items())
        for key, event in obligations:
            try:
                self._append_audit(event)
            except BaseException:
                logger.exception(
                    "authorityd audit obligation remains pending: %s", key
                )
                continue
            with self._lock:
                if self._audit_obligations.get(key) == event:
                    self._audit_obligations.pop(key, None)
        with self._lock:
            if not self._audit_obligations and not self._audit_reservations:
                self._audit_quarantined = False
            return len(self._audit_obligations)

    def _append_or_queue_audit(self, event: dict[str, Any]) -> None:
        """Append evidence, retaining it when the remote result is uncertain."""
        normalized = self._audit_event(event)
        event_id = str(normalized["event_id"])
        try:
            self._append_audit(normalized)
        except BaseException:
            self._queue_audit_obligation(normalized, key=event_id)
            raise
        else:
            self._release_audit_reservation(event_id)

    def grant(
        self,
        *,
        principal_id: str,
        project_id: str,
        runtime_id: str,
        task_id: str,
        workspace_id: str,
        workspace_generation: int,
        policy_digest: str,
        operation_class: str,
        resource_digest: str,
        authorization_epoch: int,
        ttl_seconds: float = 60 * 60.0,
        principal_kind: str = "",
        parent_principal_id: str = "",
        session_id: str = "",
        delegation_digest: str = "",
    ) -> tuple[str, float]:
        """Register a renewable grant in the independent authority owner."""
        self._expire_grants()
        if self.require_typed_principals and not principal_kind:
            raise AuthorityControlPlaneError(
                "production authorityd requires a typed principal delegation"
            )
        if not 0 < ttl_seconds <= MAX_GRANT_TTL_SECONDS:
            raise AuthorityControlPlaneError("authority grant TTL is outside the allowed range")
        if workspace_generation <= 0 or authorization_epoch < 0:
            raise AuthorityControlPlaneError(
                "authority grant generation or epoch is invalid"
            )
        for name, value in (
            ("principal_id", principal_id),
            ("project_id", project_id),
            ("runtime_id", runtime_id),
            ("task_id", task_id),
            ("workspace_id", workspace_id),
            ("operation_class", operation_class),
            ("resource_digest", resource_digest),
            ("policy_digest", policy_digest),
        ):
            _required_text(name, value)
        operation_family, separator, operation_action = operation_class.partition(".")
        if not separator or not operation_action or "*" in operation_class:
            raise AuthorityControlPlaneError("authority grant operation is invalid")
        grant_intent = AuthorizationIntent(
            principal_id=principal_id,
            project_id=project_id,
            runtime_id=runtime_id,
            task_id=task_id,
            workspace_id=workspace_id,
            operation=operation_class,
            resource_digest=resource_digest,
            policy_digest=policy_digest,
            nonce=secrets.token_hex(16),
            authorization_epoch=authorization_epoch,
            workspace_generation=workspace_generation,
            principal_kind=principal_kind,
            parent_principal_id=parent_principal_id,
            session_id=session_id,
            delegation_digest=delegation_digest,
        )
        # The grant is an authority context, but its initial operation and
        # typed resource action are still an independent daemon decision.
        # Every later intent is checked against this family and scope before
        # a short-lived receipt is signed.
        grant_policy = getattr(self.policy, "check_prepare", None)
        if callable(grant_policy):
            grant_policy(grant_intent)
        else:
            self.policy(grant_intent)
        grant_id = secrets.token_hex(24)
        issued_at = time.time()
        expires_at = issued_at + ttl_seconds
        context_payload: dict[str, object] = {
            "schema_version": 1,
            "principal_id": principal_id,
            "project_id": project_id,
            "runtime_id": runtime_id,
            "task_id": task_id,
            "workspace_id": workspace_id,
            "workspace_generation": workspace_generation,
            "policy_digest": policy_digest,
            "authorization_epoch": authorization_epoch,
        }
        if principal_kind:
            context_payload.update(
                {
                    "principal_kind": principal_kind,
                    "parent_principal_id": parent_principal_id,
                    "session_id": session_id,
                    "delegation_digest": delegation_digest,
                }
            )
        context_digest = _digest(context_payload)
        record = _GrantRecord(
            principal_id=principal_id,
            project_id=project_id,
            runtime_id=runtime_id,
            task_id=task_id,
            workspace_id=workspace_id,
            workspace_generation=workspace_generation,
            policy_digest=policy_digest,
            resource_digest=resource_digest,
            operation_family=operation_family,
            authorization_epoch=authorization_epoch,
            context_digest=context_digest,
            issued_at=issued_at,
            expires_at=expires_at,
            principal_kind=principal_kind,
            parent_principal_id=parent_principal_id,
            session_id=session_id,
            delegation_digest=delegation_digest,
        )
        grant_event = self._audit_event(
            {
                "kind": "authority.grant",
                "grant_id": grant_id,
                "context_digest": context_digest,
                "operation_class": operation_class,
                "resource_digest": resource_digest,
                "workspace_generation": workspace_generation,
                "authorization_epoch": authorization_epoch,
                "issuer_id": self.issuer_id,
            }
        )
        with self._lock:
            if self._audit_quarantined or self._audit_obligations:
                raise AuthorityControlPlaneError(
                    "authorityd audit reconciliation is pending or quarantined"
                )
            self._reserve_audit_event_locked(grant_event)
            self._grants[grant_id] = record
        try:
            self._append_or_queue_audit(grant_event)
        except BaseException:
            with self._lock:
                self._grants.pop(grant_id, None)
            raise
        return grant_id, expires_at

    def revoke_grant(self, grant_id: str) -> None:
        """Revoke a grant and atomically invalidate its PREPARED receipts."""
        self._expire_grants()
        with self._lock:
            record = self._grants.get(grant_id)
            if record is None:
                return
            events = self._commit_grant_revocation_locked(
                grant_id,
                record,
                reason="explicit-revoke",
                workspace_generation=None,
            )
        first_error: BaseException | None = None
        for event in events:
            try:
                self._append_or_queue_audit(event)
            except BaseException as exc:
                logger.exception("authorityd grant revocation evidence is pending")
                first_error = first_error or exc
        if first_error is not None:
            raise first_error

    def rotate_authorization_epoch(
        self,
        *,
        principal_id: str,
        project_id: str,
        workspace_id: str,
        authorization_epoch: int,
    ) -> None:
        self._expire_grants()
        if authorization_epoch < 0:
            raise AuthorityControlPlaneError("authorization epoch is invalid")
        with self._lock:
            revoked = [
                (grant_id, record)
                for grant_id, record in self._grants.items()
                if (
                    record.principal_id == principal_id
                    and record.project_id == project_id
                    and record.workspace_id == workspace_id
                    and record.authorization_epoch < authorization_epoch
                )
            ]
            events = self._commit_grant_revocations_locked(
                tuple(
                    (
                        grant_id,
                        record,
                        "authorization-epoch-rotated",
                        authorization_epoch,
                        None,
                    )
                    for grant_id, record in revoked
                )
            )
        first_error: BaseException | None = None
        for event in events:
            try:
                self._append_or_queue_audit(event)
            except BaseException as exc:
                logger.exception("authorityd epoch revocation evidence is pending")
                first_error = first_error or exc
        if first_error is not None:
            raise first_error

    def rotate_workspace_generation(
        self,
        *,
        principal_id: str,
        project_id: str,
        workspace_id: str,
        workspace_generation: int,
    ) -> None:
        """Invalidate grants issued for older workspace generations.

        A workspace generation is a monotonic identity boundary.  Rotation
        atomically removes older live grants and their PREPARED descendants;
        CLAIMED receipts remain completable so an already-started effect can
        still receive terminal accounting.
        """
        self._expire_grants()
        if workspace_generation <= 0:
            raise AuthorityControlPlaneError("workspace generation is invalid")
        with self._lock:
            revoked = [
                (grant_id, record)
                for grant_id, record in self._grants.items()
                if (
                    record.principal_id == principal_id
                    and record.project_id == project_id
                    and record.workspace_id == workspace_id
                    and record.workspace_generation < workspace_generation
                )
            ]
            events = self._commit_grant_revocations_locked(
                tuple(
                    (
                        grant_id,
                        record,
                        "workspace-generation-rotated",
                        None,
                        workspace_generation,
                    )
                    for grant_id, record in revoked
                )
            )
        first_error: BaseException | None = None
        for event in events:
            try:
                self._append_or_queue_audit(event)
            except BaseException as exc:
                logger.exception(
                    "authorityd workspace-generation revocation evidence is pending"
                )
                first_error = first_error or exc
        if first_error is not None:
            raise first_error

    def _validate_grant_locked(
        self,
        intent: AuthorizationIntent,
        *,
        parent_receipt: SignedAuthorizationReceipt | None = None,
        requested_resource_scope: str | None = None,
    ) -> None:
        if self.require_typed_principals and not intent.principal_kind:
            raise AuthorityControlPlaneError(
                "production authorityd requires a typed principal delegation"
            )
        if intent.grant_id is None:
            if self.require_live_grants:
                raise AuthorityControlPlaneError(
                    "production authorityd requires a live authority grant"
                )
            return
        record = self._grants.get(intent.grant_id)
        if record is None:
            terminal_state = self._grant_terminal.get(intent.grant_id)
            if terminal_state in {"expired", "revoked"}:
                raise AuthorityControlPlaneError(
                    f"authority grant is {terminal_state}"
                )
            if not self.require_live_grants:
                return
            raise AuthorityControlPlaneError("authority grant is unknown or revoked")
        if time.time() >= record.expires_at:
            (
                events,
                revoked_nonces,
                narrow_abort_plans,
            ) = self._grant_revocation_events_locked(
                intent.grant_id,
                record,
                reason="expired",
                grant_event_kind="authority.grant.expired",
            )
            for event in events:
                self._reserve_audit_event_locked(event)
            for transaction, planned_event in narrow_abort_plans:
                self._commit_narrow_abort_locked(
                    transaction,
                    planned_event=planned_event,
                    evidence_owner="grant-revocation",
                )
            self._grants.pop(intent.grant_id, None)
            self._forget_grant_descendants_locked(intent.grant_id)
            self._remember_grant_terminal_locked(intent.grant_id, "expired")
            for nonce in revoked_nonces:
                self._pending.pop(nonce, None)
                self._states.pop(nonce, None)
                self._remember_terminal_locked(nonce, "expired-grant")
            raise _ExpiredGrant(events[0], events=events)
        if intent.grant_context_digest != record.context_digest:
            raise AuthorityControlPlaneError("authority grant context does not match")
        family, separator, action = intent.operation.partition(".")
        if not separator or not action or family != record.operation_family:
            raise AuthorityControlPlaneError(
                "authority grant operation family cannot be escalated"
            )
        fields = (
            (intent.principal_id, record.principal_id),
            (intent.project_id, record.project_id),
            (intent.runtime_id, record.runtime_id),
            (intent.task_id, record.task_id),
            (intent.workspace_id, record.workspace_id),
            (intent.workspace_generation, record.workspace_generation),
            (intent.policy_digest, record.policy_digest),
            (intent.authorization_epoch, record.authorization_epoch),
            (intent.principal_kind, record.principal_kind),
            (intent.parent_principal_id, record.parent_principal_id),
            (intent.session_id, record.session_id),
            (intent.delegation_digest, record.delegation_digest),
        )
        if any(left != right for left, right in fields):
            raise AuthorityControlPlaneError(
                "authority grant owner, workspace, or epoch is stale"
            )
        if parent_receipt is None:
            if intent.resource_digest == record.resource_digest:
                return
            descendant_key = (intent.resource_digest, intent.operation)
            if descendant_key not in self._grant_descendants.get(
                intent.grant_id, set()
            ):
                raise AuthorityControlPlaneError(
                    "authority grant resource is outside its live scope"
                )
            return
        parent_record = self._states.get(parent_receipt.nonce)
        if (
            parent_record is None
            or not _same_receipt(parent_record.receipt, parent_receipt)
            or parent_record.state != _RECEIPT_NARROWING
            or parent_receipt.grant_id != intent.grant_id
            or parent_receipt.grant_context_digest != intent.grant_context_digest
        ):
            raise AuthorityControlPlaneError(
                "authority grant narrowing parent is not live"
            )
        if requested_resource_scope is None:
            raise AuthorityControlPlaneError(
                "authority grant narrowing scope is missing"
            )
        typed_order = _typed_resource_order(self.policy)
        expected_resource = (
            parent_receipt.resource_digest
            if requested_resource_scope == parent_receipt.resource_digest
            else (
                requested_resource_scope
                if typed_order is not None
                else derive_resource_digest(
                    parent_receipt.resource_digest,
                    intent.operation,
                    requested_resource_scope,
                )
            )
        )
        if intent.resource_digest != expected_resource:
            raise AuthorityControlPlaneError(
                "authority grant narrowing resource is not a signed subset"
            )

    def _remember_terminal_locked(self, nonce: str, state: str) -> None:
        self._terminal[nonce] = state
        while len(self._terminal) > self.terminal_tombstone_limit:
            self._terminal.pop(next(iter(self._terminal)))

    def _collect_expired_locked(
        self,
        *,
        now: float | None = None,
        max_events: int | None = None,
    ) -> list[dict[str, object]]:
        current = time.time() if now is None else now
        expired = [
            nonce
            for nonce, record in self._states.items()
            if record.state == _RECEIPT_PREPARED and current >= record.receipt.expires_at
        ]
        if max_events is not None:
            expired = expired[:max_events]
        events: list[dict[str, object]] = []
        for nonce in expired:
            record = self._states[nonce]
            event = {
                "kind": "execution.expired",
                "receipt_digest": record.receipt.digest,
                "audit_intent_digest": record.receipt.audit_intent_digest,
                "issuer_id": self.issuer_id,
            }
            self._reserve_audit_event_locked(event)
            # Reserve first, then remove the launchable state.  The caller
            # can therefore never observe an expired receipt disappear
            # without an owned terminal-evidence slot.
            self._states.pop(nonce, None)
            self._pending.pop(nonce, None)
            self._remember_terminal_locked(nonce, "expired")
            events.append(self._audit_event(event))
        return events

    def _expire_pending(self) -> None:
        """Garbage-collect launchable receipts without holding the audit lock."""
        while True:
            with self._lock:
                available_obligation_slots = (
                    self.max_audit_obligations
                    - len(self._audit_obligations)
                    - len(self._audit_reservations)
                )
                # Do not remove an expired receipt unless there is room to
                # retain its terminal evidence when the remote append fails.
                # Remaining expired receipts stay live and are retried after
                # the audit backlog is reconciled; this preserves evidence
                # under a bounded obligation quota.
                if available_obligation_slots <= 0:
                    self._audit_quarantined = True
                    return
                events = self._collect_expired_locked(
                    max_events=available_obligation_slots
                )
            if not events:
                self.reconcile_audit_obligations()
                return
            for event in events:
                try:
                    self._append_or_queue_audit(event)
                except BaseException:
                    logger.exception(
                        "authorityd could not append receipt expiry evidence"
                    )
            self.reconcile_audit_obligations()

    def _pending_for_principal_locked(self, principal_id: str) -> int:
        return sum(
            1
            for record in self._states.values()
            if record.receipt.principal_id == principal_id
        )

    def _record_locked(self, receipt: SignedAuthorizationReceipt) -> _ReceiptRecord:
        record = self._states.get(receipt.nonce)
        pending = self._pending.get(receipt.nonce)
        if (
            record is None
            or pending is None
            or not _same_receipt(pending, receipt)
        ):
            terminal = self._terminal.get(receipt.nonce)
            suffix = f" ({terminal})" if terminal else ""
            raise AuthorityControlPlaneError(f"receipt is unknown or revoked{suffix}")
        return record

    def prepare(
        self,
        intent: AuthorizationIntent,
        *,
        _parent_receipt: SignedAuthorizationReceipt | None = None,
        _requested_resource_scope: str | None = None,
    ) -> SignedAuthorizationReceipt:
        self._expire_grants()
        self._expire_pending()
        try:
            with self._lock:
                if self._audit_quarantined or self._audit_obligations:
                    raise AuthorityControlPlaneError(
                        "authorityd audit reconciliation is pending or quarantined"
                    )
                if len(self._pending) >= self.max_pending_receipts:
                    raise AuthorityControlPlaneError("authorityd pending receipt quota is exhausted")
                if self._pending_for_principal_locked(intent.principal_id) >= self.max_pending_per_principal:
                    raise AuthorityControlPlaneError(
                        "authorityd pending receipt principal quota is exhausted"
                    )
                if isinstance(self.policy, (_ComposedAuthorityPolicy, AuthorityPolicyKernel)):
                    self.policy.check_prepare(
                        intent,
                        parent_receipt=_parent_receipt,
                        requested_resource_scope=_requested_resource_scope,
                    )
                else:
                    self.policy(intent)
                self._validate_grant_locked(
                    intent,
                    parent_receipt=_parent_receipt,
                    requested_resource_scope=_requested_resource_scope,
                )
                audit_intent = self._audit_event({
                    "kind": "execution.prepare",
                    "intent": intent.payload(),
                    "intent_digest": intent.digest,
                    "issuer_id": self.issuer_id,
                })
                issued_at = time.time()
                expires_at = issued_at + 300.0
                receipt_fields = {
                    "schema_version": 1,
                    "algorithm": "Ed25519",
                    "principal_id": intent.principal_id,
                    "project_id": intent.project_id,
                    "runtime_id": intent.runtime_id,
                    "task_id": intent.task_id,
                    "workspace_id": intent.workspace_id,
                    "operation": intent.operation,
                    "resource_digest": intent.resource_digest,
                    "policy_digest": intent.policy_digest,
                    "nonce": intent.nonce,
                    "authorization_epoch": intent.authorization_epoch,
                    "workspace_generation": intent.workspace_generation,
                    "grant_id": intent.grant_id,
                    "grant_context_digest": intent.grant_context_digest,
                    "principal_kind": intent.principal_kind,
                    "parent_principal_id": intent.parent_principal_id,
                    "session_id": intent.session_id,
                    "delegation_digest": intent.delegation_digest,
                    "expires_at": expires_at,
                    "audit_intent_digest": _digest(audit_intent),
                    "issuer_id": self.issuer_id,
                    "issued_at": issued_at,
                }
                for optional_field in (
                    "workspace_generation",
                    "grant_id",
                    "grant_context_digest",
                    "principal_kind",
                    "parent_principal_id",
                    "session_id",
                    "delegation_digest",
                ):
                    if receipt_fields[optional_field] is None or receipt_fields[optional_field] == "":
                        receipt_fields.pop(optional_field)
                wire_receipt_fields = dict(receipt_fields)
                wire_receipt_fields["expires_at"] = _encode_receipt_timestamp(
                    receipt_fields["expires_at"], field="expires_at"
                )
                wire_receipt_fields["issued_at"] = _encode_receipt_timestamp(
                    receipt_fields["issued_at"], field="issued_at"
                )
                signature = self.signing_key.sign(_canonical(wire_receipt_fields))
                receipt = SignedAuthorizationReceipt(
                    **receipt_fields,
                    signature=__import__("base64").b64encode(signature).decode("ascii"),
                )
                self._reserve_audit_event_locked(audit_intent)
                self._pending[receipt.nonce] = receipt
                self._states[receipt.nonce] = _ReceiptRecord(
                    receipt, state=_RECEIPT_PREPARING
                )
        except _ExpiredGrant as exc:
            first_error: BaseException | None = None
            for event in exc.events:
                try:
                    self._append_or_queue_audit(event)
                except BaseException as audit_error:  # noqa: BLE001 - preserve cancellation ownership
                    first_error = first_error or audit_error
            if first_error is not None:
                raise AuthorityControlPlaneError(
                    "authority grant has expired and its terminal evidence is queued"
                ) from first_error
            raise
        try:
            self._append_or_queue_audit(audit_intent)
        except BaseException:
            with self._lock:
                self._pending.pop(receipt.nonce, None)
                self._states.pop(receipt.nonce, None)
                self._remember_terminal_locked(receipt.nonce, "prepare-audit-failed")
            raise
        with self._lock:
            record = self._record_locked(receipt)
            if record.state != _RECEIPT_PREPARING:
                raise AuthorityControlPlaneError("receipt preparation state changed")
            _set_receipt_state(record, _RECEIPT_PREPARED)
        return receipt

    @staticmethod
    def _receipt_grant_intent(
        receipt: SignedAuthorizationReceipt,
    ) -> AuthorizationIntent:
        """Reconstruct the grant-bound intent carried by a signed receipt."""
        return AuthorizationIntent(
            principal_id=receipt.principal_id,
            project_id=receipt.project_id,
            runtime_id=receipt.runtime_id,
            task_id=receipt.task_id,
            workspace_id=receipt.workspace_id,
            operation=receipt.operation,
            resource_digest=receipt.resource_digest,
            policy_digest=receipt.policy_digest,
            nonce=receipt.nonce,
            authorization_epoch=receipt.authorization_epoch,
            workspace_generation=receipt.workspace_generation,
            grant_id=receipt.grant_id,
            grant_context_digest=receipt.grant_context_digest,
            principal_kind=receipt.principal_kind,
            parent_principal_id=receipt.parent_principal_id,
            session_id=receipt.session_id,
            delegation_digest=receipt.delegation_digest,
        )

    def _validate_receipt_grant_locked(
        self, receipt: SignedAuthorizationReceipt,
    ) -> None:
        """Revalidate live grant state before a PREPARED receipt can launch."""
        if receipt.grant_id is None:
            return
        # ``_validate_grant_locked`` is intentionally reused so owner,
        # operation-family, epoch, generation, and context checks stay in one
        # authority gate.  CLAIMED receipts never call this method: revoking a
        # grant cannot retroactively invalidate an effect already admitted.
        # A child receipt has a daemon-derived or typed resource digest rather
        # than the grant's initial digest.  Its issued (resource, operation)
        # pair is retained in the daemon-owned descendant registry, while
        # owner/context/epoch/generation checks still run here.
        self._validate_grant_locked(
            self._receipt_grant_intent(receipt),
        )

    def claim(self, receipt: SignedAuthorizationReceipt) -> None:
        """Move a receipt from prepared to launched before the effect starts."""
        self._expire_grants()
        self._expire_pending()
        with self._lock:
            if self._audit_quarantined or self._audit_obligations:
                raise AuthorityControlPlaneError(
                    "authorityd audit reconciliation is pending or quarantined"
                )
            record = self._record_locked(receipt)
            if record.state != _RECEIPT_PREPARED:
                raise AuthorityControlPlaneError("receipt is not claimable")
            receipt.verify(self.signing_key.public_key())
            self._validate_receipt_grant_locked(receipt)
            claimed_event = self._audit_event(
                {
                    "kind": "execution.claimed",
                    "receipt_digest": receipt.digest,
                    "audit_intent_digest": receipt.audit_intent_digest,
                    "issuer_id": self.issuer_id,
                }
            )
            self._reserve_audit_event_locked(claimed_event)
            _set_receipt_state(record, _RECEIPT_CLAIMING)
        try:
            self._append_or_queue_audit(claimed_event)
        except BaseException:
            # A remote append may have succeeded before its response was lost;
            # keep the receipt claimed so an uncertain launch can never be
            # retried as a fresh effect.
            with self._lock:
                record = self._record_locked(receipt)
                _set_receipt_state(record, _RECEIPT_CLAIMED)
            raise
        with self._lock:
            record = self._record_locked(receipt)
            _set_receipt_state(record, _RECEIPT_CLAIMED)

    def complete(
        self,
        receipt: SignedAuthorizationReceipt,
        *,
        result: str,
        result_digest: str,
    ) -> None:
        self._expire_grants()
        self._expire_pending()
        if result not in {"success", "failed", "unknown"}:
            raise AuthorityControlPlaneError("execution result is invalid")
        if not result_digest:
            raise AuthorityControlPlaneError("execution result digest is required")
        expired_event: dict[str, object] | None = None
        result_event: dict[str, object] | None = None
        with self._lock:
            record = self._record_locked(receipt)
            receipt.verify_signature(self.signing_key.public_key())
            if record.state == _RECEIPT_PREPARED:
                # Preserve the old direct prepare -> complete protocol for
                # callers that do not need a separate launch transition.
                if time.time() >= receipt.expires_at:
                    expired_event = {
                        "kind": "execution.expired",
                        "receipt_digest": receipt.digest,
                        "audit_intent_digest": receipt.audit_intent_digest,
                        "issuer_id": self.issuer_id,
                    }
                    self._reserve_audit_event_locked(expired_event)
                    self._states.pop(receipt.nonce, None)
                    self._pending.pop(receipt.nonce, None)
                    self._remember_terminal_locked(receipt.nonce, "expired")
                else:
                    result_event = {
                        "kind": f"execution.{result}",
                        "receipt_digest": receipt.digest,
                        "audit_intent_digest": receipt.audit_intent_digest,
                        "result_digest": result_digest,
                        "issuer_id": self.issuer_id,
                    }
                    self._reserve_audit_event_locked(result_event)
                    _set_receipt_state(record, _RECEIPT_COMPLETING)
            elif record.state != _RECEIPT_CLAIMED:
                raise AuthorityControlPlaneError("receipt is not completable")
            else:
                result_event = {
                    "kind": f"execution.{result}",
                    "receipt_digest": receipt.digest,
                    "audit_intent_digest": receipt.audit_intent_digest,
                    "result_digest": result_digest,
                    "issuer_id": self.issuer_id,
                }
                self._reserve_audit_event_locked(result_event)
                _set_receipt_state(record, _RECEIPT_COMPLETING)
        if expired_event is not None:
            try:
                self._append_or_queue_audit(expired_event)
            except BaseException:
                logger.exception("authorityd could not append receipt expiry evidence")
            raise AuthorityControlPlaneError("receipt has expired")
        try:
            assert result_event is not None
            self._append_or_queue_audit(result_event)
        except BaseException:
            with self._lock:
                record = self._record_locked(receipt)
                _set_receipt_state(record, _RECEIPT_CLAIMED)
            raise
        with self._lock:
            self._pending.pop(receipt.nonce, None)
            self._states.pop(receipt.nonce, None)
            self._remember_terminal_locked(receipt.nonce, result)

    def validate(
        self,
        receipt: SignedAuthorizationReceipt,
        *,
        expected_operation: str | None = None,
        expected_resource_digest: str | None = None,
    ) -> None:
        self._expire_grants()
        self._expire_pending()
        with self._lock:
            record = self._record_locked(receipt)
            if record.state == _RECEIPT_PREPARED:
                receipt.verify(self.signing_key.public_key())
                self._validate_receipt_grant_locked(receipt)
            elif record.state == _RECEIPT_CLAIMED:
                receipt.verify_signature(self.signing_key.public_key())
            else:
                raise AuthorityControlPlaneError(
                    "receipt is in an uncommitted transition"
                )
            if expected_operation is not None and receipt.operation != expected_operation:
                raise AuthorityControlPlaneError("receipt operation is outside authority")
            if (
                expected_resource_digest is not None
                and receipt.resource_digest != expected_resource_digest
            ):
                raise AuthorityControlPlaneError("receipt resource is outside authority")

    def narrow(
        self,
        receipt: SignedAuthorizationReceipt,
        *,
        operation: str,
        resource_digest: str,
    ) -> SignedAuthorizationReceipt:
        self._expire_grants()
        self._expire_pending()
        with self._lock:
            record = self._record_locked(receipt)
            if record.state != _RECEIPT_PREPARED:
                raise AuthorityControlPlaneError("only a prepared receipt may be narrowed")
            receipt.verify(self.signing_key.public_key())
            if not resource_digest:
                raise AuthorityControlPlaneError("narrowed resource scope is required")
            source_family, source_separator, source_action = receipt.operation.partition(".")
            target_family, target_separator, target_action = (
                operation.partition(".")
                if isinstance(operation, str)
                else ("", "", "")
            )
            if (
                not source_separator
                or not source_action
                or not target_separator
                or not target_action
                or "*" in operation
                or source_family != target_family
            ):
                raise AuthorityControlPlaneError(
                    "authorityd narrowing cannot cross issuer families"
                )
            child_resource_digest = (
                receipt.resource_digest
                if resource_digest == receipt.resource_digest
                else (
                    resource_digest
                    if _typed_resource_order(self.policy) is not None
                    else derive_resource_digest(
                        receipt.resource_digest, operation, resource_digest
                    )
                )
            )
            descendant_key: tuple[str, str] | None = None
            intent = AuthorizationIntent(
                principal_id=receipt.principal_id,
                project_id=receipt.project_id,
                runtime_id=receipt.runtime_id,
                task_id=receipt.task_id,
                workspace_id=receipt.workspace_id,
                operation=operation,
                resource_digest=child_resource_digest,
                policy_digest=receipt.policy_digest,
                nonce=secrets.token_hex(16),
                authorization_epoch=receipt.authorization_epoch,
                workspace_generation=receipt.workspace_generation,
                grant_id=receipt.grant_id,
                grant_context_digest=receipt.grant_context_digest,
                principal_kind=receipt.principal_kind,
                parent_principal_id=receipt.parent_principal_id,
                session_id=receipt.session_id,
                delegation_digest=receipt.delegation_digest,
            )
            narrow_policy = getattr(self.policy, "check_narrow", None)
            if callable(narrow_policy):
                if isinstance(self.policy, (_ComposedAuthorityPolicy, AuthorityPolicyKernel)):
                    narrow_policy(
                        receipt.operation,
                        operation,
                        parent_resource_digest=receipt.resource_digest,
                        requested_resource_scope=resource_digest,
                    )
                else:
                    # Compatibility for an injected policy callback from an
                    # older embedding.  Only the built-in policy kernels are
                    # allowed to opt into typed resource semantics.
                    narrow_policy(receipt.operation, operation)
            # Child preparation and the parent terminal event are two
            # independent WORM records. Reserve the parent slot before the
            # child leaves the parent transaction so a full reconciliation
            # queue cannot strand either receipt.
            available_audit_slots = (
                self.max_audit_obligations
                - len(self._audit_obligations)
                - len(self._audit_reservations)
            )
            if available_audit_slots < 2:
                self._audit_quarantined = True
                raise AuthorityControlPlaneError(
                    "authorityd audit reconciliation quota is exhausted"
                )
            narrow_token = f"narrow:{receipt.nonce}:{secrets.token_hex(8)}"
            self._reserve_audit_token_locked(narrow_token)
            if (
                receipt.grant_id is not None
                and child_resource_digest != receipt.resource_digest
            ):
                try:
                    descendant_key = self._reserve_grant_descendant_locked(
                        receipt.grant_id,
                        child_resource_digest,
                        operation,
                    )
                except BaseException:
                    self._release_audit_reservation_locked(narrow_token)
                    raise
            narrow_transaction = _NarrowTransaction(
                transaction_id=narrow_token,
                parent_receipt=receipt,
                child_intent_nonce=intent.nonce,
                grant_id=receipt.grant_id,
                descendant_key=descendant_key,
                audit_token=narrow_token,
                state=_NARROW_CHILD_PREPARING,
            )
            self._narrow_transactions[narrow_token] = narrow_transaction
            _set_receipt_state(record, _RECEIPT_NARROWING)
        try:
            child = self.prepare(
                intent,
                _parent_receipt=receipt,
                _requested_resource_scope=resource_digest,
            )
        except BaseException:
            with self._lock:
                transaction = self._narrow_transactions.pop(narrow_token, None)
                if transaction is not None and transaction.state in {
                    _NARROW_ABORTING,
                    _NARROW_ABORTED,
                }:
                    # Grant invalidation already transferred the token to
                    # execution.narrow-aborted-by-grant and terminalized any
                    # child that had become visible.  Never release that
                    # stable event reservation a second time.
                    pass
                else:
                    self._release_audit_reservation_locked(narrow_token)
                    if descendant_key is not None and receipt.grant_id is not None:
                        self._release_grant_descendant_reservation_locked(
                            receipt.grant_id, descendant_key
                        )
                    record = self._states.get(receipt.nonce)
                    if record is not None and _same_receipt(record.receipt, receipt):
                        if record.state != _RECEIPT_NARROWING:
                            raise AuthorityControlPlaneError(
                                "receipt narrowing rollback state changed"
                            )
                        _set_receipt_state(record, _RECEIPT_PREPARED)
            raise

        with self._lock:
            transaction = self._narrow_transactions.get(narrow_token)
            if transaction is None:
                raise AuthorityControlPlaneError(
                    "authorityd narrow transaction disappeared after child prepare"
                )
            if transaction.state in {_NARROW_ABORTING, _NARROW_ABORTED}:
                self._narrow_transactions.pop(narrow_token, None)
                raise AuthorityControlPlaneError(
                    "narrowing was aborted by grant invalidation"
                )
            if transaction.state != _NARROW_CHILD_PREPARING:
                raise AuthorityControlPlaneError(
                    "authorityd narrow transaction changed during child prepare"
                )
            transaction.child_receipt = child
            transaction.state = _NARROW_CHILD_PREPARED

        # Narrowing is one-shot. Once the child is prepared, the parent is
        # terminal and no longer consumes a pending quota slot.
        narrowed_event = self._audit_event(
            {
                "kind": "execution.narrowed",
                "parent_receipt_digest": receipt.digest,
                "child_receipt_digest": child.digest,
                "parent_nonce": receipt.nonce,
                "child_nonce": child.nonce,
                "parent_operation": receipt.operation,
                "child_operation": child.operation,
                "parent_resource_digest": receipt.resource_digest,
                "child_resource_digest": child.resource_digest,
                "issuer_id": self.issuer_id,
            }
        )
        aborted_event: dict[str, Any] | None = None
        aborted_event_owner: str | None = None
        terminal_error: AuthorityControlPlaneError | None = None
        with self._lock:
            transaction = self._narrow_transactions.get(narrow_token)
            if transaction is None:
                terminal_error = AuthorityControlPlaneError(
                    "authorityd narrow transaction disappeared before terminalization"
                )
            elif transaction.state in {_NARROW_ABORTING, _NARROW_ABORTED}:
                aborted_event = transaction.abort_event
                aborted_event_owner = transaction.abort_evidence_owner
                self._narrow_transactions.pop(narrow_token, None)
                terminal_error = AuthorityControlPlaneError(
                    "narrowing was aborted by grant invalidation"
                )
            elif transaction.state != _NARROW_CHILD_PREPARED:
                terminal_error = AuthorityControlPlaneError(
                    "authorityd narrow transaction is not ready to commit"
                )
            else:
                parent_record = self._states.get(receipt.nonce)
                grant_live = (
                    receipt.grant_id is None
                    or not self.require_live_grants
                    or receipt.grant_id in self._grants
                )
                descendant_reserved = (
                    receipt.grant_id is None
                    or descendant_key is None
                    or descendant_key
                    in self._grant_descendant_reservations.get(
                        receipt.grant_id,
                        set(),
                    )
                )
                parent_live = (
                    parent_record is not None
                    and _same_receipt(parent_record.receipt, receipt)
                    and parent_record.state == _RECEIPT_NARROWING
                )
                if not grant_live or not descendant_reserved or not parent_live:
                    aborted_event = self._commit_narrow_abort_locked(
                        transaction,
                        reason="grant-disappeared-before-narrow-commit",
                        evidence_owner="narrow-commit",
                    )
                    aborted_event_owner = transaction.abort_evidence_owner
                    self._remove_narrow_receipts_locked(transaction)
                    self._narrow_transactions.pop(narrow_token, None)
                    terminal_error = AuthorityControlPlaneError(
                        "narrowing was aborted before terminalization"
                    )
                else:
                    transaction.state = _NARROW_COMMITTING
                    if descendant_key is not None and receipt.grant_id is not None:
                        self._commit_grant_descendant_locked(
                            receipt.grant_id,
                            descendant_key,
                        )
                    self._bind_audit_reservation_locked(
                        narrow_token,
                        narrowed_event,
                    )
                    self._pending.pop(receipt.nonce, None)
                    self._states.pop(receipt.nonce, None)
                    self._remember_terminal_locked(receipt.nonce, "narrowed")
                    transaction.state = _NARROW_COMMITTED
                    self._narrow_transactions.pop(narrow_token, None)
        if (
            aborted_event is not None
            and aborted_event_owner == "narrow-commit"
        ):
            try:
                self._append_or_queue_audit(aborted_event)
            except BaseException:
                logger.exception(
                    "authorityd narrow abort evidence is pending"
                )
        if terminal_error is not None:
            raise terminal_error
        try:
            self._append_or_queue_audit(narrowed_event)
        except BaseException:
            # The child remains real authority and the parent remains
            # terminal. The explicit reconciliation queue owns the evidence.
            logger.exception(
                "authorityd narrowed parent terminal evidence is pending"
            )
        return child

    def revoke(self, receipt: SignedAuthorizationReceipt) -> None:
        self._expire_pending()
        with self._lock:
            if (
                receipt.nonce not in self._states
                and self._terminal.get(receipt.nonce) == "narrowed"
            ):
                receipt.verify_signature(self.signing_key.public_key())
                return
            record = self._record_locked(receipt)
            if record.state != _RECEIPT_PREPARED:
                raise AuthorityControlPlaneError(
                    "only a prepared receipt may be revoked"
                )
            receipt.verify_signature(self.signing_key.public_key())
            revoked_event = self._audit_event(
                {
                    "kind": "execution.revoked",
                    "receipt_digest": receipt.digest,
                    "audit_intent_digest": receipt.audit_intent_digest,
                    "issuer_id": self.issuer_id,
                }
            )
            self._reserve_audit_event_locked(revoked_event)
            _set_receipt_state(record, _RECEIPT_REVOKING)
        try:
            self._append_or_queue_audit(revoked_event)
        except BaseException:
            with self._lock:
                record = self._record_locked(receipt)
                _set_receipt_state(record, _RECEIPT_PREPARED)
            raise
        with self._lock:
            self._pending.pop(receipt.nonce, None)
            self._states.pop(receipt.nonce, None)
            self._remember_terminal_locked(receipt.nonce, "revoked")

    _ATTEST_PROOF_FIELDS = (
        "platform",
        "transport",
        "service_id",
        "service_pid",
        "service_identity",
        "peer_identity",
        "peer_team_id",
        "peer_cdhash",
        "designated_requirement_digest",
        "service_instance_id",
        "protected_key_ref",
    )
    _ATTEST_HEX_FIELDS = frozenset(
        {"designated_requirement_digest", "peer_cdhash"}
    )

    def attest(
        self,
        *,
        proof_fields: dict[str, Any],
        challenge_nonce: str,
        request_raw_hex: str,
        request_digest: str,
    ) -> dict[str, Any]:
        """Sign one challenge-response attestation for a native request.

        The native frontend relays the Agent's fresh challenge and the raw
        request bytes.  The backend is the only holder of the signing key:
        it validates the challenge/digest binding, re-dispatches the inner
        request, and returns a signed attestation covering the transport
        identity fields, the challenge nonce, and the exact request
        digest.  A replayed attestation fails at the Agent because the
        nonce never repeats.
        """
        if not _is_hex(challenge_nonce, 64) or not _is_hex(request_digest, 64):
            raise AuthorityControlPlaneError(
                "authority attestation challenge or request digest is malformed"
            )
        try:
            raw = bytes.fromhex(request_raw_hex)
        except ValueError as exc:
            raise AuthorityControlPlaneError(
                "authority attestation request payload is malformed"
            ) from exc
        if not raw or len(raw) > MAX_MESSAGE_BYTES:
            raise AuthorityControlPlaneError(
                "authority attestation request payload is out of bounds"
            )
        if hashlib.sha256(raw).hexdigest() != request_digest:
            raise AuthorityControlPlaneError(
                "authority attestation request digest does not match the payload"
            )
        try:
            inner = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AuthorityControlPlaneError(
                "authority attestation request is malformed JSON"
            ) from exc
        if not isinstance(inner, dict) or inner.get("protocol") != AUTHORITYD_PROTOCOL:
            raise AuthorityControlPlaneError(
                "authority attestation request is not an authorityd request"
            )
        if set(proof_fields) != set(self._ATTEST_PROOF_FIELDS):
            raise AuthorityControlPlaneError(
                "authority attestation proof fields are incomplete"
            )
        for name, value in proof_fields.items():
            # peer_cdhash may be empty on platforms without a stable
            # code-directory-hash API (Windows); every other field is
            # required to be non-empty.
            if not isinstance(value, str) or len(value) > 256:
                raise AuthorityControlPlaneError(
                    "authority attestation proof field is invalid"
                )
            if not value and name != "peer_cdhash":
                raise AuthorityControlPlaneError(
                    "authority attestation proof field is empty"
                )
            if name in self._ATTEST_HEX_FIELDS and value and not _is_hex(value, len(value)):
                raise AuthorityControlPlaneError(
                    "authority attestation proof digest field is malformed"
                )
        try:
            service_pid = int(proof_fields["service_pid"])
        except (TypeError, ValueError) as exc:
            raise AuthorityControlPlaneError(
                "authority attestation service pid is invalid"
            ) from exc
        if service_pid <= 0:
            raise AuthorityControlPlaneError(
                "authority attestation service pid is invalid"
            )
        payload: dict[str, Any] = {
            "schema_version": 1,
            **proof_fields,
            "challenge_nonce": challenge_nonce,
            "request_digest": request_digest,
            "issuer_id": self.issuer_id,
            "issued_at": _encode_receipt_timestamp(
                time.time(), field="attestation issued_at"
            ),
        }
        signature = base64.b64encode(
            self.signing_key.sign(_canonical(payload))
        ).decode("ascii")
        response = _dispatch(self, inner)
        return {
            "ok": True,
            "response": response,
            "attestation": {**payload, "signature": signature},
        }

    def delegation_root(self, scope: DelegationScope) -> str:
        """Register one ingress root delegation (idempotent by digest)."""
        try:
            digest = self._delegations.register_root(scope)
        except PrincipalDelegationError as exc:
            raise AuthorityControlPlaneError(str(exc)) from exc
        if self._delegations.live_count > self.terminal_tombstone_limit:
            raise AuthorityControlPlaneError(
                "authority live delegation registry is full"
            )
        root_event = self._audit_event(
            {
                "kind": "delegation.root",
                "delegation_digest": digest,
                "subject": scope.subject.identity,
                "project_id": scope.project_id,
                "session_id": scope.session_id,
                "workspace_id": scope.workspace_id,
                "issuer_id": self.issuer_id,
            }
        )
        with self._lock:
            self._reserve_audit_event_locked(root_event)
        try:
            self._append_or_queue_audit(root_event)
        except BaseException:
            with self._lock:
                self._live_delegation_remove(digest)
            raise
        return digest

    def delegation_child(
        self,
        parent: DelegationScope,
        child_principal_id: str,
        child_principal_kind: str,
        *,
        operation_family: str,
        resource_scope: list[str],
        expires_at: float,
    ) -> DelegationScope:
        """Issue one narrow child delegation from a live parent scope."""
        if self._delegations.live_count >= self.terminal_tombstone_limit:
            raise AuthorityControlPlaneError(
                "authority live delegation registry is full"
            )
        try:
            child = principal_from_kind(child_principal_id, child_principal_kind)
            scope = self._delegations.delegate(
                parent,
                child,
                operation_family=operation_family,
                resource_scope=resource_scope,
                expires_at=expires_at,
            )
        except PrincipalDelegationError as exc:
            raise AuthorityControlPlaneError(str(exc)) from exc
        child_event = self._audit_event(
            {
                "kind": "delegation.child",
                "delegation_digest": scope.digest,
                "parent_digest": parent.digest,
                "subject": scope.subject.identity,
                "operation_family": scope.operation_family,
                "resource_scope": sorted(scope.resource_scope),
                "expires_at": scope.expires_at,
                "issuer_id": self.issuer_id,
            }
        )
        with self._lock:
            self._reserve_audit_event_locked(child_event)
        try:
            self._append_or_queue_audit(child_event)
        except BaseException:
            with self._lock:
                self._live_delegation_remove(scope.digest)
            raise
        return scope

    def delegation_consume(
        self,
        delegation: DelegationScope,
        *,
        principal_id: str,
        principal_kind: str,
        project_id: str,
        session_id: str,
        runtime_id: str,
        task_id: str,
        workspace_id: str,
        operation_family: str,
        resource_scope: list[str],
        policy_digest: str,
    ) -> None:
        """Consume exactly one child delegation at the effect boundary."""
        try:
            principal = principal_from_kind(principal_id, principal_kind)
            self._delegations.consume(
                delegation,
                principal=principal,
                project_id=project_id,
                session_id=session_id,
                runtime_id=runtime_id,
                task_id=task_id,
                workspace_id=workspace_id,
                operation_family=operation_family,
                resource_scope=resource_scope,
                policy_digest=policy_digest,
            )
        except PrincipalDelegationError as exc:
            raise AuthorityControlPlaneError(str(exc)) from exc
        consume_event = self._audit_event(
            {
                "kind": "delegation.consumed",
                "delegation_digest": delegation.digest,
                "subject": delegation.subject.identity,
                "issuer_id": self.issuer_id,
            }
        )
        with self._lock:
            self._reserve_audit_event_locked(consume_event)
        # The scope is already consumed at this point; a lost audit event
        # propagates but must never make the one-shot consumption reusable.
        self._append_or_queue_audit(consume_event)

    def delegation_revoke(self, delegation: DelegationScope) -> None:
        """Revoke one delegation and cascade to unclaimed descendants."""
        try:
            self._delegations.revoke(delegation)
        except PrincipalDelegationError as exc:
            raise AuthorityControlPlaneError(str(exc)) from exc
        revoke_event = self._audit_event(
            {
                "kind": "delegation.revoked",
                "delegation_digest": delegation.digest,
                "issuer_id": self.issuer_id,
            }
        )
        with self._lock:
            self._reserve_audit_event_locked(revoke_event)
        self._append_or_queue_audit(revoke_event)

    def _live_delegation_remove(self, digest: str) -> None:
        """Compensate a failed audit append by revoking the fresh scope."""
        self._delegations.revoke_digest(digest)

    def _append_audit(self, record: dict[str, Any]) -> None:
        if self.audit_writer is None:
            raise AuthorityControlPlaneError("independent audit writer is unavailable")
        with self._audit_lock:
            self.audit_writer.append(record)


class JsonlAuditWriter:
    """Development adapter, disabled by ``build_production_daemon``.

    This is useful for protocol tests only.  It deliberately does not claim
    WORM semantics and cannot be passed to the production builder.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()

    def append(self, record: dict[str, Any]) -> None:
        line = json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
        with self._lock:
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            descriptor = os.open(
                self.path,
                os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            try:
                os.write(descriptor, line.encode("utf-8"))
                os.fsync(descriptor)
            finally:
                os.close(descriptor)


def _typed_resource_order(
    policy: Callable[[AuthorizationIntent], None],
) -> TypedResourcePartialOrder | None:
    """Return the immutable catalog owned by a built-in policy wrapper."""
    if isinstance(policy, AuthorityPolicyKernel):
        return policy.resource_order
    if isinstance(policy, _ComposedAuthorityPolicy):
        return policy.kernel.resource_order
    return None


def build_production_daemon(
    *,
    socket_path: Path,
    key_path: Path,
    audit_writer: AuditWriter | None,
    issuer_id: str = "khaos-authorityd",
    policy: Callable[[AuthorizationIntent], None] | None = None,
    resource_order: TypedResourcePartialOrder | None = None,
) -> AuthorityDaemon:
    """Construct authorityd only with a policy-bound typed resource catalog."""
    if audit_writer is None:
        raise AuthorityControlPlaneError(
            "production authorityd requires an independent remote/WORM audit writer"
        )
    expected_policy_digest = os.environ.get("KHAOS_EFFECTIVE_POLICY_DIGEST")
    if not expected_policy_digest:
        raise AuthorityControlPlaneError(
            "production authorityd requires KHAOS_EFFECTIVE_POLICY_DIGEST"
        )
    if resource_order is None:
        raise AuthorityControlPlaneError(
            "production authorityd requires a typed resource catalog"
        )
    if resource_order.policy_digest != expected_policy_digest:
        raise AuthorityControlPlaneError(
            "production typed resource catalog is not bound to the effective policy"
        )
    key = Ed25519KeyStore.load_or_create(key_path, create=False)
    kernel = AuthorityPolicyKernel(
        expected_policy_digest=expected_policy_digest,
        resource_order=resource_order,
    )
    selected_policy: Callable[[AuthorizationIntent], None]
    if policy is None:
        selected_policy = kernel
    else:
        selected_policy = _ComposedAuthorityPolicy(kernel, policy)
    return AuthorityDaemon(
        socket_path=socket_path,
        signing_key=key,
        audit_writer=audit_writer,
        issuer_id=issuer_id,
        policy=selected_policy,
        require_live_grants=True,
        require_typed_principals=True,
    )


class _ComposedAuthorityPolicy:
    """Keep the production digest/family gate ahead of an extra policy."""

    def __init__(
        self,
        kernel: AuthorityPolicyKernel,
        custom: Callable[[AuthorizationIntent], None],
    ) -> None:
        self.kernel = kernel
        self.custom = custom

    def __call__(self, intent: AuthorizationIntent) -> None:
        self.kernel(intent)
        self.custom(intent)

    def check_prepare(
        self,
        intent: AuthorizationIntent,
        *,
        parent_receipt: SignedAuthorizationReceipt | None = None,
        requested_resource_scope: str | None = None,
    ) -> None:
        self.kernel.check_prepare(
            intent,
            parent_receipt=parent_receipt,
            requested_resource_scope=requested_resource_scope,
        )
        self.custom(intent)

    def check_narrow(
        self,
        source_operation: str,
        target_operation: str,
        *,
        parent_resource_digest: str | None = None,
        requested_resource_scope: str | None = None,
    ) -> None:
        self.kernel.check_narrow(
            source_operation,
            target_operation,
            parent_resource_digest=parent_resource_digest,
            requested_resource_scope=requested_resource_scope,
        )
        custom_narrow = getattr(self.custom, "check_narrow", None)
        if callable(custom_narrow):
            custom_narrow(source_operation, target_operation)


class AuthorityPolicyKernel:
    """Closed operation/resource policy owned by authorityd, not its client."""

    _FAMILIES = frozenset({"credential", "exec", "git", "network", "workspace"})

    def __init__(
        self,
        *,
        expected_policy_digest: str | None = None,
        resource_order: TypedResourcePartialOrder | None = None,
    ) -> None:
        if expected_policy_digest in {
            "",
            "legacy-unbound",
            "policy:unspecified",
            "unbound",
        }:
            raise AuthorityControlPlaneError(
                "authorityd effective policy digest is invalid"
            )
        self.expected_policy_digest = expected_policy_digest
        if (
            resource_order is not None
            and expected_policy_digest is not None
            and resource_order.policy_digest != expected_policy_digest
        ):
            raise AuthorityControlPlaneError(
                "typed resource catalog is not bound to the effective policy"
            )
        self.resource_order = resource_order

    def __call__(self, intent: AuthorizationIntent) -> None:
        self._check_intent_shape(intent)

    def _check_intent_shape(self, intent: AuthorizationIntent) -> None:
        family, separator, action = intent.operation.partition(".")
        if not separator or family not in self._FAMILIES or not action:
            raise AuthorityControlPlaneError(
                "authorityd operation is not registered with the policy kernel"
            )
        if intent.resource_digest in {"", "unrestricted", "*"}:
            raise AuthorityControlPlaneError("authorityd resource namespace is invalid")
        if intent.policy_digest in {"", "legacy-unbound", "policy:unspecified"}:
            raise AuthorityControlPlaneError("authorityd requires an effective policy digest")
        if (
            self.expected_policy_digest is not None
            and intent.policy_digest != self.expected_policy_digest
        ):
            raise AuthorityControlPlaneError(
                "authorityd policy digest does not match its compiled policy"
            )

    def check_prepare(
        self,
        intent: AuthorizationIntent,
        *,
        parent_receipt: SignedAuthorizationReceipt | None = None,
        requested_resource_scope: str | None = None,
    ) -> None:
        """Validate an intent and its semantic resource context.

        A narrowed receipt carries a derived opaque digest, so its semantic
        proof must be checked against the parent/requested scope pair before
        the child is signed.  A direct prepare instead requires the resource
        digest to be present in the immutable typed catalog.
        """
        self._check_intent_shape(intent)
        if self.resource_order is None:
            return
        try:
            if intent.operation == _NATIVE_EXECUTION_OPERATION:
                _require_native_execution_binding(
                    intent.resource_digest,
                    parent_digest=(
                        parent_receipt.resource_digest
                        if parent_receipt is not None
                        else None
                    ),
                    requested_digest=requested_resource_scope,
                )
                return
            if parent_receipt is None:
                self.resource_order.require_operation(
                    intent.resource_digest, intent.operation
                )
                return
            if requested_resource_scope is None:
                raise ResourceScopeError(
                    "typed resource narrowing requires a requested scope"
                )
            self.resource_order.require_transition(
                parent_digest=parent_receipt.resource_digest,
                requested_scope=requested_resource_scope,
                source_operation=parent_receipt.operation,
                target_operation=intent.operation,
            )
        except ResourceScopeError as exc:
            raise AuthorityControlPlaneError(
                f"typed resource prepare rejected: {exc}"
            ) from exc

    def check_narrow(
        self,
        source_operation: str,
        target_operation: str,
        *,
        parent_resource_digest: str | None = None,
        requested_resource_scope: str | None = None,
    ) -> None:
        source_family = source_operation.split(".", 1)[0]
        target_family = target_operation.split(".", 1)[0]
        if source_family != target_family:
            raise AuthorityControlPlaneError(
                "authorityd narrowing cannot cross issuer families"
            )
        if self.resource_order is None:
            return
        if parent_resource_digest is None or requested_resource_scope is None:
            raise AuthorityControlPlaneError(
                "typed resource narrowing requires parent and requested scopes"
            )
        try:
            if (
                source_operation == _NATIVE_EXECUTION_OPERATION
                or target_operation == _NATIVE_EXECUTION_OPERATION
            ):
                _require_native_execution_binding(
                    requested_resource_scope,
                    parent_digest=parent_resource_digest,
                    requested_digest=requested_resource_scope,
                )
                if source_operation != target_operation:
                    raise ResourceScopeError(
                        "native execution narrowing cannot change operation"
                    )
                return
            self.resource_order.require_transition(
                parent_digest=parent_resource_digest,
                requested_scope=requested_resource_scope,
                source_operation=source_operation,
                target_operation=target_operation,
            )
        except ResourceScopeError as exc:
            raise AuthorityControlPlaneError(
                f"typed resource narrowing rejected: {exc}"
            ) from exc


def _require_native_execution_binding(
    resource_digest: str,
    *,
    parent_digest: str | None,
    requested_digest: str | None,
) -> None:
    """Validate the TCB-owned exact launch binding outside the static catalog.

    Native execution binds a receipt to command, executable identity, directory
    identities, limits, environment and launcher options.  That digest is
    intentionally per-launch and cannot be enumerated in the startup catalog;
    the native launcher recomputes it at the final effect boundary.  The
    authority kernel still admits only the concrete ``exec.host`` action, a
    canonical SHA-256 digest, and exact reuse during renewal/narrowing.
    """
    if (
        type(resource_digest) is not str
        or len(resource_digest) != 64
        or resource_digest != resource_digest.lower()
        or any(character not in _HEX_DIGITS for character in resource_digest)
    ):
        raise ResourceScopeError(
            "native execution requires an exact launch binding digest"
        )
    if parent_digest is not None and requested_digest is None:
        raise ResourceScopeError(
            "native execution narrowing requires the requested binding"
        )
    if requested_digest is not None and requested_digest != resource_digest:
        raise ResourceScopeError(
            "native execution binding cannot change during narrowing"
        )
    if parent_digest is not None and parent_digest != resource_digest:
        raise ResourceScopeError(
            "native execution binding cannot change during renewal"
        )


def serve_unix(daemon: AuthorityDaemon, *, production: bool = True) -> None:
    """Serve requests on a private 0600 socket or agent-group 0660 socket.

    On darwin this function only runs in *backend mode*: it serves the
    ``KHAOS_AUTHORITYD_BACKEND_SOCKET`` consumed by the native launchd/XPC
    frontend, never a socket the agent could reach directly.  Every peer is
    kernel-verified through ``LOCAL_PEERCRED`` and must hold the authority
    UID (the frontend's identity).  There is no same-user agent fallback.
    """
    backend_mode = sys.platform == "darwin"
    if os.name == "nt":
        raise AuthorityControlPlaneError(
            "native authorityd transport is required on this platform; use the "
            "Windows Named Pipe backend service"
        )
    contract = read_contract_from_environment()
    if production:
        contract.validate(production=True)
        if contract.authority_uid is not None and os.geteuid() != contract.authority_uid:
            raise IdentityIsolationError("authorityd is not running as its dedicated UID")
    if backend_mode:
        # The backend socket must be the one the native frontend forwards to,
        # and it must live under authority ownership.  Serving any other
        # darwin socket would expose a direct agent -> authorityd path that
        # bypasses the XPC identity checks.
        expected_backend = os.environ.get("KHAOS_AUTHORITYD_BACKEND_SOCKET", "")
        if (
            not expected_backend
            or not Path(expected_backend).is_absolute()
            or Path(daemon.socket_path) != Path(expected_backend)
        ):
            raise AuthorityControlPlaneError(
                "darwin authorityd may only serve the configured native "
                "frontend backend socket"
            )
    daemon.socket_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if daemon.socket_path.exists():
        info = daemon.socket_path.lstat()
        if not stat.S_ISSOCK(info.st_mode):
            raise AuthorityControlPlaneError("authorityd socket path is not a socket")
        daemon.socket_path.unlink()
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        listener.bind(str(daemon.socket_path))
        configured_mode = os.environ.get("KHAOS_AUTHORITYD_SOCKET_MODE", "0600")
        try:
            socket_mode = int(configured_mode, 8)
        except ValueError as exc:
            raise AuthorityControlPlaneError(
                "KHAOS_AUTHORITYD_SOCKET_MODE must be octal"
            ) from exc
        if socket_mode not in {0o600, 0o660}:
            raise AuthorityControlPlaneError(
                "authorityd socket mode must be 0600 or 0660"
            )
        os.chmod(daemon.socket_path, socket_mode)
        if production:
            validate_private_unix_socket(
                daemon.socket_path, expected_uid=contract.authority_uid
            )
        max_connections_value = os.environ.get("KHAOS_AUTHORITYD_MAX_CONNECTIONS", "32")
        try:
            max_connections = int(max_connections_value)
        except ValueError as exc:
            raise AuthorityControlPlaneError(
                "KHAOS_AUTHORITYD_MAX_CONNECTIONS must be an integer"
            ) from exc
        if not 1 <= max_connections <= 128:
            raise AuthorityControlPlaneError(
                "KHAOS_AUTHORITYD_MAX_CONNECTIONS is outside the safe bound"
            )
        try:
            connection_timeout = float(
                os.environ.get("KHAOS_AUTHORITYD_CONNECTION_TIMEOUT", "5")
            )
        except ValueError as exc:
            raise AuthorityControlPlaneError(
                "KHAOS_AUTHORITYD_CONNECTION_TIMEOUT must be numeric"
            ) from exc
        if not 0 < connection_timeout <= 60:
            raise AuthorityControlPlaneError(
                "KHAOS_AUTHORITYD_CONNECTION_TIMEOUT is outside the safe bound"
            )
        listener.listen(max_connections)
        slots = threading.BoundedSemaphore(max_connections)
        # Backend mode (darwin): the only legitimate peer is the native
        # frontend, which runs as the authority UID.  Linux production keeps
        # validating the agent UID directly.
        if backend_mode:
            expected_peer_uid: int | None = contract.authority_uid
            if expected_peer_uid is None:
                expected_peer_uid = os.geteuid()
        else:
            expected_peer_uid = contract.agent_uid if production else None
        with ThreadPoolExecutor(
            max_workers=max_connections, thread_name_prefix="khaos-authorityd"
        ) as executor:
            while not daemon._closed:
                connection, _ = listener.accept()
                if not slots.acquire(blocking=False):
                    connection.close()
                    continue
                executor.submit(
                    _serve_connection,
                    daemon,
                    connection,
                    expected_peer_uid,
                    connection_timeout,
                    slots,
                    backend_mode,
                )
    finally:
        listener.close()
        daemon.socket_path.unlink(missing_ok=True)


def _serve_connection(
    daemon: AuthorityDaemon,
    connection: socket.socket,
    expected_uid: int | None,
    connection_timeout: float = 5.0,
    slots: threading.BoundedSemaphore | None = None,
    backend_mode: bool = False,
) -> None:
    try:
        with connection:
            connection.settimeout(connection_timeout)
            try:
                if expected_uid is not None:
                    observed_uid = (
                        peer_uid_platform(connection)
                        if backend_mode
                        else peer_uid(connection)
                    )
                    if observed_uid != expected_uid:
                        raise IdentityIsolationError(
                            "authorityd peer UID is not the expected authority peer"
                        )
                body = read_bounded_line(
                    connection, max_bytes=MAX_MESSAGE_BYTES
                )
                request = json.loads(body.decode("utf-8"))
                response = _dispatch(daemon, request)
            except RemoteAuditUnavailableError as exc:
                response = {
                    "ok": False,
                    "error": str(exc),
                    "error_code": "remote_audit_unavailable",
                }
            except (AuthorityControlPlaneError, OSError, ValueError, TypeError) as exc:
                response = {"ok": False, "error": str(exc)}
            try:
                connection.sendall(_canonical(response) + b"\n")
            except OSError:
                logger.debug("authorityd client disconnected before response", exc_info=True)
    finally:
        if slots is not None:
            slots.release()


def _dispatch(daemon: AuthorityDaemon, request: object) -> dict[str, object]:
    if not isinstance(request, dict) or request.get("protocol") != AUTHORITYD_PROTOCOL:
        raise AuthorityControlPlaneError("invalid authorityd request")
    operation = request.get("operation")
    if operation == "grant":
        grant_id, expires_at = daemon.grant(
            principal_id=str(request.get("principal_id", "")),
            project_id=str(request.get("project_id", "")),
            runtime_id=str(request.get("runtime_id", "")),
            task_id=str(request.get("task_id", "")),
            workspace_id=str(request.get("workspace_id", "")),
            workspace_generation=int(request.get("workspace_generation", 0)),
            policy_digest=str(request.get("policy_digest", "")),
            operation_class=str(request.get("operation_class", "")),
            resource_digest=str(request.get("resource_digest", "")),
            authorization_epoch=int(request.get("authorization_epoch", -1)),
            ttl_seconds=float(request.get("ttl_seconds", 0)),
            principal_kind=str(request.get("principal_kind", "")),
            parent_principal_id=str(request.get("parent_principal_id", "")),
            session_id=str(request.get("session_id", "")),
            delegation_digest=str(request.get("delegation_digest", "")),
        )
        return {"ok": True, "grant_id": grant_id, "expires_at": expires_at}
    if operation == "revoke_grant":
        daemon.revoke_grant(str(request.get("grant_id", "")))
        return {"ok": True}
    if operation == "rotate_authorization_epoch":
        daemon.rotate_authorization_epoch(
            principal_id=str(request.get("principal_id", "")),
            project_id=str(request.get("project_id", "")),
            workspace_id=str(request.get("workspace_id", "")),
            authorization_epoch=int(request.get("authorization_epoch", -1)),
        )
        return {"ok": True}
    if operation == "rotate_workspace_generation":
        daemon.rotate_workspace_generation(
            principal_id=str(request.get("principal_id", "")),
            project_id=str(request.get("project_id", "")),
            workspace_id=str(request.get("workspace_id", "")),
            workspace_generation=int(request.get("workspace_generation", 0)),
        )
        return {"ok": True}
    if operation == "prepare":
        intent = AuthorizationIntent(**_mapping(request.get("intent")))
        return {"ok": True, "receipt": daemon.prepare(intent).to_dict()}
    if operation == "complete":
        receipt = SignedAuthorizationReceipt.from_dict(request.get("receipt"))
        daemon.complete(
            receipt,
            result=str(request.get("result", "")),
            result_digest=str(request.get("result_digest", "")),
        )
        return {"ok": True}
    if operation == "claim":
        receipt = SignedAuthorizationReceipt.from_dict(request.get("receipt"))
        daemon.claim(receipt)
        return {"ok": True}
    if operation == "validate":
        receipt = SignedAuthorizationReceipt.from_dict(request.get("receipt"))
        daemon.validate(
            receipt,
            expected_operation=(
                str(request["expected_operation"])
                if request.get("expected_operation") is not None
                else None
            ),
            expected_resource_digest=(
                str(request["expected_resource_digest"])
                if request.get("expected_resource_digest") is not None
                else None
            ),
        )
        return {"ok": True}
    if operation == "narrow":
        receipt = SignedAuthorizationReceipt.from_dict(request.get("receipt"))
        narrowed = daemon.narrow(
            receipt,
            operation=str(request.get("operation_class", "")),
            resource_digest=str(request.get("resource_digest", "")),
        )
        return {"ok": True, "receipt": narrowed.to_dict()}
    if operation == "revoke":
        receipt = SignedAuthorizationReceipt.from_dict(request.get("receipt"))
        daemon.revoke(receipt)
        return {"ok": True}
    if operation == "ping":
        return {"ok": True, "issuer_id": daemon.issuer_id}
    if operation == "attest":
        return daemon.attest(
            proof_fields=_mapping(request.get("proof_fields")),
            challenge_nonce=str(request.get("challenge_nonce", "")),
            request_raw_hex=str(request.get("request_raw_hex", "")),
            request_digest=str(request.get("request_digest", "")),
        )
    if operation == "delegation_root":
        scope = DelegationScope.from_payload(request.get("scope"))
        digest = daemon.delegation_root(scope)
        return {"ok": True, "delegation_digest": digest}
    if operation == "delegation_child":
        parent = DelegationScope.from_payload(request.get("parent"))
        child = daemon.delegation_child(
            parent,
            str(request.get("child_principal_id", "")),
            str(request.get("child_principal_kind", "")),
            operation_family=str(request.get("operation_family", "")),
            resource_scope=[str(item) for item in request.get("resource_scope", [])],
            expires_at=float(request.get("expires_at", 0)),
        )
        return {"ok": True, "delegation": child.canonical()}
    if operation == "delegation_consume":
        delegation = DelegationScope.from_payload(request.get("delegation"))
        daemon.delegation_consume(
            delegation,
            principal_id=str(request.get("principal_id", "")),
            principal_kind=str(request.get("principal_kind", "")),
            project_id=str(request.get("project_id", "")),
            session_id=str(request.get("session_id", "")),
            runtime_id=str(request.get("runtime_id", "")),
            task_id=str(request.get("task_id", "")),
            workspace_id=str(request.get("workspace_id", "")),
            operation_family=str(request.get("operation_family", "")),
            resource_scope=[str(item) for item in request.get("resource_scope", [])],
            policy_digest=str(request.get("policy_digest", "")),
        )
        return {"ok": True}
    if operation == "delegation_revoke":
        delegation = DelegationScope.from_payload(request.get("delegation"))
        daemon.delegation_revoke(delegation)
        return {"ok": True}
    raise AuthorityControlPlaneError("unknown authorityd operation")


def _mapping(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AuthorityControlPlaneError("authorityd payload is not a mapping")
    return value


def _is_hex(value: str, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(character in _HEX_DIGITS for character in value)
    )


__all__ = [
    "AuthorityControlPlaneError",
    "AuthorityDaemon",
    "AuthorityPolicyKernel",
    "JsonlAuditWriter",
    "build_production_daemon",
    "serve_unix",
]
