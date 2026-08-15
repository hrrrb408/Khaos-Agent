"""Independent authority daemon for signed execution receipts.

This service is intentionally a small control-plane reference implementation.
Production deployment must run it under a dedicated OS identity and connect
an append-only/WORM ``AuditWriter``; the daemon refuses to start without both
requirements.  The local process broker is only the explicitly selected test
profile and is never a production fallback.
"""

from __future__ import annotations

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
    _required_text,
    derive_resource_digest,
)
from khaos.security.identity_isolation import (
    IdentityIsolationError,
    peer_uid,
    read_contract_from_environment,
    validate_private_unix_socket,
)

logger = logging.getLogger(__name__)

_RECEIPT_PREPARED = "prepared"
_RECEIPT_PREPARING = "preparing"
_RECEIPT_CLAIMED = "claimed"
_RECEIPT_CLAIMING = "claiming"
_RECEIPT_NARROWING = "narrowing"
_RECEIPT_COMPLETING = "completing"
_RECEIPT_REVOKING = "revoking"
_RECEIPT_TERMINAL = "terminal"


@dataclass
class _ReceiptRecord:
    receipt: SignedAuthorizationReceipt
    state: str = _RECEIPT_PREPARED


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


class _ExpiredGrant(AuthorityControlPlaneError):
    """Internal rejection carrying the audit event for an expired grant."""

    def __init__(self, event: dict[str, Any]) -> None:
        super().__init__("authority grant has expired")
        self.event = event


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
        self._closed = False

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
            available = (
                self.max_audit_obligations
                - len(self._audit_obligations)
                - len(self._audit_reservations)
            )
            if available <= 0:
                self._audit_quarantined = True
                return
            expired = [
                (grant_id, record)
                for grant_id, record in self._grants.items()
                if now >= record.expires_at
            ][:available]
            events: list[dict[str, Any]] = []
            for grant_id, record in expired:
                event = self._audit_event(
                    {
                        "kind": "authority.grant.expired",
                        "grant_id": grant_id,
                        "context_digest": record.context_digest,
                        "operation_family": record.operation_family,
                        "issuer_id": self.issuer_id,
                    }
                )
                self._reserve_audit_event_locked(event)
                self._grants.pop(grant_id, None)
                self._grant_terminal[grant_id] = "expired"
                while len(self._grant_terminal) > self.terminal_tombstone_limit:
                    self._grant_terminal.pop(next(iter(self._grant_terminal)))
                events.append(event)
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

    def _release_audit_reservation(self, key: str) -> None:
        with self._lock:
            self._audit_reservations.discard(key)
            if not self._audit_obligations and not self._audit_reservations:
                self._audit_quarantined = False

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
    ) -> tuple[str, float]:
        """Register a renewable grant in the independent authority owner."""
        self._expire_grants()
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
        )
        # The grant is an authority context, but its initial operation family
        # is still an independent daemon decision.  Every later intent is
        # checked against this family before a short-lived receipt is signed.
        self.policy(grant_intent)
        grant_id = secrets.token_hex(24)
        issued_at = time.time()
        expires_at = issued_at + ttl_seconds
        context_digest = _digest(
            {
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
        )
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
        """Revoke a grant before its expiry; stale envelopes then cannot issue."""
        self._expire_grants()
        with self._lock:
            record = self._grants.get(grant_id)
            if record is None:
                return
            event = self._audit_event(
                {
                    "kind": "authority.grant.revoked",
                    "grant_id": grant_id,
                    "context_digest": record.context_digest,
                    "issuer_id": self.issuer_id,
                }
            )
            self._reserve_audit_event_locked(event)
            self._grants.pop(grant_id, None)
        try:
            self._append_or_queue_audit(event)
        except BaseException:
            logger.exception("authorityd grant revocation evidence is pending")
            raise

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
            events = [
                (
                    grant_id,
                    self._audit_event(
                        {
                            "kind": "authority.grant.revoked",
                            "grant_id": grant_id,
                            "context_digest": record.context_digest,
                            "reason": "authorization-epoch-rotated",
                            "authorization_epoch": authorization_epoch,
                            "issuer_id": self.issuer_id,
                        }
                    ),
                )
                for grant_id, record in revoked
            ]
            if (
                len(self._audit_obligations)
                + len(self._audit_reservations)
                + len(events)
                > self.max_audit_obligations
            ):
                self._audit_quarantined = True
                raise AuthorityControlPlaneError(
                    "authorityd audit reconciliation quota is exhausted"
                )
            for _grant_id, event in events:
                self._reserve_audit_event_locked(event)
            for grant_id, _record in revoked:
                self._grants.pop(grant_id, None)
        first_error: BaseException | None = None
        for _grant_id, event in events:
            try:
                self._append_or_queue_audit(event)
            except BaseException as exc:
                logger.exception("authorityd epoch revocation evidence is pending")
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
        if intent.grant_id is None:
            if self.require_live_grants:
                raise AuthorityControlPlaneError(
                    "production authorityd requires a live authority grant"
                )
            return
        record = self._grants.get(intent.grant_id)
        if record is None:
            if not self.require_live_grants:
                return
            if self._grant_terminal.get(intent.grant_id) == "expired":
                raise AuthorityControlPlaneError("authority grant has expired")
            raise AuthorityControlPlaneError("authority grant is unknown or revoked")
        if time.time() >= record.expires_at:
            event = self._audit_event(
                {
                    "kind": "authority.grant.expired",
                    "grant_id": intent.grant_id,
                    "context_digest": record.context_digest,
                    "operation_family": record.operation_family,
                    "issuer_id": self.issuer_id,
                }
            )
            self._reserve_audit_event_locked(event)
            self._grants.pop(intent.grant_id, None)
            self._grant_terminal[intent.grant_id] = "expired"
            while len(self._grant_terminal) > self.terminal_tombstone_limit:
                self._grant_terminal.pop(next(iter(self._grant_terminal)))
            raise _ExpiredGrant(event)
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
        )
        if any(left != right for left, right in fields):
            raise AuthorityControlPlaneError(
                "authority grant owner, workspace, or epoch is stale"
            )
        if parent_receipt is None:
            if intent.resource_digest != record.resource_digest:
                raise AuthorityControlPlaneError(
                    "authority grant resource is outside its live scope"
                )
            return
        parent_record = self._states.get(parent_receipt.nonce)
        if (
            parent_record is None
            or parent_record.receipt != parent_receipt
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
        expected_resource = (
            parent_receipt.resource_digest
            if requested_resource_scope == parent_receipt.resource_digest
            else derive_resource_digest(
                parent_receipt.resource_digest,
                intent.operation,
                requested_resource_scope,
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
        if record is None or self._pending.get(receipt.nonce) != receipt:
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
                    "expires_at": expires_at,
                    "audit_intent_digest": _digest(audit_intent),
                    "issuer_id": self.issuer_id,
                    "issued_at": issued_at,
                }
                for optional_field in (
                    "workspace_generation",
                    "grant_id",
                    "grant_context_digest",
                ):
                    if receipt_fields[optional_field] is None:
                        receipt_fields.pop(optional_field)
                signature = self.signing_key.sign(_canonical(receipt_fields))
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
            try:
                self._append_or_queue_audit(exc.event)
            except BaseException as audit_error:
                raise AuthorityControlPlaneError(
                    "authority grant has expired and its terminal evidence is queued"
                ) from audit_error
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
            record.state = _RECEIPT_PREPARED
        return receipt

    def claim(self, receipt: SignedAuthorizationReceipt) -> None:
        """Move a receipt from prepared to launched before the effect starts."""
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
            claimed_event = self._audit_event(
                {
                    "kind": "execution.claimed",
                    "receipt_digest": receipt.digest,
                    "audit_intent_digest": receipt.audit_intent_digest,
                    "issuer_id": self.issuer_id,
                }
            )
            self._reserve_audit_event_locked(claimed_event)
            record.state = _RECEIPT_CLAIMING
        try:
            self._append_or_queue_audit(claimed_event)
        except BaseException:
            # A remote append may have succeeded before its response was lost;
            # keep the receipt claimed so an uncertain launch can never be
            # retried as a fresh effect.
            with self._lock:
                record = self._record_locked(receipt)
                record.state = _RECEIPT_CLAIMED
            raise
        with self._lock:
            record = self._record_locked(receipt)
            record.state = _RECEIPT_CLAIMED

    def complete(
        self,
        receipt: SignedAuthorizationReceipt,
        *,
        result: str,
        result_digest: str,
    ) -> None:
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
                    record.state = _RECEIPT_COMPLETING
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
                record.state = _RECEIPT_COMPLETING
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
                record.state = _RECEIPT_CLAIMED
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
        self._expire_pending()
        with self._lock:
            record = self._record_locked(receipt)
            if record.state == _RECEIPT_PREPARED:
                receipt.verify(self.signing_key.public_key())
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
            intent = AuthorizationIntent(
                principal_id=receipt.principal_id,
                project_id=receipt.project_id,
                runtime_id=receipt.runtime_id,
                task_id=receipt.task_id,
                workspace_id=receipt.workspace_id,
                operation=operation,
                resource_digest=(
                    receipt.resource_digest
                    if resource_digest == receipt.resource_digest
                    else derive_resource_digest(
                        receipt.resource_digest, operation, resource_digest
                    )
                ),
                policy_digest=receipt.policy_digest,
                nonce=secrets.token_hex(16),
                authorization_epoch=receipt.authorization_epoch,
                workspace_generation=receipt.workspace_generation,
                grant_id=receipt.grant_id,
                grant_context_digest=receipt.grant_context_digest,
            )
            narrow_policy = getattr(self.policy, "check_narrow", None)
            if callable(narrow_policy):
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
            record.state = _RECEIPT_NARROWING
        try:
            child = self.prepare(
                intent,
                _parent_receipt=receipt,
                _requested_resource_scope=resource_digest,
            )
        except BaseException:
            self._release_audit_reservation(narrow_token)
            with self._lock:
                record = self._states.get(receipt.nonce)
                if record is not None and record.receipt == receipt:
                    if record.state != _RECEIPT_NARROWING:
                        raise AuthorityControlPlaneError(
                            "receipt narrowing rollback state changed"
                        )
                    record.state = _RECEIPT_PREPARED
            raise

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
        with self._lock:
            self._bind_audit_reservation_locked(narrow_token, narrowed_event)
            record = self._states.get(receipt.nonce)
            if record is None or record.receipt != receipt:
                raise AuthorityControlPlaneError(
                    "receipt narrowing parent disappeared before terminalization"
                )
            if record.state != _RECEIPT_NARROWING:
                raise AuthorityControlPlaneError(
                    "receipt narrowing parent state changed"
                )
            self._pending.pop(receipt.nonce, None)
            self._states.pop(receipt.nonce, None)
            self._remember_terminal_locked(receipt.nonce, "narrowed")
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
            record.state = _RECEIPT_REVOKING
        try:
            self._append_or_queue_audit(revoked_event)
        except BaseException:
            with self._lock:
                record = self._record_locked(receipt)
                record.state = _RECEIPT_PREPARED
            raise
        with self._lock:
            self._pending.pop(receipt.nonce, None)
            self._states.pop(receipt.nonce, None)
            self._remember_terminal_locked(receipt.nonce, "revoked")

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


def build_production_daemon(
    *,
    socket_path: Path,
    key_path: Path,
    audit_writer: AuditWriter | None,
    issuer_id: str = "khaos-authorityd",
    policy: Callable[[AuthorizationIntent], None] | None = None,
) -> AuthorityDaemon:
    """Construct authorityd only when an independent writer is supplied."""
    if audit_writer is None:
        raise AuthorityControlPlaneError(
            "production authorityd requires an independent remote/WORM audit writer"
        )
    expected_policy_digest = os.environ.get("KHAOS_EFFECTIVE_POLICY_DIGEST")
    if not expected_policy_digest:
        raise AuthorityControlPlaneError(
            "production authorityd requires KHAOS_EFFECTIVE_POLICY_DIGEST"
        )
    key = Ed25519KeyStore.load_or_create(key_path, create=False)
    kernel = AuthorityPolicyKernel(expected_policy_digest=expected_policy_digest)
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

    def check_narrow(self, source_operation: str, target_operation: str) -> None:
        self.kernel.check_narrow(source_operation, target_operation)
        custom_narrow = getattr(self.custom, "check_narrow", None)
        if callable(custom_narrow):
            custom_narrow(source_operation, target_operation)


class AuthorityPolicyKernel:
    """Closed operation/resource policy owned by authorityd, not its client."""

    _FAMILIES = frozenset({"exec", "git", "network", "workspace"})

    def __init__(self, *, expected_policy_digest: str | None = None) -> None:
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

    def __call__(self, intent: AuthorizationIntent) -> None:
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

    def check_narrow(self, source_operation: str, target_operation: str) -> None:
        source_family = source_operation.split(".", 1)[0]
        target_family = target_operation.split(".", 1)[0]
        if source_family != target_family:
            raise AuthorityControlPlaneError(
                "authorityd narrowing cannot cross issuer families"
            )


def serve_unix(daemon: AuthorityDaemon, *, production: bool = True) -> None:
    """Serve requests on a private 0600 socket or agent-group 0660 socket."""
    if os.name == "nt" or sys.platform == "darwin":
        raise AuthorityControlPlaneError(
            "native authorityd transport is required on this platform; use the "
            "Windows Named Pipe or macOS launchd/XPC adapter"
        )
    contract = read_contract_from_environment()
    if production:
        contract.validate(production=True)
        if contract.authority_uid is not None and os.geteuid() != contract.authority_uid:
            raise IdentityIsolationError("authorityd is not running as its dedicated UID")
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
                    contract.agent_uid if production else None,
                    connection_timeout,
                    slots,
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
) -> None:
    try:
        with connection:
            connection.settimeout(connection_timeout)
            try:
                if expected_uid is not None and peer_uid(connection) != expected_uid:
                    raise IdentityIsolationError("authorityd peer UID is not the agent UID")
                body = _recv_line(connection)
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
    raise AuthorityControlPlaneError("unknown authorityd operation")


def _mapping(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AuthorityControlPlaneError("authorityd payload is not a mapping")
    return value


def _recv_line(connection: socket.socket) -> bytes:
    data = bytearray()
    while len(data) < MAX_MESSAGE_BYTES:
        chunk = connection.recv(min(64 * 1024, MAX_MESSAGE_BYTES - len(data)))
        if not chunk:
            break
        marker = chunk.find(b"\n")
        if marker >= 0:
            data.extend(chunk[:marker])
            return bytes(data)
        data.extend(chunk)
    raise AuthorityControlPlaneError("authorityd request is too large or incomplete")


__all__ = [
    "AuthorityControlPlaneError",
    "AuthorityDaemon",
    "AuthorityPolicyKernel",
    "JsonlAuditWriter",
    "build_production_daemon",
    "serve_unix",
]
