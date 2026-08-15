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
    MAX_MESSAGE_BYTES,
    AuditWriter,
    AuthorityControlPlaneError,
    AuthorizationIntent,
    Ed25519KeyStore,
    RemoteAuditUnavailableError,
    SignedAuthorizationReceipt,
    _canonical,
    _digest,
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
    ) -> None:
        if not socket_path.is_absolute() or audit_writer is None:
            raise AuthorityControlPlaneError(
                "authorityd requires an absolute socket and independent audit writer"
            )
        if (
            max_pending_receipts <= 0
            or max_pending_per_principal <= 0
            or terminal_tombstone_limit <= 0
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
        self.max_pending_receipts = max_pending_receipts
        self.max_pending_per_principal = max_pending_per_principal
        self.terminal_tombstone_limit = terminal_tombstone_limit
        self._closed = False

    @property
    def public_key_bytes(self) -> bytes:
        return self.signing_key.public_key().public_bytes_raw()

    @property
    def pending_count(self) -> int:
        self._expire_pending()
        with self._lock:
            return len(self._pending)

    def _remember_terminal_locked(self, nonce: str, state: str) -> None:
        self._terminal[nonce] = state
        while len(self._terminal) > self.terminal_tombstone_limit:
            self._terminal.pop(next(iter(self._terminal)))

    def _collect_expired_locked(self, *, now: float | None = None) -> list[dict[str, object]]:
        current = time.time() if now is None else now
        expired = [
            nonce
            for nonce, record in self._states.items()
            if record.state == _RECEIPT_PREPARED and current >= record.receipt.expires_at
        ]
        events: list[dict[str, object]] = []
        for nonce in expired:
            record = self._states.pop(nonce)
            self._pending.pop(nonce, None)
            self._remember_terminal_locked(nonce, "expired")
            events.append(
                {
                    "kind": "execution.expired",
                    "receipt_digest": record.receipt.digest,
                    "audit_intent_digest": record.receipt.audit_intent_digest,
                    "issuer_id": self.issuer_id,
                }
            )
        return events

    def _expire_pending(self) -> None:
        """Garbage-collect launchable receipts without holding the audit lock."""
        with self._lock:
            events = self._collect_expired_locked()
        for event in events:
            try:
                self._append_audit(event)
            except AuthorityControlPlaneError:
                logger.exception("authorityd could not append receipt expiry evidence")

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

    def prepare(self, intent: AuthorizationIntent) -> SignedAuthorizationReceipt:
        self._expire_pending()
        with self._lock:
            if len(self._pending) >= self.max_pending_receipts:
                raise AuthorityControlPlaneError("authorityd pending receipt quota is exhausted")
            if self._pending_for_principal_locked(intent.principal_id) >= self.max_pending_per_principal:
                raise AuthorityControlPlaneError(
                    "authorityd pending receipt principal quota is exhausted"
                )
            self.policy(intent)
            audit_intent = {
                "kind": "execution.prepare",
                "intent": intent.payload(),
                "intent_digest": intent.digest,
                "issuer_id": self.issuer_id,
            }
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
                "expires_at": expires_at,
                "audit_intent_digest": _digest(audit_intent),
                "issuer_id": self.issuer_id,
                "issued_at": issued_at,
            }
            signature = self.signing_key.sign(_canonical(receipt_fields))
            receipt = SignedAuthorizationReceipt(
                **receipt_fields,
                signature=__import__("base64").b64encode(signature).decode("ascii"),
            )
            self._pending[receipt.nonce] = receipt
            self._states[receipt.nonce] = _ReceiptRecord(
                receipt, state=_RECEIPT_PREPARING
            )
        try:
            self._append_audit(audit_intent)
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
            record = self._record_locked(receipt)
            if record.state != _RECEIPT_PREPARED:
                raise AuthorityControlPlaneError("receipt is not claimable")
            receipt.verify(self.signing_key.public_key())
            record.state = _RECEIPT_CLAIMING
        try:
            self._append_audit(
                {
                    "kind": "execution.claimed",
                    "receipt_digest": receipt.digest,
                    "audit_intent_digest": receipt.audit_intent_digest,
                    "issuer_id": self.issuer_id,
                }
            )
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
        with self._lock:
            record = self._record_locked(receipt)
            receipt.verify_signature(self.signing_key.public_key())
            if record.state == _RECEIPT_PREPARED:
                # Preserve the old direct prepare -> complete protocol for
                # callers that do not need a separate launch transition.
                if time.time() >= receipt.expires_at:
                    self._states.pop(receipt.nonce, None)
                    self._pending.pop(receipt.nonce, None)
                    self._remember_terminal_locked(receipt.nonce, "expired")
                    expired_event = {
                        "kind": "execution.expired",
                        "receipt_digest": receipt.digest,
                        "audit_intent_digest": receipt.audit_intent_digest,
                        "issuer_id": self.issuer_id,
                    }
            elif record.state != _RECEIPT_CLAIMED:
                raise AuthorityControlPlaneError("receipt is not completable")
            if expired_event is None:
                record.state = _RECEIPT_COMPLETING
        if expired_event is not None:
            try:
                self._append_audit(expired_event)
            except AuthorityControlPlaneError:
                logger.exception("authorityd could not append receipt expiry evidence")
            raise AuthorityControlPlaneError("receipt has expired")
        try:
            self._append_audit(
                {
                    "kind": f"execution.{result}",
                    "receipt_digest": receipt.digest,
                    "audit_intent_digest": receipt.audit_intent_digest,
                    "result_digest": result_digest,
                    "issuer_id": self.issuer_id,
                }
            )
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
            record.state = _RECEIPT_NARROWING
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
            )
            narrow_policy = getattr(self.policy, "check_narrow", None)
            if callable(narrow_policy):
                narrow_policy(receipt.operation, operation)
        try:
            return self.prepare(intent)
        except BaseException:
            with self._lock:
                record = self._record_locked(receipt)
                record.state = _RECEIPT_PREPARED
            raise

    def revoke(self, receipt: SignedAuthorizationReceipt) -> None:
        self._expire_pending()
        with self._lock:
            record = self._record_locked(receipt)
            if record.state != _RECEIPT_PREPARED:
                raise AuthorityControlPlaneError(
                    "only a prepared receipt may be revoked"
                )
            receipt.verify_signature(self.signing_key.public_key())
            record.state = _RECEIPT_REVOKING
        try:
            self._append_audit(
                {
                    "kind": "execution.revoked",
                    "receipt_digest": receipt.digest,
                    "audit_intent_digest": receipt.audit_intent_digest,
                    "issuer_id": self.issuer_id,
                }
            )
        except BaseException:
            with self._lock:
                record = self._record_locked(receipt)
                record.state = _RECEIPT_CLAIMED
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
