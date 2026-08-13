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
    SignedAuthorizationReceipt,
    _canonical,
    _digest,
)
from khaos.security.identity_isolation import (
    IdentityIsolationError,
    peer_uid,
    read_contract_from_environment,
    validate_private_unix_socket,
)

logger = logging.getLogger(__name__)


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
    ) -> None:
        if not socket_path.is_absolute() or audit_writer is None:
            raise AuthorityControlPlaneError(
                "authorityd requires an absolute socket and independent audit writer"
            )
        self.socket_path = socket_path
        self.signing_key = signing_key
        self.audit_writer = audit_writer
        self.issuer_id = issuer_id
        self.policy = policy
        self._lock = threading.RLock()
        self._pending: dict[str, SignedAuthorizationReceipt] = {}
        self._closed = False

    @property
    def public_key_bytes(self) -> bytes:
        return self.signing_key.public_key().public_bytes_raw()

    def prepare(self, intent: AuthorizationIntent) -> SignedAuthorizationReceipt:
        with self._lock:
            self.policy(intent)
            audit_intent = {
                "kind": "execution.prepare",
                "intent": intent.payload(),
                "intent_digest": intent.digest,
                "issuer_id": self.issuer_id,
            }
            self._append_audit(audit_intent)
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
            return receipt

    def complete(
        self,
        receipt: SignedAuthorizationReceipt,
        *,
        result: str,
        result_digest: str,
    ) -> None:
        with self._lock:
            pending = self._pending.get(receipt.nonce)
            if pending != receipt:
                raise AuthorityControlPlaneError("receipt is unknown or already completed")
            receipt.verify(self.signing_key.public_key())
            if time.time() >= receipt.expires_at:
                raise AuthorityControlPlaneError("receipt has expired")
            if result not in {"success", "failed", "unknown"}:
                raise AuthorityControlPlaneError("execution result is invalid")
            if not result_digest:
                raise AuthorityControlPlaneError("execution result digest is required")
            self._append_audit(
                {
                    "kind": f"execution.{result}",
                    "receipt_digest": receipt.digest,
                    "audit_intent_digest": receipt.audit_intent_digest,
                    "result_digest": result_digest,
                    "issuer_id": self.issuer_id,
                }
            )
            self._pending.pop(receipt.nonce, None)

    def validate(
        self,
        receipt: SignedAuthorizationReceipt,
        *,
        expected_operation: str | None = None,
        expected_resource_digest: str | None = None,
    ) -> None:
        with self._lock:
            pending = self._pending.get(receipt.nonce)
            if pending != receipt:
                raise AuthorityControlPlaneError("receipt is unknown or revoked")
            receipt.verify(self.signing_key.public_key())
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
        self.validate(receipt)
        intent = AuthorizationIntent(
            principal_id=receipt.principal_id,
            project_id=receipt.project_id,
            runtime_id=receipt.runtime_id,
            task_id=receipt.task_id,
            workspace_id=receipt.workspace_id,
            operation=operation,
            resource_digest=resource_digest,
            policy_digest=receipt.policy_digest,
            nonce=secrets.token_hex(16),
            authorization_epoch=receipt.authorization_epoch,
        )
        narrow_policy = getattr(self.policy, "check_narrow", None)
        if callable(narrow_policy):
            narrow_policy(receipt.operation, operation)
        return self.prepare(intent)

    def revoke(self, receipt: SignedAuthorizationReceipt) -> None:
        with self._lock:
            self.validate(receipt)
            self._pending.pop(receipt.nonce, None)

    def _append_audit(self, record: dict[str, Any]) -> None:
        if self.audit_writer is None:
            raise AuthorityControlPlaneError("independent audit writer is unavailable")
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
    """Serve newline-delimited requests on a private 0600 Unix socket."""
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
        os.chmod(daemon.socket_path, 0o600)
        if production:
            validate_private_unix_socket(
                daemon.socket_path, expected_uid=contract.authority_uid
            )
        listener.listen(16)
        while not daemon._closed:
            connection, _ = listener.accept()
            threading.Thread(
                target=_serve_connection,
                args=(daemon, connection, contract.agent_uid if production else None),
                daemon=True,
            ).start()
    finally:
        listener.close()
        daemon.socket_path.unlink(missing_ok=True)


def _serve_connection(
    daemon: AuthorityDaemon,
    connection: socket.socket,
    expected_uid: int | None,
) -> None:
    with connection:
        try:
            if expected_uid is not None and peer_uid(connection) != expected_uid:
                raise IdentityIsolationError("authorityd peer UID is not the agent UID")
            body = _recv_line(connection)
            request = json.loads(body.decode("utf-8"))
            response = _dispatch(daemon, request)
        except (AuthorityControlPlaneError, OSError, ValueError, TypeError) as exc:
            response = {"ok": False, "error": str(exc)}
        connection.sendall(_canonical(response) + b"\n")


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
