"""Broker-issued effect capabilities for privileged local effects.

``AuthorityEnvelope`` is intentionally only an owner/context description.  It
is useful in audit records, but constructing one must never be enough to cross
an effect boundary.  This module adds the missing boundary: envelopes are
broker-owned, and the capability seal and live revocation registry live in a
dedicated broker process.  A caller can copy a capability handle, but cannot
manufacture a valid token or change its owner, resource, operation, generation,
or expiry in place.

The broker is deliberately small and stdlib-only so it is available before
the rest of Khaos is initialized.  It is an intra-user boundary for trusted
control-plane code versus untrusted child processes; the stronger root-owned
kernel helper remains the authority for operations that mutate kernel state.
"""

from __future__ import annotations

import atexit
import hashlib
import hmac
import multiprocessing
import secrets
import threading
import time
from dataclasses import dataclass
from multiprocessing.connection import Connection
from typing import Any

from khaos.security.authority import AuthorityEnvelope

_BROKER_PROTOCOL = 1
_DEFAULT_TTL_SECONDS = 300.0
_MAX_TTL_SECONDS = 3600.0
_CAPABILITY_ISSUER = object()


class AuthorityBrokerError(PermissionError):
    """Raised when the broker cannot issue or validate a capability."""


@dataclass(frozen=True, slots=True, init=False)
class EffectCapability:
    """An opaque, broker-issued permission for one class of local effect.

    The context and operation fields are intentionally inspectable for audit
    and approval binding.  ``token`` and ``seal`` are only handles; trust is
    established by asking the broker process to validate them.  ``derive``
    narrows the operation label without minting a new token, so every nested
    operation remains bound to the original broker record.
    """

    authority: AuthorityEnvelope
    allowed_operation: str
    resource_digest: str
    generation: int
    authorization_epoch: int
    issued_at: float
    expires_at: float
    nonce: str
    token: str
    seal: str
    schema_version: int = 1

    def __init__(
        self,
        *,
        authority: AuthorityEnvelope,
        allowed_operation: str,
        resource_digest: str,
        generation: int,
        authorization_epoch: int,
        issued_at: float,
        expires_at: float,
        nonce: str,
        token: str,
        seal: str,
        schema_version: int = 1,
        _issuer: object | None = None,
    ) -> None:
        if _issuer is not _CAPABILITY_ISSUER:
            raise TypeError(
                "EffectCapability instances can only be created by AuthorityBroker"
            )
        for name, value in (
            ("authority", authority),
            ("allowed_operation", allowed_operation),
            ("resource_digest", resource_digest),
            ("generation", generation),
            ("authorization_epoch", authorization_epoch),
            ("issued_at", issued_at),
            ("expires_at", expires_at),
            ("nonce", nonce),
            ("token", token),
            ("seal", seal),
            ("schema_version", schema_version),
        ):
            object.__setattr__(self, name, value)
        self._validate_shape()

    def _validate_shape(self) -> None:
        if self.schema_version != 1:
            raise ValueError("unsupported effect capability schema")
        if not self.allowed_operation or len(self.allowed_operation) > 256:
            raise ValueError("effect capability operation is invalid")
        if self.resource_digest != self.authority.resource_digest:
            raise ValueError("effect capability resource does not match authority")
        if self.generation != self.authority.workspace_generation:
            raise ValueError("effect capability generation does not match authority")
        if self.authorization_epoch != self.authority.authorization_epoch:
            raise ValueError("effect capability epoch does not match authority")
        if self.expires_at <= self.issued_at:
            raise ValueError("effect capability expiry must be after issuance")
        for label, value in (("nonce", self.nonce), ("token", self.token), ("seal", self.seal)):
            if not isinstance(value, str) or not value or len(value) > 512:
                raise ValueError(f"effect capability {label} is invalid")

    @classmethod
    def _from_broker(cls, **fields: Any) -> EffectCapability:
        """Construct a capability from the broker client response only."""
        return cls(**fields, _issuer=_CAPABILITY_ISSUER)

    @property
    def context_digest(self) -> str:
        """Return the stable owner digest excluding operation/resource labels."""
        return self.authority.context_digest()

    @property
    def digest(self) -> str:
        """Return a non-secret audit digest for this capability handle."""
        payload = (
            self.context_digest,
            self.allowed_operation,
            self.resource_digest,
            self.generation,
            self.authorization_epoch,
            self.nonce,
            self.issued_at,
            self.expires_at,
        )
        return hashlib.sha256(repr(payload).encode("utf-8")).hexdigest()

    def derive(
        self,
        *,
        operation_class: str,
        resource_digest: str | None = None,
    ) -> EffectCapability:
        """Narrow the current operation while retaining the broker token."""
        if resource_digest is not None and resource_digest != self.resource_digest:
            raise ValueError(
                "effect capability resources can only be narrowed by a broker reissue"
            )
        narrowed_resource = resource_digest or self.resource_digest
        return self._from_broker(
            authority=self.authority.derive(
                operation_class=operation_class,
                resource_digest=narrowed_resource,
            ),
            allowed_operation=self.allowed_operation,
            resource_digest=narrowed_resource,
            generation=self.generation,
            authorization_epoch=self.authorization_epoch,
            issued_at=self.issued_at,
            expires_at=self.expires_at,
            nonce=self.nonce,
            token=self.token,
            seal=self.seal,
            schema_version=self.schema_version,
        )


def _canonical_record(
    *,
    context_digest: str,
    allowed_operation: str,
    resource_digest: str,
    generation: int,
    authorization_epoch: int,
    issued_at: float,
    expires_at: float,
    nonce: str,
    token: str,
) -> bytes:
    return "|".join(
        (
            str(_BROKER_PROTOCOL),
            context_digest,
            allowed_operation,
            resource_digest,
            str(generation),
            str(authorization_epoch),
            f"{issued_at:.9f}",
            f"{expires_at:.9f}",
            nonce,
            token,
        )
    ).encode("utf-8")


def _broker_main(connection: Connection) -> None:
    """Own the token secret and registry in a separate process."""
    secret = secrets.token_bytes(32)
    records: dict[str, dict[str, Any]] = {}
    try:
        while True:
            try:
                request = connection.recv()
            except (EOFError, OSError):
                return
            if not isinstance(request, dict) or request.get("protocol") != _BROKER_PROTOCOL:
                connection.send({"ok": False, "error": "invalid broker request"})
                continue
            operation = request.get("operation")
            if operation == "close":
                connection.send({"ok": True})
                return
            if operation == "issue":
                try:
                    now = time.time()
                    ttl = float(request["ttl_seconds"])
                    if not 0 < ttl <= _MAX_TTL_SECONDS:
                        raise ValueError("capability TTL is outside the allowed range")
                    fields = {
                        "context_digest": str(request["context_digest"]),
                        "allowed_operation": str(request["allowed_operation"]),
                        "resource_digest": str(request["resource_digest"]),
                        "generation": int(request["generation"]),
                        "authorization_epoch": int(request["authorization_epoch"]),
                        "issued_at": now,
                        "expires_at": now + ttl,
                        "nonce": secrets.token_hex(16),
                        "token": secrets.token_urlsafe(48),
                    }
                    seal = hmac.new(
                        secret,
                        _canonical_record(**fields),
                        hashlib.sha256,
                    ).hexdigest()
                    fields["seal"] = seal
                    records[fields["token"]] = fields
                    connection.send({"ok": True, "capability": fields})
                except (KeyError, TypeError, ValueError) as exc:
                    connection.send({"ok": False, "error": str(exc)})
                continue
            if operation == "revoke":
                token = request.get("token")
                if not isinstance(token, str):
                    connection.send({"ok": False, "error": "invalid capability token"})
                else:
                    records.pop(token, None)
                    connection.send({"ok": True})
                continue
            if operation == "validate":
                result = _validate_record(records, secret, request)
                connection.send({"ok": result is None, **({} if result is None else {"error": result})})
                continue
            connection.send({"ok": False, "error": "unknown broker operation"})
    finally:
        connection.close()


def _validate_record(
    records: dict[str, dict[str, Any]],
    secret: bytes,
    request: dict[str, Any],
) -> str | None:
    token = request.get("token")
    if not isinstance(token, str):
        return "capability token is invalid"
    record = records.get(token)
    if record is None:
        return "capability is unknown or revoked"
    if time.time() >= float(record["expires_at"]):
        records.pop(token, None)
        return "capability has expired"
    for field in (
        "context_digest",
        "allowed_operation",
        "resource_digest",
        "generation",
        "authorization_epoch",
        "issued_at",
        "expires_at",
        "nonce",
        "seal",
    ):
        if request.get(field) != record[field]:
            return f"capability {field} does not match broker record"
    expected_seal = hmac.new(
        secret,
        _canonical_record(
            context_digest=record["context_digest"],
            allowed_operation=record["allowed_operation"],
            resource_digest=record["resource_digest"],
            generation=record["generation"],
            authorization_epoch=record["authorization_epoch"],
            issued_at=record["issued_at"],
            expires_at=record["expires_at"],
            nonce=record["nonce"],
            token=record["token"],
        ),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(record["seal"], expected_seal):
        return "capability seal is invalid"
    operation_class = request.get("operation_class")
    if not isinstance(operation_class, str) or not _operation_allowed(
        record["allowed_operation"], operation_class
    ):
        return "capability operation is outside its authority"
    expected_resource = request.get("expected_resource_digest")
    if expected_resource is not None and expected_resource != record["resource_digest"]:
        return "capability resource is outside its authority"
    return None


def _operation_allowed(allowed: str, operation: str) -> bool:
    if allowed.endswith("*"):
        return operation.startswith(allowed[:-1])
    return hmac.compare_digest(allowed, operation)


class AuthorityBroker:
    """Synchronous client for the dedicated effect-capability broker."""

    _default: AuthorityBroker | None = None
    _default_lock = threading.Lock()

    def __init__(self) -> None:
        context = multiprocessing.get_context("spawn")
        parent, child = context.Pipe(duplex=True)
        process = context.Process(target=_broker_main, args=(child,), daemon=True)
        process.start()
        child.close()
        self._connection = parent
        self._process = process
        self._lock = threading.RLock()
        self._closed = False

    @classmethod
    def default(cls) -> AuthorityBroker:
        """Return the process-wide control-plane broker."""
        with cls._default_lock:
            if cls._default is None or cls._default.closed:
                cls._default = cls()
                atexit.register(cls._close_default)
            return cls._default

    @classmethod
    def _close_default(cls) -> None:
        broker = cls._default
        if broker is not None:
            broker.close()

    @property
    def closed(self) -> bool:
        return self._closed or not self._process.is_alive()

    def issue(
        self,
        authority: AuthorityEnvelope,
        *,
        allowed_operation: str | None = None,
        resource_digest: str | None = None,
        ttl_seconds: float = _DEFAULT_TTL_SECONDS,
    ) -> EffectCapability:
        """Issue a capability after binding all authority context fields."""
        if not isinstance(authority, AuthorityEnvelope):
            raise AuthorityBrokerError("authority broker requires an AuthorityEnvelope context")
        if authority._broker is not self:
            raise AuthorityBrokerError(
                "authority envelope was not created by this AuthorityBroker"
            )
        operation = allowed_operation or authority.operation_class
        resource = resource_digest or authority.resource_digest
        if not _valid_operation(operation):
            raise AuthorityBrokerError("invalid capability operation authority")
        if resource != authority.resource_digest:
            raise AuthorityBrokerError("capability resource must match authority context")
        response = self._call(
            {
                "operation": "issue",
                "context_digest": authority.context_digest(),
                "allowed_operation": operation,
                "resource_digest": resource,
                "generation": authority.workspace_generation,
                "authorization_epoch": authority.authorization_epoch,
                "ttl_seconds": ttl_seconds,
            }
        )
        fields = response.get("capability")
        if not isinstance(fields, dict):
            raise AuthorityBrokerError("authority broker returned no capability")
        try:
            return EffectCapability._from_broker(
                authority=authority,
                allowed_operation=str(fields["allowed_operation"]),
                resource_digest=str(fields["resource_digest"]),
                generation=int(fields["generation"]),
                authorization_epoch=int(fields["authorization_epoch"]),
                issued_at=float(fields["issued_at"]),
                expires_at=float(fields["expires_at"]),
                nonce=str(fields["nonce"]),
                token=str(fields["token"]),
                seal=str(fields["seal"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise AuthorityBrokerError("authority broker returned malformed capability") from exc

    def reissue(
        self,
        capability: EffectCapability,
        *,
        operation_class: str,
        resource_digest: str,
        ttl_seconds: float = _DEFAULT_TTL_SECONDS,
    ) -> EffectCapability:
        """Mint a narrower capability from an already-live capability.

        A resource transition is a new authorization decision.  It must not
        be implemented by copying the original token into a derived
        ``EffectCapability``: the broker registry would still attest the old
        resource.  Requiring a live source capability keeps the transition
        inside the capability chain and prevents a caller that only has a
        constructible ``AuthorityEnvelope`` from manufacturing a lease for a
        different resource.
        """
        if not isinstance(capability, EffectCapability):
            raise AuthorityBrokerError("capability reissue requires a broker capability")
        if not _valid_operation(operation_class):
            raise AuthorityBrokerError("invalid capability operation authority")
        if not isinstance(resource_digest, str) or not resource_digest:
            raise AuthorityBrokerError("capability reissue resource is invalid")
        self.validate(capability, expected_operation=operation_class)
        authority = capability.authority.derive(
            operation_class=operation_class,
            resource_digest=resource_digest,
        )
        return self.issue(
            authority,
            allowed_operation=operation_class,
            resource_digest=resource_digest,
            ttl_seconds=ttl_seconds,
        )

    def envelope(
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
        authorization_epoch: int = 0,
        schema_version: int = 1,
    ) -> AuthorityEnvelope:
        """Create one broker-owned context for a later capability issue."""
        try:
            return AuthorityEnvelope._from_broker(
                broker=self,
                principal_id=principal_id,
                project_id=project_id,
                runtime_id=runtime_id,
                task_id=task_id,
                workspace_id=workspace_id,
                workspace_generation=workspace_generation,
                policy_digest=policy_digest,
                operation_class=operation_class,
                resource_digest=resource_digest,
                authorization_epoch=authorization_epoch,
                schema_version=schema_version,
            )
        except (TypeError, ValueError) as exc:
            raise AuthorityBrokerError("authority envelope is invalid") from exc

    def validate(
        self,
        capability: EffectCapability,
        *,
        expected_operation: str | None = None,
        expected_resource_digest: str | None = None,
    ) -> None:
        """Validate a handle against the live broker registry."""
        if not isinstance(capability, EffectCapability):
            raise AuthorityBrokerError("effect boundary requires a broker capability")
        try:
            capability._validate_shape()
        except (AttributeError, TypeError, ValueError) as exc:
            raise AuthorityBrokerError("effect capability shape is invalid") from exc
        response = self._call(
            {
                "operation": "validate",
                "token": capability.token,
                "context_digest": capability.context_digest,
                "allowed_operation": capability.allowed_operation,
                "resource_digest": capability.resource_digest,
                "generation": capability.generation,
                "authorization_epoch": capability.authorization_epoch,
                "issued_at": capability.issued_at,
                "expires_at": capability.expires_at,
                "nonce": capability.nonce,
                "seal": capability.seal,
                "operation_class": expected_operation or capability.authority.operation_class,
                "expected_resource_digest": expected_resource_digest,
            }
        )
        if not response.get("ok"):
            raise AuthorityBrokerError(str(response.get("error") or "capability rejected"))

    def revoke(self, capability: EffectCapability) -> None:
        """Revoke a capability before its expiry."""
        if not isinstance(capability, EffectCapability):
            raise AuthorityBrokerError("cannot revoke a non-capability")
        self._call({"operation": "revoke", "token": capability.token})

    def close(self) -> None:
        """Stop the broker and make all issued capabilities invalid."""
        with self._lock:
            if self._closed:
                return
            try:
                self._call({"operation": "close"})
            except AuthorityBrokerError:
                pass
            self._closed = True
            self._connection.close()
            self._process.join(timeout=2.0)
            if self._process.is_alive():
                self._process.kill()
                self._process.join(timeout=1.0)

    def _call(self, request: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            if self.closed:
                raise AuthorityBrokerError("authority broker is closed or unavailable")
            request = {"protocol": _BROKER_PROTOCOL, **request}
            try:
                self._connection.send(request)
                response = self._connection.recv()
            except (EOFError, OSError) as exc:
                self._closed = True
                raise AuthorityBrokerError("authority broker IPC failed") from exc
            if not isinstance(response, dict) or not response.get("ok"):
                raise AuthorityBrokerError(str(response.get("error") if isinstance(response, dict) else "invalid broker response"))
            return response


def _valid_operation(operation: str) -> bool:
    return (
        isinstance(operation, str)
        and 1 <= len(operation) <= 256
        and all(character.isalnum() or character in "._:-*" for character in operation)
        and operation.count("*") <= 1
        and ("*" not in operation or operation.endswith("*"))
    )


__all__ = ["AuthorityBroker", "AuthorityBrokerError", "EffectCapability"]
