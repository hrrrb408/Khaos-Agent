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
import os
import secrets
import threading
import time
from dataclasses import dataclass
from multiprocessing.connection import Connection
from typing import Any

from khaos.security.authority import AuthorityEnvelope
from khaos.security.authority_transport import AuthorityTransportConfig
from khaos.security.authorityd_protocol import (
    AuthorityControlPlaneError,
    AuthorityDaemonClient,
    AuthorizationIntent,
    SignedAuthorizationReceipt,
)
from khaos.security.identity_isolation import (
    read_contract_from_environment,
    require_distinct_linux_identities,
)

_BROKER_PROTOCOL = 1
_DEFAULT_TTL_SECONDS = 300.0
_MAX_TTL_SECONDS = 3600.0
_DEFAULT_GRANT_TTL_SECONDS = 60 * 60.0
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
    receipt: SignedAuthorizationReceipt | None = None

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
        receipt: SignedAuthorizationReceipt | None = None,
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
            ("receipt", receipt),
        ):
            object.__setattr__(self, name, value)
        self._validate_shape()

    def _validate_shape(self) -> None:
        if self.schema_version != 1:
            raise ValueError("unsupported effect capability schema")
        if not _valid_operation(self.allowed_operation):
            raise ValueError("effect capability operation is invalid")
        if not _valid_operation(self.authority.operation_class):
            raise ValueError("effect capability authority operation is invalid")
        if not _operation_allowed(
            self.allowed_operation, self.authority.operation_class
        ):
            raise ValueError("effect capability operation is outside authority")
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
        if self.receipt is not None:
            if self.receipt.operation != self.authority.operation_class:
                raise ValueError(
                    "effect capability receipt operation does not match authority"
                )
            if not _operation_allowed(self.allowed_operation, self.receipt.operation):
                raise ValueError(
                    "effect capability receipt operation is outside authority"
                )
            if self.receipt.nonce != self.nonce or self.receipt.signature != self.seal:
                raise ValueError("effect capability receipt does not match its handles")
            if self.receipt.resource_digest != self.resource_digest:
                raise ValueError("effect capability receipt resource does not match")
            if self.receipt.authorization_epoch != self.authorization_epoch:
                raise ValueError("effect capability receipt epoch does not match")
            if self.receipt.workspace_generation != self.generation:
                raise ValueError("effect capability receipt generation does not match")
            if self.receipt.grant_id != self.authority.grant_id:
                raise ValueError("effect capability receipt grant does not match")
            if self.receipt.grant_context_digest != self.authority.context_digest():
                raise ValueError("effect capability receipt grant context does not match")

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
        broker = self.authority._broker
        if self.receipt is not None and broker is not None:
            narrow = getattr(broker, "reissue", None)
            if callable(narrow):
                narrowed_resource = resource_digest or self.resource_digest
                if self.expires_at > time.time():
                    return narrow(
                        self,
                        operation_class=operation_class,
                        resource_digest=narrowed_resource,
                    )
                # A receipt is a one-shot, short-lived effect handle.  The
                # broker-owned context is the renewable authority grant; an
                # expired handle must never be revived or narrowed through
                # the old receipt.
                authority = self.authority.derive(
                    operation_class=operation_class,
                    resource_digest=narrowed_resource,
                )
                issue = getattr(broker, "issue", None)
                if callable(issue):
                    return issue(
                        authority,
                        allowed_operation=operation_class,
                        resource_digest=narrowed_resource,
                    )
        if resource_digest is not None and resource_digest != self.resource_digest:
            raise ValueError(
                "effect capability resources can only be narrowed by a broker reissue"
            )
        narrowed_resource = resource_digest or self.resource_digest
        try:
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
                receipt=self.receipt,
            )
        except (TypeError, ValueError) as exc:
            raise AuthorityBrokerError(
                "effect capability operation is outside its authority"
            ) from exc


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
    grant_id: str,
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
            grant_id,
        )
    ).encode("utf-8")


def _broker_main(connection: Connection) -> None:
    """Own the token secret and registry in a separate process."""
    secret = secrets.token_bytes(32)
    grants: dict[str, dict[str, Any]] = {}
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
            if operation == "grant":
                try:
                    ttl = float(request["ttl_seconds"])
                    if not 0 < ttl <= _DEFAULT_GRANT_TTL_SECONDS:
                        raise ValueError("authority grant TTL is outside the allowed range")
                    operation_class = str(request["operation_class"])
                    resource_digest = str(request["resource_digest"])
                    generation = int(request["generation"])
                    authorization_epoch = int(request["authorization_epoch"])
                    if (
                        not _valid_operation(operation_class)
                        or not resource_digest
                        or generation <= 0
                        or authorization_epoch < 0
                    ):
                        raise ValueError("invalid authority grant context")
                    now = time.time()
                    grant_id = secrets.token_hex(24)
                    grants[grant_id] = {
                        "context_digest": str(request["context_digest"]),
                        "principal_id": str(request["principal_id"]),
                        "project_id": str(request["project_id"]),
                        "runtime_id": str(request["runtime_id"]),
                        "task_id": str(request["task_id"]),
                        "workspace_id": str(request["workspace_id"]),
                        "generation": generation,
                        "policy_digest": str(request["policy_digest"]),
                        "resource_digest": resource_digest,
                        "operation_family": operation_class.split(".", 1)[0],
                        "authorization_epoch": authorization_epoch,
                        "issued_at": now,
                        "expires_at": now + ttl,
                    }
                    connection.send(
                        {
                            "ok": True,
                            "grant_id": grant_id,
                            "expires_at": now + ttl,
                        }
                    )
                except (KeyError, TypeError, ValueError) as exc:
                    connection.send({"ok": False, "error": str(exc)})
                continue
            if operation == "revoke_grant":
                grant_id = request.get("grant_id")
                if not isinstance(grant_id, str):
                    connection.send({"ok": False, "error": "invalid authority grant id"})
                else:
                    grants.pop(grant_id, None)
                    connection.send({"ok": True})
                continue
            if operation == "rotate_authorization_epoch":
                try:
                    principal_id = str(request["principal_id"])
                    project_id = str(request["project_id"])
                    workspace_id = str(request["workspace_id"])
                    epoch = int(request["authorization_epoch"])
                    if epoch < 0:
                        raise ValueError("authorization epoch is invalid")
                    for grant_id, grant in tuple(grants.items()):
                        if (
                            grant["principal_id"] == principal_id
                            and grant["project_id"] == project_id
                            and grant["workspace_id"] == workspace_id
                            and grant["authorization_epoch"] < epoch
                        ):
                            grants.pop(grant_id, None)
                    connection.send({"ok": True})
                except (KeyError, TypeError, ValueError) as exc:
                    connection.send({"ok": False, "error": str(exc)})
                continue
            if operation == "rotate_workspace_generation":
                try:
                    principal_id = str(request["principal_id"])
                    project_id = str(request["project_id"])
                    workspace_id = str(request["workspace_id"])
                    generation = int(request["workspace_generation"])
                    if generation <= 0:
                        raise ValueError("workspace generation is invalid")
                    for grant_id, grant in tuple(grants.items()):
                        if (
                            grant["principal_id"] == principal_id
                            and grant["project_id"] == project_id
                            and grant["workspace_id"] == workspace_id
                            and grant["generation"] < generation
                        ):
                            grants.pop(grant_id, None)
                    connection.send({"ok": True})
                except (KeyError, TypeError, ValueError) as exc:
                    connection.send({"ok": False, "error": str(exc)})
                continue
            if operation == "issue":
                try:
                    parent = request.get("parent")
                    if parent is not None:
                        if not isinstance(parent, dict):
                            raise ValueError("capability parent is invalid")
                        parent_error = _validate_record(
                            records, grants, secret, parent
                        )
                        if parent_error is not None:
                            raise ValueError(parent_error)
                        parent_record = records.get(str(parent.get("token")))
                        if parent_record is None or parent_record.get("grant_id") != request.get("grant_id"):
                            raise ValueError("capability parent grant does not match")
                        grant_error = _validate_grant(
                            grants, request, record=parent_record
                        )
                    else:
                        grant_error = _validate_grant(grants, request)
                    if grant_error is not None:
                        raise ValueError(grant_error)
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
                        "grant_id": str(request["grant_id"]),
                        "operation_class": str(request["operation_class"]),
                        "issued_at": now,
                        "expires_at": now + ttl,
                        "nonce": secrets.token_hex(16),
                        "token": secrets.token_urlsafe(48),
                    }
                    seal = hmac.new(
                        secret,
                        _canonical_record(
                            context_digest=fields["context_digest"],
                            allowed_operation=fields["allowed_operation"],
                            resource_digest=fields["resource_digest"],
                            generation=fields["generation"],
                            authorization_epoch=fields["authorization_epoch"],
                            issued_at=fields["issued_at"],
                            expires_at=fields["expires_at"],
                            nonce=fields["nonce"],
                            token=fields["token"],
                            grant_id=fields["grant_id"],
                        ),
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
            if operation == "claim":
                result = _validate_record(records, grants, secret, request)
                connection.send({"ok": result is None, **({} if result is None else {"error": result})})
                continue
            if operation == "complete":
                result = _validate_record(
                    records, grants, secret, request, allow_expired=True
                )
                if result is None:
                    records.pop(str(request.get("token")), None)
                connection.send({"ok": result is None, **({} if result is None else {"error": result})})
                continue
            if operation == "validate":
                result = _validate_record(records, grants, secret, request)
                connection.send({"ok": result is None, **({} if result is None else {"error": result})})
                continue
            connection.send({"ok": False, "error": "unknown broker operation"})
    finally:
        connection.close()


def _validate_record(
    records: dict[str, dict[str, Any]],
    grants: dict[str, dict[str, Any]],
    secret: bytes,
    request: dict[str, Any],
    *,
    allow_expired: bool = False,
) -> str | None:
    token = request.get("token")
    if not isinstance(token, str):
        return "capability token is invalid"
    record = records.get(token)
    if record is None:
        return "capability is unknown or revoked"
    if not allow_expired:
        grant_error = _validate_grant(grants, request, record=record)
        if grant_error is not None:
            return grant_error
    if not allow_expired and time.time() >= float(record["expires_at"]):
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
        "grant_id",
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
            grant_id=record["grant_id"],
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


def _validate_grant(
    grants: dict[str, dict[str, Any]],
    request: dict[str, Any],
    *,
    record: dict[str, Any] | None = None,
) -> str | None:
    grant_id = request.get("grant_id")
    if not isinstance(grant_id, str):
        return "authority grant id is invalid"
    grant = grants.get(grant_id)
    if grant is None:
        return "authority grant is unknown or revoked"
    if time.time() >= float(grant["expires_at"]):
        grants.pop(grant_id, None)
        return "authority grant has expired"
    operation = request.get("operation_class")
    if (
        not isinstance(operation, str)
        or operation.split(".", 1)[0] != grant["operation_family"]
    ):
        return "authority grant operation family cannot be escalated"
    expected = record or request
    if record is None and expected.get("resource_digest") != grant["resource_digest"]:
        return "authority grant resource is outside its live scope"
    for field in (
        "context_digest",
        "generation",
        "authorization_epoch",
        "operation_family",
    ):
        if field == "operation_family":
            operation = expected.get("operation_class")
            if not isinstance(operation, str) or operation.split(".", 1)[0] != grant[field]:
                return f"authority grant {field} does not match live grant"
            continue
        if expected.get(field) != grant[field]:
            return f"authority grant {field} does not match live grant"
    return None


def _operation_allowed(allowed: str, operation: str) -> bool:
    if allowed == "*":
        return False
    if allowed.endswith("*"):
        prefix = allowed[:-1]
        return (
            bool(prefix)
            and operation.startswith(prefix)
            and prefix.rstrip(".").split(".", 1)[0]
            == operation.split(".", 1)[0]
        )
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
        """Return the process-wide control-plane broker.

        Production is fail-closed: the default broker is always a client of
        an independently deployed ``khaos-authorityd`` selected by
        ``AuthorityTransportConfig``.  The local HMAC broker remains
        available only when the test/development profile is explicit
        (``KHAOS_DEV_MODE=1``) or when a caller constructs ``AuthorityBroker()``
        directly for unit tests.
        """
        with cls._default_lock:
            if cls._default is None or cls._default.closed:
                if os.environ.get("KHAOS_DEV_MODE") == "1":
                    cls._default = cls()
                else:
                    try:
                        deployment = AuthorityTransportConfig.from_environment()
                        contract = read_contract_from_environment()
                        deployment.validate_contract(contract)
                        if (
                            deployment.platform_name.startswith("linux")
                            and not deployment.is_community
                        ):
                            if (
                                contract.agent_uid is None
                                or contract.authority_uid is None
                                or contract.job_uid is None
                            ):
                                raise AuthorityBrokerError(
                                    "Linux authority contract is missing execution UIDs"
                                )
                            require_distinct_linux_identities(
                                agent_uid=contract.agent_uid,
                                authority_uid=contract.authority_uid,
                                job_uid=contract.job_uid,
                            )
                        client = deployment.client(contract)
                    except (OSError, PermissionError, ValueError) as exc:
                        raise AuthorityBrokerError(
                            "production AuthorityBroker transport configuration is invalid"
                        ) from exc
                    cls._default = AuthorityDaemonBroker(
                        client
                    )
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
        _parent_capability: EffectCapability | None = None,
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
        request: dict[str, Any] = {
            "operation": "issue",
            "context_digest": authority.context_digest(),
            "grant_id": authority.grant_id,
            "operation_class": authority.operation_class,
            "allowed_operation": operation,
            "resource_digest": resource,
            "generation": authority.workspace_generation,
            "authorization_epoch": authority.authorization_epoch,
            "ttl_seconds": ttl_seconds,
        }
        if _parent_capability is not None:
            if _parent_capability.authority._broker is not self:
                raise AuthorityBrokerError(
                    "capability parent was not created by this AuthorityBroker"
                )
            request["parent"] = {
                "token": _parent_capability.token,
                "context_digest": _parent_capability.context_digest,
                "grant_id": _parent_capability.authority.grant_id,
                "allowed_operation": _parent_capability.allowed_operation,
                "resource_digest": _parent_capability.resource_digest,
                "generation": _parent_capability.generation,
                "authorization_epoch": _parent_capability.authorization_epoch,
                "issued_at": _parent_capability.issued_at,
                "expires_at": _parent_capability.expires_at,
                "nonce": _parent_capability.nonce,
                "seal": _parent_capability.seal,
                "operation_class": _parent_capability.authority.operation_class,
                "expected_resource_digest": _parent_capability.resource_digest,
            }
        response = self._call(request)
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
            _parent_capability=capability,
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
        principal_kind: str = "",
        parent_principal_id: str = "",
        session_id: str = "",
        delegation_digest: str = "",
        source_transport: str = "",
        delegation_resource: str = "",
    ) -> AuthorityEnvelope:
        """Create one broker-owned context for a later capability issue."""
        try:
            context = {
                "principal_id": principal_id,
                "project_id": project_id,
                "runtime_id": runtime_id,
                "task_id": task_id,
                "workspace_id": workspace_id,
                "workspace_generation": workspace_generation,
                "policy_digest": policy_digest,
                "operation_class": operation_class,
                "resource_digest": resource_digest,
                "authorization_epoch": authorization_epoch,
                "principal_kind": principal_kind,
                "parent_principal_id": parent_principal_id,
                "session_id": session_id,
                "delegation_digest": delegation_digest,
                "source_transport": source_transport,
                "delegation_resource": delegation_resource,
            }
            # The broker process, rather than the Python object, generates
            # and owns the opaque live grant id.
            provisional = AuthorityEnvelope._from_broker(
                broker=self,
                grant_id="provisional-grant",
                grant_expires_at=time.time() + _DEFAULT_GRANT_TTL_SECONDS,
                **context,
            )
            response = self._call(
                {
                    "operation": "grant",
                    "context_digest": provisional.context_digest(),
                    "principal_id": principal_id,
                    "project_id": project_id,
                    "runtime_id": runtime_id,
                    "task_id": task_id,
                    "workspace_id": workspace_id,
                    "generation": workspace_generation,
                    "policy_digest": policy_digest,
                    "operation_class": operation_class,
                    "resource_digest": resource_digest,
                    "authorization_epoch": authorization_epoch,
                    "principal_kind": principal_kind,
                    "parent_principal_id": parent_principal_id,
                    "session_id": session_id,
                    "delegation_digest": delegation_digest,
                    "source_transport": source_transport,
                    "delegation_resource": delegation_resource,
                    "ttl_seconds": _DEFAULT_GRANT_TTL_SECONDS,
                }
            )
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
                grant_id=str(response["grant_id"]),
                grant_expires_at=float(response["expires_at"]),
                principal_kind=principal_kind,
                parent_principal_id=parent_principal_id,
                session_id=session_id,
                delegation_digest=delegation_digest,
                source_transport=source_transport,
                delegation_resource=delegation_resource,
            )
        except (KeyError, TypeError, ValueError, AuthorityBrokerError) as exc:
            raise AuthorityBrokerError("authority envelope is invalid") from exc

    def revoke_grant(self, authority: AuthorityEnvelope) -> None:
        """Revoke the live grant so stale envelope objects cannot mint again."""
        if not isinstance(authority, AuthorityEnvelope) or authority._broker is not self:
            raise AuthorityBrokerError("authority grant was not created by this broker")
        self._call({"operation": "revoke_grant", "grant_id": authority.grant_id})

    def rotate_authorization_epoch(
        self,
        *,
        principal_id: str,
        project_id: str,
        workspace_id: str,
        authorization_epoch: int,
    ) -> None:
        if authorization_epoch < 0:
            raise AuthorityBrokerError("authorization epoch is invalid")
        self._call(
            {
                "operation": "rotate_authorization_epoch",
                "principal_id": principal_id,
                "project_id": project_id,
                "workspace_id": workspace_id,
                "authorization_epoch": authorization_epoch,
            }
        )

    def rotate_workspace_generation(
        self,
        *,
        principal_id: str,
        project_id: str,
        workspace_id: str,
        workspace_generation: int,
    ) -> None:
        if workspace_generation <= 0:
            raise AuthorityBrokerError("workspace generation is invalid")
        self._call(
            {
                "operation": "rotate_workspace_generation",
                "principal_id": principal_id,
                "project_id": project_id,
                "workspace_id": workspace_id,
                "workspace_generation": workspace_generation,
            }
        )

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
                "grant_id": capability.authority.grant_id,
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

    def claim(self, capability: EffectCapability) -> None:
        """Reserve a local effect immediately before it starts."""
        self.validate(
            capability,
            expected_operation=capability.authority.operation_class,
            expected_resource_digest=capability.resource_digest,
        )

    def complete(
        self,
        capability: EffectCapability,
        *,
        result: str,
        result_digest: str,
    ) -> None:
        if result not in {"success", "failed", "unknown"} or not result_digest:
            raise AuthorityBrokerError("invalid local effect result")
        self._call(
            {
                "operation": "complete",
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
                "grant_id": capability.authority.grant_id,
                "operation_class": capability.authority.operation_class,
            }
        )

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


class AuthorityDaemonBroker(AuthorityBroker):
    """AuthorityBroker-compatible client backed by independent authorityd."""

    def __init__(self, client: AuthorityDaemonClient) -> None:
        self._authorityd = client
        self._connection = None
        self._process = None
        self._lock = threading.RLock()
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

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
        principal_kind: str = "",
        parent_principal_id: str = "",
        session_id: str = "",
        delegation_digest: str = "",
        source_transport: str = "",
        delegation_resource: str = "",
    ) -> AuthorityEnvelope:
        grant = getattr(self._authorityd, "grant", None)
        if callable(grant):
            grant_id, grant_expires_at = grant(
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
                principal_kind=principal_kind,
                parent_principal_id=parent_principal_id,
                session_id=session_id,
                delegation_digest=delegation_digest,
                source_transport=source_transport,
                delegation_resource=delegation_resource,
            )
        else:
            # Protocol test doubles predating live grants remain usable only
            # outside the production authorityd client. Real authorityd
            # clients always expose the grant registration operation.
            grant_id = f"legacy-{secrets.token_hex(16)}"
            grant_expires_at = time.time() + _DEFAULT_GRANT_TTL_SECONDS
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
                grant_id=grant_id,
                grant_expires_at=grant_expires_at,
                principal_kind=principal_kind,
                parent_principal_id=parent_principal_id,
                session_id=session_id,
                delegation_digest=delegation_digest,
                source_transport=source_transport,
                delegation_resource=delegation_resource,
            )
        except (TypeError, ValueError) as exc:
            raise AuthorityBrokerError("authority envelope is invalid") from exc

    def revoke_grant(self, authority: AuthorityEnvelope) -> None:
        if not isinstance(authority, AuthorityEnvelope) or authority._broker is not self:
            raise AuthorityBrokerError("authority grant was not created by this broker")
        try:
            revoke = getattr(self._authorityd, "revoke_grant", None)
            if not callable(revoke):
                raise AuthorityBrokerError(
                    "production authorityd client does not support grant revocation"
                )
            revoke(authority.grant_id)
        except AuthorityControlPlaneError as exc:
            raise AuthorityBrokerError(str(exc)) from exc

    def rotate_authorization_epoch(
        self,
        *,
        principal_id: str,
        project_id: str,
        workspace_id: str,
        authorization_epoch: int,
    ) -> None:
        try:
            rotate = getattr(self._authorityd, "rotate_authorization_epoch", None)
            if not callable(rotate):
                raise AuthorityBrokerError(
                    "production authorityd client does not support epoch rotation"
                )
            rotate(
                principal_id=principal_id,
                project_id=project_id,
                workspace_id=workspace_id,
                authorization_epoch=authorization_epoch,
            )
        except AuthorityControlPlaneError as exc:
            raise AuthorityBrokerError(str(exc)) from exc

    def rotate_workspace_generation(
        self,
        *,
        principal_id: str,
        project_id: str,
        workspace_id: str,
        workspace_generation: int,
    ) -> None:
        try:
            rotate = getattr(self._authorityd, "rotate_workspace_generation", None)
            if not callable(rotate):
                raise AuthorityBrokerError(
                    "production authorityd client does not support workspace generation rotation"
                )
            rotate(
                principal_id=principal_id,
                project_id=project_id,
                workspace_id=workspace_id,
                workspace_generation=workspace_generation,
            )
        except AuthorityControlPlaneError as exc:
            raise AuthorityBrokerError(str(exc)) from exc

    def issue(
        self,
        authority: AuthorityEnvelope,
        *,
        allowed_operation: str | None = None,
        resource_digest: str | None = None,
        ttl_seconds: float = _DEFAULT_TTL_SECONDS,
    ) -> EffectCapability:
        if not isinstance(authority, AuthorityEnvelope) or authority._broker is not self:
            raise AuthorityBrokerError("authority envelope was not created by this broker")
        operation = allowed_operation or authority.operation_class
        resource = resource_digest or authority.resource_digest
        if (
            not _valid_operation(operation)
            or not _operation_allowed(operation, authority.operation_class)
            or resource != authority.resource_digest
        ):
            raise AuthorityBrokerError("invalid daemon authority request")
        if not 0 < ttl_seconds <= _MAX_TTL_SECONDS:
            raise AuthorityBrokerError("capability TTL is outside the allowed range")
        intent = AuthorizationIntent(
            principal_id=authority.principal_id,
            project_id=authority.project_id,
            runtime_id=authority.runtime_id,
            task_id=authority.task_id,
            workspace_id=authority.workspace_id,
            # The signed receipt carries the exact operation admitted at this
            # boundary.  ``allowed_operation`` remains a caller-side family
            # label (for example ``git.*``), but a native helper must never
            # validate a wildcard receipt against a concrete operation.
            operation=authority.operation_class,
            resource_digest=resource,
            policy_digest=authority.policy_digest,
            nonce=secrets.token_hex(16),
            authorization_epoch=authority.authorization_epoch,
            workspace_generation=authority.workspace_generation,
            grant_id=authority.grant_id,
            grant_context_digest=authority.context_digest(),
            principal_kind=authority.principal_kind,
            parent_principal_id=authority.parent_principal_id,
            session_id=authority.session_id,
            delegation_digest=authority.delegation_digest,
            source_transport=authority.source_transport,
            delegation_resource=authority.delegation_resource,
        )
        try:
            receipt = self._authorityd.prepare(intent)
        except AuthorityControlPlaneError as exc:
            raise AuthorityBrokerError(str(exc)) from exc
        return EffectCapability._from_broker(
            authority=authority,
            allowed_operation=operation,
            resource_digest=resource,
            generation=authority.workspace_generation,
            authorization_epoch=authority.authorization_epoch,
            issued_at=receipt.issued_at,
            expires_at=receipt.expires_at,
            nonce=receipt.nonce,
            token=receipt.nonce,
            seal=receipt.signature,
            receipt=receipt,
        )

    def reissue(
        self,
        capability: EffectCapability,
        *,
        operation_class: str,
        resource_digest: str,
        ttl_seconds: float = _DEFAULT_TTL_SECONDS,
    ) -> EffectCapability:
        if capability.receipt is None:
            raise AuthorityBrokerError("daemon reissue requires a signed receipt")
        if not _valid_operation(operation_class) or not resource_digest:
            raise AuthorityBrokerError("invalid daemon reissue authority")
        self.validate(
            capability,
            expected_operation=capability.receipt.operation,
        )
        try:
            receipt = self._authorityd.narrow(
                capability.receipt,
                operation=operation_class,
                resource_digest=resource_digest,
            )
        except AuthorityControlPlaneError as exc:
            raise AuthorityBrokerError(str(exc)) from exc
        signed_resource = receipt.resource_digest
        authority = capability.authority.derive(
            operation_class=operation_class,
            resource_digest=signed_resource,
        )
        return EffectCapability._from_broker(
            authority=authority,
            allowed_operation=operation_class,
            resource_digest=signed_resource,
            generation=authority.workspace_generation,
            authorization_epoch=authority.authorization_epoch,
            issued_at=receipt.issued_at,
            expires_at=receipt.expires_at,
            nonce=receipt.nonce,
            token=receipt.nonce,
            seal=receipt.signature,
            receipt=receipt,
        )

    def validate(
        self,
        capability: EffectCapability,
        *,
        expected_operation: str | None = None,
        expected_resource_digest: str | None = None,
    ) -> None:
        if not isinstance(capability, EffectCapability) or capability.receipt is None:
            raise AuthorityBrokerError("effect boundary requires a signed receipt")
        try:
            capability._validate_shape()
            self._authorityd.validate(
                capability.receipt,
                expected_operation=expected_operation or capability.authority.operation_class,
                expected_resource_digest=expected_resource_digest,
            )
        except (AuthorityControlPlaneError, TypeError, ValueError) as exc:
            raise AuthorityBrokerError(str(exc)) from exc

    def claim(self, capability: EffectCapability) -> None:
        if not isinstance(capability, EffectCapability) or capability.receipt is None:
            raise AuthorityBrokerError("effect claim requires a signed receipt")
        try:
            claim = getattr(self._authorityd, "claim", None)
            if callable(claim):
                claim(capability.receipt)
            else:
                # Compatibility for protocol test doubles from before the
                # explicit claim transition existed.
                self._authorityd.validate(
                    capability.receipt,
                    expected_operation=capability.receipt.operation,
                    expected_resource_digest=capability.resource_digest,
                )
        except (AuthorityControlPlaneError, TypeError, ValueError) as exc:
            raise AuthorityBrokerError(str(exc)) from exc

    def revoke(self, capability: EffectCapability) -> None:
        if not isinstance(capability, EffectCapability) or capability.receipt is None:
            raise AuthorityBrokerError("cannot revoke a non-receipt capability")
        try:
            self._authorityd.revoke(capability.receipt)
        except AuthorityControlPlaneError as exc:
            raise AuthorityBrokerError(str(exc)) from exc

    def complete(
        self,
        capability: EffectCapability,
        *,
        result: str,
        result_digest: str,
    ) -> None:
        """Commit the native execution result through the external authority."""
        if not isinstance(capability, EffectCapability) or capability.receipt is None:
            raise AuthorityBrokerError("execution result requires a signed receipt")
        try:
            self._authorityd.complete(
                capability.receipt,
                result=result,
                result_digest=result_digest,
            )
        except AuthorityControlPlaneError as exc:
            raise AuthorityBrokerError(str(exc)) from exc

    def close(self) -> None:
        self._closed = True


def _valid_operation(operation: str) -> bool:
    return (
        isinstance(operation, str)
        and 1 <= len(operation) <= 256
        and "." in operation
        and all(character.isalnum() or character in "._:-*" for character in operation)
        and operation.count("*") <= 1
        and ("*" not in operation or operation.endswith("*"))
    )


__all__ = [
    "AuthorityBroker",
    "AuthorityBrokerError",
    "AuthorityDaemonBroker",
    "EffectCapability",
]
