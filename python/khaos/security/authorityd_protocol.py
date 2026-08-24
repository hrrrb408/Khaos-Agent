"""Fail-closed protocol for the independent ``khaos-authorityd`` service.

The Python agent is a client of this protocol in production.  The authority
daemon owns the signing key, policy decision, and two-phase audit commit.  A
local SQLite database or JSONL file may be retained as a diagnostic mirror,
but it is never accepted as the production audit authority.
"""

from __future__ import annotations

import base64
import json
import math
import os
import socket
import stat
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from khaos.security.identity_isolation import (
    IdentityIsolationError,
    validate_private_unix_socket,
)
from khaos.security.local_trust import (
    LocalTrustRootError,
    local_authority_root,
    validate_trusted_local_path,
)
from khaos.security.principals import DelegationScope, PrincipalKind
from khaos.security.protocol_boundary import canonical_digest, canonical_json_bytes

AUTHORITYD_PROTOCOL = 1
MAX_MESSAGE_BYTES = 1024 * 1024

# Windows os.open defaults to CRT text mode when neither O_BINARY nor O_TEXT
# is passed: 0x1A acts as EOF (truncating ~12% of random 32-byte Ed25519
# public keys) and CRLF pairs are collapsed.  Key material is binary — every
# descriptor the keystore opens must force binary mode.  POSIX has no
# O_BINARY; the getattr keeps those platforms unchanged.
_O_BINARY = getattr(os, "O_BINARY", 0)
MAX_TTL_SECONDS = 300.0
MAX_GRANT_TTL_SECONDS = 24 * 60 * 60.0
# Receipt timestamps are part of the signed wire payload. JSON floating-point
# spellings are not stable across Python and Rust serializers, so the wire
# contract uses exact, non-negative integer milliseconds while the Python API
# continues to expose seconds as floats.
AUTHORITY_TIMESTAMP_SCALE = 1000
MAX_WIRE_TIMESTAMP = (1 << 53) - 1


class AuthorityControlPlaneError(PermissionError):
    """Base error for unavailable, malformed, or rejected authority control."""


class RemoteAuditUnavailableError(AuthorityControlPlaneError):
    """The external audit writer did not durably accept a lifecycle event."""


class UnknownExecutionError(AuthorityControlPlaneError):
    """Execution completed or may have completed but result commit failed."""


class AuditWriter(Protocol):
    """External append-only audit sink contract."""

    def append(self, record: dict[str, Any]) -> None:
        """Durably append one prepare/result record or raise."""


class NativeAuthorityAdapter(Protocol):
    """Minimal request surface implemented by platform-native clients."""

    def request(self, payload: dict[str, object]) -> dict[str, object]:
        """Send one signed request through the platform frontend."""
        ...


def _encode_receipt_timestamp(value: object, *, field: str) -> int:
    """Encode a receipt timestamp into the cross-language wire contract."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise AuthorityControlPlaneError(f"authorization receipt {field} is invalid")
    numeric = float(value)
    if not math.isfinite(numeric) or numeric < 0:
        raise AuthorityControlPlaneError(f"authorization receipt {field} is invalid")
    try:
        encoded = round(numeric * AUTHORITY_TIMESTAMP_SCALE)
    except (OverflowError, ValueError) as exc:
        raise AuthorityControlPlaneError(
            f"authorization receipt {field} is invalid"
        ) from exc
    if encoded < 0 or encoded > MAX_WIRE_TIMESTAMP:
        raise AuthorityControlPlaneError(f"authorization receipt {field} is invalid")
    return encoded


def _decode_receipt_timestamp(value: object, *, field: str) -> float:
    """Decode the exact integer timestamp representation from the wire."""
    if type(value) is not int or value < 0 or value > MAX_WIRE_TIMESTAMP:
        raise AuthorityControlPlaneError(f"authorization receipt {field} is invalid")
    return value / AUTHORITY_TIMESTAMP_SCALE


def derive_resource_digest(
    parent_digest: str, operation: str, requested_scope: str
) -> str:
    """Bind a narrowed resource to its parent and typed operation.

    ``resource_digest`` is intentionally opaque at the native boundary.  A
    narrowing request therefore carries the requested scope into a new
    digest; the authority daemon, rather than the client, decides the parent
    relation and signs the resulting child resource.  Replacing a resource
    with an unrelated digest is no longer an accepted narrowing operation.
    """

    _required_text("parent_resource_digest", parent_digest)
    _required_text("operation", operation)
    _required_text("requested_resource_scope", requested_scope)
    return canonical_digest(
        {
            "schema_version": 1,
            "kind": "authority-resource-subset-v1",
            "parent_resource_digest": parent_digest,
            "operation": operation,
            "requested_resource_scope": requested_scope,
        }
    )


def _required_text(name: str, value: object, *, max_length: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value) > max_length:
        raise AuthorityControlPlaneError(f"{name} is invalid")
    if "\x00" in value:
        raise AuthorityControlPlaneError(f"{name} contains NUL")
    return value


def _validate_typed_principal_binding(
    *,
    principal_kind: str,
    parent_principal_id: str,
    session_id: str,
    delegation_digest: str,
) -> bool:
    """Validate the optional M6.4 identity binding as one atomic tuple.

    Legacy protocol fixtures may omit the tuple.  Once any member is present,
    accepting a partial tuple would make the omitted field an unbound replay
    dimension, so the wire contract requires all four fields together.
    Production ``AuthorityDaemon`` instances enable the stricter requirement.
    """
    values = (
        principal_kind,
        parent_principal_id,
        session_id,
        delegation_digest,
    )
    if not any(values):
        return False
    if not all(values):
        raise AuthorityControlPlaneError(
            "typed principal binding must include kind, parent, session, and delegation"
        )
    try:
        PrincipalKind(principal_kind)
    except ValueError as exc:
        raise AuthorityControlPlaneError("principal_kind is invalid") from exc
    _required_text("parent_principal_id", parent_principal_id)
    _required_text("session_id", session_id)
    if (
        len(delegation_digest) != 64
        or any(character not in "0123456789abcdef" for character in delegation_digest)
    ):
        raise AuthorityControlPlaneError("delegation_digest is invalid")
    return True


@dataclass(frozen=True, slots=True)
class AuthorizationIntent:
    """Immutable, canonical prepare request sent to the authority daemon."""

    principal_id: str
    project_id: str
    runtime_id: str
    task_id: str
    workspace_id: str
    operation: str
    resource_digest: str
    policy_digest: str
    nonce: str
    authorization_epoch: int
    schema_version: int = 1
    workspace_generation: int | None = None
    grant_id: str | None = None
    grant_context_digest: str | None = None
    principal_kind: str = ""
    parent_principal_id: str = ""
    session_id: str = ""
    delegation_digest: str = ""
    source_transport: str = ""
    delegation_resource: str = ""

    def __post_init__(self) -> None:
        for name in (
            "principal_id",
            "project_id",
            "runtime_id",
            "task_id",
            "workspace_id",
            "operation",
            "resource_digest",
            "policy_digest",
            "nonce",
        ):
            _required_text(name, getattr(self, name))
        if type(self.schema_version) is not int or self.schema_version != 1:
            raise AuthorityControlPlaneError(
                "unsupported authorization intent schema"
            )
        if self.authorization_epoch < 0:
            raise AuthorityControlPlaneError("authorization_epoch is invalid")
        if self.workspace_generation is not None and self.workspace_generation <= 0:
            raise AuthorityControlPlaneError("workspace_generation is invalid")
        if (self.grant_id is None) != (self.grant_context_digest is None):
            raise AuthorityControlPlaneError(
                "grant_id and grant_context_digest must be supplied together"
            )
        if self.grant_id is not None:
            _required_text("grant_id", self.grant_id, max_length=128)
            _required_text(
                "grant_context_digest", self.grant_context_digest, max_length=128
            )
        _validate_typed_principal_binding(
            principal_kind=self.principal_kind,
            parent_principal_id=self.parent_principal_id,
            session_id=self.session_id,
            delegation_digest=self.delegation_digest,
        )
        for name, value in (
            ("source_transport", self.source_transport),
            ("delegation_resource", self.delegation_resource),
        ):
            if not isinstance(value, str) or len(value) > 256:
                raise AuthorityControlPlaneError(f"{name} is invalid")

    def payload(self) -> dict[str, object]:
        payload = {
            "schema_version": self.schema_version,
            "principal_id": self.principal_id,
            "project_id": self.project_id,
            "runtime_id": self.runtime_id,
            "task_id": self.task_id,
            "workspace_id": self.workspace_id,
            "operation": self.operation,
            "resource_digest": self.resource_digest,
            "policy_digest": self.policy_digest,
            "nonce": self.nonce,
            "authorization_epoch": self.authorization_epoch,
        }
        if self.source_transport:
            payload["source_transport"] = self.source_transport
        if self.delegation_resource:
            payload["delegation_resource"] = self.delegation_resource
        if self.grant_id is not None:
            payload["grant_id"] = self.grant_id
            payload["grant_context_digest"] = self.grant_context_digest
        if self.workspace_generation is not None:
            payload["workspace_generation"] = self.workspace_generation
        if self.principal_kind:
            payload["principal_kind"] = self.principal_kind
            payload["parent_principal_id"] = self.parent_principal_id
            payload["session_id"] = self.session_id
            payload["delegation_digest"] = self.delegation_digest
        return payload

    @property
    def digest(self) -> str:
        return canonical_digest(self.payload())


@dataclass(frozen=True, slots=True)
class SignedAuthorizationReceipt:
    """Ed25519-signed authorization accepted by native execution helpers."""

    principal_id: str
    project_id: str
    runtime_id: str
    task_id: str
    workspace_id: str
    operation: str
    resource_digest: str
    policy_digest: str
    nonce: str
    authorization_epoch: int
    expires_at: float
    audit_intent_digest: str
    issuer_id: str
    issued_at: float
    signature: str
    schema_version: int = 1
    algorithm: str = "Ed25519"
    workspace_generation: int | None = None
    grant_id: str | None = None
    grant_context_digest: str | None = None
    principal_kind: str = ""
    parent_principal_id: str = ""
    session_id: str = ""
    delegation_digest: str = ""
    source_transport: str = ""
    delegation_resource: str = ""

    def __post_init__(self) -> None:
        for name in (
            "principal_id",
            "project_id",
            "runtime_id",
            "task_id",
            "workspace_id",
            "operation",
            "resource_digest",
            "policy_digest",
            "nonce",
            "audit_intent_digest",
            "issuer_id",
            "signature",
        ):
            _required_text(name, getattr(self, name))
        if self.schema_version != 1 or self.algorithm != "Ed25519":
            raise AuthorityControlPlaneError("unsupported authorization receipt")
        if self.expires_at <= self.issued_at:
            raise AuthorityControlPlaneError("authorization receipt expiry is invalid")
        if not math.isfinite(self.issued_at) or not math.isfinite(self.expires_at):
            raise AuthorityControlPlaneError("authorization receipt timestamps are invalid")
        _encode_receipt_timestamp(self.issued_at, field="issued_at")
        _encode_receipt_timestamp(self.expires_at, field="expires_at")
        if self.expires_at - self.issued_at > MAX_TTL_SECONDS:
            raise AuthorityControlPlaneError("authorization receipt TTL is too long")
        if self.authorization_epoch < 0:
            raise AuthorityControlPlaneError("authorization_epoch is invalid")
        if self.workspace_generation is not None and self.workspace_generation <= 0:
            raise AuthorityControlPlaneError("workspace_generation is invalid")
        if (self.grant_id is None) != (self.grant_context_digest is None):
            raise AuthorityControlPlaneError(
                "receipt grant_id and grant_context_digest must be supplied together"
            )
        if self.grant_id is not None:
            _required_text("grant_id", self.grant_id, max_length=128)
            _required_text(
                "grant_context_digest", self.grant_context_digest, max_length=128
            )
        _validate_typed_principal_binding(
            principal_kind=self.principal_kind,
            parent_principal_id=self.parent_principal_id,
            session_id=self.session_id,
            delegation_digest=self.delegation_digest,
        )
        for name, value in (
            ("source_transport", self.source_transport),
            ("delegation_resource", self.delegation_resource),
        ):
            if not isinstance(value, str) or len(value) > 256:
                raise AuthorityControlPlaneError(f"{name} is invalid")

    def unsigned_payload(self) -> dict[str, object]:
        payload = {
            "schema_version": self.schema_version,
            "algorithm": self.algorithm,
            "principal_id": self.principal_id,
            "project_id": self.project_id,
            "runtime_id": self.runtime_id,
            "task_id": self.task_id,
            "workspace_id": self.workspace_id,
            "operation": self.operation,
            "resource_digest": self.resource_digest,
            "policy_digest": self.policy_digest,
            "nonce": self.nonce,
            "authorization_epoch": self.authorization_epoch,
            "expires_at": _encode_receipt_timestamp(
                self.expires_at, field="expires_at"
            ),
            "audit_intent_digest": self.audit_intent_digest,
            "issuer_id": self.issuer_id,
            "issued_at": _encode_receipt_timestamp(
                self.issued_at, field="issued_at"
            ),
        }
        if self.source_transport:
            payload["source_transport"] = self.source_transport
        if self.delegation_resource:
            payload["delegation_resource"] = self.delegation_resource
        if self.grant_id is not None:
            payload["grant_id"] = self.grant_id
            payload["grant_context_digest"] = self.grant_context_digest
        if self.workspace_generation is not None:
            payload["workspace_generation"] = self.workspace_generation
        if self.principal_kind:
            payload["principal_kind"] = self.principal_kind
            payload["parent_principal_id"] = self.parent_principal_id
            payload["session_id"] = self.session_id
            payload["delegation_digest"] = self.delegation_digest
        return payload

    @property
    def digest(self) -> str:
        return canonical_digest({**self.unsigned_payload(), "signature": self.signature})

    def to_dict(self) -> dict[str, object]:
        return {**self.unsigned_payload(), "signature": self.signature}

    @classmethod
    def from_dict(cls, value: object) -> SignedAuthorizationReceipt:
        if not isinstance(value, dict):
            raise AuthorityControlPlaneError("authorization receipt is not a mapping")
        try:
            return cls(
                principal_id=str(value["principal_id"]),
                project_id=str(value["project_id"]),
                runtime_id=str(value["runtime_id"]),
                task_id=str(value["task_id"]),
                workspace_id=str(value["workspace_id"]),
                operation=str(value["operation"]),
                resource_digest=str(value["resource_digest"]),
                policy_digest=str(value["policy_digest"]),
                nonce=str(value["nonce"]),
                authorization_epoch=int(value["authorization_epoch"]),
                expires_at=_decode_receipt_timestamp(
                    value["expires_at"], field="expires_at"
                ),
                audit_intent_digest=str(value["audit_intent_digest"]),
                issuer_id=str(value["issuer_id"]),
                issued_at=_decode_receipt_timestamp(
                    value["issued_at"], field="issued_at"
                ),
                signature=str(value["signature"]),
                schema_version=int(value.get("schema_version", 1)),
                algorithm=str(value.get("algorithm", "Ed25519")),
                workspace_generation=(
                    int(value["workspace_generation"])
                    if value.get("workspace_generation") is not None
                    else None
                ),
                grant_id=(
                    str(value["grant_id"])
                    if value.get("grant_id") is not None
                    else None
                ),
                grant_context_digest=(
                    str(value["grant_context_digest"])
                    if value.get("grant_context_digest") is not None
                    else None
                ),
                principal_kind=str(value.get("principal_kind", "")),
                parent_principal_id=str(value.get("parent_principal_id", "")),
                session_id=str(value.get("session_id", "")),
                delegation_digest=str(value.get("delegation_digest", "")),
                source_transport=str(value.get("source_transport", "")),
                delegation_resource=str(value.get("delegation_resource", "")),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise AuthorityControlPlaneError(
                "authorization receipt fields are malformed"
            ) from exc

    def verify_signature(self, public_key: Ed25519PublicKey) -> None:
        """Verify authenticity without applying the launch-time expiry gate."""
        try:
            signature = base64.b64decode(self.signature.encode("ascii"), validate=True)
            public_key.verify(signature, canonical_json_bytes(self.unsigned_payload()))
        except (InvalidSignature, ValueError, UnicodeError) as exc:
            raise AuthorityControlPlaneError("authorization receipt signature is invalid") from exc

    def verify(
        self, public_key: Ed25519PublicKey, *, now: float | None = None
    ) -> None:
        """Verify a receipt that is still eligible to start a new effect."""
        current = time.time() if now is None else now
        if current >= self.expires_at:
            raise AuthorityControlPlaneError("authorization receipt has expired")
        self.verify_signature(public_key)


class Ed25519KeyStore:
    """Load or create a daemon-owned Ed25519 private key with safe permissions."""

    @staticmethod
    def load_public_key(path: Path) -> Ed25519PublicKey:
        """Load the deployment trust anchor without following a symlink."""
        path = path.expanduser().absolute()
        try:
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise AuthorityControlPlaneError(
                    "authority public key is not a regular single-link file"
                )
            # Group/other bits are the POSIX leak signal.  Windows ``stat``
            # synthesizes them from the read-only attribute (every writable
            # file reads as 0666), so they carry no ACL information there;
            # the Windows key confinement is the service-account NTFS ACL.
            if os.name == "posix" and info.st_mode & 0o022:
                raise AuthorityControlPlaneError(
                    "authority public key has unsafe permissions"
                )
            descriptor = os.open(
                path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | _O_BINARY
            )
            try:
                payload = _read_descriptor(descriptor, 4096)
            finally:
                os.close(descriptor)
        except OSError as exc:
            raise AuthorityControlPlaneError(
                "authority public key is unavailable"
            ) from exc
        try:
            if len(payload) == 32:
                return Ed25519PublicKey.from_public_bytes(payload)
            key = serialization.load_pem_public_key(payload)
        except (ValueError, TypeError) as exc:
            raise AuthorityControlPlaneError(
                "authority public key is malformed"
            ) from exc
        if not isinstance(key, Ed25519PublicKey):
            raise AuthorityControlPlaneError("authority public key is not Ed25519")
        return key

    @staticmethod
    def load_or_create(path: Path, *, create: bool = False) -> Ed25519PrivateKey:
        path = path.expanduser().absolute()
        if path.exists():
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise AuthorityControlPlaneError(
                    "authority signing key is not a regular single-link file"
                )
            # See load_public_key: the group/other-bit leak signal exists
            # only on POSIX filesystems; Windows confines the signing key
            # with the service-account NTFS ACL instead.
            if os.name == "posix" and info.st_mode & 0o077:
                raise AuthorityControlPlaneError("authority signing key has unsafe permissions")
            descriptor = os.open(
                path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | _O_BINARY
            )
            try:
                key = serialization.load_pem_private_key(os.read(descriptor, 64 * 1024), password=None)
            finally:
                os.close(descriptor)
            if not isinstance(key, Ed25519PrivateKey):
                raise AuthorityControlPlaneError("authority signing key is not Ed25519")
            return key
        if not create:
            raise AuthorityControlPlaneError("authority signing key is unavailable")
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        key = Ed25519PrivateKey.generate()
        payload = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        descriptor = os.open(
            path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | _O_BINARY,
            0o600,
        )
        try:
            offset = 0
            while offset < len(payload):
                written = os.write(descriptor, payload[offset:])
                if written <= 0:
                    raise OSError("authority signing key write made no progress")
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return key


class AuthorityDaemonClient:
    """Synchronous UDS client used by Python control-plane callers."""

    def __init__(
        self,
        socket_path: Path | None = None,
        *,
        timeout_seconds: float = 3.0,
        expected_authority_uid: int | None = None,
        native_adapter: NativeAuthorityAdapter | None = None,
        transport: str | None = None,
        public_key_path: Path | None = None,
        trusted_local_root: Path | None = None,
    ) -> None:
        # The caller (normally AuthorityTransportConfig) selects the
        # transport.  For direct protocol tests, preserve the intuitive
        # shape: an injected adapter means native; a socket path means Unix.
        selected_transport = transport or (
            "native" if native_adapter is not None else "unix"
        )
        if selected_transport not in {"unix", "native"}:
            raise ValueError("authorityd transport is invalid")
        if selected_transport == "unix" and sys.platform.startswith(
            ("win", "cygwin", "msys")
        ):
            raise ValueError("Unix authority transport is not valid on Windows")
        if (
            (socket_path is None and native_adapter is None)
            or (socket_path is not None and not socket_path.is_absolute())
            or (selected_transport == "unix" and socket_path is None)
            or (selected_transport == "native" and socket_path is not None)
            or (selected_transport == "unix" and native_adapter is not None)
            or timeout_seconds <= 0
        ):
            raise ValueError("authorityd socket and timeout are invalid")
        if expected_authority_uid is not None and expected_authority_uid < 0:
            raise ValueError("authorityd UID is invalid")
        if public_key_path is not None and not public_key_path.is_absolute():
            raise ValueError("authorityd public key path must be absolute")
        if trusted_local_root is not None and not trusted_local_root.is_absolute():
            raise ValueError("authorityd trusted root must be absolute")
        if (
            trusted_local_root is not None
            and os.environ.get("KHAOS_DEV_MODE") != "1"
            and trusted_local_root != local_authority_root()
        ):
            raise ValueError(
                "production Community authorityd trusted root must be the system home root"
            )
        self.socket_path = socket_path
        self.timeout_seconds = timeout_seconds
        self.expected_authority_uid = expected_authority_uid
        self.native_adapter = native_adapter
        self.transport = selected_transport
        self.public_key_path = public_key_path
        self.trusted_local_root = trusted_local_root

    def _verify_receipt(self, value: object) -> SignedAuthorizationReceipt:
        """Parse and verify a receipt against the configured local trust anchor."""

        receipt = SignedAuthorizationReceipt.from_dict(value)
        if self.public_key_path is not None:
            try:
                if self.trusted_local_root is not None:
                    validate_trusted_local_path(
                        self.public_key_path,
                        kind="file",
                        root=self.trusted_local_root,
                    )
                public_key = Ed25519KeyStore.load_public_key(self.public_key_path)
                receipt.verify(public_key)
            except (AuthorityControlPlaneError, LocalTrustRootError) as exc:
                raise AuthorityControlPlaneError(
                    "authorityd receipt does not match the trusted local authority key"
                ) from exc
        return receipt

    def request(self, payload: dict[str, object]) -> dict[str, object]:
        body = canonical_json_bytes({"protocol": AUTHORITYD_PROTOCOL, **payload}) + b"\n"
        if len(body) > MAX_MESSAGE_BYTES:
            raise AuthorityControlPlaneError("authorityd request is too large")
        if self.transport == "native":
            try:
                adapter = self.native_adapter
                if adapter is None:
                    from khaos.security.native_authority import (
                        build_native_authority_adapter,
                    )

                    adapter = build_native_authority_adapter(production=True)
                response = adapter.request({"protocol": AUTHORITYD_PROTOCOL, **payload})
            except IdentityIsolationError as exc:
                raise AuthorityControlPlaneError(
                    "native authority transport identity is invalid"
                ) from exc
            except OSError as exc:
                raise RemoteAuditUnavailableError("native authorityd is unavailable") from exc
            if not isinstance(response, dict) or response.get("ok") is not True:
                if isinstance(response, dict):
                    message = str(response.get("error", "native authorityd rejected request"))
                    if response.get("error_code") == "remote_audit_unavailable":
                        raise RemoteAuditUnavailableError(message)
                    raise AuthorityControlPlaneError(message)
                raise AuthorityControlPlaneError("native authorityd returned an invalid response")
            return response
        try:
            if self.socket_path is None:
                raise AuthorityControlPlaneError(
                    "authorityd Unix transport has no socket path"
                )
            if self.trusted_local_root is not None:
                try:
                    validate_trusted_local_path(
                        self.socket_path,
                        kind="socket",
                        root=self.trusted_local_root,
                    )
                except LocalTrustRootError as exc:
                    raise AuthorityControlPlaneError(
                        "authorityd local socket is outside the trusted local root"
                    ) from exc
            validate_private_unix_socket(
                self.socket_path,
                expected_uid=self.expected_authority_uid,
                require_private=self.trusted_local_root is not None,
            )
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(self.timeout_seconds)
                connection.connect(str(self.socket_path))
                connection.sendall(body)
                response = _recv_line(connection)
        except IdentityIsolationError as exc:
            raise AuthorityControlPlaneError(
                "authorityd transport identity is invalid"
            ) from exc
        except (OSError, TimeoutError) as exc:
            raise RemoteAuditUnavailableError("authorityd is unavailable") from exc
        try:
            decoded = json.loads(response.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise AuthorityControlPlaneError("authorityd returned malformed data") from exc
        if not isinstance(decoded, dict) or decoded.get("ok") is not True:
            if isinstance(decoded, dict):
                message = str(decoded.get("error", "authorityd rejected request"))
                if decoded.get("error_code") == "remote_audit_unavailable":
                    raise RemoteAuditUnavailableError(message)
                raise AuthorityControlPlaneError(message)
            raise AuthorityControlPlaneError("authorityd returned an invalid response")
        return decoded

    def prepare(self, intent: AuthorizationIntent) -> SignedAuthorizationReceipt:
        response = self.request({"operation": "prepare", "intent": intent.payload()})
        return self._verify_receipt(response.get("receipt"))

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
        source_transport: str = "",
        delegation_resource: str = "",
    ) -> tuple[str, float]:
        response = self.request(
            {
                "operation": "grant",
                "principal_id": _required_text("principal_id", principal_id),
                "project_id": _required_text("project_id", project_id),
                "runtime_id": _required_text("runtime_id", runtime_id),
                "task_id": _required_text("task_id", task_id),
                "workspace_id": _required_text("workspace_id", workspace_id),
                "workspace_generation": workspace_generation,
                "policy_digest": _required_text("policy_digest", policy_digest),
                "operation_class": _required_text("operation_class", operation_class),
                "resource_digest": _required_text("resource_digest", resource_digest),
                "authorization_epoch": authorization_epoch,
                "ttl_seconds": ttl_seconds,
                "principal_kind": principal_kind,
                "parent_principal_id": parent_principal_id,
                "session_id": session_id,
                "delegation_digest": delegation_digest,
                "source_transport": source_transport,
                "delegation_resource": delegation_resource,
            }
        )
        try:
            grant_value = response["grant_id"]
            expires_value = response["expires_at"]
            if not isinstance(expires_value, (int, float, str)):
                raise TypeError("authorityd grant expiry is not numeric")
            grant_id = str(grant_value)
            expires_at = float(expires_value)
        except (KeyError, TypeError, ValueError) as exc:
            raise AuthorityControlPlaneError("authorityd returned malformed grant") from exc
        return grant_id, expires_at

    def revoke_grant(self, grant_id: str) -> None:
        self.request(
            {
                "operation": "revoke_grant",
                "grant_id": _required_text("grant_id", grant_id, max_length=128),
            }
        )

    def rotate_authorization_epoch(
        self,
        *,
        principal_id: str,
        project_id: str,
        workspace_id: str,
        authorization_epoch: int,
    ) -> None:
        self.request(
            {
                "operation": "rotate_authorization_epoch",
                "principal_id": _required_text("principal_id", principal_id),
                "project_id": _required_text("project_id", project_id),
                "workspace_id": _required_text("workspace_id", workspace_id),
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
        """Invalidate grants bound to older workspace generations."""
        self.request(
            {
                "operation": "rotate_workspace_generation",
                "principal_id": _required_text("principal_id", principal_id),
                "project_id": _required_text("project_id", project_id),
                "workspace_id": _required_text("workspace_id", workspace_id),
                "workspace_generation": workspace_generation,
            }
        )

    def complete(
        self,
        receipt: SignedAuthorizationReceipt,
        *,
        result: str,
        result_digest: str,
    ) -> None:
        try:
            self.request(
                {
                    "operation": "complete",
                    "receipt": receipt.to_dict(),
                    "result": _required_text("result", result, max_length=64),
                    "result_digest": _required_text(
                        "result_digest", result_digest, max_length=256
                    ),
                }
            )
        except RemoteAuditUnavailableError as exc:
            raise UnknownExecutionError(
                "execution result could not be committed to authorityd"
            ) from exc

    def claim(self, receipt: SignedAuthorizationReceipt) -> None:
        """Claim a prepared receipt immediately before starting an effect."""
        self.request({"operation": "claim", "receipt": receipt.to_dict()})

    def validate(
        self,
        receipt: SignedAuthorizationReceipt,
        *,
        expected_operation: str | None = None,
        expected_resource_digest: str | None = None,
    ) -> None:
        self.request(
            {
                "operation": "validate",
                "receipt": receipt.to_dict(),
                "expected_operation": expected_operation,
                "expected_resource_digest": expected_resource_digest,
            }
        )

    def narrow(
        self,
        receipt: SignedAuthorizationReceipt,
        *,
        operation: str,
        resource_digest: str,
    ) -> SignedAuthorizationReceipt:
        response = self.request(
            {
                "operation": "narrow",
                "receipt": receipt.to_dict(),
                "operation_class": operation,
                "resource_digest": resource_digest,
            }
        )
        return self._verify_receipt(response.get("receipt"))

    def revoke(self, receipt: SignedAuthorizationReceipt) -> None:
        self.request({"operation": "revoke", "receipt": receipt.to_dict()})

    def delegation_register_root(self, scope: DelegationScope) -> str:
        """Register one ingress root delegation with the authority owner."""
        response = self.request(
            {"operation": "delegation_root", "scope": scope.canonical()}
        )
        return str(response["delegation_digest"])

    def delegation_issue_child(
        self,
        parent: DelegationScope,
        child_principal_id: str,
        child_principal_kind: str,
        *,
        operation_family: str,
        resource_scope: list[str],
        expires_at: float,
        session_id: str | None = None,
        runtime_id: str | None = None,
        task_id: str | None = None,
        workspace_id: str | None = None,
    ) -> DelegationScope:
        """Issue one narrow child delegation from a live parent scope."""
        response = self.request(
            {
                "operation": "delegation_child",
                "parent": parent.canonical(),
                "child_principal_id": child_principal_id,
                "child_principal_kind": child_principal_kind,
                "operation_family": operation_family,
                "resource_scope": resource_scope,
                "expires_at": expires_at,
                "session_id": session_id or "",
                "runtime_id": runtime_id or "",
                "task_id": task_id or "",
                "workspace_id": workspace_id or "",
            }
        )
        return DelegationScope.from_payload(response.get("delegation"))

    def delegation_consume(self, delegation: DelegationScope, **effect: str) -> None:
        """Consume exactly one child delegation at the effect boundary."""
        self.request(
            {
                "operation": "delegation_consume",
                "delegation": delegation.canonical(),
                **effect,
            }
        )

    def delegation_revoke(self, delegation: DelegationScope) -> None:
        self.request(
            {"operation": "delegation_revoke", "delegation": delegation.canonical()}
        )


@dataclass
class AuthorityReceiptFDs:
    """Already-open receipt and trust-anchor descriptors for native helpers."""

    receipt_file: BinaryIO
    public_key_file: BinaryIO

    @property
    def pass_fds(self) -> tuple[int, int]:
        return (self.receipt_file.fileno(), self.public_key_file.fileno())

    def close(self) -> None:
        self.receipt_file.close()
        self.public_key_file.close()


def open_authority_receipt_fds(
    receipt: SignedAuthorizationReceipt, public_key_path: Path
) -> AuthorityReceiptFDs:
    """Materialize only verified receipt bytes into private inherited FDs."""
    public_key = Ed25519KeyStore.load_public_key(public_key_path)
    receipt.verify(public_key)
    receipt_file = tempfile.TemporaryFile(  # noqa: SIM115 - ownership transfers to returned handles
        mode="w+b"
    )
    public_key_file = tempfile.TemporaryFile(  # noqa: SIM115 - ownership transfers to returned handles
        mode="w+b"
    )
    try:
        receipt_file.write(canonical_json_bytes(receipt.to_dict()))
        receipt_file.flush()
        receipt_file.seek(0)
        public_key_file.write(public_key.public_bytes_raw())
        public_key_file.flush()
        public_key_file.seek(0)
        return AuthorityReceiptFDs(receipt_file, public_key_file)
    except BaseException:
        receipt_file.close()
        public_key_file.close()
        raise


class ExecutionAuditControlPlane:
    """Two-phase execution wrapper with unknown/quarantine semantics."""

    def __init__(self, client: AuthorityDaemonClient) -> None:
        self.client = client

    def prepare(self, intent: AuthorizationIntent) -> SignedAuthorizationReceipt:
        return self.client.prepare(intent)

    def claim(self, receipt: SignedAuthorizationReceipt) -> None:
        """Record the authorize-then-launch transition."""
        self.client.claim(receipt)

    def complete(
        self,
        receipt: SignedAuthorizationReceipt,
        *,
        result: str,
        result_digest: str,
    ) -> None:
        self.client.complete(receipt, result=result, result_digest=result_digest)

    def commit_unknown(
        self, receipt: SignedAuthorizationReceipt, *, result_digest: str
    ) -> None:
        """Try to record ``unknown``; if the sink is down keep quarantine local."""
        self.client.complete(receipt, result="unknown", result_digest=result_digest)


def _recv_line(connection: socket.socket) -> bytes:
    chunks = bytearray()
    while len(chunks) < MAX_MESSAGE_BYTES:
        chunk = connection.recv(min(64 * 1024, MAX_MESSAGE_BYTES - len(chunks)))
        if not chunk:
            break
        newline = chunk.find(b"\n")
        if newline >= 0:
            chunks.extend(chunk[:newline])
            return bytes(chunks)
        chunks.extend(chunk)
    raise AuthorityControlPlaneError("authorityd response is too large or incomplete")


def _read_descriptor(descriptor: int, maximum: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while total <= maximum:
        chunk = os.read(descriptor, min(64 * 1024, maximum + 1 - total))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        total += len(chunk)
    raise AuthorityControlPlaneError("authority descriptor exceeds its bound")


__all__ = [
    "AUTHORITYD_PROTOCOL",
    "AuditWriter",
    "AuthorityControlPlaneError",
    "AuthorityDaemonClient",
    "AuthorityReceiptFDs",
    "AuthorizationIntent",
    "Ed25519KeyStore",
    "ExecutionAuditControlPlane",
    "NativeAuthorityAdapter",
    "RemoteAuditUnavailableError",
    "SignedAuthorizationReceipt",
    "UnknownExecutionError",
    "derive_resource_digest",
    "open_authority_receipt_fds",
]
