"""Authenticated Khaos RPC protocol primitives.

This module owns the wire contract that is shared by the Python server and
Gateway adapters.  It deliberately has no service or process-lifecycle
dependencies: protocol validation can be tested without constructing an
Agent runtime or opening a database.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
import socket
import struct
import sys
import time
from typing import Any

from khaos.security.protocol_boundary import canonical_json_bytes
from khaos.runtime_profile import RuntimeProfile, resolve_runtime_profile

RPC_MAX_REQUEST_BYTES = 1024 * 1024
RPC_AUTH_WINDOW_SECONDS = 30
RPC_PROTOCOL_VERSION = 2
RPC_PROTOCOL_MIN_VERSION = 2
RPC_PROTOCOL_MAX_VERSION = 2
RPC_SCHEMA_VERSION = 1
RPC_METHOD_SCHEMA_VERSION = 1
RPC_INITIALIZE_METHOD = "RPC.Initialize"
RPC_FEATURES = (
    "hmac-v2",
    "project-policy-claims",
    "method-schema-v1",
    "typed-error-codes",
    "unknown-fields-reject",
)
RPC_REQUIRED_SECURITY_FIELDS = (
    "principal_id",
    "payload_digest",
    "project_id",
    "policy_digest",
)
RPC_ERROR_CODES = (
    "invalid_json",
    "unauthenticated",
    "rpc_negotiation_required",
    "rpc_protocol_unsupported",
    "rpc_schema_unsupported",
    "rpc_feature_mismatch",
    "rpc_unknown_field",
    "rpc_claim_missing",
    "project_drift",
    "policy_drift",
    "unknown_method",
)


class RPCProtocolError(PermissionError):
    """Structured protocol error used during RPC envelope negotiation."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def rpc_binding_claim_error(
    payload: dict[str, Any],
    *,
    bound_project_id: str,
    bound_policy_digest: str,
    require_claims: bool,
) -> tuple[str, str] | None:
    """Return a stable error for missing or drifting deployment claims."""
    claimed_project_id = payload.get("project_id")
    claimed_policy_digest = payload.get("policy_digest")
    if require_claims:
        if not isinstance(claimed_project_id, str) or not claimed_project_id.strip():
            return (
                "rpc_claim_missing",
                "project_id claim is required for production RPC v2",
            )
        if not isinstance(claimed_policy_digest, str) or not claimed_policy_digest.strip():
            return (
                "rpc_claim_missing",
                "policy_digest claim is required for production RPC v2",
            )
    if claimed_project_id and claimed_project_id != bound_project_id:
        return (
            "project_drift",
            (f"payload project_id {claimed_project_id!r} does not match "
             f"server-bound project_id {bound_project_id!r}"),
        )
    if claimed_policy_digest and claimed_policy_digest != bound_policy_digest:
        return (
            "policy_drift",
            (f"payload policy_digest {claimed_policy_digest!r} does not match "
             f"server-bound policy_digest {bound_policy_digest!r}"),
        )
    return None


def rpc_feature_digest(features: list[str] | tuple[str, ...]) -> str:
    """Hash the canonical feature list that is bound into the HMAC."""
    canonical = canonical_json_bytes(sorted(features))
    return hashlib.sha256(canonical).hexdigest()


def rpc_protocol_metadata(
    request: dict[str, Any], *, require: bool,
) -> dict[str, Any] | None:
    """Validate negotiated protocol metadata on one request."""
    metadata = request.get("protocol")
    if metadata is None and not require:
        return None
    if not isinstance(metadata, dict):
        raise RPCProtocolError(
            "rpc_schema_unsupported",
            "RPC protocol metadata is required",
        )
    allowed = {
        "min_version", "max_version", "schema_version",
        "method_schema_version", "features", "feature_digest",
        "unknown_field_policy",
    }
    unknown = set(metadata) - allowed
    if unknown:
        raise RPCProtocolError(
            "rpc_unknown_field",
            "RPC protocol metadata contains unknown fields",
        )
    min_version = metadata.get("min_version")
    max_version = metadata.get("max_version")
    schema_version = metadata.get("schema_version")
    method_schema_version = metadata.get("method_schema_version")
    if any(
        type(value) is not int
        for value in (min_version, max_version, schema_version, method_schema_version)
    ):
        raise RPCProtocolError(
            "rpc_schema_unsupported",
            "RPC protocol versions must be integers",
        )
    if not (
        min_version <= RPC_PROTOCOL_VERSION <= max_version
        and min_version <= max_version
    ):
        raise RPCProtocolError(
            "rpc_protocol_unsupported",
            "RPC protocol version is outside the supported negotiation window",
        )
    if schema_version != RPC_SCHEMA_VERSION:
        raise RPCProtocolError(
            "rpc_schema_unsupported",
            "RPC envelope schema version is unsupported",
        )
    if method_schema_version != RPC_METHOD_SCHEMA_VERSION:
        raise RPCProtocolError(
            "rpc_schema_unsupported",
            "RPC method schema version is unsupported",
        )
    features = metadata.get("features")
    if (
        not isinstance(features, list)
        or any(type(feature) is not str for feature in features)
        or len(set(features)) != len(features)
    ):
        raise RPCProtocolError(
            "rpc_feature_mismatch",
            "RPC feature capability list is invalid",
        )
    feature_digest = metadata.get("feature_digest")
    if type(feature_digest) is not str or not hmac.compare_digest(
        feature_digest, rpc_feature_digest(features)
    ):
        raise RPCProtocolError(
            "rpc_feature_mismatch",
            "RPC feature capability digest is invalid",
        )
    if metadata.get("unknown_field_policy") != "reject":
        raise RPCProtocolError(
            "rpc_unknown_field",
            "RPC unknown-field policy must be reject",
        )
    missing = set(RPC_FEATURES) - set(features)
    if missing:
        raise RPCProtocolError(
            "rpc_feature_mismatch",
            "RPC client omitted required security features",
        )
    return metadata


def rpc_initialize_response(payload: dict[str, Any]) -> dict[str, Any]:
    """Validate an initialize payload and return the selected contract."""
    allowed = {
        "min_protocol_version", "max_protocol_version", "schema_version",
        "method_schema_version", "features", "project_id", "policy_digest",
    }
    unknown = set(payload) - allowed
    if unknown:
        raise RPCProtocolError(
            "rpc_unknown_field",
            "RPC initialize payload contains unknown fields",
        )
    min_version = payload.get("min_protocol_version")
    max_version = payload.get("max_protocol_version")
    schema_version = payload.get("schema_version")
    method_schema_version = payload.get("method_schema_version")
    if any(
        type(value) is not int
        for value in (min_version, max_version, schema_version, method_schema_version)
    ):
        raise RPCProtocolError(
            "rpc_schema_unsupported",
            "RPC initialize versions must be integers",
        )
    if not (
        min_version <= RPC_PROTOCOL_VERSION <= max_version
        and min_version <= max_version
    ):
        raise RPCProtocolError(
            "rpc_protocol_unsupported",
            "RPC initialize version range is unsupported",
        )
    if schema_version != RPC_SCHEMA_VERSION:
        raise RPCProtocolError(
            "rpc_schema_unsupported",
            "RPC initialize schema version is unsupported",
        )
    if method_schema_version != RPC_METHOD_SCHEMA_VERSION:
        raise RPCProtocolError(
            "rpc_schema_unsupported",
            "RPC initialize method schema version is unsupported",
        )
    features = payload.get("features")
    if (
        not isinstance(features, list)
        or any(type(feature) is not str for feature in features)
        or len(set(features)) != len(features)
    ):
        raise RPCProtocolError(
            "rpc_feature_mismatch",
            "RPC initialize feature capability list is invalid",
        )
    missing = set(RPC_FEATURES) - set(features)
    if missing:
        raise RPCProtocolError(
            "rpc_feature_mismatch",
            "RPC client omitted required security features",
        )
    return {
        "ok": True,
        "protocol": {
            "selected_version": RPC_PROTOCOL_VERSION,
            "min_supported_version": RPC_PROTOCOL_MIN_VERSION,
            "max_supported_version": RPC_PROTOCOL_MAX_VERSION,
            "schema_version": RPC_SCHEMA_VERSION,
            "method_schema_version": RPC_METHOD_SCHEMA_VERSION,
            "features": list(RPC_FEATURES),
            "required_security_fields": list(RPC_REQUIRED_SECURITY_FIELDS),
            "unknown_field_policy": "reject",
            "error_codes": list(RPC_ERROR_CODES),
        },
    }


class GatewayRPCAuthenticator:
    """Verify peer identity and one-shot method-scoped capabilities.

    Protocol v1 remains available only for explicit development-mode callers;
    production requests must negotiate v2 before a service is dispatched.
    """

    def __init__(
        self,
        capability: str,
        *,
        expected_uid: int | None = None,
        expected_pid: int | None = None,
        require_protocol_v2: bool | None = None,
        require_protocol_metadata: bool = False,
        runtime_profile: RuntimeProfile | str | None = None,
    ) -> None:
        if len(capability) < 32:
            raise ValueError("Gateway RPC capability must contain at least 32 characters")
        self._key = capability.encode("utf-8")
        self._expected_uid = (
            (os.getuid() if hasattr(os, "getuid") else -1)
            if expected_uid is None
            else expected_uid
        )
        self._expected_pid = expected_pid
        self.runtime_profile = resolve_runtime_profile(runtime_profile)
        self._require_protocol_v2 = (
            self.runtime_profile.is_production
            if require_protocol_v2 is None
            else require_protocol_v2
        )
        self._require_protocol_metadata = (
            require_protocol_metadata or self.runtime_profile.is_production
        )
        self._bound_pid: int | None = None
        self._used_nonces: dict[str, float] = {}

    def verify_peer(self, writer: asyncio.StreamWriter) -> int | None:
        """Verify the OS peer identity associated with a socket writer."""
        peer = writer.get_extra_info("socket")
        if peer is None:
            raise PermissionError("RPC peer socket identity is unavailable")
        peer = getattr(peer, "_sock", peer)
        peer_pid: int | None = None
        try:
            if hasattr(peer, "getpeereid"):
                peer_uid, _peer_gid = peer.getpeereid()
                if sys.platform == "darwin":
                    peer_pid = struct.unpack(
                        "=i",
                        peer.getsockopt(getattr(socket, "SOL_LOCAL", 0), 2, 4),
                    )[0]
            elif hasattr(socket, "LOCAL_PEERCRED"):
                credentials = peer.getsockopt(
                    getattr(socket, "SOL_LOCAL", 0), socket.LOCAL_PEERCRED, 128
                )
                if len(credentials) < 8:
                    raise PermissionError("RPC peer credentials are truncated")
                _version, peer_uid = struct.unpack_from("=II", credentials)
                if sys.platform == "darwin":
                    peer_pid = struct.unpack(
                        "=i",
                        peer.getsockopt(getattr(socket, "SOL_LOCAL", 0), 2, 4),
                    )[0]
            elif hasattr(socket, "SO_PEERCRED"):
                credentials = peer.getsockopt(
                    socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
                )
                peer_pid, peer_uid, _peer_gid = struct.unpack("3i", credentials)
            else:
                raise PermissionError("RPC peer credentials are unsupported")
        except PermissionError:
            raise
        except OSError as exc:
            raise PermissionError(
                f"RPC peer socket is not connected: {exc} "
                "(fail-closed — peer identity unavailable)"
            ) from exc
        if peer_uid != self._expected_uid:
            raise PermissionError("RPC peer UID is not the configured Gateway UID")
        if peer_pid is None or peer_pid <= 0:
            if self._expected_pid is None:
                return None
            raise PermissionError("RPC peer PID is unavailable")
        if self._expected_pid is not None and peer_pid != self._expected_pid:
            raise PermissionError("RPC peer PID is not the configured Gateway PID")
        return peer_pid

    def authenticate(self, request: dict[str, Any], *, peer_pid: int | None = None) -> str:
        """Verify an authenticated envelope and consume its nonce."""
        method = str(request.get("method") or "")
        payload = request.get("payload", {})
        auth = request.get("auth")
        if not isinstance(auth, dict) or not isinstance(payload, dict):
            raise PermissionError("RPC authentication envelope is required")
        try:
            protocol_version = int(request.get("protocol_version", 1))
        except (TypeError, ValueError) as exc:
            raise PermissionError("RPC protocol_version is invalid") from exc
        if protocol_version not in (1, RPC_PROTOCOL_VERSION):
            raise PermissionError("RPC protocol_version is unsupported")
        if self._require_protocol_v2 and protocol_version != RPC_PROTOCOL_VERSION:
            raise PermissionError("RPC protocol version 2 is required")
        protocol_metadata = rpc_protocol_metadata(
            request, require=self._require_protocol_metadata,
        )
        nonce = str(auth.get("nonce") or "")
        principal_id = str(auth.get("principal_id") or "")
        payload_digest = str(auth.get("payload_digest") or "")
        mac = str(auth.get("mac") or "")
        try:
            issued_at = int(auth.get("issued_at"))
        except (TypeError, ValueError) as exc:
            raise PermissionError("RPC issued_at is invalid") from exc
        now = int(time.time())
        if abs(now - issued_at) > RPC_AUTH_WINDOW_SECONDS:
            raise PermissionError("RPC capability has expired")
        if len(nonce) < 32 or nonce in self._used_nonces:
            raise PermissionError("RPC nonce is invalid or replayed")
        canonical_payload = canonical_json_bytes(payload)
        expected_digest = hashlib.sha256(canonical_payload).hexdigest()
        if not hmac.compare_digest(payload_digest, expected_digest):
            raise PermissionError("RPC payload digest mismatch")
        if protocol_version == RPC_PROTOCOL_VERSION:
            signed_text = (
                f"{protocol_version}\n{method}\n{nonce}\n{issued_at}\n"
                f"{principal_id}\n{payload_digest}"
            )
            if protocol_metadata is not None:
                signed_text += (
                    f"\n{protocol_metadata['min_version']}"
                    f"\n{protocol_metadata['max_version']}"
                    f"\n{protocol_metadata['schema_version']}"
                    f"\n{protocol_metadata['method_schema_version']}"
                    f"\n{protocol_metadata['feature_digest']}"
                )
        else:
            signed_text = (
                f"{method}\n{nonce}\n{issued_at}\n{principal_id}\n"
                f"{payload_digest}"
            )
        method_key = hmac.new(
            self._key,
            f"khaos-rpc-method-v{protocol_version}\n{method}".encode(),
            hashlib.sha256,
        ).digest()
        expected_mac = hmac.new(method_key, signed_text.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(mac, expected_mac):
            raise PermissionError("RPC method capability is invalid")
        claimed_principal = str(payload.get("principal_id") or "")
        if claimed_principal and claimed_principal != principal_id:
            raise PermissionError("RPC payload principal is not transport-bound")
        if peer_pid is not None:
            if self._bound_pid is None:
                self._bound_pid = peer_pid
            elif peer_pid != self._bound_pid:
                raise PermissionError("RPC peer PID does not match the bound Gateway")
        self._used_nonces[nonce] = float(issued_at)
        cutoff = now - RPC_AUTH_WINDOW_SECONDS
        self._used_nonces = {
            key: value for key, value in self._used_nonces.items()
            if value >= cutoff
        }
        return principal_id


__all__ = [
    "RPC_AUTH_WINDOW_SECONDS",
    "RPC_ERROR_CODES",
    "RPC_FEATURES",
    "RPC_INITIALIZE_METHOD",
    "RPC_MAX_REQUEST_BYTES",
    "RPC_METHOD_SCHEMA_VERSION",
    "RPC_PROTOCOL_MAX_VERSION",
    "RPC_PROTOCOL_MIN_VERSION",
    "RPC_PROTOCOL_VERSION",
    "RPC_REQUIRED_SECURITY_FIELDS",
    "RPC_SCHEMA_VERSION",
    "GatewayRPCAuthenticator",
    "RPCProtocolError",
    "rpc_binding_claim_error",
    "rpc_feature_digest",
    "rpc_initialize_response",
    "rpc_protocol_metadata",
]
