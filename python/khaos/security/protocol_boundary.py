"""Pure security-boundary primitives shared by transport and authority code.

This module intentionally has no sockets, subprocesses, database handles, or
mutable service objects.  It owns canonical serialization, bounded schema
validation, protocol negotiation, exact-effect digesting, and the legal
receipt/owner transitions that larger orchestration modules must call.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType


class ProtocolBoundaryError(ValueError):
    """An immutable protocol or state-machine input is invalid."""


def canonical_json_bytes(value: object) -> bytes:
    """Serialize a protocol value with one cross-language canonical form."""
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ProtocolBoundaryError("value is not canonically serializable") from exc


def canonical_digest(value: object) -> str:
    """Return the SHA-256 digest of the canonical wire representation."""
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def validate_object_schema(
    value: object,
    *,
    allowed_fields: frozenset[str],
    required_fields: frozenset[str] = frozenset(),
    label: str,
) -> Mapping[str, object]:
    """Validate a closed object schema and return an immutable view."""
    if not isinstance(value, dict):
        raise ProtocolBoundaryError(f"{label} must be an object")
    unknown = set(value) - allowed_fields
    if unknown:
        raise ProtocolBoundaryError(f"{label} contains unknown fields")
    missing = required_fields - set(value)
    if missing:
        raise ProtocolBoundaryError(f"{label} is missing required fields")
    return MappingProxyType(dict(value))


@dataclass(frozen=True, slots=True)
class ProtocolNegotiation:
    """Pure result of a bounded protocol/version/feature negotiation."""

    selected_version: int
    minimum: int
    maximum: int
    schema_version: int
    method_schema_version: int
    features: tuple[str, ...]

    @classmethod
    def negotiate(
        cls,
        *,
        minimum: object,
        maximum: object,
        supported_version: int,
        schema_version: object,
        supported_schema_version: int,
        method_schema_version: object,
        supported_method_schema_version: int,
        features: object,
        required_features: frozenset[str],
    ) -> ProtocolNegotiation:
        values = (minimum, maximum, schema_version, method_schema_version)
        if any(type(value) is not int for value in values):
            raise ProtocolBoundaryError("protocol versions must be integers")
        if not minimum <= supported_version <= maximum or minimum > maximum:
            raise ProtocolBoundaryError("protocol version is outside the supported range")
        if schema_version != supported_schema_version:
            raise ProtocolBoundaryError("protocol schema version is unsupported")
        if method_schema_version != supported_method_schema_version:
            raise ProtocolBoundaryError("method schema version is unsupported")
        if (
            not isinstance(features, list)
            or any(type(feature) is not str or not feature for feature in features)
            or len(set(features)) != len(features)
            or not required_features.issubset(features)
        ):
            raise ProtocolBoundaryError("protocol feature set is invalid")
        return cls(
            selected_version=supported_version,
            minimum=minimum,
            maximum=maximum,
            schema_version=schema_version,
            method_schema_version=method_schema_version,
            features=tuple(features),
        )

    @property
    def feature_digest(self) -> str:
        return canonical_digest(sorted(self.features))


class ReceiptState(StrEnum):
    PREPARING = "preparing"
    PREPARED = "prepared"
    CLAIMING = "claiming"
    CLAIMED = "claimed"
    COMPLETING = "completing"
    TERMINAL = "terminal"
    NARROWING = "narrowing"
    REVOKING = "revoking"


_RECEIPT_TRANSITIONS: frozenset[tuple[str, str]] = frozenset(
    {
        (ReceiptState.PREPARING, ReceiptState.PREPARED),
        (ReceiptState.PREPARED, ReceiptState.CLAIMING),
        (ReceiptState.CLAIMING, ReceiptState.CLAIMED),
        (ReceiptState.PREPARED, ReceiptState.COMPLETING),
        (ReceiptState.CLAIMED, ReceiptState.COMPLETING),
        (ReceiptState.COMPLETING, ReceiptState.CLAIMED),
        (ReceiptState.COMPLETING, ReceiptState.TERMINAL),
        (ReceiptState.PREPARED, ReceiptState.NARROWING),
        (ReceiptState.NARROWING, ReceiptState.PREPARED),
        (ReceiptState.PREPARED, ReceiptState.REVOKING),
        (ReceiptState.REVOKING, ReceiptState.PREPARED),
    }
)


def require_receipt_transition(current: str, next_state: str) -> str:
    """Validate one state transition without relying on object identity."""
    if (current, next_state) not in _RECEIPT_TRANSITIONS:
        raise ProtocolBoundaryError(
            f"illegal authority receipt transition: {current!r} -> {next_state!r}"
        )
    return next_state


class OwnerState(StrEnum):
    OPEN = "open"
    CLOSING = "closing"
    QUARANTINED = "quarantined"
    CLOSED = "closed"


def require_owner_transition(
    current: OwnerState,
    next_state: OwnerState,
    *,
    terminal_proven: bool = False,
    owned_resources: Sequence[str] = (),
) -> OwnerState:
    """Validate lifecycle transitions and the CLOSED postcondition."""
    allowed = {
        (OwnerState.OPEN, OwnerState.CLOSING),
        (OwnerState.CLOSING, OwnerState.QUARANTINED),
        (OwnerState.CLOSING, OwnerState.CLOSED),
        (OwnerState.QUARANTINED, OwnerState.CLOSING),
        (OwnerState.CLOSED, OwnerState.CLOSED),
    }
    if (current, next_state) not in allowed:
        raise ProtocolBoundaryError(
            f"illegal resource-owner transition: {current.value} -> {next_state.value}"
        )
    if next_state is OwnerState.CLOSED and (not terminal_proven or owned_resources):
        raise ProtocolBoundaryError("CLOSED requires terminal proof and empty ownership")
    return next_state


@dataclass(frozen=True, slots=True)
class EffectBinding:
    """Immutable exact-effect binding used by approval/launcher boundaries."""

    operation: str
    resource_digest: str
    effect_digest: str

    @classmethod
    def create(
        cls,
        *,
        operation: str,
        resource: object,
        effect: object,
    ) -> EffectBinding:
        if not operation or "\x00" in operation:
            raise ProtocolBoundaryError("effect operation is invalid")
        return cls(
            operation=operation,
            resource_digest=canonical_digest(resource),
            effect_digest=canonical_digest(effect),
        )

    def matches(self, *, operation: str, resource: object, effect: object) -> bool:
        return (
            self.operation == operation
            and self.resource_digest == canonical_digest(resource)
            and self.effect_digest == canonical_digest(effect)
        )


def read_bounded_line(
    connection: object,
    *,
    max_bytes: int,
    chunk_size: int = 64 * 1024,
) -> bytes:
    """Read one newline-terminated frame with a hard byte bound.

    Pure transport framing for the authority control plane: the frame is
    capped before parsing, an embedded newline terminates it, and an
    oversized or unterminated frame fails closed instead of buffering
    unbounded bytes.  Extracted from authorityd so the framing contract
    is a single reviewable, testable boundary.
    """
    if max_bytes <= 0 or chunk_size <= 0:
        raise ProtocolBoundaryError("bounded line limits must be positive")
    data = bytearray()
    recv = getattr(connection, "recv", None)
    if not callable(recv):
        raise ProtocolBoundaryError("connection does not expose recv()")
    while len(data) < max_bytes:
        chunk = recv(min(chunk_size, max_bytes - len(data)))
        if not chunk:
            break
        marker = chunk.find(b"\n")
        if marker >= 0:
            data.extend(chunk[:marker])
            return bytes(data)
        data.extend(chunk)
    raise ProtocolBoundaryError("bounded frame is too large or incomplete")


__all__ = [
    "EffectBinding",
    "OwnerState",
    "ProtocolBoundaryError",
    "ProtocolNegotiation",
    "ReceiptState",
    "canonical_digest",
    "canonical_json_bytes",
    "read_bounded_line",
    "require_owner_transition",
    "require_receipt_transition",
    "validate_object_schema",
]
