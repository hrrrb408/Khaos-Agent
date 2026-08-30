"""Immutable production trust material bindings.

The runtime and ``authorityd`` may load the same files, but a pathname alone
does not prove that they loaded the same security boundary.  This module owns
the small, secret-free value exchanged during startup: protocol identity,
authority identity, effective-policy digest, semantic catalog digest, key
fingerprint, and deployment-environment digest.

It deliberately contains no sockets, subprocesses, database handles, or
fallback policy.  Callers must obtain the values from their respective trusted
owners and then compare the complete binding before exposing an effectful
runtime.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from khaos.security.protocol_boundary import canonical_digest

PRODUCTION_TRUST_SCHEMA_VERSION: Final = 1
_HEX_DIGITS: Final = frozenset("0123456789abcdef")


class ProductionTrustError(PermissionError):
    """Production trust material is missing, malformed, or inconsistent."""


def _require_digest(field: str, value: object) -> str:
    if type(value) is not str or len(value) != 64 or value != value.lower():
        raise ProductionTrustError(f"production trust {field} is invalid")
    if any(character not in _HEX_DIGITS for character in value):
        raise ProductionTrustError(f"production trust {field} is not hexadecimal")
    return value


def _require_text(field: str, value: object) -> str:
    if type(value) is not str or not value or "\x00" in value or len(value) > 256:
        raise ProductionTrustError(f"production trust {field} is invalid")
    return value


@dataclass(frozen=True, slots=True)
class ProductionTrustBinding:
    """The complete non-secret identity of one production authority boundary."""

    protocol_version: int
    authority_id: str
    policy_digest: str
    catalog_digest: str
    public_key_fingerprint: str
    environment_digest: str
    schema_version: int = PRODUCTION_TRUST_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != PRODUCTION_TRUST_SCHEMA_VERSION:
            raise ProductionTrustError("production trust schema version is unsupported")
        if type(self.protocol_version) is not int or self.protocol_version <= 0:
            raise ProductionTrustError("production trust protocol version is invalid")
        _require_text("authority_id", self.authority_id)
        _require_digest("policy_digest", self.policy_digest)
        _require_digest("catalog_digest", self.catalog_digest)
        _require_digest("public_key_fingerprint", self.public_key_fingerprint)
        _require_digest("environment_digest", self.environment_digest)

    @classmethod
    def create(
        cls,
        *,
        protocol_version: int,
        authority_id: str,
        policy_digest: str,
        catalog_digest: str,
        public_key_fingerprint: str,
        environment_digest: str,
    ) -> ProductionTrustBinding:
        """Construct a validated binding from trusted startup inputs."""
        return cls(
            protocol_version=protocol_version,
            authority_id=authority_id,
            policy_digest=policy_digest,
            catalog_digest=catalog_digest,
            public_key_fingerprint=public_key_fingerprint,
            environment_digest=environment_digest,
        )

    @property
    def catalog_semantic_digest(self) -> str:
        """Alias used by startup evidence to distinguish content from a path."""
        return self.catalog_digest

    def canonical(self) -> dict[str, object]:
        """Return the exact secret-free binding payload without its self-digest."""
        return {
            "schema_version": self.schema_version,
            "protocol_version": self.protocol_version,
            "authority_id": self.authority_id,
            "policy_digest": self.policy_digest,
            "catalog_digest": self.catalog_digest,
            "public_key_fingerprint": self.public_key_fingerprint,
            "environment_digest": self.environment_digest,
        }

    @property
    def digest(self) -> str:
        """Return the canonical digest of the complete trust binding."""
        return canonical_digest(self.canonical())

    def to_payload(self) -> dict[str, object]:
        """Return the wire payload including its tamper-detecting digest."""
        return {**self.canonical(), "binding_digest": self.digest}

    @classmethod
    def from_payload(cls, value: object) -> ProductionTrustBinding:
        """Parse and verify a closed startup binding payload."""
        if not isinstance(value, Mapping):
            raise ProductionTrustError("production trust binding is not an object")
        allowed = {
            "schema_version",
            "protocol_version",
            "authority_id",
            "policy_digest",
            "catalog_digest",
            "public_key_fingerprint",
            "environment_digest",
            "binding_digest",
        }
        if set(value) != allowed:
            raise ProductionTrustError("production trust binding fields are not exact")
        binding = cls(
            schema_version=value["schema_version"],
            protocol_version=value["protocol_version"],
            authority_id=value["authority_id"],
            policy_digest=value["policy_digest"],
            catalog_digest=value["catalog_digest"],
            public_key_fingerprint=value["public_key_fingerprint"],
            environment_digest=value["environment_digest"],
        )
        if value["binding_digest"] != binding.digest:
            raise ProductionTrustError("production trust binding digest does not match")
        return binding

    def matches(self, other: object) -> bool:
        """Compare two bindings by every canonical field."""
        return isinstance(other, ProductionTrustBinding) and self.canonical() == other.canonical()


def public_key_fingerprint(public_key_bytes: bytes) -> str:
    """Return the non-secret SHA-256 fingerprint of a raw public key."""
    if type(public_key_bytes) is not bytes or len(public_key_bytes) != 32:
        raise ProductionTrustError("authority public key bytes are invalid")
    return hashlib.sha256(public_key_bytes).hexdigest()


def deployment_environment_digest(
    *, platform_name: str, profile: str, transport: str
) -> str:
    """Digest the platform/transport identity that participates in startup."""
    if not all(type(value) is str and value for value in (platform_name, profile, transport)):
        raise ProductionTrustError("authority deployment environment is invalid")
    return canonical_digest(
        {
            "platform": platform_name,
            "profile": profile,
            "transport": transport,
        }
    )


def compare_trust_bindings(
    expected: ProductionTrustBinding, observed: ProductionTrustBinding
) -> None:
    """Raise a single fail-closed error when any trusted field differs."""
    if not expected.matches(observed):
        raise ProductionTrustError("production authority trust binding mismatch")


__all__ = [
    "PRODUCTION_TRUST_SCHEMA_VERSION",
    "ProductionTrustBinding",
    "ProductionTrustError",
    "compare_trust_bindings",
    "deployment_environment_digest",
    "public_key_fingerprint",
]
