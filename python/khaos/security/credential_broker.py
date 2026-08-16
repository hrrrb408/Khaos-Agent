"""Short-lived credential leases owned by the trusted runtime.

``CredentialScope`` describes *which* named credential may be used.  This
module owns the separate *how*: a provider loader stays inside the trusted
runtime, while a lease exposed to a tool contains only opaque identity and
expiry metadata.  Secret material is returned only for the final execution
environment and is never part of a scope, approval binding, repr, or audit
record.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from khaos.security.resource_scope import CredentialScope

CredentialLoader = Callable[[], Mapping[str, str]]


class CredentialBrokerError(PermissionError):
    """Raised when a credential lease cannot be issued or materialized."""


@dataclass(frozen=True, slots=True)
class CredentialLease:
    """Opaque short-lived credential identity; it intentionally has no secret."""

    lease_id: str
    scope: CredentialScope
    binding_digest: str
    policy_digest: str
    principal_id: str
    issued_at: float
    expires_at: float

    def summary(self) -> dict[str, object]:
        """Return metadata safe for approval/audit diagnostics."""
        return {
            "lease_id": self.lease_id,
            "provider": self.scope.provider,
            "names": sorted(self.scope.names),
            "operations": sorted(self.scope.operations),
            "binding_digest": self.binding_digest,
            "policy_digest": self.policy_digest,
            "principal_id": self.principal_id,
            "expires_at": self.expires_at,
        }


@dataclass(frozen=True, slots=True)
class _LeaseRecord:
    lease: CredentialLease
    loader: CredentialLoader


def credential_binding_digest(binding: Mapping[str, object] | str) -> str:
    """Hash a non-secret target binding used by a credential lease."""
    if isinstance(binding, str):
        payload: object = binding
    else:
        payload = dict(binding)
    encoded = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class CredentialBroker:
    """Trusted owner for provider loaders and expiring credential leases."""

    def __init__(
        self,
        *,
        policy_digest: str = "",
        principal_id: str = "",
        max_ttl_seconds: float = 300.0,
        allow_context_adoption: bool = False,
    ) -> None:
        if max_ttl_seconds <= 0:
            raise ValueError("credential broker max TTL must be positive")
        self.policy_digest = policy_digest
        self.principal_id = principal_id
        self.max_ttl_seconds = max_ttl_seconds
        self.allow_context_adoption = allow_context_adoption
        self._loaders: dict[str, CredentialLoader] = {}
        self._leases: dict[str, _LeaseRecord] = {}
        self._lock = threading.RLock()
        self._closed = False

    def register(self, scope: CredentialScope, loader: CredentialLoader) -> None:
        """Register a trusted provider loader for one exact typed scope."""
        if not isinstance(scope, CredentialScope) or not callable(loader):
            raise CredentialBrokerError("credential provider registration is invalid")
        with self._lock:
            self._ensure_open()
            self._loaders[scope.digest()] = loader

    def bind_runtime(self, *, policy_digest: str, principal_id: str) -> None:
        """Bind this broker to one immutable runtime identity."""
        if not isinstance(policy_digest, str) or not policy_digest:
            raise CredentialBrokerError("credential broker policy digest is required")
        if not isinstance(principal_id, str) or not principal_id:
            raise CredentialBrokerError("credential broker principal is required")
        with self._lock:
            self._ensure_open()
            if self.policy_digest and self.policy_digest != policy_digest:
                raise CredentialBrokerError(
                    "credential broker policy digest does not match the runtime"
                )
            if self.principal_id and self.principal_id != principal_id:
                raise CredentialBrokerError(
                    "credential broker principal does not match the runtime"
                )
            self.policy_digest = policy_digest
            self.principal_id = principal_id

    def issue(
        self,
        scope: CredentialScope,
        *,
        binding: Mapping[str, object] | str,
        operation: str,
        ttl_seconds: float = 120.0,
    ) -> CredentialLease:
        """Issue a lease only for a registered exact scope and operation."""
        if not isinstance(scope, CredentialScope):
            raise CredentialBrokerError("credential scope is invalid")
        if operation not in scope.operations:
            raise CredentialBrokerError("credential operation is outside its scope")
        if ttl_seconds <= 0 or ttl_seconds > self.max_ttl_seconds:
            raise CredentialBrokerError("credential lease TTL is outside its bound")
        with self._lock:
            self._ensure_open()
            loader = self._loaders.get(scope.digest())
            if loader is None:
                raise CredentialBrokerError("credential provider is not registered")
            return self._issue_with_loader(
                scope,
                loader,
                binding=binding,
                ttl_seconds=ttl_seconds,
                operation=operation,
            )

    def issue_named(
        self,
        *,
        provider: str,
        name: str,
        operation: str,
        binding: Mapping[str, object] | str,
        ttl_seconds: float = 120.0,
    ) -> CredentialLease:
        """Issue a lease from a pre-registered provider/name pair."""
        scope = CredentialScope(
            provider=provider,
            names=frozenset({name}),
            operations=frozenset({operation}),
        )
        return self.issue(
            scope,
            binding=binding,
            operation=operation,
            ttl_seconds=ttl_seconds,
        )

    def adopt_context(
        self,
        context: object,
        *,
        provider: str,
        name: str,
        operation: str,
        binding: Mapping[str, object] | str,
        ttl_seconds: float = 120.0,
    ) -> CredentialLease:
        """Adopt a server-owned legacy context into a broker lease.

        This compatibility path is disabled by default and is intended for a
        trusted server adapter that is migrating from the old environment
        dictionary contract.  A production runtime should register a native
        provider loader and issue leases directly instead.
        """
        if not self.allow_context_adoption:
            raise CredentialBrokerError(
                "raw credential contexts are disabled; register a provider loader"
            )
        if ttl_seconds <= 0 or ttl_seconds > self.max_ttl_seconds:
            raise CredentialBrokerError("credential lease TTL is outside its bound")
        if not isinstance(context, Mapping):
            raise CredentialBrokerError("credential context is invalid")
        if context.get("scope") != name:
            raise CredentialBrokerError("credential context name does not match scope")
        environment = context.get("environment")
        if not isinstance(environment, Mapping) or not environment:
            raise CredentialBrokerError("credential context environment is missing")
        if any(
            type(key) is not str
            or not key
            or "\x00" in key
            or type(value) is not str
            or not value
            or "\x00" in value
            for key, value in environment.items()
        ):
            raise CredentialBrokerError("credential context environment is malformed")
        scope = CredentialScope(
            provider=provider,
            names=frozenset({name}),
            operations=frozenset({operation}),
        )
        secret_environment = {str(key): str(value) for key, value in environment.items()}
        with self._lock:
            self._ensure_open()
            return self._issue_with_loader(
                scope,
                lambda: dict(secret_environment),
                binding=binding,
                ttl_seconds=ttl_seconds,
                operation=operation,
            )

    def materialize(
        self,
        lease: CredentialLease,
        *,
        binding: Mapping[str, object] | str,
        operation: str,
    ) -> dict[str, str]:
        """Resolve one valid lease into a bounded execution environment."""
        if not isinstance(lease, CredentialLease):
            raise CredentialBrokerError("credential lease is invalid")
        expected_binding = credential_binding_digest(binding)
        with self._lock:
            self._ensure_open()
            record = self._leases.get(lease.lease_id)
            if record is None or record.lease != lease:
                raise CredentialBrokerError("credential lease is unknown or revoked")
            if lease.expires_at <= time.time():
                self._leases.pop(lease.lease_id, None)
                raise CredentialBrokerError("credential lease is expired")
            if lease.binding_digest != expected_binding:
                raise CredentialBrokerError("credential lease target binding changed")
            if operation not in lease.scope.operations:
                raise CredentialBrokerError("credential lease operation is outside its scope")
            loader = record.loader
        try:
            environment = loader()
        except Exception as exc:
            raise CredentialBrokerError("credential provider failed") from exc
        if not isinstance(environment, Mapping) or not environment:
            raise CredentialBrokerError("credential provider returned no material")
        if len(environment) > 8 or any(
            type(key) is not str
            or not key
            or "\x00" in key
            or type(value) is not str
            or not value
            or "\x00" in value
            for key, value in environment.items()
        ):
            raise CredentialBrokerError("credential provider returned malformed material")
        return {str(key): str(value) for key, value in environment.items()}

    def revoke(self, lease: CredentialLease) -> None:
        """Forget one lease and release the provider closure it owns."""
        if isinstance(lease, CredentialLease):
            with self._lock:
                self._leases.pop(lease.lease_id, None)

    def owned_resources(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(f"credential-lease:{lease_id}" for lease_id in self._leases)

    def terminal_postcondition(self) -> bool:
        with self._lock:
            return not self._leases

    def close(self) -> None:
        with self._lock:
            self._leases.clear()
            self._loaders.clear()
            self._closed = True

    @property
    def closed(self) -> bool:
        with self._lock:
            return self._closed

    @property
    def terminal_closed(self) -> bool:
        """Return the lifecycle proof required by ``RuntimeResult``."""
        with self._lock:
            return self._closed and not self._leases

    def _ensure_open(self) -> None:
        if self._closed:
            raise CredentialBrokerError("credential broker is closed")

    def _issue_with_loader(
        self,
        scope: CredentialScope,
        loader: CredentialLoader,
        *,
        binding: Mapping[str, object] | str,
        operation: str,
        ttl_seconds: float,
    ) -> CredentialLease:
        now = time.time()
        lease = CredentialLease(
            lease_id=secrets.token_urlsafe(24),
            scope=scope,
            binding_digest=credential_binding_digest(binding),
            policy_digest=self.policy_digest,
            principal_id=self.principal_id,
            issued_at=now,
            expires_at=now + ttl_seconds,
        )
        self._leases[lease.lease_id] = _LeaseRecord(lease=lease, loader=loader)
        return lease


__all__ = [
    "CredentialBroker",
    "CredentialBrokerError",
    "CredentialLease",
    "credential_binding_digest",
]
