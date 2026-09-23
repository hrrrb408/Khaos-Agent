"""Short-lived credential leases owned by the trusted runtime.

``CredentialScope`` describes *which* named credential may be used.  This
module owns the separate *how*: a provider loader stays inside the trusted
runtime, while a lease exposed to a tool contains only opaque identity and
expiry metadata.  Secret material is returned only for the final execution
environment and is never part of a scope, approval binding, repr, or audit
record.

The broker also owns the materialization transaction.  A provider call is
not an untracked callback outside the lifecycle theorem: it is registered as
an owned resource before the loader runs, and the result is discarded unless
the same lease, generation, target, operation, policy, principal, and broker
are still live when the loader returns.
"""

from __future__ import annotations

import asyncio
import hashlib
import itertools
import json
import re
import secrets
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

from khaos.security.credential_provider_host import (
    CredentialProviderHost,
    CredentialProviderHostError,
)
from khaos.security.credential_provider_worker import (
    ProviderSpecError,
    validate_provider_spec,
)
from khaos.security.credentials import (
    _TRANSPORT_CAPABILITY,
    CredentialAccessMode,
    CredentialHandle,
    CredentialNotFound,
    CredentialProvisioningCancelled,
    CredentialRef,
    CredentialStore,
    CredentialStoreDiagnostic,
    CredentialStoreError,
    CredentialStoreUnavailable,
    SecretValue,
    credential_store_backend,
)
from khaos.security.resource_scope import CredentialScope
from khaos.security.secret_redaction import SecretRedactor

CredentialLoader = Callable[[], Mapping[str, str]]

MAX_PROVIDER_ENTRIES = 8
MAX_PROVIDER_VALUE_BYTES = 64 * 1024
DEFAULT_PROVIDER_WORKERS = 4
DEFAULT_PENDING_PROVIDERS = 8
DEFAULT_PROVIDER_DEADLINE_SECONDS = 60.0
_ENVIRONMENT_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


class CredentialBrokerError(PermissionError):
    """Raised when a credential lease cannot be issued or materialized."""

    def __init__(
        self,
        message: str,
        *,
        diagnostic: CredentialStoreDiagnostic | None = None,
        code: str | None = None,
    ) -> None:
        super().__init__(message)
        self.diagnostic = diagnostic
        self.code = code

    def safe_metadata(self) -> dict[str, object]:
        """Return bounded broker failure metadata without secret material."""
        payload: dict[str, object] = {"error_type": type(self).__name__}
        if self.code is not None:
            payload["code"] = self.code
        if self.diagnostic is not None:
            payload["diagnostic"] = self.diagnostic.to_payload()
        return payload


class CredentialSessionError(CredentialBrokerError):
    """Base error for the explicit trusted-runtime credential session."""


class CredentialSessionLocked(CredentialSessionError):
    """A runtime request was made without an active credential session lease."""

    def __init__(self, message: str = "credential session is locked") -> None:
        super().__init__(message, code="CREDENTIAL_SESSION_LOCKED")


class CredentialSessionMissing(CredentialSessionError):
    """The requested provider has no persistent credential to unlock."""

    def __init__(self, message: str = "credential is missing") -> None:
        super().__init__(message, code="CREDENTIAL_MISSING")


class CredentialUnlockCancelled(CredentialSessionError):
    """The operator cancelled an explicit interactive unlock operation."""

    def __init__(
        self,
        message: str = "credential unlock was cancelled",
        *,
        diagnostic: CredentialStoreDiagnostic | None = None,
    ) -> None:
        super().__init__(
            message,
            diagnostic=diagnostic,
            code="CREDENTIAL_UNLOCK_CANCELLED",
        )


@dataclass(frozen=True, slots=True)
class CredentialEnvironmentSchema:
    """The only environment shape a registered provider may materialize."""

    allowed_keys: frozenset[str]
    max_entries: int
    max_value_bytes: int = MAX_PROVIDER_VALUE_BYTES

    def __post_init__(self) -> None:
        if type(self.max_entries) is not int or type(self.max_value_bytes) is not int:
            raise CredentialBrokerError(
                "credential provider environment limits must be integers"
            )
        if not self.allowed_keys:
            raise CredentialBrokerError(
                "credential provider environment schema must allow at least one key"
            )
        if len(self.allowed_keys) > MAX_PROVIDER_ENTRIES:
            raise CredentialBrokerError(
                "credential provider environment schema allows too many keys"
            )
        if self.max_entries <= 0 or self.max_entries > MAX_PROVIDER_ENTRIES:
            raise CredentialBrokerError(
                "credential provider environment entry limit is invalid"
            )
        if self.max_entries > len(self.allowed_keys):
            raise CredentialBrokerError(
                "credential provider environment entry limit exceeds allowed keys"
            )
        if self.max_value_bytes <= 0 or self.max_value_bytes > MAX_PROVIDER_VALUE_BYTES:
            raise CredentialBrokerError(
                "credential provider environment value limit is invalid"
            )
        if any(
            type(key) is not str
            or not _ENVIRONMENT_KEY.fullmatch(key)
            for key in self.allowed_keys
        ):
            raise CredentialBrokerError(
                "credential provider environment key is invalid"
            )

    def digest(self) -> str:
        """Return a non-secret digest for this immutable provider schema."""
        payload = {
            "allowed_keys": sorted(self.allowed_keys),
            "max_entries": self.max_entries,
            "max_value_bytes": self.max_value_bytes,
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
        ).hexdigest()


@dataclass(frozen=True, slots=True)
class CredentialLease:
    """Opaque short-lived credential identity; it intentionally has no secret."""

    lease_id: str
    scope: CredentialScope
    authorized_operation: str
    binding_digest: str
    policy_digest: str
    principal_id: str
    generation: int
    environment_schema_digest: str
    issued_at: float
    expires_at: float

    def summary(self) -> dict[str, object]:
        """Return metadata safe for approval/audit diagnostics."""
        return {
            "lease_id": self.lease_id,
            "provider": self.scope.provider,
            "names": sorted(self.scope.names),
            # ``operations`` describes the provider's maximum capability;
            # ``authorized_operation`` is the one operation this lease may
            # actually claim.
            "operations": sorted(self.scope.operations),
            "authorized_operation": self.authorized_operation,
            "binding_digest": self.binding_digest,
            "policy_digest": self.policy_digest,
            "principal_id": self.principal_id,
            "generation": self.generation,
            "environment_schema_digest": self.environment_schema_digest,
            "expires_at": self.expires_at,
        }


@dataclass(frozen=True, slots=True)
class _ProviderRecord:
    loader: CredentialLoader | None
    schema: CredentialEnvironmentSchema
    # Hosted providers execute a validated data spec in a killable child
    # process instead of an in-process callable.
    spec: Mapping[str, object] | None = None
    deadline_seconds: float = DEFAULT_PROVIDER_DEADLINE_SECONDS


@dataclass(frozen=True, slots=True)
class _ProviderCredentialRecord:
    """Broker-owned mapping from one provider reference to one store."""

    provider: str
    ref: CredentialRef
    store: CredentialStore
    session_required: bool


@dataclass(frozen=True, slots=True)
class _LeaseRecord:
    lease: CredentialLease
    provider: _ProviderRecord


@dataclass(frozen=True, slots=True)
class _MaterializationRecord:
    transaction_id: str
    lease_id: str
    generation: int
    canceled: bool = False


@dataclass(frozen=True, slots=True)
class CredentialSessionLease:
    """Opaque process-lifetime lease metadata for one unlocked provider."""

    provider: str
    ref: CredentialRef
    generation: int
    issued_at: float

    def summary(self) -> dict[str, object]:
        """Return only non-secret session metadata."""
        return {
            "provider": self.provider,
            "credential_ref": self.ref.value,
            "generation": self.generation,
            "issued_at": self.issued_at,
            "lifetime": "trusted-runtime-session",
        }


@dataclass(frozen=True, slots=True)
class _SessionCredential:
    lease: CredentialSessionLease
    secret: SecretValue


class CredentialSession:
    """Operator-controlled session facade owned by one CredentialBroker.

    This facade never exposes a secret.  It exists so the explicit unlock/lock
    lifecycle is visible to trusted CLI/TUI composition without creating a
    second credential store or authority.  Agent tools are not given this
    facade and the runtime path only consumes its private Broker cache.
    """

    def __init__(self, broker: CredentialBroker) -> None:
        self._broker = broker

    def unlock(
        self, ref: CredentialRef, *, provider: str | None = None
    ) -> CredentialSessionLease:
        """Load one persistent credential during an explicit operator action."""
        return self._broker.unlock_provider_credential(ref, provider=provider)

    def lock(self, ref: CredentialRef, *, provider: str | None = None) -> None:
        """Invalidate one in-memory lease without touching persistence."""
        self._broker.lock_provider_credential(ref, provider=provider)

    def lock_all(self) -> None:
        """Invalidate every in-memory lease owned by this Broker."""
        self._broker.lock_all_credentials()

    def status(
        self, ref: CredentialRef, *, provider: str | None = None
    ) -> dict[str, object]:
        """Return safe state for one provider session."""
        return self._broker.credential_session_status(ref, provider=provider)


def credential_binding_digest(
    binding: Mapping[str, object] | str, operation: str | None = None
) -> str:
    """Hash a non-secret target binding and, when supplied, its exact action."""
    if isinstance(binding, str):
        payload: object = binding
    else:
        payload = dict(binding)
    if operation is not None:
        payload = {"binding": payload, "operation": operation}
    encoded = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class CredentialBroker:
    """Trusted owner for provider loaders and expiring credential leases.

    The provider callable is synchronous because deployment adapters commonly
    wrap platform keychains and credential managers with a synchronous API.
    Its call is nevertheless lifecycle-owned.  ``close()`` closes admission
    immediately, revokes all leases, and leaves an in-flight transaction
    registered until its result has been checked and discarded.  This avoids
    blocking runtime shutdown on an unavailable provider while making
    ``terminal_closed`` false until the provider call settles.

    Providers classified as blocking or untrusted must be registered with
    ``register_hosted`` instead: their loader is a validated data spec
    executed by :class:`~khaos.security.credential_provider_host.
    CredentialProviderHost` in a killable child process, so a permanently
    hung provider is reclaimed by SIGTERM/SIGKILL within a bounded grace
    instead of pinning a broker thread (and a clean shutdown) forever.

    ``materialize()`` runs the loader on the calling thread and is reserved
    for contexts that already execute off the Agent event loop (background
    workers, threads).  Async callers must use ``materialize_async()``, which
    moves the same owned transaction onto an executor so a slow or hung
    provider can never block cancellation, shutdown, or other sessions.
    """

    def __init__(
        self,
        *,
        policy_digest: str = "",
        principal_id: str = "",
        max_ttl_seconds: float = 300.0,
        allow_context_adoption: bool = False,
        max_provider_workers: int = DEFAULT_PROVIDER_WORKERS,
        max_pending_providers: int = DEFAULT_PENDING_PROVIDERS,
        untrusted_helper_roots: Iterable[Path] | None = None,
    ) -> None:
        if max_ttl_seconds <= 0:
            raise ValueError("credential broker max TTL must be positive")
        if (
            type(max_provider_workers) is not int
            or max_provider_workers <= 0
            or type(max_pending_providers) is not int
            or max_pending_providers < 0
        ):
            raise ValueError("credential provider bounds must be non-negative")
        self.policy_digest = policy_digest
        self.principal_id = principal_id
        self.max_ttl_seconds = max_ttl_seconds
        self.allow_context_adoption = allow_context_adoption
        self.max_provider_workers = max_provider_workers
        self.max_pending_providers = max_pending_providers
        # Model-writable roots (task worktrees, untrusted checkouts) that a
        # hosted command provider executable must never resolve beneath.
        self._untrusted_helper_roots = tuple(untrusted_helper_roots or ())
        self._loaders: dict[str, _ProviderRecord] = {}
        self._leases: dict[str, _LeaseRecord] = {}
        self._materializations: dict[str, _MaterializationRecord] = {}
        self._materialization_by_lease: dict[str, str] = {}
        # Credential providers run on a dedicated bounded executor so a hung
        # Keychain/Vault/plugin can never occupy or starve the asyncio
        # default executor shared by unrelated runtime work.  Admission is
        # bounded separately: once workers + queued calls are exhausted the
        # next materialization fails closed instead of queueing forever.
        self._provider_executor = ThreadPoolExecutor(
            max_workers=max_provider_workers,
            thread_name_prefix="khaos-credential-provider",
        )
        self._async_provider_admission = 0
        self._active_hosts: dict[int, CredentialProviderHost] = {}
        self._retained_hosts: dict[int, CredentialProviderHost] = {}
        self._host_tokens = itertools.count(1)
        self._lock = threading.RLock()
        self._generation = 0
        self._closing = False
        self._closed = False
        self._quarantined = False
        # Provider credential stores are deliberately a second capability of
        # this same broker, not a parallel authority.  The broker is the only
        # runtime component that may turn a SecretValue into transport bytes.
        self._broker_id = secrets.token_urlsafe(18)
        self._credential_stores: dict[str, _ProviderCredentialRecord] = {}
        self._session_credentials: dict[str, _SessionCredential] = {}
        # Explicit deletion is remembered only in this live Broker. This
        # lets post-delete runtime requests report CREDENTIAL_MISSING without
        # probing the persistent store or triggering Keychain UI.
        self._session_missing: set[str] = set()
        self._session_generation = 0
        self._credential_session = CredentialSession(self)
        self._secret_redactor = SecretRedactor()

    @property
    def secret_redactor(self) -> SecretRedactor:
        """Return the process-local redactor owned by this broker."""
        return self._secret_redactor

    @property
    def credential_session(self) -> CredentialSession:
        """Return the operator-facing session facade owned by this Broker."""
        return self._credential_session

    def register_credential_store(
        self,
        ref: CredentialRef,
        store: CredentialStore,
        *,
        provider: str | None = None,
        session_required: bool | None = None,
    ) -> None:
        """Register a provider-bound platform store with this broker.

        Registration carries only an opaque reference.  A store cannot be
        looked up under another provider name, which prevents cross-provider
        credential confusion in router configuration.
        """
        if not isinstance(ref, CredentialRef):
            raise CredentialBrokerError("credential reference is invalid")
        provider_name = provider.casefold() if isinstance(provider, str) else ref.provider
        if provider_name != ref.provider:
            raise CredentialBrokerError("credential reference provider mismatch")
        if not isinstance(store, CredentialStore):
            raise CredentialBrokerError("credential store is invalid")
        if session_required is None:
            session_required = bool(getattr(store, "requires_session_unlock", False))
        if type(session_required) is not bool:
            raise CredentialBrokerError("credential session policy is invalid")
        with self._lock:
            self._ensure_open()
            existing = self._credential_stores.get(ref.value)
            if existing is not None and existing.provider != provider_name:
                raise CredentialBrokerError("credential reference is already bound")
            if existing is not None and (
                existing.store is not store
                or existing.session_required != session_required
            ):
                self._session_credentials.pop(ref.value, None)
                self._session_missing.discard(ref.value)
            self._credential_stores[ref.value] = _ProviderCredentialRecord(
                provider=provider_name,
                ref=ref,
                store=store,
                session_required=session_required,
            )

    def provider_credential_status(
        self, ref: CredentialRef, *, provider: str | None = None
    ) -> dict[str, object]:
        """Return presence/backend metadata without loading a secret."""
        if not isinstance(ref, CredentialRef):
            raise CredentialBrokerError("credential reference is invalid")
        provider_name = provider.casefold() if isinstance(provider, str) else ref.provider
        if provider_name != ref.provider:
            raise CredentialBrokerError("credential reference provider mismatch")
        with self._lock:
            record = self._credential_stores.get(ref.value)
            active_session = self._session_credentials.get(ref.value)
        if record is None:
            return {
                "provider": provider_name,
                "credential_ref": ref.value,
                "credential_present": False,
                "backend": "unregistered",
                "status": "UNREGISTERED",
                "session": "LOCKED",
                "runtime_credential": "UNAVAILABLE",
            }
        if record.session_required and active_session is not None:
            return {
                "provider": provider_name,
                "credential_ref": ref.value,
                "credential_present": True,
                "backend": credential_store_backend(record.store),
                "status": "PRESENT",
                "session": "UNLOCKED",
                "runtime_credential": "AVAILABLE",
                "session_generation": active_session.lease.generation,
            }
        try:
            present = bool(
                record.store.exists(
                    ref, access_mode=CredentialAccessMode.RUNTIME
                )
            )
        except CredentialStoreError as exc:
            payload = {
                "provider": provider_name,
                "credential_ref": ref.value,
                "credential_present": None,
                "backend": credential_store_backend(record.store),
                "status": (
                    "INTERACTION_REQUIRED"
                    if exc.diagnostic is not None
                    and exc.diagnostic.category == "INTERACTION_REQUIRED"
                    else "UNAVAILABLE"
                ),
                "session": "LOCKED" if record.session_required else "NOT_REQUIRED",
                "runtime_credential": "UNAVAILABLE",
            }
            if isinstance(exc.diagnostic, CredentialStoreDiagnostic):
                payload["diagnostic"] = exc.diagnostic.to_payload()
            return payload
        except Exception:  # noqa: BLE001 - status diagnostics fail closed
            return {
                "provider": provider_name,
                "credential_ref": ref.value,
                "credential_present": None,
                "backend": credential_store_backend(record.store),
                "status": "ERROR",
                "session": "LOCKED" if record.session_required else "NOT_REQUIRED",
                "runtime_credential": "UNAVAILABLE",
            }
        return {
            "provider": provider_name,
            "credential_ref": ref.value,
            "credential_present": present,
            "backend": credential_store_backend(record.store),
            "status": "PRESENT" if present else "MISSING",
            "session": "LOCKED" if record.session_required else "NOT_REQUIRED",
            "runtime_credential": (
                "AVAILABLE" if present and not record.session_required else "UNAVAILABLE"
            ),
        }

    def credential_session_status(
        self, ref: CredentialRef, *, provider: str | None = None
    ) -> dict[str, object]:
        """Return session state without consulting the persistent store."""
        record = self._credential_record(ref, provider=provider)
        with self._lock:
            active = self._session_credentials.get(ref.value)
            missing = ref.value in self._session_missing
        if active is None:
            if missing:
                return {
                    "provider": record.provider,
                    "credential_ref": ref.value,
                    "session": "LOCKED",
                    "runtime_credential": "MISSING",
                    "credential": "MISSING",
                    "session_generation": None,
                }
            return {
                "provider": record.provider,
                "credential_ref": ref.value,
                "session": "LOCKED",
                "runtime_credential": "UNAVAILABLE",
                "session_generation": None,
            }
        return {
            "provider": record.provider,
            "credential_ref": ref.value,
            "session": "UNLOCKED",
            "runtime_credential": "AVAILABLE",
            "session_generation": active.lease.generation,
        }

    def unlock_provider_credential(
        self, ref: CredentialRef, *, provider: str | None = None
    ) -> CredentialSessionLease:
        """Explicitly load one persistent credential into the Broker session.

        This is the only session path that may use the provisioning access
        mode.  Runtime transport never calls the persistent store for a
        session-required provider.
        """
        record = self._credential_record(ref, provider=provider)
        try:
            secret = record.store.get(
                ref, access_mode=CredentialAccessMode.PROVISIONING
            )
        except CredentialNotFound as exc:
            with self._lock:
                if self._credential_stores.get(ref.value) is record:
                    self._session_credentials.pop(ref.value, None)
                    self._session_missing.add(ref.value)
            raise CredentialSessionMissing() from exc
        except CredentialProvisioningCancelled as exc:
            raise CredentialUnlockCancelled(
                diagnostic=exc.diagnostic
            ) from exc
        except CredentialStoreError as exc:
            raise CredentialSessionError(
                "credential unlock failed",
                diagnostic=exc.diagnostic,
                code="CREDENTIAL_UNLOCK_FAILED",
            ) from exc
        except Exception as exc:
            raise CredentialSessionError(
                "credential unlock failed", code="CREDENTIAL_UNLOCK_FAILED"
            ) from exc
        with self._lock:
            self._ensure_open()
            current = self._credential_stores.get(ref.value)
            if current is not record:
                raise CredentialSessionError(
                    "credential store changed during unlock",
                    code="CREDENTIAL_UNLOCK_FAILED",
                )
            self._session_generation += 1
            lease = CredentialSessionLease(
                provider=record.provider,
                ref=record.ref,
                generation=self._session_generation,
                issued_at=time.time(),
            )
            self._session_credentials[ref.value] = _SessionCredential(
                lease=lease,
                secret=secret,
            )
            self._session_missing.discard(ref.value)
            return lease

    def lock_provider_credential(
        self, ref: CredentialRef, *, provider: str | None = None
    ) -> None:
        """Invalidate one in-memory credential lease without deleting it."""
        record = self._credential_record(ref, provider=provider)
        with self._lock:
            self._session_credentials.pop(record.ref.value, None)

    def lock_all_credentials(self) -> None:
        """Invalidate every in-memory credential lease owned by this Broker."""
        with self._lock:
            self._session_credentials.clear()

    def provision_provider_credential(
        self,
        ref: CredentialRef,
        secret: SecretValue,
        *,
        provider: str | None = None,
    ) -> None:
        """Store one operator-supplied secret through the provisioning path.

        This method is intentionally named for its authority.  It must only
        be reached from explicit operator setup/replace flows; runtime model
        and tool paths use ``authorize_provider_headers`` and never call it.
        """
        if not isinstance(secret, SecretValue):
            raise CredentialBrokerError("provider credentials require SecretValue")
        record = self._credential_record(ref, provider=provider)
        try:
            record.store.put(
                ref,
                secret,
                access_mode=CredentialAccessMode.PROVISIONING,
            )
        except CredentialStoreError as exc:
            raise CredentialBrokerError(
                "credential provisioning failed", diagnostic=exc.diagnostic
            ) from exc
        except Exception as exc:
            raise CredentialBrokerError("credential provisioning failed") from exc
        # A replacement must never leave a stale runtime secret usable.  The
        # operator can explicitly unlock the new persistent value afterwards.
        with self._lock:
            self._session_credentials.pop(ref.value, None)
            self._session_missing.discard(ref.value)

    def put_provider_credential(
        self,
        ref: CredentialRef,
        secret: SecretValue,
        *,
        provider: str | None = None,
    ) -> None:
        """Compatibility alias for the explicit operator provisioning path."""
        self.provision_provider_credential(ref, secret, provider=provider)

    def snapshot_provisioned_provider_credential(
        self, ref: CredentialRef, *, provider: str | None = None
    ) -> SecretValue | None:
        """Snapshot an existing credential for an atomic operator replace.

        The value remains wrapped in memory and is only used by the trusted
        configuration transaction to restore a previous value after a config
        publication failure.  Runtime callers have no corresponding method.
        """
        record = self._credential_record(ref, provider=provider)
        try:
            if not record.store.exists(
                ref, access_mode=CredentialAccessMode.PROVISIONING
            ):
                return None
            return record.store.get(
                ref, access_mode=CredentialAccessMode.PROVISIONING
            )
        except CredentialNotFound:
            return None
        except CredentialStoreError as exc:
            raise CredentialBrokerError(
                "credential provisioning snapshot failed", diagnostic=exc.diagnostic
            ) from exc
        except Exception as exc:
            raise CredentialBrokerError(
                "credential provisioning snapshot failed"
            ) from exc

    def delete_provisioned_provider_credential(
        self, ref: CredentialRef, *, provider: str | None = None
    ) -> None:
        """Delete one credential from the explicit operator path.

        There is deliberately no runtime auto-delete operation.  A provider
        read failure cannot destroy a stored credential.
        """
        record = self._credential_record(ref, provider=provider)
        try:
            record.store.delete(
                ref,
                access_mode=CredentialAccessMode.PROVISIONING,
            )
        except CredentialStoreError as exc:
            raise CredentialBrokerError(
                "credential deletion failed", diagnostic=exc.diagnostic
            ) from exc
        except Exception as exc:
            raise CredentialBrokerError("credential deletion failed") from exc
        with self._lock:
            self._session_credentials.pop(ref.value, None)
            self._session_missing.add(ref.value)

    def delete_provider_credential(
        self, ref: CredentialRef, *, provider: str | None = None
    ) -> None:
        """Compatibility alias for explicit operator credential deletion."""
        self.delete_provisioned_provider_credential(ref, provider=provider)

    def issue_provider_handle(
        self,
        ref: CredentialRef,
        *,
        provider: str | None = None,
        binding: Mapping[str, object] | str,
        operation: str = "provider.request",
        ttl_seconds: float = 120.0,
    ) -> CredentialHandle:
        """Issue a runtime, non-interactive handle for one provider operation."""
        return self._issue_provider_handle(
            ref,
            provider=provider,
            binding=binding,
            operation=operation,
            ttl_seconds=ttl_seconds,
            access_mode=CredentialAccessMode.RUNTIME,
        )

    def issue_provisioning_provider_handle(
        self,
        ref: CredentialRef,
        *,
        provider: str | None = None,
        binding: Mapping[str, object] | str,
        operation: str = "provider.discovery",
        ttl_seconds: float = 120.0,
    ) -> CredentialHandle:
        """Issue a provisioning-only handle for explicit model discovery."""
        if operation != "provider.discovery":
            raise CredentialBrokerError(
                "provisioning handles are limited to provider discovery"
            )
        return self._issue_provider_handle(
            ref,
            provider=provider,
            binding=binding,
            operation=operation,
            ttl_seconds=ttl_seconds,
            access_mode=CredentialAccessMode.PROVISIONING,
        )

    def _issue_provider_handle(
        self,
        ref: CredentialRef,
        *,
        provider: str | None,
        binding: Mapping[str, object] | str,
        operation: str,
        ttl_seconds: float,
        access_mode: CredentialAccessMode,
    ) -> CredentialHandle:
        """Issue a handle after an explicitly selected store-mode check."""
        mode = access_mode
        if ttl_seconds <= 0 or ttl_seconds > self.max_ttl_seconds:
            raise CredentialBrokerError("credential handle TTL is outside its bound")
        record = self._credential_record(ref, provider=provider)
        session_generation = (
            self._runtime_session_generation(record, ref)
            if mode is CredentialAccessMode.RUNTIME
            else None
        )
        if session_generation is None:
            try:
                if not record.store.exists(ref, access_mode=mode):
                    raise CredentialBrokerError("provider credential is not present")
            except CredentialBrokerError:
                raise
            except CredentialStoreError as exc:
                raise CredentialBrokerError(
                    "credential store unavailable", diagnostic=exc.diagnostic
                ) from exc
            except Exception as exc:
                raise CredentialBrokerError(
                    "credential store presence check failed"
                ) from exc
        now = datetime.now(UTC)
        return CredentialHandle(
            provider=record.provider,
            ref=record.ref,
            operation=operation,
            binding_digest=credential_binding_digest(binding, operation),
            broker_id=self._broker_id,
            issued_at=now,
            expires_at=now + timedelta(seconds=ttl_seconds),
            access_mode=mode,
            session_generation=session_generation,
        )

    def authorize_provider_headers(
        self,
        headers: dict[str, str],
        handle: CredentialHandle,
        *,
        provider: str,
        binding: Mapping[str, object] | str,
        operation: str = "provider.request",
        header_name: str = "Authorization",
        scheme: str = "Bearer",
    ) -> None:
        """Resolve a handle directly into a mutable transport header map.

        This is the narrow transport boundary.  No caller receives the raw
        value; the value exists only long enough for the HTTP client to build
        its request.  All validation happens before the store is touched.
        """
        self._authorize_provider_headers(
            headers,
            handle,
            provider=provider,
            binding=binding,
            operation=operation,
            header_name=header_name,
            scheme=scheme,
            access_mode=CredentialAccessMode.RUNTIME,
        )

    def authorize_provisioning_provider_headers(
        self,
        headers: dict[str, str],
        handle: CredentialHandle,
        *,
        provider: str,
        binding: Mapping[str, object] | str,
        operation: str = "provider.discovery",
        header_name: str = "Authorization",
        scheme: str = "Bearer",
    ) -> None:
        """Resolve a provisioning handle only for explicit setup discovery."""
        if operation != "provider.discovery":
            raise CredentialBrokerError(
                "provisioning headers are limited to provider discovery"
            )
        self._authorize_provider_headers(
            headers,
            handle,
            provider=provider,
            binding=binding,
            operation=operation,
            header_name=header_name,
            scheme=scheme,
            access_mode=CredentialAccessMode.PROVISIONING,
        )

    def _authorize_provider_headers(
        self,
        headers: dict[str, str],
        handle: CredentialHandle,
        *,
        provider: str,
        binding: Mapping[str, object] | str,
        operation: str,
        header_name: str,
        scheme: str,
        access_mode: CredentialAccessMode,
    ) -> None:
        """Shared validation/materialization for the two named authorities."""
        mode = access_mode
        if not isinstance(headers, dict) or not isinstance(handle, CredentialHandle):
            raise CredentialBrokerError("provider transport authorization is invalid")
        provider_name = provider.casefold() if isinstance(provider, str) else ""
        if provider_name != handle.provider or handle.broker_id != self._broker_id:
            raise CredentialBrokerError("provider credential handle is not owned by broker")
        if handle.access_mode is not mode:
            raise CredentialBrokerError("provider credential handle access mode mismatched")
        if handle.operation != operation or handle.expired:
            raise CredentialBrokerError("provider credential handle is expired or mismatched")
        expected_binding = credential_binding_digest(binding, operation)
        if handle.binding_digest != expected_binding:
            raise CredentialBrokerError("provider credential target binding changed")
        if not header_name or any(
            ord(char) < 0x20 or ord(char) == 0x7F for char in f"{header_name}{scheme}"
        ):
            raise CredentialBrokerError("provider authorization header is invalid")
        record = self._credential_record(handle.ref, provider=provider_name)
        try:
            session_secret = (
                self._runtime_session_secret(record, handle)
                if mode is CredentialAccessMode.RUNTIME
                else None
            )
            secret = session_secret
            if secret is None:
                secret = record.store.get(handle.ref, access_mode=mode)
            self._secret_redactor.register(secret)
            raw = secret._reveal_for_transport(_TRANSPORT_CAPABILITY)
        except CredentialNotFound as exc:
            raise CredentialBrokerError("provider credential is not present") from exc
        except CredentialStoreError as exc:
            raise CredentialBrokerError(
                "credential store unavailable", diagnostic=exc.diagnostic
            ) from exc
        except CredentialBrokerError:
            raise
        except Exception as exc:
            raise CredentialBrokerError("credential store read failed") from exc
        headers[header_name] = f"{scheme} {raw}" if scheme else raw

    def _runtime_session_generation(
        self, record: _ProviderCredentialRecord, ref: CredentialRef
    ) -> int | None:
        """Return the active session generation without touching the store."""
        with self._lock:
            active = self._session_credentials.get(ref.value)
            missing = ref.value in self._session_missing
        if active is None:
            if missing:
                raise CredentialSessionMissing()
            if record.session_required:
                raise CredentialSessionLocked()
            return None
        return active.lease.generation

    def _runtime_session_secret(
        self, record: _ProviderCredentialRecord, handle: CredentialHandle
    ) -> SecretValue | None:
        """Return a cached secret only when the handle matches the session."""
        with self._lock:
            active = self._session_credentials.get(handle.ref.value)
        if active is None:
            with self._lock:
                missing = handle.ref.value in self._session_missing
            if missing:
                raise CredentialSessionMissing()
            if record.session_required or handle.session_generation is not None:
                raise CredentialSessionLocked()
            return None
        if handle.session_generation != active.lease.generation:
            raise CredentialSessionLocked("credential session lease is stale")
        return active.secret

    def _credential_record(
        self, ref: CredentialRef, *, provider: str | None = None
    ) -> _ProviderCredentialRecord:
        if not isinstance(ref, CredentialRef):
            raise CredentialBrokerError("credential reference is invalid")
        provider_name = provider.casefold() if isinstance(provider, str) else ref.provider
        if provider_name != ref.provider:
            raise CredentialBrokerError("credential reference provider mismatch")
        with self._lock:
            self._ensure_open()
            record = self._credential_stores.get(ref.value)
        if record is None or record.provider != provider_name or record.ref != ref:
            raise CredentialBrokerError("provider credential is not registered")
        return record

    def register(
        self,
        scope: CredentialScope,
        loader: CredentialLoader,
        *,
        allowed_environment_keys: Iterable[str] | None = None,
        max_entries: int | None = None,
        max_value_bytes: int = MAX_PROVIDER_VALUE_BYTES,
    ) -> None:
        """Register a trusted loader with an explicit output environment schema.

        Known built-in providers retain narrow compatibility defaults
        (GitHub token and Git/SSH helpers).  New provider families must pass
        ``allowed_environment_keys`` explicitly; a provider cannot expand the
        subprocess environment merely by returning additional mapping keys.
        """
        if not isinstance(scope, CredentialScope) or not callable(loader):
            raise CredentialBrokerError("credential provider registration is invalid")
        schema = self._schema_for_scope(
            scope,
            allowed_environment_keys=allowed_environment_keys,
            max_entries=max_entries,
            max_value_bytes=max_value_bytes,
        )
        with self._lock:
            self._ensure_open()
            self._loaders[scope.digest()] = _ProviderRecord(loader, schema)

    def register_hosted(
        self,
        scope: CredentialScope,
        spec: Mapping[str, object],
        *,
        allowed_environment_keys: Iterable[str] | None = None,
        max_entries: int | None = None,
        max_value_bytes: int = MAX_PROVIDER_VALUE_BYTES,
        deadline_seconds: float = DEFAULT_PROVIDER_DEADLINE_SECONDS,
    ) -> None:
        """Register a blocking/untrusted provider as a killable child spec.

        Hosted containment is the classification boundary for providers
        that may hang (keychain integrations, network-backed secret
        stores, enterprise plugins): the spec is validated data, the
        loader runs in a dedicated child process, and any deadline breach
        or broker close escalates SIGTERM → SIGKILL → wait so physical
        reclamation never requires exiting the trusted runtime.
        """
        if not isinstance(scope, CredentialScope):
            raise CredentialBrokerError("credential provider registration is invalid")
        try:
            validate_provider_spec(spec)
        except ProviderSpecError as exc:
            raise CredentialBrokerError(f"credential provider spec is invalid: {exc}") from exc
        if deadline_seconds <= 0:
            raise CredentialBrokerError("credential provider deadline must be positive")
        schema = self._schema_for_scope(
            scope,
            allowed_environment_keys=allowed_environment_keys,
            max_entries=max_entries,
            max_value_bytes=max_value_bytes,
        )
        record = _ProviderRecord(
            None,
            schema,
            spec=dict(spec),
            deadline_seconds=deadline_seconds,
        )
        with self._lock:
            self._ensure_open()
            self._loaders[scope.digest()] = record

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
            if self._generation == 0:
                self._generation = 1
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
        if type(operation) is not str or not operation:
            raise CredentialBrokerError("credential operation is invalid")
        if operation not in scope.operations:
            raise CredentialBrokerError("credential operation is outside its scope")
        if ttl_seconds <= 0 or ttl_seconds > self.max_ttl_seconds:
            raise CredentialBrokerError("credential lease TTL is outside its bound")
        with self._lock:
            self._ensure_open()
            provider = self._loaders.get(scope.digest())
            if provider is None:
                raise CredentialBrokerError("credential provider is not registered")
            return self._issue_with_provider(
                scope,
                provider,
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

    def validate_named_provider(
        self, *, provider: str, name: str, operation: str
    ) -> None:
        """Check provider availability without invoking its loader."""
        scope = CredentialScope(
            provider=provider,
            names=frozenset({name}),
            operations=frozenset({operation}),
        )
        with self._lock:
            self._ensure_open()
            if operation not in scope.operations:
                raise CredentialBrokerError("credential operation is outside its scope")
            if scope.digest() not in self._loaders:
                raise CredentialBrokerError("credential provider is not registered")

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
        scope = CredentialScope(
            provider=provider,
            names=frozenset({name}),
            operations=frozenset({operation}),
        )
        schema = self._schema_for_scope(scope)
        secret_environment = self._validate_environment(environment, schema)
        with self._lock:
            self._ensure_open()
            return self._issue_with_provider(
                scope,
                _ProviderRecord(lambda: dict(secret_environment), schema),
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
        """Claim one lease and resolve it into a bounded execution environment."""
        if not isinstance(lease, CredentialLease):
            raise CredentialBrokerError("credential lease is invalid")
        if type(operation) is not str or not operation:
            raise CredentialBrokerError("credential operation is invalid")
        expected_binding = credential_binding_digest(binding, operation)
        with self._lock:
            provider, transaction = self._reserve_materialization_locked(
                lease, expected_binding, operation
            )
        if provider.spec is not None:
            with self._lock:
                self._abort_materialization_locked(
                    transaction.transaction_id, lease.lease_id
                )
            raise CredentialBrokerError(
                "hosted credential providers require materialize_async "
                "so the kill ladder can run on the event loop"
            )
        succeeded = False
        try:
            try:
                environment = provider.loader()
            except Exception as exc:
                raise CredentialBrokerError("credential provider failed") from exc
            normalized = self._validate_environment(environment, provider.schema)
            with self._lock:
                result = self._settle_materialization_locked(
                    lease, transaction, normalized
                )
                succeeded = True
                return result
        finally:
            if not succeeded:
                with self._lock:
                    self._abort_materialization_locked(
                        transaction.transaction_id, lease.lease_id
                    )

    async def materialize_async(
        self,
        lease: CredentialLease,
        *,
        binding: Mapping[str, object] | str,
        operation: str,
        timeout: float | None = None,
        executor: object | None = None,
    ) -> dict[str, str]:
        """Claim one lease without letting a provider block the event loop.

        The provider loader runs on this broker's dedicated bounded executor
        (never the shared asyncio default executor) while this coroutine only
        awaits its completion.  Admission is bounded: once all provider
        workers and queue slots are owned by in-flight calls, the next
        materialization fails closed instead of queueing without bound.
        Caller cancellation and provider timeout mark the materialization
        transaction canceled: any secret the worker still produces is
        discarded by the return fence, and the transaction stays owned until
        the worker settles, so ``close()`` never observes a false terminal
        state while a provider call is still executing.
        """
        if not isinstance(lease, CredentialLease):
            raise CredentialBrokerError("credential lease is invalid")
        if type(operation) is not str or not operation:
            raise CredentialBrokerError("credential operation is invalid")
        if timeout is not None and (
            type(timeout) not in (int, float) or timeout <= 0
        ):
            raise CredentialBrokerError("credential provider timeout is invalid")
        expected_binding = credential_binding_digest(binding, operation)
        with self._lock:
            self._ensure_open()
            if (
                self._async_provider_admission
                >= self.max_provider_workers + self.max_pending_providers
            ):
                raise CredentialBrokerError(
                    "credential provider admission is full"
                )
            self._async_provider_admission += 1
            try:
                provider, transaction = self._reserve_materialization_locked(
                    lease, expected_binding, operation
                )
            except BaseException:
                self._async_provider_admission -= 1
                raise
        loop = asyncio.get_running_loop()
        provider_executor = executor or self._provider_executor

        async def _owned_worker() -> dict[str, str]:
            try:
                try:
                    if provider.spec is None:
                        environment = await loop.run_in_executor(
                            provider_executor, provider.loader
                        )
                    else:
                        environment = await self._run_hosted_provider(provider)
                finally:
                    # The provider call (running or queued) no longer holds an
                    # admission slot once the loader itself has settled.
                    with self._lock:
                        self._async_provider_admission -= 1
            except CredentialBrokerError:
                with self._lock:
                    self._abort_materialization_locked(
                        transaction.transaction_id, lease.lease_id
                    )
                raise
            except Exception as exc:
                with self._lock:
                    self._abort_materialization_locked(
                        transaction.transaction_id, lease.lease_id
                    )
                raise CredentialBrokerError("credential provider failed") from exc
            try:
                normalized = self._validate_environment(environment, provider.schema)
            except CredentialBrokerError:
                with self._lock:
                    self._abort_materialization_locked(
                        transaction.transaction_id, lease.lease_id
                    )
                raise
            with self._lock:
                return self._settle_materialization_locked(
                    lease, transaction, normalized
                )

        worker = asyncio.ensure_future(_owned_worker())
        worker.add_done_callback(self._reap_worker)
        try:
            if timeout is None:
                return await asyncio.shield(worker)
            return await asyncio.wait_for(asyncio.shield(worker), timeout)
        except TimeoutError as exc:
            self._cancel_materialization(transaction.transaction_id)
            raise CredentialBrokerError("credential provider timed out") from exc
        except asyncio.CancelledError:
            self._cancel_materialization(transaction.transaction_id)
            raise

    async def _run_hosted_provider(
        self, provider: _ProviderRecord
    ) -> dict[str, str]:
        """Execute one hosted provider spec under tracked host ownership.

        The host stays registered in ``_active_hosts`` for the entire child
        lifetime so ``owned_resources()`` and ``close()`` can see — and
        terminate — a provider that is hung.  A host whose execution domain
        cannot be proven terminal (surviving descendants) is moved to
        ``_retained_hosts`` instead of being dropped: the broker must never
        report CLOSED over a live provider process.
        """
        host = CredentialProviderHost(
            untrusted_roots=self._untrusted_helper_roots
        )
        token = next(self._host_tokens)
        with self._lock:
            self._active_hosts[token] = host
        try:
            return await host.materialize(
                provider.spec or {}, deadline=provider.deadline_seconds
            )
        except CredentialProviderHostError as exc:
            raise CredentialBrokerError(str(exc)) from exc
        finally:
            with self._lock:
                self._active_hosts.pop(token, None)
                if host.alive:
                    # Unproven termination: retain the host (quarantine).
                    self._retained_hosts[token] = host

    def revoke(self, lease: CredentialLease) -> None:
        """Revoke one lease; any in-flight claim will fail its return fence."""
        if not isinstance(lease, CredentialLease):
            return
        with self._lock:
            record = self._leases.get(lease.lease_id)
            if record is not None and record.lease == lease:
                self._leases.pop(lease.lease_id, None)
                self._maybe_complete_close_locked()

    def owned_resources(self) -> tuple[str, ...]:
        """Return leases, provider calls, and hosts still owned by this broker."""
        with self._lock:
            resources = [
                f"credential-lease:{lease_id}" for lease_id in self._leases
            ]
            resources.extend(
                f"credential-session:{ref}"
                for ref in self._session_credentials
            )
            resources.extend(
                f"credential-materialization:{transaction_id}"
                for transaction_id in self._materializations
            )
            resources.extend(
                f"credential-provider-host:{host.pid}"
                for host in (*self._active_hosts.values(), *self._retained_hosts.values())
                if host.alive
            )
            return tuple(sorted(resources))

    def _any_host_alive_locked(self) -> bool:
        return any(
            host.alive
            for host in (*self._active_hosts.values(), *self._retained_hosts.values())
        )

    def terminal_postcondition(self) -> bool:
        """Prove that no lease or provider transaction remains owned."""
        with self._lock:
            return (
                not self._leases
                and not self._materializations
                and not self._session_credentials
            )

    def close(self) -> None:
        """Close admission without falsely claiming in-flight materialization is gone."""
        with self._lock:
            if self._closed:
                return
            self._closing = True
            self._leases.clear()
            self._session_credentials.clear()
            self._session_missing.clear()
            # Every owned provider host receives SIGTERM immediately; the
            # hosted workers finish the kill ladder and abort their
            # transactions, so a hung provider delays close by the bounded
            # termination grace, not by its full materialization deadline.
            # Retained (unproven-termination) hosts are re-signalled too.
            for host in (
                *self._active_hosts.values(),
                *self._retained_hosts.values(),
            ):
                host.request_termination()
            if self._materializations:
                self._quarantined = True
                return
            self._closed = True
            self._loaders.clear()
            self._credential_stores.clear()
            self._session_credentials.clear()
            self._session_missing.clear()
            self._secret_redactor.clear()
            self._quarantined = False
        # Already-submitted provider calls remain owned until they settle;
        # shutdown only rejects new submissions on the dedicated executor.
        self._provider_executor.shutdown(wait=False)

    async def aclose(self) -> None:
        """Async ResourceOwner adapter for runtime shutdown."""
        await asyncio.to_thread(self.close)

    @property
    def admission_closed(self) -> bool:
        return self.generation_admission_closed

    @property
    def generation_admission_closed(self) -> bool:
        with self._lock:
            return self._closing or self._closed

    @property
    def child_admission_closed(self) -> bool:
        with self._lock:
            return self._closing or self._closed

    @property
    def closed(self) -> bool:
        with self._lock:
            return self._closed

    @property
    def is_quarantined(self) -> bool:
        with self._lock:
            return self._quarantined

    @property
    def terminal_closed(self) -> bool:
        """Return true only after close and all owned transactions are terminal."""
        with self._lock:
            return (
                self._closed
                and not self._leases
                and not self._materializations
                and not self._session_credentials
                and not self._any_host_alive_locked()
            )

    def _reserve_materialization_locked(
        self,
        lease: CredentialLease,
        expected_binding: str,
        operation: str,
    ) -> tuple[_ProviderRecord, _MaterializationRecord]:
        """Validate a claim and register its transaction; caller holds the lock."""
        self._ensure_open()
        record = self._leases.get(lease.lease_id)
        if record is None or record.lease != lease:
            raise CredentialBrokerError("credential lease is unknown or revoked")
        if lease.authorized_operation != operation:
            raise CredentialBrokerError(
                "credential lease is bound to a different operation"
            )
        if lease.binding_digest != expected_binding:
            raise CredentialBrokerError("credential lease target binding changed")
        if (
            lease.generation != self._generation
            or lease.policy_digest != self.policy_digest
            or lease.principal_id != self.principal_id
        ):
            raise CredentialBrokerError("credential lease runtime binding changed")
        if lease.expires_at <= time.time():
            self._leases.pop(lease.lease_id, None)
            raise CredentialBrokerError("credential lease is expired")
        if lease.lease_id in self._materialization_by_lease:
            raise CredentialBrokerError("credential lease has already been claimed")
        transaction_id = secrets.token_urlsafe(24)
        transaction = _MaterializationRecord(
            transaction_id=transaction_id,
            lease_id=lease.lease_id,
            generation=lease.generation,
        )
        self._materializations[transaction_id] = transaction
        self._materialization_by_lease[lease.lease_id] = transaction_id
        return record.provider, transaction

    def _settle_materialization_locked(
        self,
        lease: CredentialLease,
        transaction: _MaterializationRecord,
        normalized: dict[str, str],
    ) -> dict[str, str]:
        """Re-check every fence after the loader returns; finish or fail closed."""
        current = self._leases.get(lease.lease_id)
        current_transaction = self._materializations.get(transaction.transaction_id)
        if current_transaction is not None and current_transaction.canceled:
            self._abort_materialization_locked(
                transaction.transaction_id, lease.lease_id
            )
            raise CredentialBrokerError(
                "credential materialization was canceled while the provider ran"
            )
        if current is None or current.lease != lease or current_transaction is None:
            self._abort_materialization_locked(
                transaction.transaction_id, lease.lease_id
            )
            raise CredentialBrokerError(
                "credential lease was revoked during materialization"
            )
        if self._closing or self._closed:
            self._abort_materialization_locked(
                transaction.transaction_id, lease.lease_id
            )
            raise CredentialBrokerError(
                "credential broker closed during materialization"
            )
        if transaction.generation != self._generation:
            self._abort_materialization_locked(
                transaction.transaction_id, lease.lease_id
            )
            raise CredentialBrokerError(
                "credential lease generation changed during materialization"
            )
        if lease.expires_at <= time.time():
            self._abort_materialization_locked(
                transaction.transaction_id, lease.lease_id
            )
            raise CredentialBrokerError(
                "credential lease expired during materialization"
            )
        # The operation and target digest were checked before the provider
        # call and the immutable lease still matches here.
        self._finish_materialization_locked(transaction.transaction_id, lease.lease_id)
        return normalized

    def _cancel_materialization(self, transaction_id: str) -> None:
        """Mark a transaction canceled under the broker lock.

        Every mutation of the materialization state table must hold the same
        broker mutex, including the cancel/timeout paths driven from async
        callbacks; this wrapper keeps that discipline in one place.
        """
        with self._lock:
            self._cancel_materialization_locked(transaction_id)

    def _cancel_materialization_locked(self, transaction_id: str) -> None:
        """Mark a transaction canceled; it stays owned until the worker settles."""
        transaction = self._materializations.get(transaction_id)
        if transaction is None or transaction.canceled:
            return
        self._materializations[transaction_id] = replace(transaction, canceled=True)

    @staticmethod
    def _reap_worker(worker: asyncio.Future[dict[str, str]]) -> None:
        """Retrieve worker exceptions so settled transactions never warn."""
        if not worker.cancelled():
            worker.exception()

    def _ensure_open(self) -> None:
        if self._closing or self._closed:
            raise CredentialBrokerError("credential broker is closed")

    def _issue_with_provider(
        self,
        scope: CredentialScope,
        provider: _ProviderRecord,
        *,
        binding: Mapping[str, object] | str,
        operation: str,
        ttl_seconds: float,
    ) -> CredentialLease:
        now = time.time()
        lease = CredentialLease(
            lease_id=secrets.token_urlsafe(24),
            scope=scope,
            authorized_operation=operation,
            binding_digest=credential_binding_digest(binding, operation),
            policy_digest=self.policy_digest,
            principal_id=self.principal_id,
            generation=self._generation,
            environment_schema_digest=provider.schema.digest(),
            issued_at=now,
            expires_at=now + ttl_seconds,
        )
        self._leases[lease.lease_id] = _LeaseRecord(lease=lease, provider=provider)
        return lease

    def _finish_materialization_locked(
        self, transaction_id: str, lease_id: str
    ) -> None:
        self._materializations.pop(transaction_id, None)
        if self._materialization_by_lease.get(lease_id) == transaction_id:
            self._materialization_by_lease.pop(lease_id, None)
        self._leases.pop(lease_id, None)
        self._maybe_complete_close_locked()

    def _abort_materialization_locked(
        self, transaction_id: str, lease_id: str
    ) -> None:
        self._materializations.pop(transaction_id, None)
        if self._materialization_by_lease.get(lease_id) == transaction_id:
            self._materialization_by_lease.pop(lease_id, None)
        self._leases.pop(lease_id, None)
        self._maybe_complete_close_locked()

    def _maybe_complete_close_locked(self) -> None:
        if (
            self._closing
            and not self._materializations
            and not self._leases
            and not self._any_host_alive_locked()
        ):
            self._closed = True
            self._loaders.clear()
            self._credential_stores.clear()
            self._session_credentials.clear()
            self._session_missing.clear()
            self._secret_redactor.clear()
            self._quarantined = False
            self._retained_hosts.clear()
            # Terminal: no owned provider call remains, so the dedicated
            # executor can stop accepting work without abandoning anything.
            self._provider_executor.shutdown(wait=False)

    @staticmethod
    def _validate_environment(
        environment: object, schema: CredentialEnvironmentSchema
    ) -> dict[str, str]:
        if not isinstance(environment, Mapping) or not environment:
            raise CredentialBrokerError("credential provider returned no material")
        normalized: dict[str, str] = {}
        for key, value in environment.items():
            if (
                type(key) is not str
                or key not in schema.allowed_keys
                or type(value) is not str
                or not value
                or "\x00" in key
                or "\x00" in value
            ):
                raise CredentialBrokerError(
                    "credential provider returned an environment key outside its schema"
                )
            try:
                value_size = len(value.encode("utf-8"))
            except UnicodeError as exc:
                raise CredentialBrokerError(
                    "credential provider returned invalid environment text"
                ) from exc
            if value_size > schema.max_value_bytes:
                raise CredentialBrokerError(
                    "credential provider returned an environment value over its bound"
                )
            normalized[key] = value
        if len(normalized) > schema.max_entries:
            raise CredentialBrokerError(
                "credential provider returned too many environment entries"
            )
        return normalized

    @staticmethod
    def _schema_for_scope(
        scope: CredentialScope,
        *,
        allowed_environment_keys: Iterable[str] | None = None,
        max_entries: int | None = None,
        max_value_bytes: int = MAX_PROVIDER_VALUE_BYTES,
    ) -> CredentialEnvironmentSchema:
        if allowed_environment_keys is not None:
            if isinstance(allowed_environment_keys, (str, bytes)):
                raise CredentialBrokerError(
                    "credential provider environment keys must be an iterable of names"
                )
            keys = frozenset(allowed_environment_keys)
            entries = len(keys) if max_entries is None else max_entries
            return CredentialEnvironmentSchema(keys, entries, max_value_bytes)
        if scope.provider == "github":
            return CredentialEnvironmentSchema(
                frozenset({"GH_TOKEN", "GITHUB_TOKEN"}),
                1 if max_entries is None else max_entries,
                max_value_bytes,
            )
        if scope.provider == "git" and scope.names == frozenset({"ssh-agent"}):
            return CredentialEnvironmentSchema(
                frozenset({"SSH_AUTH_SOCK"}),
                1 if max_entries is None else max_entries,
                max_value_bytes,
            )
        if scope.provider == "git" and scope.names == frozenset({"https-askpass"}):
            return CredentialEnvironmentSchema(
                frozenset({"GIT_ASKPASS", "GIT_USERNAME", "GIT_PASSWORD"}),
                3 if max_entries is None else max_entries,
                max_value_bytes,
            )
        raise CredentialBrokerError(
            "credential provider environment schema is required for this provider"
        )


__all__ = [
    "CredentialBroker",
    "CredentialBrokerError",
    "CredentialEnvironmentSchema",
    "CredentialHandle",
    "CredentialLease",
    "CredentialRef",
    "CredentialSession",
    "CredentialSessionError",
    "CredentialSessionLease",
    "CredentialSessionLocked",
    "CredentialSessionMissing",
    "CredentialStore",
    "CredentialStoreUnavailable",
    "CredentialUnlockCancelled",
    "SecretValue",
    "credential_binding_digest",
]
