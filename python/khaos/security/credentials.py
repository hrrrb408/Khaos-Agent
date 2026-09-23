"""Secretless provider credential primitives.

Provider configuration is intentionally made of opaque references and safe
metadata.  Secret material enters Khaos only through a :class:`CredentialStore`
owned by :class:`~khaos.security.credential_broker.CredentialBroker` and is
revealed at the HTTP transport boundary for one request.  This module does
not provide a plaintext-file or environment-variable fallback.

The in-memory store is test-only.  macOS uses the system Keychain through
Security.framework rather than the ``security`` command, so a credential is
never placed in an argv vector, a temporary file, or a subprocess environment.
Windows deliberately exposes an unavailable fail-closed backend until a
platform-native store is implemented. Linux uses the desktop Secret Service
through the system ``libsecret`` library when that service is available.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import hashlib
import hmac
import json
import logging
import re
import sys
import threading
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import NoReturn, Protocol, runtime_checkable

logger = logging.getLogger(__name__)


class CredentialAccessMode(StrEnum):
    """Authority mode for one credential-store operation.

    ``PROVISIONING`` is reserved for an explicit operator-facing setup path.
    Normal AgentLoop/provider transport code must use ``RUNTIME``; it is
    always non-interactive and therefore cannot open a desktop authorization
    sheet.
    """

    PROVISIONING = "provisioning"
    RUNTIME = "runtime"


def _validate_access_mode(access_mode: CredentialAccessMode) -> CredentialAccessMode:
    if not isinstance(access_mode, CredentialAccessMode):
        raise TypeError("credential access mode is invalid")
    return access_mode


@dataclass(frozen=True, slots=True)
class CredentialStoreDiagnostic:
    """Bounded native-store metadata safe for diagnostics and audit."""

    backend: str
    operation: str
    native_status: int | None
    category: str
    interaction_allowed: bool | None = None

    def __post_init__(self) -> None:
        for field_name in ("backend", "operation", "category"):
            value = getattr(self, field_name)
            if (
                not isinstance(value, str)
                or not value
                or len(value) > 64
                or not re.fullmatch(r"[A-Za-z0-9_.:-]+", value)
            ):
                raise ValueError(f"credential diagnostic {field_name} is invalid")
        if self.native_status is not None and (
            type(self.native_status) is not int
            or not -(2**31) <= self.native_status < 2**31
        ):
            raise ValueError("credential diagnostic native status is invalid")
        if self.interaction_allowed is not None and type(self.interaction_allowed) is not bool:
            raise ValueError("credential diagnostic interaction policy is invalid")

    def to_payload(self) -> dict[str, object]:
        """Return only bounded, non-secret fields for durable output."""
        payload: dict[str, object] = {
            "backend": self.backend,
            "operation": self.operation,
            "native_status": self.native_status,
            "category": self.category,
        }
        if self.interaction_allowed is not None:
            payload["interaction_allowed"] = self.interaction_allowed
        return payload


class CredentialStoreError(RuntimeError):
    """Base class for credential-store failures without secret details."""

    def __init__(
        self,
        message: str,
        *,
        diagnostic: CredentialStoreDiagnostic | None = None,
    ) -> None:
        super().__init__(message)
        self.diagnostic = diagnostic

    def safe_metadata(self) -> dict[str, object]:
        """Return safe error metadata without native text or credential data."""
        payload: dict[str, object] = {"error_type": type(self).__name__}
        if self.diagnostic is not None:
            payload["diagnostic"] = self.diagnostic.to_payload()
        return payload


class CredentialNotFound(CredentialStoreError):
    """The requested opaque reference has no stored credential."""


class CredentialStoreUnavailable(CredentialStoreError):
    """The platform credential backend is unavailable or cannot be trusted."""


class CredentialProvisioningCancelled(CredentialStoreError):
    """An operator cancelled an explicit interactive provisioning operation."""


class CredentialReferenceError(ValueError):
    """An opaque credential reference is malformed or provider-mismatched."""


_PROVIDER_NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}\Z")
_OPAQUE_REFERENCE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
_CREDENTIAL_REFERENCE_PREFIX = "khaos/providers/"
_REDACTED = "[REDACTED]"
_MAX_SECRET_BYTES = 64 * 1024


@dataclass(frozen=True, slots=True)
class CredentialRef:
    """An opaque, provider-bound identifier with no credential material."""

    provider: str
    value: str

    def __post_init__(self) -> None:
        provider = self.provider.casefold() if isinstance(self.provider, str) else ""
        if not _PROVIDER_NAME.fullmatch(provider):
            raise CredentialReferenceError("credential provider name is invalid")
        if not isinstance(self.value, str) or not _OPAQUE_REFERENCE.fullmatch(self.value):
            raise CredentialReferenceError("credential reference is invalid")
        if ".." in self.value or "//" in self.value:
            raise CredentialReferenceError("credential reference contains traversal")
        if not self.value.startswith(f"{_CREDENTIAL_REFERENCE_PREFIX}{provider}/"):
            raise CredentialReferenceError("credential reference is not bound to provider")
        object.__setattr__(self, "provider", provider)

    @classmethod
    def for_provider(cls, provider: str, name: str = "default") -> CredentialRef:
        """Create the canonical opaque reference for one provider slot."""
        normalized = provider.casefold() if isinstance(provider, str) else ""
        if not _PROVIDER_NAME.fullmatch(normalized):
            raise CredentialReferenceError("credential provider name is invalid")
        if not isinstance(name, str) or not _OPAQUE_REFERENCE.fullmatch(name):
            raise CredentialReferenceError("credential reference name is invalid")
        if "/" in name or ".." in name:
            raise CredentialReferenceError("credential reference name is invalid")
        return cls(normalized, f"{_CREDENTIAL_REFERENCE_PREFIX}{normalized}/{name}")

    @classmethod
    def from_config(cls, provider: str, value: object) -> CredentialRef:
        """Parse a serialized reference and bind it to the expected provider."""
        if not isinstance(value, str):
            raise CredentialReferenceError("credential_ref must be an opaque string")
        return cls(provider.casefold(), value)

    def __str__(self) -> str:
        return self.value

    def __repr__(self) -> str:
        return f"CredentialRef(provider={self.provider!r}, value={self.value!r})"

    def to_config(self) -> str:
        """Return the only representation allowed in normal configuration."""
        return self.value


class _SecretCapability:
    """Unexported capability used only by trusted store/transport code."""


_STORE_CAPABILITY = _SecretCapability()
_TRANSPORT_CAPABILITY = _SecretCapability()


class SecretValue:
    """Defensive wrapper that cannot accidentally stringify a secret.

    Python cannot guarantee memory zeroization against a same-process attacker;
    the wrapper instead makes ordinary logging, repr, JSON, YAML, and pickle
    paths fail safe.  Only the broker's private transport capability can
    reveal the value, and the value is never returned by a public Khaos API.
    """

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        if not isinstance(value, str) or not value:
            raise ValueError("credential secret must be a non-empty string")
        if "\x00" in value:
            raise ValueError("credential secret contains NUL")
        if len(value.encode("utf-8")) > _MAX_SECRET_BYTES:
            raise ValueError("credential secret exceeds the bounded size")
        self._value = value

    def __str__(self) -> str:
        return _REDACTED

    def __repr__(self) -> str:
        return "SecretValue([REDACTED])"

    def __format__(self, _format_spec: str) -> str:
        return _REDACTED

    def __bytes__(self) -> bytes:
        raise TypeError("secret bytes are available only at the transport boundary")

    def __reduce__(self):
        raise TypeError("SecretValue cannot be serialized")

    def __getstate__(self):
        raise TypeError("SecretValue cannot be serialized")

    def _reveal_for_store(self, capability: object) -> str:
        if capability is not _STORE_CAPABILITY:
            raise PermissionError("secret store capability required")
        return self._value

    def _reveal_for_transport(self, capability: object) -> str:
        if capability is not _TRANSPORT_CAPABILITY:
            raise PermissionError("transport capability required")
        return self._value

    def matches(self, other: SecretValue) -> bool:
        """Compare two wrapped values without exposing either value."""
        if not isinstance(other, SecretValue):
            return False
        return hmac.compare_digest(self._value, other._value)


@dataclass(frozen=True, slots=True)
class CredentialHandle:
    """Short-lived, binding-scoped provider handle with no secret material."""

    provider: str
    ref: CredentialRef
    operation: str
    binding_digest: str
    broker_id: str
    issued_at: datetime
    expires_at: datetime
    access_mode: CredentialAccessMode = CredentialAccessMode.RUNTIME
    session_generation: int | None = None

    def __post_init__(self) -> None:
        if self.provider != self.ref.provider:
            raise CredentialReferenceError("credential handle provider mismatch")
        if not self.operation or len(self.operation) > 128:
            raise ValueError("credential handle operation is invalid")
        if not re.fullmatch(r"[0-9a-f]{64}", self.binding_digest):
            raise ValueError("credential handle binding digest is invalid")
        if not self.broker_id or len(self.broker_id) > 128:
            raise ValueError("credential handle broker id is invalid")
        if self.expires_at <= self.issued_at:
            raise ValueError("credential handle expiry is invalid")
        _validate_access_mode(self.access_mode)
        if self.session_generation is not None and (
            type(self.session_generation) is not int or self.session_generation <= 0
        ):
            raise ValueError("credential handle session generation is invalid")

    @property
    def expired(self) -> bool:
        return self.expires_at <= datetime.now(UTC)

    def summary(self) -> dict[str, object]:
        """Return metadata safe for logs, audit, and model-independent reports."""
        return {
            "provider": self.provider,
            "credential_ref": self.ref.value,
            "operation": self.operation,
            "binding_digest": self.binding_digest,
            "broker_id": self.broker_id,
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "access_mode": self.access_mode.value,
            "session_generation": self.session_generation,
        }

    def __repr__(self) -> str:
        return (
            "CredentialHandle("
            f"provider={self.provider!r}, ref={self.ref.value!r}, "
            f"operation={self.operation!r}, expires_at={self.expires_at.isoformat()!r})"
        )


@runtime_checkable
class CredentialStore(Protocol):
    """Platform credential-store interface owned by the trusted broker."""

    backend_name: str

    def put(
        self,
        ref: CredentialRef,
        secret: SecretValue,
        *,
        access_mode: CredentialAccessMode = CredentialAccessMode.RUNTIME,
    ) -> None:
        """Create or replace one credential without exposing its value."""
        ...

    def get(
        self,
        ref: CredentialRef,
        *,
        access_mode: CredentialAccessMode = CredentialAccessMode.RUNTIME,
    ) -> SecretValue:
        """Load one credential for broker-controlled transport use."""
        ...

    def exists(
        self,
        ref: CredentialRef,
        *,
        access_mode: CredentialAccessMode = CredentialAccessMode.RUNTIME,
    ) -> bool:
        """Return presence without returning credential material."""
        ...

    def delete(
        self,
        ref: CredentialRef,
        *,
        access_mode: CredentialAccessMode = CredentialAccessMode.RUNTIME,
    ) -> None:
        """Delete one credential; absence is idempotent."""
        ...


class InMemoryCredentialStore:
    """Explicit test-only store; never selected by production factories."""

    backend_name = "memory-test-only"
    requires_session_unlock = False

    def __init__(self) -> None:
        self._values: dict[CredentialRef, SecretValue] = {}

    def put(
        self,
        ref: CredentialRef,
        secret: SecretValue,
        *,
        access_mode: CredentialAccessMode = CredentialAccessMode.RUNTIME,
    ) -> None:
        _validate_access_mode(access_mode)
        _validate_secret_pair(ref, secret)
        self._values[ref] = secret

    def get(
        self,
        ref: CredentialRef,
        *,
        access_mode: CredentialAccessMode = CredentialAccessMode.RUNTIME,
    ) -> SecretValue:
        _validate_access_mode(access_mode)
        try:
            return self._values[ref]
        except KeyError as exc:
            raise CredentialNotFound("credential reference is not present") from exc

    def exists(
        self,
        ref: CredentialRef,
        *,
        access_mode: CredentialAccessMode = CredentialAccessMode.RUNTIME,
    ) -> bool:
        _validate_access_mode(access_mode)
        return ref in self._values

    def delete(
        self,
        ref: CredentialRef,
        *,
        access_mode: CredentialAccessMode = CredentialAccessMode.RUNTIME,
    ) -> None:
        _validate_access_mode(access_mode)
        self._values.pop(ref, None)

    def __repr__(self) -> str:
        return f"InMemoryCredentialStore(entries={len(self._values)})"


class UnavailableCredentialStore:
    """Fail-closed placeholder for unsupported platform backends."""

    backend_name = "unavailable"
    requires_session_unlock = False

    def __init__(
        self,
        reason: str = "platform credential store is unavailable",
        *,
        diagnostic: CredentialStoreDiagnostic | None = None,
    ) -> None:
        self._reason = reason
        self._diagnostic = diagnostic

    def _fail(self) -> NoReturn:
        raise CredentialStoreUnavailable(self._reason, diagnostic=self._diagnostic)

    def put(
        self,
        ref: CredentialRef,
        secret: SecretValue,
        *,
        access_mode: CredentialAccessMode = CredentialAccessMode.RUNTIME,
    ) -> None:
        del ref, secret
        _validate_access_mode(access_mode)
        self._fail()

    def get(
        self,
        ref: CredentialRef,
        *,
        access_mode: CredentialAccessMode = CredentialAccessMode.RUNTIME,
    ) -> SecretValue:
        del ref
        _validate_access_mode(access_mode)
        self._fail()
        raise AssertionError("unreachable")

    def exists(
        self,
        ref: CredentialRef,
        *,
        access_mode: CredentialAccessMode = CredentialAccessMode.RUNTIME,
    ) -> bool:
        del ref
        _validate_access_mode(access_mode)
        self._fail()

    def delete(
        self,
        ref: CredentialRef,
        *,
        access_mode: CredentialAccessMode = CredentialAccessMode.RUNTIME,
    ) -> None:
        del ref
        _validate_access_mode(access_mode)
        self._fail()

    def __repr__(self) -> str:
        return "UnavailableCredentialStore()"


class LinuxSecretServiceCredentialStore:
    """Linux Secret Service store backed by the system ``libsecret`` ABI.

    The store uses libsecret's bounded synchronous API rather than invoking a
    command-line helper. Attribute names and values are non-secret lookup
    metadata; the provider credential is passed only as the password argument
    at the native Secret Service boundary. The Broker still requires an
    explicit session unlock before runtime transport can use the credential.
    """

    backend_name = "linux-secret-service"
    requires_session_unlock = True
    _attribute_provider = "khaos-provider"
    _attribute_reference = "khaos-reference"
    _label_prefix = "Khaos provider credential: "
    _library_candidates = (
        "libsecret-1.so.0",
        "libsecret-1.so",
    )

    def __init__(self) -> None:
        if not sys.platform.startswith("linux"):
            raise CredentialStoreUnavailable(
                "Linux Secret Service is unavailable on this platform",
                diagnostic=CredentialStoreDiagnostic(
                    backend=self.backend_name,
                    operation="INITIALIZE",
                    native_status=None,
                    category="UNSUPPORTED_PLATFORM",
                ),
            )
        self._library_lock = threading.RLock()
        self._secret_library: ctypes.CDLL | None = None
        self._glib_library: ctypes.CDLL | None = None

    @classmethod
    def backend_audit(cls) -> dict[str, object]:
        """Return static Secret Service metadata without reading a secret."""
        return {
            "backend": cls.backend_name,
            "api": "libsecret-secret-service",
            "collection": "default",
            "attributes": (cls._attribute_provider, cls._attribute_reference),
            "runtime_authentication_ui": "FAIL_CLOSED",
            "provisioning_authentication_ui": "ALLOW",
            "session_unlock": True,
            "secret_material_in_argv": False,
            "secret_material_in_environment": False,
        }

    def _diagnostic(
        self,
        operation: str,
        category: str,
        access_mode: CredentialAccessMode = CredentialAccessMode.RUNTIME,
    ) -> CredentialStoreDiagnostic:
        mode = _validate_access_mode(access_mode)
        return CredentialStoreDiagnostic(
            backend=self.backend_name,
            operation=operation,
            native_status=None,
            category=category,
            interaction_allowed=mode is CredentialAccessMode.PROVISIONING,
        )

    def _libraries(self) -> tuple[ctypes.CDLL, ctypes.CDLL]:
        """Load and configure the system libsecret and GLib entry points."""
        with self._library_lock:
            if self._secret_library is not None and self._glib_library is not None:
                return self._secret_library, self._glib_library

            loaded_secret: ctypes.CDLL | None = None
            for candidate in self._library_candidates:
                try:
                    loaded_secret = ctypes.CDLL(candidate)
                except OSError:
                    continue
                break
            if loaded_secret is None:
                discovered = ctypes.util.find_library("secret-1")
                if discovered:
                    try:
                        loaded_secret = ctypes.CDLL(discovered)
                    except OSError:
                        loaded_secret = None
            if loaded_secret is None:
                raise CredentialStoreUnavailable(
                    "Linux Secret Service library is unavailable",
                    diagnostic=self._diagnostic(
                        "LOAD_LIBRARY", "LIBRARY_UNAVAILABLE"
                    ),
                )

            discovered_glib = ctypes.util.find_library("glib-2.0")
            glib_candidates = (
                discovered_glib,
                "libglib-2.0.so.0",
                "libglib-2.0.so",
            )
            loaded_glib: ctypes.CDLL | None = None
            for candidate in glib_candidates:
                if not candidate:
                    continue
                try:
                    loaded_glib = ctypes.CDLL(candidate)
                except OSError:
                    continue
                break
            if loaded_glib is None:
                raise CredentialStoreUnavailable(
                    "Linux Secret Service GLib library is unavailable",
                    diagnostic=self._diagnostic("LOAD_GLIB", "LIBRARY_UNAVAILABLE"),
                )

            try:
                loaded_secret.secret_password_storev_sync.argtypes = [
                    ctypes.c_void_p,
                    ctypes.c_void_p,
                    ctypes.c_char_p,
                    ctypes.c_char_p,
                    ctypes.c_char_p,
                    ctypes.c_void_p,
                    ctypes.POINTER(ctypes.c_void_p),
                ]
                loaded_secret.secret_password_storev_sync.restype = ctypes.c_int
                loaded_secret.secret_password_lookupv_sync.argtypes = [
                    ctypes.c_void_p,
                    ctypes.c_void_p,
                    ctypes.c_void_p,
                    ctypes.POINTER(ctypes.c_void_p),
                ]
                loaded_secret.secret_password_lookupv_sync.restype = ctypes.c_void_p
                loaded_secret.secret_password_clearv_sync.argtypes = [
                    ctypes.c_void_p,
                    ctypes.c_void_p,
                    ctypes.c_void_p,
                    ctypes.POINTER(ctypes.c_void_p),
                ]
                loaded_secret.secret_password_clearv_sync.restype = ctypes.c_int
                loaded_secret.secret_password_free.argtypes = [ctypes.c_void_p]
                loaded_secret.secret_password_free.restype = None
                loaded_glib.g_hash_table_new.argtypes = [
                    ctypes.c_void_p,
                    ctypes.c_void_p,
                ]
                loaded_glib.g_hash_table_new.restype = ctypes.c_void_p
                loaded_glib.g_hash_table_insert.argtypes = [
                    ctypes.c_void_p,
                    ctypes.c_void_p,
                    ctypes.c_void_p,
                ]
                loaded_glib.g_hash_table_insert.restype = None
                loaded_glib.g_hash_table_unref.argtypes = [ctypes.c_void_p]
                loaded_glib.g_hash_table_unref.restype = None
                loaded_glib.g_error_free.argtypes = [ctypes.c_void_p]
                loaded_glib.g_error_free.restype = None
            except AttributeError as exc:
                raise CredentialStoreUnavailable(
                    "Linux Secret Service ABI is unavailable",
                    diagnostic=self._diagnostic("CONFIGURE_ABI", "ABI_UNAVAILABLE"),
                ) from exc

            self._secret_library = loaded_secret
            self._glib_library = loaded_glib
            return loaded_secret, loaded_glib

    def _attributes(
        self,
        ref: CredentialRef,
        glib: ctypes.CDLL,
    ) -> tuple[object, list[object]]:
        """Build a native attribute table and retain its backing buffers."""
        try:
            hash_function = ctypes.cast(glib.g_str_hash, ctypes.c_void_p)
            equal_function = ctypes.cast(glib.g_str_equal, ctypes.c_void_p)
            table = glib.g_hash_table_new(hash_function, equal_function)
        except (AttributeError, OSError, TypeError, ValueError) as exc:
            raise CredentialStoreUnavailable(
                "Linux Secret Service attribute table is unavailable",
                diagnostic=self._diagnostic("ATTRIBUTES", "ABI_UNAVAILABLE"),
            ) from exc
        if not table:
            raise CredentialStoreUnavailable(
                "Linux Secret Service attribute table could not be created",
                diagnostic=self._diagnostic("ATTRIBUTES", "ALLOCATION_FAILED"),
            )

        buffers: list[object] = []
        try:
            for key, value in (
                (self._attribute_provider, ref.provider),
                (self._attribute_reference, ref.value),
            ):
                key_buffer = ctypes.create_string_buffer(key.encode("utf-8"))
                value_buffer = ctypes.create_string_buffer(value.encode("utf-8"))
                buffers.extend((key_buffer, value_buffer))
                glib.g_hash_table_insert(
                    table,
                    ctypes.cast(key_buffer, ctypes.c_void_p),
                    ctypes.cast(value_buffer, ctypes.c_void_p),
                )
        except (AttributeError, OSError, TypeError, ValueError) as exc:
            self._release_table(glib, table)
            raise CredentialStoreUnavailable(
                "Linux Secret Service attribute table is invalid",
                diagnostic=self._diagnostic("ATTRIBUTES", "ABI_UNAVAILABLE"),
            ) from exc
        return table, buffers

    @staticmethod
    def _free_error(glib: ctypes.CDLL, error: ctypes.c_void_p) -> None:
        if error:
            try:
                glib.g_error_free(error)
            except (AttributeError, OSError, TypeError):
                pass

    @staticmethod
    def _release_table(glib: ctypes.CDLL, table: object) -> None:
        if not table:
            return
        try:
            glib.g_hash_table_unref(table)
        except (AttributeError, OSError, TypeError):
            logger.warning("Linux Secret Service attribute table cleanup failed")

    def put(
        self,
        ref: CredentialRef,
        secret: SecretValue,
        *,
        access_mode: CredentialAccessMode = CredentialAccessMode.RUNTIME,
    ) -> None:
        mode = _validate_access_mode(access_mode)
        _validate_secret_pair(ref, secret)
        library, glib = self._libraries()
        table, buffers = self._attributes(ref, glib)
        error = ctypes.c_void_p()
        secret_buffer = ctypes.create_string_buffer(
            secret._reveal_for_store(_STORE_CAPABILITY).encode("utf-8")
        )
        label = f"{self._label_prefix}{ref.provider}".encode()
        succeeded = False
        try:
            try:
                succeeded = bool(
                    library.secret_password_storev_sync(
                        None,
                        table,
                        None,
                        label,
                        ctypes.cast(secret_buffer, ctypes.c_char_p),
                        None,
                        ctypes.byref(error),
                    )
                )
            except (OSError, TypeError, ValueError) as exc:
                self._free_error(glib, error)
                raise CredentialStoreUnavailable(
                    "Linux Secret Service write failed",
                    diagnostic=self._diagnostic("PUT", "ABI_ERROR", mode),
                ) from exc
        finally:
            self._release_table(glib, table)
            del buffers
        self._free_error(glib, error)
        if not succeeded:
            raise CredentialStoreUnavailable(
                "Linux Secret Service write failed",
                diagnostic=self._diagnostic("PUT", "SERVICE_ERROR", mode),
            )

    def get(
        self,
        ref: CredentialRef,
        *,
        access_mode: CredentialAccessMode = CredentialAccessMode.RUNTIME,
    ) -> SecretValue:
        mode = _validate_access_mode(access_mode)
        if not isinstance(ref, CredentialRef):
            raise TypeError("credential stores accept CredentialRef and SecretValue only")
        library, glib = self._libraries()
        table, buffers = self._attributes(ref, glib)
        error = ctypes.c_void_p()
        result = None
        try:
            try:
                result = library.secret_password_lookupv_sync(
                    None,
                    table,
                    None,
                    ctypes.byref(error),
                )
            except (OSError, TypeError, ValueError) as exc:
                self._free_error(glib, error)
                raise CredentialStoreUnavailable(
                    "Linux Secret Service read failed",
                    diagnostic=self._diagnostic("GET", "ABI_ERROR", mode),
                ) from exc
        finally:
            self._release_table(glib, table)
            del buffers
        if error:
            if result:
                library.secret_password_free(result)
            self._free_error(glib, error)
            raise CredentialStoreUnavailable(
                "Linux Secret Service read failed",
                diagnostic=self._diagnostic("GET", "SERVICE_ERROR", mode),
            )
        if not result:
            raise CredentialNotFound(
                "credential reference is not present",
                diagnostic=self._diagnostic("GET", "ITEM_NOT_FOUND", mode),
            )
        try:
            raw = ctypes.string_at(result)
        finally:
            library.secret_password_free(result)
        try:
            return SecretValue(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise CredentialStoreUnavailable(
                "Linux Secret Service credential encoding is invalid",
                diagnostic=self._diagnostic("GET", "INVALID_ENCODING", mode),
            ) from exc

    def exists(
        self,
        ref: CredentialRef,
        *,
        access_mode: CredentialAccessMode = CredentialAccessMode.RUNTIME,
    ) -> bool:
        try:
            self.get(ref, access_mode=access_mode)
        except CredentialNotFound:
            return False
        return True

    def delete(
        self,
        ref: CredentialRef,
        *,
        access_mode: CredentialAccessMode = CredentialAccessMode.RUNTIME,
    ) -> None:
        mode = _validate_access_mode(access_mode)
        if not isinstance(ref, CredentialRef):
            raise TypeError("credential stores accept CredentialRef and SecretValue only")
        library, glib = self._libraries()
        table, buffers = self._attributes(ref, glib)
        error = ctypes.c_void_p()
        succeeded = False
        try:
            try:
                succeeded = bool(
                    library.secret_password_clearv_sync(
                        None,
                        table,
                        None,
                        ctypes.byref(error),
                    )
                )
            except (OSError, TypeError, ValueError) as exc:
                self._free_error(glib, error)
                raise CredentialStoreUnavailable(
                    "Linux Secret Service delete failed",
                    diagnostic=self._diagnostic("DELETE", "ABI_ERROR", mode),
                ) from exc
        finally:
            self._release_table(glib, table)
            del buffers
        self._free_error(glib, error)
        if not succeeded:
            raise CredentialStoreUnavailable(
                "Linux Secret Service delete failed",
                diagnostic=self._diagnostic("DELETE", "SERVICE_ERROR", mode),
            )

    def __repr__(self) -> str:
        return "LinuxSecretServiceCredentialStore(backend='linux-secret-service')"


class MacOSKeychainCredentialStore:
    """Native macOS generic-password store backed by Security.framework."""

    backend_name = "macos-keychain"
    # Keychain persistence is protected at rest, while runtime use is served
    # from the trusted Broker session after one explicit operator unlock.
    requires_session_unlock = True
    service_name = "com.khaos.agent.credentials"
    _ERR_SUCCESS = 0
    _ERR_DUPLICATE = -25299
    _ERR_NOT_FOUND = -25300
    _interaction_lock = threading.RLock()

    def __init__(self, *, service_name: str | None = None) -> None:
        if sys.platform != "darwin":
            raise CredentialStoreUnavailable(
                "macOS Keychain is unavailable on this platform",
                diagnostic=CredentialStoreDiagnostic(
                    backend=self.backend_name,
                    operation="INITIALIZE",
                    native_status=None,
                    category="UNSUPPORTED_PLATFORM",
                ),
            )
        self.service_name = service_name or self.service_name
        if not self.service_name or "\x00" in self.service_name:
            raise ValueError("Keychain service name is invalid")

    @staticmethod
    def _library():
        try:
            return ctypes.CDLL(
                "/System/Library/Frameworks/Security.framework/Security"
            )
        except OSError as exc:
            raise CredentialStoreUnavailable(
                "macOS Keychain Security.framework is unavailable",
                diagnostic=CredentialStoreDiagnostic(
                    backend=MacOSKeychainCredentialStore.backend_name,
                    operation="LOAD_FRAMEWORK",
                    native_status=None,
                    category="FRAMEWORK_UNAVAILABLE",
                ),
            ) from exc

    @classmethod
    def _set_interaction_allowed(cls, library, allowed: bool) -> None:
        """Set the process-global legacy Keychain interaction policy safely."""
        set_interaction = getattr(
            library, "SecKeychainSetUserInteractionAllowed", None
        )
        if set_interaction is None:
            raise CredentialStoreUnavailable(
                "macOS Keychain interaction policy is unavailable",
                diagnostic=CredentialStoreDiagnostic(
                    backend=cls.backend_name,
                    operation="CONFIGURE_INTERACTION",
                    native_status=None,
                    category="INTERACTION_POLICY_UNAVAILABLE",
                    interaction_allowed=None,
                ),
            )
        set_interaction.argtypes = [ctypes.c_bool]
        set_interaction.restype = ctypes.c_int32
        try:
            status = int(set_interaction(bool(allowed)))
        except (OSError, TypeError, ValueError) as exc:
            raise CredentialStoreUnavailable(
                "macOS Keychain interaction policy could not be configured",
                diagnostic=CredentialStoreDiagnostic(
                    backend=cls.backend_name,
                    operation="CONFIGURE_INTERACTION",
                    native_status=None,
                    category="INTERACTION_POLICY_UNAVAILABLE",
                    interaction_allowed=None,
                ),
            ) from exc
        if status != cls._ERR_SUCCESS:
            raise CredentialStoreUnavailable(
                "macOS Keychain interaction policy could not be configured",
                diagnostic=_native_diagnostic(
                    "CONFIGURE_INTERACTION",
                    status,
                    interaction_allowed=allowed,
                ),
            )

    @classmethod
    @contextmanager
    def _interaction_scope(
        cls,
        library,
        access_mode: CredentialAccessMode,
    ) -> Iterator[None]:
        """Serialize and bound the process-global Keychain UI policy.

        The provisioning path is the only path allowed to set the policy to
        ``True``.  Every scope restores ``False`` before releasing the lock so
        a later runtime operation cannot inherit interactive behavior.
        """
        mode = _validate_access_mode(access_mode)
        with cls._interaction_lock:
            cls._set_interaction_allowed(
                library, mode is CredentialAccessMode.PROVISIONING
            )
            try:
                yield
            finally:
                cls._set_interaction_allowed(library, False)

    def _find(
        self,
        ref: CredentialRef,
        *,
        access_mode: CredentialAccessMode = CredentialAccessMode.RUNTIME,
    ):
        mode = _validate_access_mode(access_mode)
        service = self.service_name.encode("utf-8")
        account = ref.value.encode("utf-8")
        password_length = ctypes.c_uint32(0)
        password_data = ctypes.c_void_p()
        item = ctypes.c_void_p()
        library = self._library()
        find = library.SecKeychainFindGenericPassword
        find.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_char_p,
            ctypes.c_uint32,
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_void_p),
        ]
        find.restype = ctypes.c_int32
        try:
            with self._interaction_scope(library, mode):
                status = int(
                    find(
                        None,
                        len(service),
                        service,
                        len(account),
                        account,
                        ctypes.byref(password_length),
                        ctypes.byref(password_data),
                        ctypes.byref(item),
                    )
                )
        except (CredentialStoreError, OSError, TypeError, ValueError):
            self._free_content(library, password_data)
            if item:
                self._release_item(library, item)
            raise
        return library, status, password_length, password_data, item

    @staticmethod
    def _free_content(library, password_data: ctypes.c_void_p) -> None:
        if not password_data:
            return
        free_content = library.SecKeychainItemFreeContent
        free_content.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        free_content.restype = ctypes.c_int32
        free_content(None, password_data)

    def put(
        self,
        ref: CredentialRef,
        secret: SecretValue,
        *,
        access_mode: CredentialAccessMode = CredentialAccessMode.RUNTIME,
    ) -> None:
        mode = _validate_access_mode(access_mode)
        _validate_secret_pair(ref, secret)
        value = secret._reveal_for_store(_STORE_CAPABILITY).encode("utf-8")
        service = self.service_name.encode("utf-8")
        account = ref.value.encode("utf-8")
        library = self._library()
        add = library.SecKeychainAddGenericPassword
        add.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_char_p,
            ctypes.c_uint32,
            ctypes.c_char_p,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        add.restype = ctypes.c_int32
        item = ctypes.c_void_p()
        password = ctypes.create_string_buffer(value)
        try:
            with self._interaction_scope(library, mode):
                status = int(
                    add(
                        None,
                        len(service),
                        service,
                        len(account),
                        account,
                        len(value),
                        ctypes.cast(password, ctypes.c_void_p),
                        ctypes.byref(item),
                    )
                )
        finally:
            if item:
                self._release_item(library, item)
        if status == self._ERR_SUCCESS:
            return
        if status != self._ERR_DUPLICATE:
            raise _native_store_failure(
                "macOS Keychain write failed", "PUT", status, access_mode=mode
            )

        found_library, find_status, _length, _data, existing = self._find(
            ref, access_mode=mode
        )
        self._free_content(found_library, _data)
        if find_status != self._ERR_SUCCESS or not existing:
            if existing:
                self._release_item(found_library, existing)
            raise _native_store_failure(
                "macOS Keychain update lookup failed",
                "UPDATE_LOOKUP",
                find_status,
                access_mode=mode,
            )
        modify = found_library.SecKeychainItemModifyContent
        modify.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_void_p,
        ]
        modify.restype = ctypes.c_int32
        try:
            with self._interaction_scope(found_library, mode):
                update_status = int(
                    modify(
                        existing,
                        None,
                        len(value),
                        ctypes.cast(password, ctypes.c_void_p),
                    )
                )
        finally:
            release = getattr(found_library, "CFRelease", None)
            if release is not None:
                release.argtypes = [ctypes.c_void_p]
                release.restype = None
                release(existing)
        if update_status != self._ERR_SUCCESS:
            raise _native_store_failure(
                "macOS Keychain update failed",
                "UPDATE",
                update_status,
                access_mode=mode,
            )

    def get(
        self,
        ref: CredentialRef,
        *,
        access_mode: CredentialAccessMode = CredentialAccessMode.RUNTIME,
    ) -> SecretValue:
        mode = _validate_access_mode(access_mode)
        library, status, length, data, item = self._find(ref, access_mode=mode)
        try:
            if status == self._ERR_NOT_FOUND:
                raise CredentialNotFound(
                    "credential reference is not present",
                    diagnostic=_native_diagnostic("GET", status, access_mode=mode),
                )
            if status != self._ERR_SUCCESS or not data:
                raise _native_store_failure(
                    "macOS Keychain read failed", "GET", status, access_mode=mode
                )
            raw = ctypes.string_at(data, int(length.value))
        finally:
            self._free_content(library, data)
            if item:
                release = getattr(library, "CFRelease", None)
                if release is not None:
                    release.argtypes = [ctypes.c_void_p]
                    release.restype = None
                    release(item)
        try:
            return SecretValue(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise CredentialStoreUnavailable(
                "macOS Keychain credential encoding is invalid",
                diagnostic=_native_diagnostic(
                    "GET",
                    self._ERR_SUCCESS,
                    category="INVALID_ENCODING",
                    access_mode=mode,
                ),
            ) from exc

    def exists(
        self,
        ref: CredentialRef,
        *,
        access_mode: CredentialAccessMode = CredentialAccessMode.RUNTIME,
    ) -> bool:
        mode = _validate_access_mode(access_mode)
        library, status, _length, data, item = self._find(ref, access_mode=mode)
        self._free_content(library, data)
        if item:
            release = getattr(library, "CFRelease", None)
            if release is not None:
                release.argtypes = [ctypes.c_void_p]
                release.restype = None
                release(item)
        if status == self._ERR_NOT_FOUND:
            return False
        if status != self._ERR_SUCCESS:
            raise _native_store_failure(
                "macOS Keychain presence check failed",
                "EXISTS",
                status,
                access_mode=mode,
            )
        return True

    def delete(
        self,
        ref: CredentialRef,
        *,
        access_mode: CredentialAccessMode = CredentialAccessMode.RUNTIME,
    ) -> None:
        mode = _validate_access_mode(access_mode)
        library, status, length, data, item = self._find(ref, access_mode=mode)
        self._free_content(library, data)
        del length
        if status == self._ERR_NOT_FOUND:
            if item:
                self._release_item(library, item)
            return
        if status != self._ERR_SUCCESS or not item:
            raise _native_store_failure(
                "macOS Keychain lookup failed",
                "DELETE_LOOKUP",
                status,
                access_mode=mode,
            )
        try:
            delete = library.SecKeychainItemDelete
            delete.argtypes = [ctypes.c_void_p]
            delete.restype = ctypes.c_int32
            with self._interaction_scope(library, mode):
                delete_status = int(delete(item))
        finally:
            self._release_item(library, item)
        if delete_status != self._ERR_SUCCESS:
            raise _native_store_failure(
                "macOS Keychain delete failed",
                "DELETE",
                delete_status,
                access_mode=mode,
            )

    @staticmethod
    def _release_item(library, item: ctypes.c_void_p) -> None:
        release = getattr(library, "CFRelease", None)
        if release is not None:
            release.argtypes = [ctypes.c_void_p]
            release.restype = None
            release(item)

    @classmethod
    def backend_audit(cls) -> dict[str, object]:
        """Return the static, secretless audit of the current native backend.

        The implementation remains on the legacy generic password API for the
        local-first path. Data Protection Keychain migration is optional future
        hardening for packaged builds; this method performs no Keychain query
        and cannot trigger UI.
        """
        return {
            "backend": cls.backend_name,
            "api": "legacy-SecKeychain",
            "data_protection_keychain": False,
            "accessibility": "UNSPECIFIED_LEGACY",
            "access_control": "NONE",
            "user_presence": False,
            "synchronizable": False,
            "access_group": None,
            "interaction_policy_api": "SecKeychainSetUserInteractionAllowed",
            "runtime_authentication_ui": "FAIL",
            "provisioning_authentication_ui": "ALLOW",
            "data_protection_decision": "OPTIONAL_FUTURE_HARDENING",
        }

    def __repr__(self) -> str:
        return "MacOSKeychainCredentialStore(backend='macos-keychain')"


def build_platform_credential_store() -> CredentialStore:
    """Return the native store or an explicit unavailable fail-closed backend."""
    if sys.platform == "darwin":
        try:
            return MacOSKeychainCredentialStore()
        except CredentialStoreUnavailable as exc:
            return UnavailableCredentialStore(
                str(exc), diagnostic=exc.diagnostic
            )
    if sys.platform.startswith("linux"):
        try:
            return LinuxSecretServiceCredentialStore()
        except CredentialStoreUnavailable as exc:
            return UnavailableCredentialStore(
                str(exc), diagnostic=exc.diagnostic
            )
    return UnavailableCredentialStore(
        f"native credential store is not implemented for {sys.platform}"
    )


def provider_config_digest(config: Mapping[str, object]) -> str:
    """Digest only non-secret provider metadata; never hash secret material."""
    safe: dict[str, object] = {}
    for key in ("provider", "type", "base_url", "credential_ref", "models", "timeout"):
        if key not in config:
            continue
        value = config[key]
        if key == "base_url" and isinstance(value, str):
            value = _safe_endpoint_profile(value)
        safe[key] = value
    return hashlib.sha256(
        json.dumps(safe, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    ).hexdigest()


def _safe_endpoint_profile(value: str) -> str:
    """Keep endpoint metadata bounded and exclude credentials/query strings."""
    from urllib.parse import urlsplit

    try:
        parsed = urlsplit(value)
    except ValueError:
        return "invalid"
    if parsed.scheme not in {"http", "https", "mock"} or not parsed.hostname:
        return "invalid"
    host = parsed.hostname.casefold()
    port = f":{parsed.port}" if parsed.port is not None else ""
    path = parsed.path.rstrip("/")
    return f"{parsed.scheme}://{host}{port}{path}"[:256]


def credential_store_backend(store: CredentialStore) -> str:
    """Return a bounded backend label for safe diagnostics."""
    value = getattr(store, "backend_name", "unknown")
    if not isinstance(value, str) or not value or len(value) > 64:
        return "unknown"
    return value


def credential_store_backend_audit(store: CredentialStore) -> dict[str, object]:
    """Return bounded backend attributes without touching credential data."""
    if isinstance(store, MacOSKeychainCredentialStore):
        return store.backend_audit()
    if isinstance(store, LinuxSecretServiceCredentialStore):
        return store.backend_audit()
    return {
        "backend": credential_store_backend(store),
        "api": "test-or-unavailable",
        "data_protection_keychain": None,
        "accessibility": "NOT_AVAILABLE",
        "access_control": "NOT_AVAILABLE",
        "user_presence": None,
        "synchronizable": None,
        "access_group": None,
        "data_protection_decision": "NOT_APPLICABLE",
    }


_NATIVE_STATUS_CATEGORIES = {
    -50: "INVALID_PARAMETERS",
    -128: "USER_CANCELED",
    -25291: "KEYCHAIN_UNAVAILABLE",
    -25293: "ACCESS_DENIED",
    -25294: "KEYCHAIN_UNAVAILABLE",
    -25295: "KEYCHAIN_UNAVAILABLE",
    -25299: "DUPLICATE_ITEM",
    -25300: "ITEM_NOT_FOUND",
    -25308: "INTERACTION_REQUIRED",
}


def native_status_category(status: int) -> str:
    """Map a bounded Security.framework status to a stable safe category."""
    if type(status) is not int or not (-(2**31) <= status < 2**31):
        return "INVALID_STATUS"
    return _NATIVE_STATUS_CATEGORIES.get(status, "UNKNOWN_NATIVE_ERROR")


def _native_diagnostic(
    operation: str,
    status: int,
    *,
    access_mode: CredentialAccessMode = CredentialAccessMode.RUNTIME,
    interaction_allowed: bool | None = None,
    category: str | None = None,
) -> CredentialStoreDiagnostic:
    mode = _validate_access_mode(access_mode)
    return CredentialStoreDiagnostic(
        backend=MacOSKeychainCredentialStore.backend_name,
        operation=operation,
        native_status=status,
        category=category or native_status_category(status),
        interaction_allowed=(
            mode is CredentialAccessMode.PROVISIONING
            if interaction_allowed is None
            else interaction_allowed
        ),
    )


def _native_store_failure(
    message: str,
    operation: str,
    status: int,
    *,
    access_mode: CredentialAccessMode = CredentialAccessMode.RUNTIME,
) -> CredentialStoreError:
    mode = _validate_access_mode(access_mode)
    diagnostic = _native_diagnostic(operation, status, access_mode=mode)
    if status == -128 and mode is CredentialAccessMode.PROVISIONING:
        return CredentialProvisioningCancelled(message, diagnostic=diagnostic)
    return CredentialStoreUnavailable(message, diagnostic=diagnostic)


def _validate_secret_pair(ref: CredentialRef, secret: SecretValue) -> None:
    if not isinstance(ref, CredentialRef) or not isinstance(secret, SecretValue):
        raise TypeError("credential stores accept CredentialRef and SecretValue only")


__all__ = [
    "CredentialAccessMode",
    "CredentialHandle",
    "CredentialNotFound",
    "CredentialProvisioningCancelled",
    "CredentialRef",
    "CredentialReferenceError",
    "CredentialStore",
    "CredentialStoreDiagnostic",
    "CredentialStoreError",
    "CredentialStoreUnavailable",
    "InMemoryCredentialStore",
    "LinuxSecretServiceCredentialStore",
    "MacOSKeychainCredentialStore",
    "SecretValue",
    "UnavailableCredentialStore",
    "build_platform_credential_store",
    "credential_store_backend",
    "credential_store_backend_audit",
    "native_status_category",
    "provider_config_digest",
]
