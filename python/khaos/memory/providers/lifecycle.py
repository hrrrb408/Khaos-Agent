"""Provider manifests, lifecycle ownership, and permission boundaries.

The registry is intentionally small and local-first.  A provider is not
considered active merely because its Python object was constructed: it must
pass manifest validation, mount, start, and health checks.  All cleanup is
owned by the registry so a failed provider cannot leak tasks or connections
into the AgentLoop.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol

from khaos.memory.core.contracts import (
    MemoryCapabilities,
    MemoryProvider,
    ProviderHealth,
    canonical_json,
)


class ProviderLifecycleError(RuntimeError):
    """Raised when a provider cannot reach a safe lifecycle state."""


class ProviderLifecycleState(str, Enum):
    REGISTERED = "registered"
    INSTALLED = "installed"
    VALIDATED = "validated"
    MOUNTED = "mounted"
    STARTED = "started"
    HEALTHY = "healthy"
    STOPPED = "stopped"
    UNMOUNTED = "unmounted"
    FAILED = "failed"


_PROVIDER_ID = re.compile(r"^[a-z][a-z0-9._-]{1,127}$")
_ALLOWED_FORBIDDEN_AUTHORITY = {
    "system_policy",
    "approval_policy",
    "credential_access",
    "sandbox_bypass",
}


@dataclass(frozen=True, slots=True)
class ProviderManifest:
    """Declarative provider identity and requested capabilities."""

    provider_id: str
    provider_type: str = "memory-provider"
    version: str = "1.0.0"
    permissions: frozenset[str] = frozenset()
    network_required: bool = False
    filesystem_write: tuple[str, ...] = ()
    capabilities: MemoryCapabilities = field(default_factory=MemoryCapabilities)
    forbidden_authority: frozenset[str] = frozenset(_ALLOWED_FORBIDDEN_AUTHORITY)
    endpoint: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not _PROVIDER_ID.fullmatch(self.provider_id):
            raise ProviderLifecycleError(f"invalid provider id: {self.provider_id!r}")
        if self.provider_type != "memory-provider":
            raise ProviderLifecycleError("provider manifest type must be memory-provider")
        if not self.version.strip():
            raise ProviderLifecycleError("provider manifest version is required")
        if not self.forbidden_authority.issubset(_ALLOWED_FORBIDDEN_AUTHORITY):
            raise ProviderLifecycleError("provider requested forbidden authority override")
        if self.network_required and not self.endpoint:
            raise ProviderLifecycleError("network providers require an explicit endpoint")
        if not isinstance(self.metadata, Mapping):
            raise ProviderLifecycleError("provider metadata must be a mapping")
        try:
            canonical_json(self.metadata)
        except (TypeError, ValueError) as exc:
            raise ProviderLifecycleError("provider metadata is not JSON serializable") from exc

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> ProviderManifest:
        """Parse a manifest and fail closed on unknown or malformed fields."""

        allowed = {
            "id",
            "provider_id",
            "type",
            "provider_type",
            "version",
            "permissions",
            "network",
            "network_required",
            "filesystem",
            "filesystem_write",
            "capabilities",
            "forbidden_authority",
            "endpoint",
            "metadata",
        }
        unknown = set(data) - allowed
        if unknown:
            raise ProviderLifecycleError(f"unknown provider manifest fields: {sorted(unknown)}")
        provider_id = data.get("provider_id", data.get("id"))
        if not isinstance(provider_id, str):
            raise ProviderLifecycleError("provider manifest requires id")
        raw_network = data.get("network", data.get("network_required", False))
        if isinstance(raw_network, Mapping):
            network_required = bool(raw_network.get("required", False))
            endpoint = raw_network.get("endpoint", data.get("endpoint"))
        else:
            network_required = bool(raw_network)
            endpoint = data.get("endpoint")
        raw_filesystem = data.get("filesystem", data.get("filesystem_write", ()))
        if isinstance(raw_filesystem, Mapping):
            raw_filesystem = raw_filesystem.get("write", ())
        capabilities = _capabilities_from_mapping(data.get("capabilities", {}))
        permissions = _string_values(data.get("permissions", ()), "permissions")
        filesystem_write = _string_values(raw_filesystem, "filesystem")
        forbidden_authority = _string_values(
            data.get("forbidden_authority", _ALLOWED_FORBIDDEN_AUTHORITY),
            "forbidden_authority",
        )
        metadata = data.get("metadata", {})
        if not isinstance(metadata, Mapping):
            raise ProviderLifecycleError("provider metadata must be a mapping")
        return cls(
            provider_id=provider_id,
            provider_type=str(data.get("provider_type", data.get("type", "memory-provider"))),
            version=str(data.get("version", "1.0.0")),
            permissions=frozenset(permissions),
            network_required=network_required,
            filesystem_write=filesystem_write,
            capabilities=capabilities,
            forbidden_authority=frozenset(value.lower() for value in forbidden_authority),
            endpoint=str(endpoint) if endpoint is not None else None,
            metadata=dict(metadata),
        )

    def to_mapping(self) -> dict[str, Any]:
        """Serialize a stable manifest for audit and persistence."""

        return {
            "id": self.provider_id,
            "type": self.provider_type,
            "version": self.version,
            "permissions": sorted(self.permissions),
            "network": {"required": self.network_required, "endpoint": self.endpoint},
            "filesystem": {"write": list(self.filesystem_write)},
            "capabilities": {
                name: getattr(self.capabilities, name)
                for name in self.capabilities.__dataclass_fields__
            },
            "forbidden_authority": sorted(self.forbidden_authority),
            "metadata": dict(self.metadata),
        }


class ProviderFactory(Protocol):
    """Factory for a provider bound to host-owned dependencies."""

    def __call__(self, manifest: ProviderManifest) -> MemoryProvider:
        """Construct a provider without starting external effects."""

        ...


CleanupHook = Callable[[], Awaitable[None] | None]


@dataclass
class ProviderHandle:
    """Lifecycle state and cleanup owner for one provider instance."""

    manifest: ProviderManifest
    provider: MemoryProvider
    state: ProviderLifecycleState = ProviderLifecycleState.REGISTERED
    generation: int = 0
    cleanup_hooks: list[CleanupHook] = field(default_factory=list)
    last_error: str = ""

    async def install(self) -> None:
        await _call_optional(self.provider, "install")
        self.state = ProviderLifecycleState.INSTALLED

    async def validate(self) -> None:
        await _call_optional(self.provider, "validate")
        declared = self.provider.capabilities()
        if not _capabilities_cover(self.manifest.capabilities, declared):
            raise ProviderLifecycleError(
                f"provider {self.manifest.provider_id} does not implement its manifest capabilities"
            )
        self.state = ProviderLifecycleState.VALIDATED

    async def mount(self) -> None:
        await _call_optional(self.provider, "mount")
        self.state = ProviderLifecycleState.MOUNTED

    async def start(self) -> None:
        await _call_optional(self.provider, "start")
        self.state = ProviderLifecycleState.STARTED

    async def check_health(self) -> ProviderHealth:
        health = await self.provider.health()
        if not health.healthy:
            self.state = ProviderLifecycleState.FAILED
            self.last_error = health.detail
            raise ProviderLifecycleError(
                f"provider {self.manifest.provider_id} is unhealthy: {health.detail}"
            )
        self.generation += 1
        self.state = ProviderLifecycleState.HEALTHY
        return ProviderHealth(
            provider_id=health.provider_id,
            healthy=True,
            detail=health.detail,
            lifecycle=self.state.value,
            generation=self.generation,
            last_error=self.last_error,
        )

    async def stop(self) -> None:
        await _call_optional(self.provider, "stop")
        self.state = ProviderLifecycleState.STOPPED

    async def unmount(self) -> None:
        for hook in reversed(self.cleanup_hooks):
            result = hook()
            if asyncio.iscoroutine(result):
                await result
        await _call_optional(self.provider, "unmount")
        self.state = ProviderLifecycleState.UNMOUNTED

    async def close(self) -> None:
        """Run the complete terminal cleanup sequence, best effort but bounded."""

        errors: list[BaseException] = []
        for action in (self.stop, self.unmount):
            try:
                await action()
            except BaseException as exc:  # noqa: BLE001 - cleanup aggregates evidence
                errors.append(exc)
                self.state = ProviderLifecycleState.FAILED
                self.last_error = type(exc).__name__
        if errors:
            raise ProviderLifecycleError(
                f"provider cleanup failed for {self.manifest.provider_id}: "
                f"{', '.join(type(error).__name__ for error in errors)}"
            ) from errors[0]


class MemoryProviderRegistry:
    """Validated provider registry with one active primary provider."""

    def __init__(self, *, network_allowed: bool = False) -> None:
        self.network_allowed = network_allowed
        self._factories: dict[str, tuple[ProviderManifest, ProviderFactory]] = {}
        self._handles: dict[str, ProviderHandle] = {}
        self._active_id: str | None = None
        self._lock = asyncio.Lock()

    def register(self, manifest: ProviderManifest, factory: ProviderFactory) -> None:
        """Register a factory after validating its static manifest."""

        if manifest.network_required and not self.network_allowed:
            raise ProviderLifecycleError(
                f"network provider {manifest.provider_id} is disabled by local policy"
            )
        if manifest.provider_id in self._factories:
            raise ProviderLifecycleError(f"provider already registered: {manifest.provider_id}")
        self._factories[manifest.provider_id] = (manifest, factory)

    def manifests(self) -> tuple[ProviderManifest, ...]:
        """Return registered manifests in stable order."""

        return tuple(self._factories[key][0] for key in sorted(self._factories))

    def active_id(self) -> str | None:
        """Return the active provider id, if one has been started."""

        return self._active_id

    def active(self) -> ProviderHandle | None:
        """Return the active lifecycle handle."""

        return self._handles.get(self._active_id) if self._active_id else None

    def handle(self, provider_id: str) -> ProviderHandle | None:
        """Return a started handle without constructing or starting anything."""

        return self._handles.get(provider_id)

    def is_ready(self, provider: Any) -> bool:
        """Return whether the exact provider object passed Broker validation."""

        return any(
            handle.provider is provider
            and handle.state is ProviderLifecycleState.HEALTHY
            for handle in self._handles.values()
        )

    async def start(self, provider_id: str) -> ProviderHandle:
        """Install, validate, mount, start, and health-check a provider."""

        async with self._lock:
            if provider_id not in self._factories:
                raise ProviderLifecycleError(f"unknown memory provider: {provider_id}")
            existing = self._handles.get(provider_id)
            if existing is not None and existing.state is ProviderLifecycleState.HEALTHY:
                return existing
            manifest, factory = self._factories[provider_id]
            handle = ProviderHandle(manifest=manifest, provider=factory(manifest))
            self._handles[provider_id] = handle
            try:
                await handle.install()
                await handle.validate()
                await handle.mount()
                await handle.start()
                await handle.check_health()
            except BaseException as exc:
                handle.state = ProviderLifecycleState.FAILED
                handle.last_error = type(exc).__name__
                try:
                    await handle.close()
                except ProviderLifecycleError:
                    pass
                self._handles.pop(provider_id, None)
                raise ProviderLifecycleError(
                    f"provider startup failed: {provider_id}: {type(exc).__name__}"
                ) from exc
            return handle

    async def activate(self, provider_id: str) -> ProviderHandle:
        """Start a provider and mark it active without stopping the old one."""

        handle = await self.start(provider_id)
        async with self._lock:
            self._active_id = provider_id
        return handle

    async def stop(self, provider_id: str) -> None:
        """Stop and unmount one provider, clearing active selection if needed."""

        async with self._lock:
            handle = self._handles.pop(provider_id, None)
            if self._active_id == provider_id:
                self._active_id = None
        if handle is not None:
            await handle.close()

    async def close(self) -> None:
        """Stop every provider and leave no registered runtime handle alive."""

        provider_ids = tuple(self._handles)
        errors: list[BaseException] = []
        for provider_id in provider_ids:
            try:
                await self.stop(provider_id)
            except BaseException as exc:  # noqa: BLE001 - close must attempt all
                errors.append(exc)
        if errors:
            raise ProviderLifecycleError(
                f"provider registry close failed for {len(errors)} provider(s)"
            ) from errors[0]


async def _call_optional(provider: Any, name: str) -> None:
    method = getattr(provider, name, None)
    if not callable(method):
        return
    result = method()
    if asyncio.iscoroutine(result):
        await result


def _capabilities_from_mapping(raw: Any) -> MemoryCapabilities:
    if raw is None:
        return MemoryCapabilities()
    if not isinstance(raw, Mapping):
        raise ProviderLifecycleError("provider capabilities must be a mapping")
    names = set(MemoryCapabilities.__dataclass_fields__)
    unknown = set(raw) - names
    if unknown:
        raise ProviderLifecycleError(f"unknown provider capabilities: {sorted(unknown)}")
    return MemoryCapabilities(**{name: bool(raw[name]) for name in raw})


def _string_values(value: Any, field_name: str) -> tuple[str, ...]:
    """Parse a manifest string collection without treating strings as iterables."""

    if value is None:
        return ()
    if isinstance(value, (str, bytes)) or not isinstance(value, (list, tuple, set, frozenset)):
        raise ProviderLifecycleError(f"provider {field_name} must be a string list")
    values = tuple(str(item) for item in value)
    if any(not item.strip() for item in values):
        raise ProviderLifecycleError(f"provider {field_name} contains an empty value")
    return values


def _capabilities_cover(requested: MemoryCapabilities, declared: MemoryCapabilities) -> bool:
    for name in MemoryCapabilities.__dataclass_fields__:
        if bool(getattr(requested, name)) and not bool(getattr(declared, name)):
            return False
    return True


__all__ = [
    "MemoryProviderRegistry",
    "ProviderFactory",
    "ProviderHandle",
    "ProviderLifecycleError",
    "ProviderLifecycleState",
    "ProviderManifest",
]
