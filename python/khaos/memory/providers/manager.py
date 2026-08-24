"""Active-provider selection and canonical replay orchestration."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, cast

from khaos.memory.core.broker import MemoryBroker
from khaos.memory.core.contracts import (
    MemoryCapabilities,
    MemoryEventType,
    RuntimeMemoryContext,
    SourceType,
    TrustHint,
)
from khaos.memory.events import MemoryEventBridge
from khaos.memory.providers.http import MemoryHttpProvider
from khaos.memory.providers.lifecycle import (
    MemoryProviderRegistry,
    ProviderLifecycleError,
    ProviderLifecycleState,
    ProviderManifest,
)
from khaos.memory.providers.native import NativeMemoryProvider

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class ProviderStatus:
    """User-facing lifecycle snapshot."""

    provider_id: str
    state: str
    active: bool
    healthy: bool
    detail: str
    capabilities: MemoryCapabilities


class MemoryProviderManager:
    """Switch primary providers only after replay and smoke validation."""

    def __init__(
        self,
        registry: MemoryProviderRegistry,
        broker: MemoryBroker,
        *,
        database: Any = None,
    ) -> None:
        self.registry = registry
        self.broker = broker
        self.database = database
        self._switch_lock = asyncio.Lock()
        self.broker.bind_provider_registry(registry)

    async def statuses(self) -> tuple[ProviderStatus, ...]:
        """Return registry state without exposing provider internals."""

        result: list[ProviderStatus] = []
        for manifest in self.registry.manifests():
            handle = self.registry.handle(manifest.provider_id)
            if handle is None:
                result.append(
                    ProviderStatus(
                        manifest.provider_id,
                        ProviderLifecycleState.REGISTERED.value,
                        False,
                        False,
                        "not started",
                        manifest.capabilities,
                    )
                )
                continue
            health = await handle.provider.health()
            result.append(
                ProviderStatus(
                    manifest.provider_id,
                    handle.state.value,
                    self.registry.active_id() == manifest.provider_id,
                    health.healthy,
                    health.detail,
                    handle.provider.capabilities(),
                )
            )
        return tuple(result)

    async def set_provider(
        self,
        provider_id: str,
        runtime: RuntimeMemoryContext,
    ) -> ProviderStatus:
        """Run validate → replay → rebuild → smoke → activate as one workflow."""

        async with self._switch_lock:
            previous = self.broker.provider
            previous_id = previous.provider_id
            if previous_id == provider_id:
                handle = await self.registry.start(provider_id)
                health = await handle.check_health()
                await self.persist()
                return ProviderStatus(
                    provider_id,
                    handle.state.value,
                    True,
                    health.healthy,
                    health.detail,
                    handle.provider.capabilities(),
                )
            bridge = MemoryEventBridge(self.broker)
            await bridge.record(
                MemoryEventType.PROVIDER_SWITCH_REQUESTED,
                runtime,
                {"from_provider": previous_id, "to_provider": provider_id},
                source_type=SourceType.SYSTEM,
                trust_hint=TrustHint.TOOL_OBSERVED,
            )
            target = await self.registry.start(provider_id)
            try:
                shared_projection = self.broker._shares_projection(target.provider)
                replay = getattr(target.provider, "rebuild_from_events", None)
                if callable(replay) and not shared_projection:
                    events = await self.broker._read_all_replay_events(
                        runtime, page_size=10_000
                    )
                    await cast(Callable[..., Awaitable[Any]], replay)(events)
                elif not target.provider.capabilities().import_data:
                    raise ProviderLifecycleError(
                        f"provider {provider_id} cannot import canonical memory data"
                    )
                rebuild = getattr(target.provider, "rebuild_indexes", None)
                if callable(rebuild) and not shared_projection:
                    await cast(Callable[..., Awaitable[Any]], rebuild)()
                health = await target.provider.health()
                if not health.healthy:
                    raise ProviderLifecycleError(
                        f"provider {provider_id} failed smoke health check: {health.detail}"
                    )
                # Activate the prepared handle before publishing the Broker
                # pointer.  The pointer remains the serving commit point;
                # registry state can therefore be restored if it fails.
                await self.registry.activate(provider_id)
                await self.broker.set_provider(
                    target.provider,
                    runtime,
                    provider_id=provider_id,
                    prepared=True,
                    emit_event=False,
                )
                # Persist and audit the serving-state commit before stopping
                # the old provider.  If either commit step fails, the old
                # pointer and provider remain recoverable and no
                # PROVIDER_CHANGED event is emitted.
                await self.persist()
                await self.broker.record_audit(
                    "MEMORY_PROVIDER_SWITCH_COMMITTED",
                    runtime,
                    detail={"from_provider": previous_id, "to_provider": provider_id},
                )
                await bridge.record(
                    MemoryEventType.PROVIDER_SWITCH_COMMITTED,
                    runtime,
                    {"from_provider": previous_id, "to_provider": provider_id},
                    source_type=SourceType.SYSTEM,
                    trust_hint=TrustHint.TOOL_OBSERVED,
                )
                if previous_id in {manifest.provider_id for manifest in self.registry.manifests()}:
                    try:
                        await self.registry.stop(previous_id)
                    except ProviderLifecycleError:
                        # The target is already the committed serving provider;
                        # a stale old handle is safe to collect on the next
                        # lifecycle sweep.
                        pass
            except BaseException as exc:
                rollback_ok = self.broker.provider is previous
                if self.registry.handle(previous_id) is not None:
                    try:
                        await self.registry.activate(previous_id)
                    except ProviderLifecycleError:
                        rollback_ok = False
                # Restore the serving pointer through the Broker's same
                # provider/projection locks.  Direct assignment here would
                # let a concurrent search observe a half-rolled-back switch
                # and would bypass the registry readiness check.
                if self.broker.provider is not previous:
                    try:
                        await self.broker.set_provider(
                            previous,
                            runtime,
                            provider_id=previous_id,
                            prepared=True,
                            emit_event=False,
                        )
                    except Exception as rollback_error:
                        # Preserve the original switch error; the Broker
                        # pointer remains the last committed value.  Keep
                        # that provider alive below so no in-flight search is
                        # stranded on a stopped serving object.
                        logger.warning(
                            "provider switch pointer rollback failed: %s",
                            type(rollback_error).__name__,
                            exc_info=True,
                        )
                        rollback_ok = False
                if rollback_ok:
                    try:
                        await self.registry.stop(provider_id)
                    except ProviderLifecycleError:
                        pass
                elif self.broker.provider is not previous:
                    try:
                        await self.registry.activate(provider_id)
                    except ProviderLifecycleError:
                        pass
                try:
                    await bridge.record(
                        MemoryEventType.PROVIDER_SWITCH_FAILED,
                        runtime,
                        {
                            "from_provider": previous_id,
                            "to_provider": provider_id,
                            "error": type(exc).__name__,
                        },
                        source_type=SourceType.SYSTEM,
                        trust_hint=TrustHint.TOOL_OBSERVED,
                    )
                except Exception as bridge_error:
                    # The original switch failure is the authoritative error;
                    # a secondary ledger failure must not hide it.
                    logger.warning(
                        "provider switch failure audit failed: %s",
                        type(bridge_error).__name__,
                        exc_info=True,
                    )
                raise
            handle = self.registry.handle(provider_id)
            if handle is None:
                raise ProviderLifecycleError("active provider handle disappeared")
            return ProviderStatus(
                provider_id,
                handle.state.value,
                True,
                health.healthy,
                health.detail,
                handle.provider.capabilities(),
            )

    async def persist(self) -> None:
        """Persist lifecycle state without persisting provider secrets."""

        if self.database is None:
            return
        now = datetime.now(UTC).isoformat()
        async with self.database.transaction() as conn:
            for manifest in self.registry.manifests():
                handle = self.registry.handle(manifest.provider_id)
                state = handle.state.value if handle is not None else "registered"
                generation = handle.generation if handle is not None else 0
                last_error = handle.last_error if handle is not None else ""
                await conn.execute(
                    "INSERT INTO memory_provider_registry ("
                    "provider_id, manifest_json, lifecycle_state, active, generation, "
                    "last_error, installed_at, updated_at"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(provider_id) DO UPDATE SET "
                    "manifest_json=excluded.manifest_json, "
                    "lifecycle_state=excluded.lifecycle_state, "
                    "active=excluded.active, generation=excluded.generation, "
                    "last_error=excluded.last_error, installed_at=excluded.installed_at, "
                    "updated_at=excluded.updated_at",
                    (
                        manifest.provider_id,
                        json.dumps(manifest.to_mapping(), sort_keys=True),
                        state,
                        int(self.registry.active_id() == manifest.provider_id),
                        generation,
                        last_error,
                        now if handle is not None else None,
                        now,
                    ),
                )


def build_native_registry(
    db: Any,
    *,
    network_allowed: bool = False,
    config: Any = None,
) -> MemoryProviderRegistry:
    """Create the local registry and explicitly configured remote adapters.

    A remote provider is never discovered implicitly.  It must be present in
    the trusted effective configuration, carry an explicit endpoint, and be
    allowed by the effective network policy before it can be registered.
    """

    registry = MemoryProviderRegistry(network_allowed=network_allowed)
    native_manifest = ProviderManifest(
        provider_id="khaos-native",
        capabilities=MemoryCapabilities(
            exact_search=True,
            keyword_search=True,
            semantic_search=False,
            entity_linking=True,
            graph_traversal=False,
            temporal_search=True,
            historical_query=True,
            profile=False,
            bulk_import=True,
            forget=True,
            update=True,
            graph_expand=False,
            vector_search=False,
            export_data=True,
            import_data=True,
            compact=True,
            bulk_rebuild=True,
            stream_events=True,
        ),
    )
    registry.register(native_manifest, lambda manifest: NativeMemoryProvider(db))
    _register_http_providers(registry, config)
    return registry


def _register_http_providers(
    registry: MemoryProviderRegistry,
    config: Any,
) -> None:
    if not isinstance(config, dict):
        return
    memory = config.get("memory", {})
    if not isinstance(memory, dict):
        return
    raw_providers = memory.get("providers", {})
    if isinstance(raw_providers, dict):
        entries = []
        for provider_id, raw in raw_providers.items():
            if not isinstance(raw, dict):
                raise ProviderLifecycleError(
                    f"memory provider {provider_id!r} must be a mapping"
                )
            entries.append({"id": provider_id, **raw})
    elif isinstance(raw_providers, list):
        entries = raw_providers
    else:
        raise ProviderLifecycleError("memory.providers must be a mapping or list")
    for raw in entries:
        if not isinstance(raw, dict):
            raise ProviderLifecycleError("memory provider entries must be mappings")
        manifest = ProviderManifest.from_mapping(
            {key: value for key, value in raw.items() if key not in {"adapter", "api_key_env"}}
        )
        if manifest.provider_id == "khaos-native":
            continue
        adapter = str(raw.get("adapter", "http")).lower()
        if adapter != "http":
            raise ProviderLifecycleError(
                f"unsupported memory provider adapter: {adapter}"
            )
        api_key = _read_api_key(raw)
        registry.register(
            manifest,
            lambda manifest, key=api_key: MemoryHttpProvider(
                manifest,
                api_key=key,
            ),
        )


def _read_api_key(raw: dict[str, Any]) -> str | None:
    env_name = raw.get("api_key_env")
    if env_name is None:
        return None
    if not isinstance(env_name, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", env_name):
        raise ProviderLifecycleError("memory provider api_key_env is malformed")
    value = os.environ.get(env_name, "")
    return value or None


__all__ = ["MemoryProviderManager", "ProviderStatus", "build_native_registry"]
