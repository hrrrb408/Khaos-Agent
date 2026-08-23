"""Principal- and project-scoped memory RPC service.

The service owns no transport state.  The caller supplies an immutable
``RequestContext`` and this module constructs a short-lived ``MemoryStore``
from that context for each operation.  Keeping that binding here makes it
harder for a future RPC handler to accidentally reuse a server-level store
with the wrong principal.
"""

from __future__ import annotations

from dataclasses import asdict
from datetime import timedelta

from khaos.memory import (
    Memory,
    MemoryAuthority,
    MemoryBroker,
    MemoryCandidate,
    MemoryConfidence,
    MemoryEvent,
    MemoryEventType,
    MemoryHit,
    MemoryRepository,
    MemoryScope,
    MemoryStore,
    RuntimeMemoryContext,
    SourceType,
    TrustHint,
)
from khaos.memory.core.contracts import utc_now
from khaos.memory.ledger import SqliteEventLedger
from khaos.memory.providers import NativeMemoryProvider
from khaos.runtime import RequestContext


class MemoryService:
    """Expose memory operations with context-derived ownership."""

    def __init__(
        self,
        repository: MemoryRepository,
        audit_logger=None,
        broker: MemoryBroker | None = None,
    ) -> None:
        """Create the service from explicit persistence and audit ports."""
        self.repository = repository
        self.audit_logger = audit_logger
        if broker is None:
            database = getattr(repository, "database", None)
            if database is not None:
                broker = MemoryBroker(
                    NativeMemoryProvider(database),
                    SqliteEventLedger(database),
                )
        self.broker = broker

    def _store(self, ctx: RequestContext) -> MemoryStore:
        """Build a store bound to the authenticated principal and project."""
        audit_sink = None
        if self.audit_logger is not None:
            audit_sink = self.audit_logger.bind(
                principal_id=ctx.principal_id,
                project_id=ctx.project_id,
                policy_digest=ctx.policy_digest or self.audit_logger.policy_digest,
                runtime_id=ctx.runtime_id or None,
                source_transport=ctx.source_transport,
            )
        return MemoryStore(
            self.repository,
            principal_id=ctx.principal_id,
            project_id=ctx.project_id,
            audit_logger=audit_sink,
            audit_session_id=ctx.session_id or None,
        )

    async def get_memory(
        self, ctx: RequestContext, scope: str, key: str
    ) -> dict[str, object]:
        """Return one memory or raise ``KeyError`` when it is not present."""
        if self.broker is not None:
            runtime = self._runtime(ctx, scope)
            hit = await self.broker.get_current(
                runtime,
                scope=scope,
                key=key,
                namespace="private",
            )
            if hit is not None:
                return hit_to_dict(hit)
            raise KeyError(key)
        memory = await self._store(ctx).get(MemoryScope(scope), key)
        if memory is None:
            raise KeyError(key)
        return memory_to_dict(memory)

    async def set_memory(
        self,
        ctx: RequestContext,
        scope: str,
        key: str,
        value: str,
        ttl: int = 604800,
        confidence: int = 2,
    ) -> dict[str, object]:
        """Create or replace a memory in the caller's scope."""
        memory_scope = MemoryScope(scope)
        if self.broker is not None:
            runtime = self._runtime(ctx, scope)
            source_event = MemoryEvent.create(
                MemoryEventType.USER_MESSAGE,
                principal_id=runtime.principal_id,
                project_id=runtime.project_id,
                session_id=runtime.session_id,
                source_type=SourceType.USER,
                trust_hint=TrustHint.USER_STATED,
                payload={"key": key, "value": value, "scope": scope},
            )
            await self.broker.record_event(source_event)
            valid_from = utc_now()
            candidate = MemoryCandidate(
                memory_type="USER_MEMORY",
                claim=value,
                key=key,
                scope=scope,
                namespace="private",
                authority=MemoryAuthority.USER_STATED,
                confidence=max(0.0, min(1.0, confidence / 3.0)),
                source_event_ids=(source_event.event_id,),
                valid_from=valid_from,
                valid_to=valid_from + timedelta(seconds=max(0, int(ttl))),
            )
            decision = await self.broker.propose_memory(candidate, runtime)
            if not decision.accepted:
                return {
                    "ok": False,
                    "error": decision.reason,
                    "status": decision.status.value,
                }
            # Keep the old table as a compatibility projection for released
            # clients.  It is not read by the V2 model-context path.
            projection = await self._store(ctx).set(
                Memory(
                    id=None,
                    scope=memory_scope,
                    key=key,
                    value=value,
                    ttl=ttl,
                    confidence=MemoryConfidence(confidence),
                )
            )
            return {
                "ok": True,
                "id": decision.memory_id,
                "memory_id": decision.memory_id,
                "legacy_id": projection.id if projection is not None else None,
                "status": decision.status.value,
            }
        memory = await self._store(ctx).set(
            Memory(
                id=None,
                scope=memory_scope,
                key=key,
                value=value,
                ttl=ttl,
                confidence=MemoryConfidence(confidence),
            )
        )
        # ``MemoryStore.set`` returns the stored row for the supported
        # conflict modes.  Keep the explicit guard so a future unresolved
        # conflict cannot be reported as a successful write.
        if memory is None:
            return {"ok": False, "error": "memory conflict unresolved"}
        return {"ok": True, "id": memory.id}

    async def delete_memory(
        self, ctx: RequestContext, memory_id: int | str
    ) -> dict[str, object]:
        """Delete only a row owned by this principal and project."""
        if self.broker is not None:
            runtime = self._runtime(ctx, "global")
            canonical_id = str(memory_id)
            if canonical_id and not canonical_id.isdigit():
                legacy_hit = None
                getter = getattr(self.broker.provider, "get_by_id", None)
                if callable(getter):
                    legacy_hit = await getter(runtime, canonical_id)
                await self.broker.forget((canonical_id,), runtime, mode="soft")
                if legacy_hit is not None and legacy_hit.key:
                    await self._store(ctx).delete(
                        MemoryScope(legacy_hit.scope),
                        legacy_hit.key,
                    )
                return {"ok": True}
        # Keep deletion on the same MemoryStore boundary as every other
        # operation so ownership and audit behavior cannot drift between RPC
        # methods and local runtime callers.
        await self._store(ctx).delete_by_id(int(memory_id))
        return {"ok": True}

    async def search_memory(
        self, ctx: RequestContext, query: str, top_k: int = 5
    ) -> list[dict[str, object]]:
        """Search only the caller's principal/project memory view."""
        if self.broker is not None:
            runtime = self._runtime(ctx, "global")
            class SearchBudget:
                max_hits = top_k

            resolution = await self.broker.search(query, runtime, SearchBudget())
            return [hit_to_dict(hit) for hit in resolution.primary_hits]
        memories = await self._store(ctx).search(query, top_k)
        return [memory_to_dict(memory) for memory in memories]

    def _runtime(self, ctx: RequestContext, scope: str) -> RuntimeMemoryContext:
        """Bind RPC identity before the request reaches the Broker."""

        return RuntimeMemoryContext(
            principal_id=ctx.principal_id or "legacy-principal",
            project_id=ctx.project_id or "legacy-project",
            session_id=ctx.session_id or None,
            task_id=None,
            workspace_id=None,
            mode=scope,
            environment_fingerprint="rpc",
        )


def memory_to_dict(memory: Memory) -> dict[str, object]:
    """Serialize a memory without leaking enum or datetime internals."""
    data: dict[str, object] = asdict(memory)
    data["scope"] = memory.scope.value
    data["confidence"] = memory.confidence.value
    data["created_at"] = memory.created_at.isoformat() if memory.created_at else ""
    data["updated_at"] = memory.updated_at.isoformat() if memory.updated_at else ""
    return data


def hit_to_dict(hit: MemoryHit) -> dict[str, object]:
    """Serialize an admitted V2 hit with V1-compatible aliases."""

    return {
        "id": hit.memory_id or hit.external_id,
        "memory_id": hit.memory_id or hit.external_id,
        "scope": hit.scope,
        "key": hit.key or "",
        "value": hit.content,
        "content": hit.content,
        "confidence": hit.confidence_hint or 0.0,
        "authority": hit.authority_hint or "AGENT_INFERRED",
        "status": hit.status,
        "memory_type": hit.memory_type,
        "namespace": hit.namespace,
        "source_ref": hit.source_ref or "",
        "event_ids": list(hit.event_ids),
        "valid_from": hit.valid_from.isoformat() if hit.valid_from else "",
        "valid_to": hit.valid_to.isoformat() if hit.valid_to else "",
    }


__all__ = ["MemoryService", "hit_to_dict", "memory_to_dict"]
