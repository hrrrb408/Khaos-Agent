"""Principal- and project-scoped memory RPC service.

The service owns no provider or authority state.  Production composition
injects one application-scoped ``MemoryHost``; request identity is still
bound into a fresh immutable runtime context for each operation.  The legacy
``MemoryStore`` adapter is retained only for explicitly non-production callers.
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
    MemoryHit,
    MemoryRepository,
    MemoryScope,
    MemoryStore,
    RuntimeMemoryContext,
)
from khaos.memory.core.contracts import utc_now
from khaos.memory.events import MemoryEventBridge
from khaos.memory.runtime import MemoryHost
from khaos.runtime import RequestContext


class MemoryService:
    """Expose memory operations with context-derived ownership."""

    def __init__(
        self,
        repository: MemoryRepository,
        audit_logger=None,
        broker: MemoryBroker | None = None,
        memory_host: MemoryHost | None = None,
        *,
        require_host: bool = False,
    ) -> None:
        """Create the service from explicit persistence and audit ports."""
        self.repository = repository
        self.audit_logger = audit_logger
        self.memory_host = memory_host
        if require_host and memory_host is None:
            raise RuntimeError("production MemoryService requires the canonical MemoryHost")
        if broker is None and memory_host is not None:
            broker = memory_host.broker
        if require_host and (memory_host is None or broker is not memory_host.broker):
            raise RuntimeError("production MemoryService broker must belong to MemoryHost")
        # No provider or Broker is constructed here.  The gRPC composition
        # passes ``require_host=True``; the MemoryStore branch is limited to
        # explicit legacy/unit callers and is never reachable from production
        # transport composition.
        self.broker = broker
        self.event_bridge = MemoryEventBridge(broker) if broker is not None else None

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
            if self.event_bridge is None:
                raise RuntimeError("MemoryService has no canonical event bridge")
            source_event = await self.event_bridge.user_message(
                runtime,
                content=value,
                key=key,
                scope=scope,
            )
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
            return {
                "ok": True,
                "id": decision.memory_id,
                "memory_id": decision.memory_id,
                "legacy_id": None,
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
            legacy_hit = await self.broker.get(canonical_id, runtime)
            if legacy_hit is not None:
                await self.broker.forget((canonical_id,), runtime, mode="soft")
            # Forget is intentionally non-enumerating: an unknown or foreign
            # id has the same public result as an owned id.  Most importantly,
            # a production Broker must never fall through to the legacy
            # integer-id store after canonical composition has been selected.
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

        if self.broker is not None and (not ctx.principal_id or not ctx.project_id):
            raise PermissionError("Memory V2 RPC context requires principal and project identity")

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
