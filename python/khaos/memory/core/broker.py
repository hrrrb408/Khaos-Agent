"""Non-bypassable Memory V2 Broker.

The Broker is the only component allowed to turn provider output into
model-visible memory.  It binds scope from the runtime, reclassifies provider
authority, applies applicability and temporal gates, and records every
decision.  Providers remain replaceable evidence engines below this boundary.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import replace
from datetime import UTC, datetime
from functools import wraps
from time import monotonic
from typing import Any, cast

from khaos.memory.audit import DurableMemoryAuditSink, TrustKernelMemoryAuditSink
from khaos.memory.core.authority import VerificationReceiptVerifier
from khaos.memory.core.contracts import (
    EvidenceResolution,
    ForgetResult,
    MemoryAuthority,
    MemoryBudget,
    MemoryCandidate,
    MemoryDecision,
    MemoryEvent,
    MemoryEventType,
    MemoryForgetRequest,
    MemoryHit,
    MemoryObjectIdentity,
    MemoryProvider,
    MemorySearchRequest,
    MemoryStatus,
    MemoryWriteRequest,
    RuntimeMemoryContext,
    SourceType,
    TrustHint,
    enum_value,
)
from khaos.memory.core.policy import (
    MemoryPolicy,
    ScreeningAction,
    SupersessionPolicy,
    applicability_matches,
    candidate_status,
    reclassify_provider_authority,
    scope_matches,
    screen_text,
    temporal_matches,
    usage_allows_injection,
)
from khaos.memory.ledger import SqliteEventLedger
from khaos.memory.profiles import MemoryProfile

logger = logging.getLogger(__name__)


def _serialized_projection_mutation(method: Callable[..., Awaitable[Any]]) -> Callable[..., Awaitable[Any]]:
    """Serialize ledger-backed projection mutations with a rebuild."""

    @wraps(method)
    async def wrapped(self: MemoryBroker, *args: Any, **kwargs: Any) -> Any:
        async with self._projection_lock:
            return await method(self, *args, **kwargs)

    return wrapped


class MemoryBroker:
    """Admission, provenance, retrieval, and forget authority for memory."""

    def __init__(
        self,
        provider: MemoryProvider,
        ledger: SqliteEventLedger,
        *,
        policy: MemoryPolicy | None = None,
        verification_verifier: Any = None,
        profile: MemoryProfile | None = None,
        codegraph: Any = None,
        observability: Any = None,
        provider_registry: Any = None,
        audit_sink: Any = None,
        audit_required: bool = False,
    ) -> None:
        self.provider = provider
        self.ledger = ledger
        self.profile = profile
        self.policy = (profile.policy(policy) if profile is not None else policy) or MemoryPolicy()
        if verification_verifier is not None:
            self.verification_verifier = verification_verifier
        else:
            self.verification_verifier = VerificationReceiptVerifier()
        self.codegraph = codegraph
        self.observability = observability
        self._provider_registry = provider_registry
        self._provider_lock = asyncio.Lock()
        self._rebuild_lock = asyncio.Lock()
        self._projection_lock = asyncio.Lock()
        self._rebuild_idle = asyncio.Event()
        self._rebuild_idle.set()
        self.supersession_policy = SupersessionPolicy()
        if audit_sink is not None:
            self.audit_sink = audit_sink
        elif audit_required:
            self.audit_sink = TrustKernelMemoryAuditSink(None, required=True)
        else:
            self.audit_sink = DurableMemoryAuditSink(ledger.database)
        self.audit_required = audit_required

    def bind_provider_registry(self, registry: Any) -> None:
        """Bind the lifecycle authority used by production provider switching."""

        if self._provider_registry is not None and self._provider_registry is not registry:
            raise RuntimeError("memory provider registry is already bound")
        self._provider_registry = registry

    async def record_event(self, event: MemoryEvent) -> str:
        """Append a canonical event before any derived-memory write."""

        return await self.ledger.append(event)

    @_serialized_projection_mutation
    async def propose_memory(
        self,
        candidate: MemoryCandidate,
        runtime: RuntimeMemoryContext,
    ) -> MemoryDecision:
        """Screen, persist, and audit one derived-memory proposal."""

        self._validate_candidate_scope(candidate, runtime)
        candidate = await self._bind_candidate_authority(candidate, runtime)
        await self._audit(
            "MEMORY_WRITE_REQUESTED",
            runtime,
            detail={
                "memory_type": enum_value(candidate.memory_type),
                "namespace": candidate.namespace,
                "scope": candidate.scope,
            },
        )
        try:
            candidate_size = _candidate_size(candidate)
        except (TypeError, ValueError):
            return self._decision(
                False,
                MemoryStatus.REJECTED,
                "candidate_not_serializable",
            )
        if candidate_size > self.policy.max_candidate_bytes:
            return self._decision(
                False,
                MemoryStatus.REJECTED,
                "candidate_oversized",
            )
        if not candidate.source_event_ids and not candidate.evidence_refs:
            return self._decision(False, MemoryStatus.REJECTED, "evidence_required")
        for event_id in candidate.source_event_ids:
            if await self.ledger.get(event_id, runtime) is None:
                return self._decision(False, MemoryStatus.REJECTED, "source_event_out_of_scope")

        source_type = self._candidate_source_type(candidate)
        screening = screen_text(
            candidate.claim,
            source_type=source_type,
            policy=self.policy,
        )
        verified = (
            enum_value(candidate.authority) == MemoryAuthority.VERIFICATION_CONFIRMED.value
            and self.verification_verifier.validate(
                candidate,
                token=candidate.verification_proof,
                verification_run_id=candidate.verification_run_id,
                principal_id=runtime.principal_id,
                project_id=runtime.project_id,
                session_id=runtime.session_id,
                task_id=runtime.task_id,
                workspace_id=runtime.workspace_id,
                result_digest=candidate.verification_result_digest,
            )
        )
        status, reason = candidate_status(
            candidate,
            verified=verified,
            screened=screening,
            policy=self.policy,
        )
        authority = self._admitted_authority(candidate, verified)
        candidate_event = MemoryEvent.create(
            MemoryEventType.MEMORY_CANDIDATE_CREATED,
            principal_id=runtime.principal_id,
            project_id=runtime.project_id,
            session_id=runtime.session_id,
            task_id=runtime.task_id,
            workspace_id=runtime.workspace_id,
            repo_id=runtime.repo_id,
            branch=runtime.branch,
            commit_sha=runtime.commit_sha,
            source_type=SourceType.SYSTEM,
            trust_hint=TrustHint.AGENT_INFERRED,
            sensitivity=candidate.sensitivity,
            payload={
                "claim": candidate.claim,
                "memory_type": enum_value(candidate.memory_type),
                "key": candidate.key or "",
                "namespace": candidate.namespace,
                "scope": candidate.scope,
                "status": status.value,
                "reason": reason,
                "source_event_ids": list(candidate.source_event_ids),
                "requested_authority": enum_value(candidate.authority),
                "admitted_authority": authority.value,
                "confidence": candidate.confidence,
                "sensitivity": enum_value(candidate.sensitivity),
                "usage_policy": enum_value(candidate.usage_policy),
                "preconditions": dict(candidate.preconditions),
                "environment": dict(candidate.environment),
                "session_id": candidate.session_id or "",
                "valid_from": candidate.valid_from.isoformat() if candidate.valid_from else "",
                "valid_to": candidate.valid_to.isoformat() if candidate.valid_to else "",
                "verification_run_id": candidate.verification_run_id or "",
                "verification_result_digest": candidate.verification_result_digest or "",
                "source_kind": enum_value(candidate.source_kind) if candidate.source_kind else "",
                "provenance": dict(candidate.provenance),
                "mode": runtime.mode,
                "environment_fingerprint": runtime.environment_fingerprint,
                "runtime_environment": dict(runtime.environment),
                "evidence_refs": [
                    {
                        "source_type": enum_value(ref.source_type),
                        "source_ref": ref.source_ref,
                        "event_id": ref.event_id,
                        "verification_run_id": ref.verification_run_id,
                        "commit_sha": ref.commit_sha,
                    }
                    for ref in candidate.evidence_refs
                ],
                "entities": [
                    {
                        "entity_type": entity.entity_type,
                        "canonical_name": entity.canonical_name,
                        "entity_id": entity.entity_id,
                    }
                    for entity in candidate.entities
                ],
                "relations": [
                    {
                        "relation": relation.relation,
                        "target_kind": relation.target_kind,
                        "target_id": relation.target_id,
                        "confidence": relation.confidence,
                    }
                    for relation in candidate.relations
                ],
            },
        )
        await self.ledger.append(candidate_event)
        if status is MemoryStatus.REJECTED:
            await self._audit("MEMORY_WRITE_REJECTED", runtime, detail={"reason": reason})
            return self._decision(False, status, reason, event_id=candidate_event.event_id)

        supersede_ids, conflict_reason = await self._supersession_targets(
            candidate,
            runtime,
            authority=authority,
            status=status,
        )
        if conflict_reason:
            await self._append_state_event(
                MemoryEventType.MEMORY_CONFLICT_DETECTED,
                runtime,
                "",
                (),
                detail={
                    "key": candidate.key or "",
                    "memory_type": enum_value(candidate.memory_type),
                    "reason": conflict_reason,
                },
            )
        admitted = MemoryWriteRequest(
            candidate=candidate,
            runtime=runtime,
            status=status,
            authority=authority,
            provider_id=self.provider.provider_id,
            candidate_event_id=candidate_event.event_id,
            supersede_memory_ids=supersede_ids,
        )
        try:
            result = await self.provider.add(admitted)
        except Exception as exc:
            logger.exception("memory provider add failed")
            await self._audit(
                "MEMORY_PROVIDER_FAILED",
                runtime,
                detail={"operation": "add", "error": type(exc).__name__},
            )
            return self._decision(
                False,
                MemoryStatus.QUARANTINED,
                "provider_failure",
                event_id=candidate_event.event_id,
            )

        if supersede_ids:
            await self._append_state_event(
                MemoryEventType.MEMORY_SUPERSEDED,
                runtime,
                result.memory_id,
                supersede_ids,
            )
        if status in {MemoryStatus.ACTIVE, MemoryStatus.VERIFIED}:
            await self._append_state_event(
                MemoryEventType.MEMORY_PROMOTED,
                runtime,
                result.memory_id,
                (candidate_event.event_id,),
            )
        action = (
            "MEMORY_WRITE_QUARANTINED"
            if status is MemoryStatus.QUARANTINED
            else "MEMORY_WRITE_ACCEPTED"
        )
        await self._audit(
            action,
            runtime,
            memory_id=result.memory_id,
            detail={
                "status": status.value,
                "reason": reason,
                "superseded": len(supersede_ids),
                "evidence_added": result.evidence_added,
            },
        )
        return self._decision(
            True,
            status,
            reason,
            memory_id=result.memory_id,
            event_id=candidate_event.event_id,
        )

    async def search(
        self,
        query: str,
        runtime: RuntimeMemoryContext,
        budget: Any,
        *,
        include_historical: bool = False,
    ) -> EvidenceResolution:
        """Retrieve evidence and admit only safe, applicable current hits."""

        await self._rebuild_idle.wait()
        if not isinstance(query, str) or len(query) > self.policy.max_search_query_length:
            raise ValueError("memory search query is missing or too long")
        started = monotonic()
        provider = self.provider
        limit = min(
            max(int(getattr(budget, "max_hits", 32)), 0),
            self.policy.max_search_hits,
        )
        if limit == 0:
            await self._record_metric(
                "memory.search.latency_ms",
                (monotonic() - started) * 1000,
                runtime,
                unit="ms",
                operation="search",
            )
            return EvidenceResolution(())
        request = MemorySearchRequest(
            query=query,
            runtime=runtime,
            limit=limit,
            include_historical=include_historical,
            profile_id=self.profile.profile_id if self.profile is not None else "",
            filters={"mode": runtime.mode},
            source_kinds=("memory", "codegraph") if self.codegraph is not None else ("memory",),
        )
        await self._audit(
            "MEMORY_SEARCH_REQUESTED",
            runtime,
            detail={"query_hash": _hash_query(query), "limit": limit},
        )
        raw_hits: list[MemoryHit] = []
        provider_error: str | None = None
        source_tasks: list[asyncio.Future[Any] | asyncio.Task[Any] | Any] = []
        source_kinds: list[str] = []
        capabilities = provider.capabilities()
        provider_search_enabled = self.profile is None or self.profile.fts or (
            self.profile.vector and bool(getattr(capabilities, "vector_search", False))
        )
        if provider_search_enabled:
            source_tasks.append(provider.search(request))
            source_kinds.append("memory")
        if self.codegraph is not None and self.profile is not None and self.profile.codegraph:
            source_tasks.append(
                self.codegraph.search(
                    query,
                    runtime,
                    limit=limit,
                    max_hops=self.profile.max_graph_hops,
                )
            )
            source_kinds.append("codegraph")
        results = await asyncio.gather(*source_tasks, return_exceptions=True)
        for index, result in enumerate(results):
            source_kind = source_kinds[index]
            if isinstance(result, Exception):
                error_name = type(result).__name__
                logger.error("memory source search failed: %s", type(result).__name__)
                if source_kind == "memory":
                    provider_error = error_name
                    await self._audit(
                        "MEMORY_PROVIDER_FAILED",
                        runtime,
                        detail={"operation": "search", "error": error_name},
                    )
                else:
                    await self._audit(
                        "MEMORY_PROVIDER_FAILED",
                        runtime,
                        detail={"operation": f"{source_kind}_search", "error": error_name},
                    )
                continue
            if not isinstance(result, Sequence) or isinstance(result, (str, bytes)):
                error_name = "malformed_result"
                if source_kind == "memory":
                    provider_error = error_name
                await self._audit(
                    "MEMORY_PROVIDER_FAILED",
                    runtime,
                    detail={
                        "operation": "search" if source_kind == "memory" else f"{source_kind}_search",
                        "error": error_name,
                    },
                )
                continue
            for rank, hit in enumerate(
                (item for item in result if isinstance(item, MemoryHit)),
                start=1,
            ):
                metadata = dict(hit.provider_metadata)
                metadata["retrieval_source"] = source_kind
                retained_source_kind = hit.source_kind
                if not retained_source_kind or retained_source_kind == "memory":
                    retained_source_kind = source_kind
                raw_hits.append(
                    replace(
                        hit,
                        provider_metadata=metadata,
                        source_rank=rank,
                        source_kind=retained_source_kind,
                    )
                )
        if not raw_hits and provider_error is not None:
            await self._record_metric(
                "memory.search.latency_ms",
                (monotonic() - started) * 1000,
                runtime,
                unit="ms",
                operation="search",
                metadata={"provider_error": provider_error},
            )
            return EvidenceResolution((), provider_error=provider_error)

        accepted: list[MemoryHit] = []
        filtered = 0
        explicit_query = bool(query.strip())
        bounded_raw_hits = raw_hits[: self.policy.max_search_hits]
        try:
            revoked_ids = await self._revoked_ids(
                runtime,
                [
                    hit.memory_id
                    for hit in bounded_raw_hits
                    if isinstance(hit, MemoryHit) and hit.memory_id
                ],
                provider_id=provider.provider_id,
            )
        except Exception as exc:
            logger.exception("memory revocation ledger read failed")
            await self._record_metric(
                "memory.search.latency_ms",
                (monotonic() - started) * 1000,
                runtime,
                unit="ms",
                operation="search",
                metadata={"provider_error": type(exc).__name__},
            )
            return EvidenceResolution((), provider_error=type(exc).__name__)
        for raw_hit in bounded_raw_hits:
            try:
                normalized = await self._normalize_hit(raw_hit, runtime, provider=provider)
            except (AttributeError, TypeError, ValueError):
                normalized = None
            if normalized is None:
                filtered += 1
                continue
            if not scope_matches(normalized, runtime):
                filtered += 1
                continue
            if normalized.memory_id and normalized.memory_id in revoked_ids:
                filtered += 1
                continue
            screening = screen_text(
                normalized.content,
                source_type=normalized.source_type,
                policy=self.policy,
            )
            if screening.action is not ScreeningAction.ALLOW:
                filtered += 1
                continue
            if not applicability_matches(normalized, runtime):
                filtered += 1
                continue
            if not temporal_matches(
                normalized,
                include_historical=include_historical,
            ):
                filtered += 1
                continue
            if not usage_allows_injection(
                normalized,
                runtime,
                explicit_query=explicit_query,
                include_historical=include_historical,
            ):
                filtered += 1
                continue
            accepted.append(normalized)

        accepted = _fuse_hits(accepted)
        accepted.sort(key=_hit_sort_key)
        primary, supporting, conflicts = _partition_hits(accepted)
        latest = _latest_valid(primary or supporting)
        if accepted and hasattr(provider, "record_retrieval"):
            try:
                await provider.record_retrieval(  # type: ignore[attr-defined]
                    [hit.memory_id for hit in accepted if hit.memory_id],
                    runtime,
                )
            except Exception:
                logger.warning("memory retrieval statistics update failed", exc_info=True)
        if accepted and hasattr(provider, "record_application"):
            try:
                await provider.record_application(  # type: ignore[attr-defined]
                    [hit.memory_id for hit in accepted if hit.memory_id],
                    runtime,
                )
            except Exception:
                logger.warning("memory application statistics update failed", exc_info=True)
        if filtered:
            await self._audit(
                "MEMORY_HIT_FILTERED",
                runtime,
                detail={"count": filtered},
            )
        if primary or supporting:
            await self._audit(
                "MEMORY_HIT_INJECTED",
                runtime,
                detail={"count": len(primary) + len(supporting)},
            )
        await self._record_metric(
            "memory.search.latency_ms",
            (monotonic() - started) * 1000,
            runtime,
            unit="ms",
            operation="search",
            metadata={
                "accepted": len(primary) + len(supporting),
                "conflicts": len(conflicts),
                "filtered": filtered,
            },
        )
        return EvidenceResolution(
            tuple(primary),
            tuple(supporting),
            tuple(conflicts),
            latest_valid_fact=latest,
            provider_error=provider_error,
        )

    async def resolve_evidence(
        self,
        query: str,
        runtime: RuntimeMemoryContext,
        budget: MemoryBudget,
        *,
        required_types: Sequence[str] = (),
        include_historical: bool = False,
    ) -> EvidenceResolution:
        """Resolve localization and evidence completion as one bounded call."""

        resolution = await self.search(
            query,
            runtime,
            budget,
            include_historical=include_historical,
        )
        required = {str(value) for value in required_types if str(value).strip()}
        if not required:
            return resolution

        supporting = list(resolution.supporting_hits)
        conflicts = list(resolution.conflicts)
        primary = list(resolution.primary_hits)
        candidates = [*primary, *supporting]
        max_nodes = min(
            max(int(getattr(budget, "max_candidate_nodes", 64)), 0),
            self.policy.max_search_hits,
        )
        max_expansions = min(
            max(int(getattr(budget, "max_evidence_expansions", 64)), 0),
            max_nodes,
        )
        available_memory_types = {
            enum_value(hit.memory_type) for hit in candidates[:max_nodes]
        }
        available_event_types: set[str] = set()
        available_sources: set[str] = set()
        available_relations: set[str] = set()
        has_provenance = False
        has_verification = False
        has_temporal_relation = False

        # Source-event completion is deliberately ledger-backed.  Provider
        # metadata can point at an event, but only a scoped local ledger row
        # can make that reference usable evidence.
        for hit in candidates[:max_nodes]:
            if hit.event_ids or hit.evidence_refs:
                has_provenance = True
            refs = [*hit.event_ids, *(ref.event_id for ref in hit.evidence_refs)]
            for event_id in tuple(dict.fromkeys(value for value in refs if value))[:32]:
                row = await self.ledger.get(str(event_id), runtime)
                if row is None:
                    continue
                has_provenance = True
                available_event_types.add(str(row.get("event_type") or ""))
                available_sources.add(str(row.get("source_type") or ""))
                if str(row.get("event_type")) == MemoryEventType.VERIFICATION_RESULT.value:
                    has_verification = True

        related_ids = ()
        if self.profile is None or self.profile.graph:
            related_ids = await self._related_memory_ids(
                runtime,
                [hit.memory_id for hit in candidates[:max_nodes] if hit.memory_id],
                max_hops=max(0, int(getattr(budget, "max_graph_hops", 2))),
                limit=max_expansions,
            )
        temporal_relations = {
            "PRECEDES",
            "FOLLOWS",
            "SUPERSEDES",
            "SUPERSEDED_BY",
            "TEMPORAL",
            "TEMPORAL_PREDECESSOR",
            "TEMPORAL_SUCCESSOR",
        }
        for relation, memory_id in related_ids:
            available_relations.add(relation)
            if relation.upper() in temporal_relations:
                has_temporal_relation = True
            if len(supporting) >= max_expansions:
                break
            if any(hit.memory_id == memory_id for hit in candidates):
                continue
            related = await self.get(memory_id, runtime, include_historical=True)
            if related is None:
                continue
            if any(
                (hit.scope, hit.key, hit.content) ==
                (related.scope, related.key, related.content)
                for hit in (*primary, *supporting)
            ):
                continue
            if any(
                hit.scope == related.scope and hit.key == related.key
                and hit.content != related.content
                for hit in primary
            ):
                conflicts.append(related)
            else:
                supporting.append(related)

        # Temporal predecessor/successor completion is bounded to each
        # localized key.  It deliberately preserves the Broker's normal
        # normalization and scope gates; a provider cannot inject a related
        # row merely by returning an id in metadata.
        temporal_terms = {"temporal", "temporal_predecessor", "temporal_successor"}
        if (
            (self.profile is None or self.profile.temporal)
            and required.intersection(temporal_terms)
            and len(supporting) < max_expansions
        ):
            for hit in primary[:max_nodes]:
                if not hit.key:
                    continue
                search = _async_method(self.provider, "search")
                if search is None:
                    continue
                try:
                    rows = await search(
                        MemorySearchRequest(
                            query=hit.key,
                            runtime=runtime,
                            limit=min(max_expansions, 16),
                            include_historical=True,
                        )
                    )
                except Exception as exc:  # noqa: BLE001 - provider evidence is fail-closed
                    logger.debug(
                        "bounded temporal evidence expansion failed: %s",
                        type(exc).__name__,
                    )
                    rows = ()
                for raw in rows if isinstance(rows, Sequence) else ():
                    if not isinstance(raw, MemoryHit) or raw.memory_id == hit.memory_id:
                        continue
                    normalized = await self._normalize_hit(raw, runtime)
                    if normalized is None or not scope_matches(normalized, runtime):
                        continue
                    if normalized.key != hit.key:
                        continue
                    if any(existing.memory_id == normalized.memory_id for existing in (*primary, *supporting)):
                        continue
                    supporting.append(normalized)
                    has_temporal_relation = True
                    if len(supporting) >= max_expansions:
                        break
                if has_temporal_relation:
                    break

        available: set[str] = set(available_memory_types)
        if has_provenance:
            available.update({"provenance", "source_event"})
        if has_verification:
            available.update({"verification", "verification_result"})
        if has_temporal_relation:
            available.update({"temporal", "temporal_predecessor", "temporal_successor"})
        available.update(f"event:{value}" for value in available_event_types if value)
        available.update(f"source:{value}" for value in available_sources if value)
        available.update(f"relation:{value}" for value in available_relations if value)
        missing = tuple(sorted(required - available))
        if missing:
            await self._audit(
                "MEMORY_EVIDENCE_INCOMPLETE",
                runtime,
                detail={
                    "query_hash": _hash_query(query),
                    "missing": list(missing)[:32],
                    "expanded": len(supporting) - len(resolution.supporting_hits),
                },
            )
        return replace(
            resolution,
            supporting_hits=tuple(supporting[:max_expansions]),
            conflicts=tuple(conflicts[:max_expansions]),
            missing_requirements=missing,
        )

    async def _related_memory_ids(
        self,
        runtime: RuntimeMemoryContext,
        memory_ids: Sequence[str],
        *,
        max_hops: int,
        limit: int,
    ) -> tuple[tuple[str, str], ...]:
        """Read a bounded, scope-closed relation frontier from native storage."""

        if max_hops <= 0 or not memory_ids or limit <= 0:
            return ()
        database = getattr(self.ledger, "database", None)
        if database is None:
            return ()
        frontier = {str(value) for value in memory_ids if value}
        visited = set(frontier)
        found: list[tuple[str, str]] = []
        for _ in range(min(max_hops, 4)):
            if not frontier or len(found) >= limit:
                break
            placeholders = ",".join("?" for _ in frontier)
            async with database.read_connection() as conn:
                rows = await (
                    await conn.execute(
                        "SELECT relation, from_kind, from_id, to_kind, to_id "
                        "FROM memory_edges WHERE project_id = ? "
                        "AND (principal_id = ? OR principal_id = '') "
                        "AND ((from_kind = 'memory' AND from_id IN (" + placeholders + ")) "
                        "OR (to_kind = 'memory' AND to_id IN (" + placeholders + "))) "
                        "LIMIT ?",
                        (
                            runtime.project_id,
                            runtime.principal_id,
                            *frontier,
                            *frontier,
                            limit,
                        ),
                    )
                ).fetchall()
            next_frontier: set[str] = set()
            for row in rows:
                relation = str(row["relation"] or "")
                if row["from_kind"] == "memory" and row["from_id"] in frontier:
                    target = str(row["to_id"] or "") if row["to_kind"] == "memory" else ""
                elif row["to_kind"] == "memory" and row["to_id"] in frontier:
                    target = str(row["from_id"] or "") if row["from_kind"] == "memory" else ""
                else:
                    target = ""
                if not target or target in visited:
                    continue
                visited.add(target)
                next_frontier.add(target)
                found.append((relation, target))
                if len(found) >= limit:
                    break
            frontier = next_frontier
        return tuple(found[:limit])

    @_serialized_projection_mutation
    async def forget(
        self,
        selector: MemoryForgetRequest | Sequence[str],
        actor: RuntimeMemoryContext | None = None,
        *,
        mode: str = "soft",
    ) -> ForgetResult:
        """Forget memory without allowing a foreign selector to widen scope."""

        if isinstance(selector, MemoryForgetRequest):
            request = selector
            runtime = selector.runtime
        else:
            if actor is None:
                raise ValueError("actor runtime is required for forget")
            request = MemoryForgetRequest(tuple(selector), actor, mode=mode)
            runtime = actor
        # Resolve ownership before recording intent.  A foreign selector must
        # not create a project-wide revocation marker for another principal's
        # private memory.  The lookup does not leak existence to the caller.
        target_ids = await self._owned_forget_targets(request)
        owned_identities: list[MemoryObjectIdentity] = []
        # Record intent before mutating derived storage.  A crash after this
        # append but before provider deletion remains recoverable and fail
        # closed: the next search/rebuild sees the revocation marker.
        for memory_id in target_ids:
            identity = await self._owned_forget_identity(memory_id, runtime)
            if identity is None:
                continue
            owned_identities.append(identity)
            await self._append_state_event(
                MemoryEventType.MEMORY_REVOKED,
                runtime,
                memory_id,
                (),
                detail={
                    "forget_mode": request.mode,
                    "project_id": runtime.project_id,
                    "principal_id": identity.principal_id,
                    "session_id": identity.session_id or "",
                    "namespace": identity.namespace,
                    "scope": request.scope or "",
                    "provider_id": identity.provider_id,
                },
            )
        request = replace(
            request,
            memory_ids=tuple(identity.memory_id for identity in owned_identities),
            identities=tuple(owned_identities),
        )
        if not owned_identities:
            await self._audit(
                "MEMORY_FORGOTTEN",
                runtime,
                detail={"mode": request.mode, "count": 0},
            )
            return ForgetResult((), request.mode)
        try:
            result = await self.provider.forget(request)
        except Exception as exc:
            await self._audit(
                "MEMORY_PROVIDER_FAILED",
                runtime,
                detail={"operation": "forget", "error": type(exc).__name__},
            )
            raise RuntimeError("memory provider forget failed") from exc
        await self._audit(
            "MEMORY_FORGOTTEN",
            runtime,
            detail={"mode": request.mode, "count": len(result.forgotten_ids)},
        )
        return result

    @_serialized_projection_mutation
    async def promote_memory(
        self,
        memory_id: str,
        runtime: RuntimeMemoryContext,
        *,
        verification_run_id: str | None = None,
        verification_proof: str | None = None,
        verification_result_digest: str | None = None,
        user_approved: bool = False,
    ) -> MemoryDecision:
        """Promote a persisted candidate only through trusted evidence."""

        getter = _async_method(self.provider, "get_by_id")
        promoter = _async_method(self.provider, "promote")
        if getter is None or promoter is None:
            return self._decision(False, MemoryStatus.REJECTED, "provider_promotion_unsupported")
        raw_hit = await getter(runtime, memory_id)
        if not isinstance(raw_hit, MemoryHit):
            return self._decision(False, MemoryStatus.REJECTED, "memory_not_found")
        hit = await self._normalize_hit(raw_hit, runtime)
        if hit is None or not scope_matches(hit, runtime):
            return self._decision(False, MemoryStatus.REJECTED, "memory_out_of_scope")
        verified = user_approved or self.verification_verifier.validate_memory(
            hit,
            token=verification_proof,
            verification_run_id=verification_run_id,
            principal_id=runtime.principal_id,
            project_id=runtime.project_id,
            session_id=runtime.session_id,
            task_id=runtime.task_id,
            workspace_id=runtime.workspace_id,
            result_digest=verification_result_digest,
        )
        if not verified:
            await self._audit(
                "MEMORY_WRITE_REJECTED",
                runtime,
                memory_id=memory_id,
                detail={"reason": "verification_authority_missing"},
            )
            return self._decision(False, MemoryStatus.QUARANTINED, "verification_authority_missing")
        authority = (
            MemoryAuthority.USER_STATED.value
            if user_approved
            else MemoryAuthority.VERIFICATION_CONFIRMED.value
        )
        promoted = await promoter(
            memory_id,
            runtime,
            authority=authority,
            status=MemoryStatus.VERIFIED,
        )
        if not promoted:
            return self._decision(False, MemoryStatus.REJECTED, "memory_not_found")
        await self._append_state_event(
            MemoryEventType.MEMORY_PROMOTED,
            runtime,
            memory_id,
            hit.event_ids,
            detail={
                "promotion": "user_approved" if user_approved else "verification_authority",
                "verification_run_id": verification_run_id or "",
            },
        )
        await self._audit(
            "MEMORY_PROMOTED",
            runtime,
            memory_id=memory_id,
            detail={"verification_run_id": verification_run_id or ""},
        )
        return self._decision(True, MemoryStatus.VERIFIED, "promotion_authorized", memory_id=memory_id)

    async def record_observation(
        self,
        memory_id: str,
        runtime: RuntimeMemoryContext,
        *,
        success: bool | None = None,
        contradiction: bool = False,
        user_confirmed: bool = False,
    ) -> bool:
        """Record outcome telemetry without changing authority implicitly."""

        recorder = _async_method(self.provider, "record_observation")
        if not callable(recorder):
            return False
        updated = bool(
            await recorder(
                memory_id,
                runtime,
                success=success,
                contradiction=contradiction,
                user_confirmed=user_confirmed,
            )
        )
        if updated:
            await self._audit(
                "MEMORY_OBSERVATION_RECORDED",
                runtime,
                memory_id=memory_id,
                detail={
                    "success": success,
                    "contradiction": contradiction,
                    "user_confirmed": user_confirmed,
                },
            )
        return updated

    async def compact(self, runtime: RuntimeMemoryContext, *, limit: int = 256) -> int:
        """Run conservative cleanup without deleting canonical evidence."""

        compact = _async_method(self.provider, "compact")
        if not callable(compact):
            return 0
        await self._audit("MEMORY_REBUILD_STARTED", runtime, detail={"operation": "compact"})
        removed = int(await compact(runtime, limit=limit))
        await self._audit(
            "MEMORY_REBUILD_FINISHED",
            runtime,
            detail={"operation": "compact", "removed": removed},
        )
        return removed

    async def _owned_forget_targets(
        self,
        request: MemoryForgetRequest,
    ) -> tuple[str, ...]:
        """Return selectors proven to be in the provider's runtime scope."""

        getter = _async_method(self.provider, "get_by_id")
        if not callable(getter):
            raise TypeError(
                "forget requires a provider capability that proves scoped ownership"
            )
        owned: list[str] = []
        for memory_id in request.memory_ids:
            raw_hit = await getter(request.runtime, memory_id)
            if not isinstance(raw_hit, MemoryHit):
                continue
            normalized = await self._normalize_hit(raw_hit, request.runtime)
            if normalized is None:
                continue
            if normalized.memory_id != memory_id or not scope_matches(normalized, request.runtime):
                continue
            if request.namespace is not None and normalized.namespace != request.namespace:
                continue
            if request.scope is not None and normalized.scope != request.scope:
                continue
            if request.identities:
                identity = MemoryObjectIdentity.from_hit(normalized)
                if identity not in request.identities:
                    continue
            owned.append(memory_id)
        return tuple(owned)

    async def _owned_forget_identity(
        self,
        memory_id: str,
        runtime: RuntimeMemoryContext,
    ) -> MemoryObjectIdentity | None:
        """Resolve the exact identity again before writing a revoke event."""

        getter = _async_method(self.provider, "get_by_id")
        if not callable(getter):
            return None
        raw_hit = await getter(runtime, memory_id)
        if not isinstance(raw_hit, MemoryHit):
            return None
        normalized = await self._normalize_hit(raw_hit, runtime)
        if normalized is None or not scope_matches(normalized, runtime):
            return None
        if normalized.memory_id != memory_id:
            return None
        return MemoryObjectIdentity.from_hit(normalized)

    async def get_current(
        self,
        runtime: RuntimeMemoryContext,
        *,
        scope: str,
        key: str,
        namespace: str = "private",
        session_id: str | None = None,
    ) -> MemoryHit | None:
        """Resolve a current key through the same Broker admission gates."""

        provider = self.provider
        getter = _async_method(provider, "get_current")
        if not callable(getter):
            resolution = await self.search(key, runtime, _KeyBudget(), include_historical=False)
            return next((hit for hit in resolution.primary_hits if hit.key == key), None)
        raw_hit = await getter(
            runtime,
            scope=scope,
            key=key,
            namespace=namespace,
            session_id=session_id,
        )
        if raw_hit is None:
            return None
        normalized = await self._normalize_hit(raw_hit, runtime, provider=provider)
        if normalized is None:
            return None
        if not scope_matches(normalized, runtime):
            return None
        if normalized.memory_id:
            try:
                if normalized.memory_id in await self._revoked_ids(
                    runtime,
                    [normalized.memory_id],
                    provider_id=provider.provider_id,
                ):
                    return None
            except Exception:
                logger.exception("memory revocation ledger read failed")
                return None
        screening = screen_text(
            normalized.content,
            source_type=normalized.source_type,
            policy=self.policy,
        )
        if screening.action is not ScreeningAction.ALLOW:
            return None
        if not usage_allows_injection(normalized, runtime, explicit_query=True):
            return None
        if not applicability_matches(normalized, runtime):
            return None
        if not temporal_matches(normalized):
            return None
        return normalized

    async def get(
        self,
        memory_id: str,
        runtime: RuntimeMemoryContext,
        *,
        include_historical: bool = True,
    ) -> MemoryHit | None:
        """Resolve one memory for user-facing inspection through the Broker."""

        if not memory_id:
            return None
        provider = self.provider
        getter = _async_method(provider, "get_by_id")
        if not callable(getter):
            return None
        raw_hit = await getter(runtime, memory_id)
        if raw_hit is None:
            return None
        normalized = await self._normalize_hit(raw_hit, runtime, provider=provider)
        if normalized is None or not scope_matches(normalized, runtime):
            return None
        if memory_id in await self._revoked_ids(
            runtime,
            [memory_id],
            provider_id=provider.provider_id,
        ):
            return None
        screening = screen_text(
            normalized.content,
            source_type=normalized.source_type,
            policy=self.policy,
        )
        if screening.action is not ScreeningAction.ALLOW:
            return None
        if not usage_allows_injection(
            normalized,
            runtime,
            explicit_query=True,
            include_historical=include_historical,
        ):
            return None
        if not applicability_matches(normalized, runtime):
            return None
        if not temporal_matches(normalized, include_historical=include_historical):
            return None
        return normalized

    async def health(self) -> Any:
        """Return provider health without altering security policy."""

        return await self.provider.health()

    def capabilities(self) -> Any:
        """Return provider capabilities for explicit feature negotiation."""

        return self.provider.capabilities()

    async def set_provider(
        self,
        provider: MemoryProvider,
        runtime: RuntimeMemoryContext,
        *,
        provider_id: str | None = None,
        prepared: bool = False,
        emit_event: bool = True,
    ) -> None:
        """Atomically replace the active provider after a complete smoke test."""

        async with self._provider_lock:
            if self._provider_registry is not None:
                ready = getattr(self._provider_registry, "is_ready", None)
                if not callable(ready) or not ready(provider):
                    raise RuntimeError(
                        "provider must be started and health-checked by the registry"
                    )
            health = await provider.health()
            if not health.healthy:
                raise RuntimeError(f"target memory provider is unhealthy: {health.detail}")
            if not prepared:
                shared_projection = self._shares_projection(provider)
                replay = _async_method(provider, "rebuild_from_events")
                if replay is not None and not shared_projection:
                    events = await self._read_all_replay_events(runtime, page_size=10_000)
                    await replay(events)
                    rebuild = _async_method(provider, "rebuild_indexes")
                    if rebuild is not None and not shared_projection:
                        await rebuild()
                smoke = await provider.search(
                    MemorySearchRequest(
                        query="",
                        runtime=runtime,
                        limit=1,
                        profile_id=self.profile.profile_id if self.profile else "",
                    )
                )
                if not isinstance(smoke, Sequence):
                    raise RuntimeError("target provider returned malformed smoke result")
            previous = self.provider.provider_id
            # The pointer is the only serving-state mutation and happens
            # after target replay/rebuild/health.  Existing searches either
            # use the old pointer or the new one; no partially rebuilt target
            # is ever published.
            async with self._projection_lock:
                self.provider = provider
                if emit_event:
                    await self.record_event(
                        MemoryEvent.create(
                            MemoryEventType.PROVIDER_CHANGED,
                            principal_id=runtime.principal_id,
                            project_id=runtime.project_id,
                            session_id=runtime.session_id,
                            task_id=runtime.task_id,
                            workspace_id=runtime.workspace_id,
                            repo_id=runtime.repo_id,
                            branch=runtime.branch,
                            commit_sha=runtime.commit_sha,
                            source_type=SourceType.SYSTEM,
                            trust_hint=TrustHint.TOOL_OBSERVED,
                            payload={
                                "from_provider": previous,
                                "to_provider": provider_id or provider.provider_id,
                            },
                        )
                    )
                    await self._audit(
                        "MEMORY_PROVIDER_CHANGED",
                        runtime,
                        detail={"from_provider": previous, "to_provider": provider.provider_id},
                    )

    async def _read_all_replay_events(
        self,
        runtime: RuntimeMemoryContext,
        *,
        page_size: int,
    ) -> list[dict[str, Any]]:
        """Read all replay events using the canonical stable cursor."""

        events: list[dict[str, Any]] = []
        after_recorded_at: str | None = None
        after_event_id: str | None = None
        while True:
            page = await self.ledger.list(
                runtime,
                event_types=(
                    MemoryEventType.MEMORY_CANDIDATE_CREATED.value,
                    MemoryEventType.MEMORY_PROMOTED.value,
                    MemoryEventType.MEMORY_SUPERSEDED.value,
                    MemoryEventType.MEMORY_REVOKED.value,
                ),
                limit=page_size,
                include_all_sessions=True,
                include_all_principals=True,
                after_recorded_at=after_recorded_at,
                after_event_id=after_event_id,
            )
            if not page:
                return events
            events.extend(page)
            last = page[-1]
            next_cursor = (str(last.get("recorded_at") or ""), str(last.get("event_id") or ""))
            if not all(next_cursor) or next_cursor == (after_recorded_at, after_event_id):
                raise RuntimeError("provider replay cursor did not advance")
            after_recorded_at, after_event_id = next_cursor
            if len(page) < page_size:
                return events

    def _shares_projection(self, provider: Any) -> bool:
        """Return whether a provider uses the Broker's live SQLite projection."""

        return (
            getattr(provider, "database", None)
            is getattr(self.ledger, "database", None)
        )

    async def source(
        self,
        runtime: RuntimeMemoryContext,
        memory_id: str,
    ) -> dict[str, Any] | None:
        """Return user-facing provenance for a memory or CodeGraph node."""

        if self.codegraph is not None and memory_id.startswith("codegraph:"):
            source = await self.codegraph.source(runtime, memory_id.removeprefix("codegraph:"))
            return source
        getter = _async_method(self.provider, "get_source")
        if callable(getter):
            return await getter(runtime, memory_id)
        hit = await self.get(memory_id, runtime, include_historical=True)
        if hit is None:
            return None
        return {
            "memory_id": hit.memory_id,
            "memory_type": enum_value(hit.memory_type),
            "source_ref": hit.source_ref,
            "event_ids": list(hit.event_ids),
            "evidence_refs": [ref.source_ref for ref in hit.evidence_refs],
        }

    async def evidence(
        self,
        runtime: RuntimeMemoryContext,
        memory_id: str,
    ) -> list[dict[str, Any]]:
        """Return bounded evidence rows behind a memory or graph node."""

        if self.codegraph is not None and memory_id.startswith("codegraph:"):
            return await self.codegraph.evidence(runtime, memory_id.removeprefix("codegraph:"))
        getter = _async_method(self.provider, "get_evidence")
        if callable(getter):
            return await getter(runtime, memory_id)
        hit = await self.get(memory_id, runtime, include_historical=True)
        return [
            {
                "source_type": enum_value(ref.source_type),
                "source_ref": ref.source_ref,
                "event_id": ref.event_id,
                "verification_run_id": ref.verification_run_id,
                "commit_sha": ref.commit_sha,
            }
            for ref in (hit.evidence_refs if hit is not None else ())
        ]

    async def conflicts(
        self,
        query: str,
        runtime: RuntimeMemoryContext,
        budget: MemoryBudget,
    ) -> tuple[MemoryHit, ...]:
        """Return only conflict candidates for inspection and maintenance."""

        return (await self.search(query, runtime, budget, include_historical=True)).conflicts

    async def rebuild(self) -> int:
        """Rebuild provider indexes from canonical tables when supported."""

        rebuild = _async_method(self.provider, "rebuild_indexes")
        if not callable(rebuild):
            raise TypeError("provider does not support index rebuild")
        return int(await rebuild())

    async def record_audit(
        self,
        action: str,
        runtime: RuntimeMemoryContext,
        *,
        detail: dict[str, Any] | None = None,
    ) -> None:
        """Expose bounded operational audit without exposing the provider."""

        await self._audit(action, runtime, detail=detail)

    async def rebuild_from_ledger(
        self,
        runtime: RuntimeMemoryContext,
        *,
        limit: int = 10_000,
    ) -> int:
        """Replay the complete ledger with a stable cursor.

        ``limit`` is a page size, never a total-event cap.  The provider is
        invoked only after every page has been read, so a successful call is a
        complete replay rather than a silently partial projection.
        """

        if limit <= 0 or limit > 10_000:
            raise ValueError("memory rebuild page size must be between 1 and 10000")
        replay = _async_method(self.provider, "rebuild_from_events")
        if not callable(replay):
            raise TypeError("provider does not support ledger replay")
        async with self._rebuild_lock, self._projection_lock:
            self._rebuild_idle.clear()
            await self._audit(
                "MEMORY_REBUILD_STARTED",
                runtime,
                detail={"page_size": limit},
            )
            events: list[dict[str, Any]] = []
            cursor_recorded_at: str | None = None
            cursor_event_id: str | None = None
            try:
                while True:
                    page = await self.ledger.list(
                        runtime,
                        event_types=(
                            MemoryEventType.MEMORY_CANDIDATE_CREATED.value,
                            MemoryEventType.MEMORY_PROMOTED.value,
                            MemoryEventType.MEMORY_SUPERSEDED.value,
                            MemoryEventType.MEMORY_REVOKED.value,
                        ),
                        limit=limit,
                        include_all_sessions=True,
                        include_all_principals=True,
                        after_recorded_at=cursor_recorded_at,
                        after_event_id=cursor_event_id,
                    )
                    if not page:
                        break
                    events.extend(page)
                    last = page[-1]
                    next_recorded_at = str(last.get("recorded_at") or "")
                    next_event_id = str(last.get("event_id") or "")
                    if not next_recorded_at or not next_event_id:
                        raise RuntimeError("ledger page has no stable cursor")
                    if (next_recorded_at, next_event_id) == (
                        cursor_recorded_at,
                        cursor_event_id,
                    ):
                        raise RuntimeError("ledger cursor did not advance")
                    cursor_recorded_at, cursor_event_id = next_recorded_at, next_event_id
                    if len(page) < limit:
                        break
                count = int(await replay(events))
                candidate_event_count = sum(
                    1
                    for event in events
                    if event.get("event_type")
                    == MemoryEventType.MEMORY_CANDIDATE_CREATED.value
                )
                await self._audit(
                    "MEMORY_REBUILD_FINISHED",
                    runtime,
                    detail={
                        "ledger_events": len(events),
                        "candidate_events": candidate_event_count,
                        "replayed": count,
                        "cursor": {
                            "recorded_at": cursor_recorded_at or "",
                            "event_id": cursor_event_id or "",
                        },
                    },
                )
                return count
            except BaseException as exc:
                await self._audit(
                    "MEMORY_REBUILD_FAILED",
                    runtime,
                    detail={"error": type(exc).__name__, "events_read": len(events)},
                )
                raise
            finally:
                self._rebuild_idle.set()

    async def _append_state_event(
        self,
        event_type: MemoryEventType,
        runtime: RuntimeMemoryContext,
        memory_id: str,
        related_ids: Sequence[str],
        detail: dict[str, Any] | None = None,
    ) -> None:
        event = MemoryEvent.create(
            event_type,
            principal_id=runtime.principal_id,
            project_id=runtime.project_id,
            session_id=runtime.session_id,
            task_id=runtime.task_id,
            workspace_id=runtime.workspace_id,
            repo_id=runtime.repo_id,
            branch=runtime.branch,
            commit_sha=runtime.commit_sha,
            source_type=SourceType.SYSTEM,
            trust_hint=TrustHint.TOOL_OBSERVED,
            payload={
                "memory_id": memory_id,
                "related_ids": list(related_ids),
                **(detail or {}),
            },
        )
        await self.ledger.append(event)

    async def _audit(
        self,
        action: str,
        runtime: RuntimeMemoryContext,
        *,
        memory_id: str = "",
        detail: dict[str, Any] | None = None,
    ) -> None:
        sink = self.audit_sink
        if sink is None:
            if self.audit_required:
                raise RuntimeError("memory safety audit sink is unavailable")
            return
        log_decision = _async_method(sink, "log_decision")
        if callable(log_decision):
            await log_decision(
                action,
                runtime,
                memory_id=memory_id,
                detail=detail,
            )
            return
        logger_method = _async_method(sink, "log")
        if callable(logger_method):
            result = "error" if "FAILED" in action or "REJECTED" in action else "success"
            await logger_method(
                action,
                memory_id or "memory",
                result,
                detail or {},
                runtime.session_id,
                task_id=runtime.task_id,
            )
            return
        if self.audit_required:
            raise RuntimeError("memory safety audit sink has no logging port")

    async def _record_metric(
        self,
        metric_name: str,
        value: float,
        runtime: RuntimeMemoryContext,
        *,
        unit: str,
        operation: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Best-effort metric recording that cannot alter Broker decisions."""

        recorder = _async_method(self.observability, "record")
        if not callable(recorder):
            return
        try:
            await recorder(
                metric_name,
                value,
                runtime,
                unit=unit,
                provider_id=self.provider.provider_id,
                profile_id=self.profile.profile_id if self.profile else "",
                operation=operation,
                metadata=metadata,
            )
        except Exception:
            logger.warning("memory metric recording failed", exc_info=True)

    async def _revoked_ids(
        self,
        runtime: RuntimeMemoryContext,
        memory_ids: Sequence[str],
        *,
        provider_id: str | None = None,
    ) -> set[str]:
        """Read bounded revocation markers before admitting provider hits."""

        resolver = _async_method(self.ledger, "revoked_ids")
        if callable(resolver):
            return set(
                await resolver(
                    runtime,
                    list(memory_ids),
                    provider_id=provider_id or self.provider.provider_id,
                )
            )
        if not memory_ids:
            return set()
        rows = await self.ledger.list(
            runtime,
            event_types=(MemoryEventType.MEMORY_REVOKED.value,),
            limit=100_000,
            include_all_sessions=True,
            include_all_principals=True,
        )
        revoked: set[str] = set()
        for row in rows:
            payload = row.get("payload_json")
            if not isinstance(payload, str):
                continue
            try:
                value = json.loads(payload)
            except (TypeError, ValueError):
                continue
            memory_id = value.get("memory_id") if isinstance(value, dict) else None
            if isinstance(memory_id, str) and memory_id:
                revoked.add(memory_id)
        return revoked

    async def _is_revoked(
        self,
        memory_id: str,
        runtime: RuntimeMemoryContext,
    ) -> bool:
        return memory_id in await self._revoked_ids(runtime, [memory_id])

    async def _normalize_hit(
        self,
        hit: MemoryHit,
        runtime: RuntimeMemoryContext,
        *,
        provider: MemoryProvider | None = None,
    ) -> MemoryHit | None:
        """Sanitize provider output using local ledger evidence.

        ``source_type``, ``authority_hint`` and ``status`` are all untrusted
        for remote providers.  A USER/TOOL authority survives only when the
        referenced event is present in the local ledger with the same scoped
        principal/project/session and matching source type.
        """

        if not hit.content or len(hit.content.encode("utf-8")) > self.policy.max_provider_content_bytes:
            return None
        if not hit.memory_id and not hit.external_id:
            return None
        try:
            metadata = dict(hit.provider_metadata)
            if len(json.dumps(metadata, ensure_ascii=False).encode("utf-8")) > self.policy.max_provider_metadata_bytes:
                return None
        except (TypeError, ValueError):
            return None
        try:
            normalized_status = MemoryStatus(enum_value(hit.status))
        except ValueError:
            # An unknown provider lifecycle value is not an admissible
            # default.  Failing closed here prevents a future status added by
            # a remote service from accidentally bypassing usage gates.
            return None
        active_provider = provider or self.provider
        canonical = bool(
            getattr(active_provider, "trusted_canonical", False)
            and metadata.get("canonical_record") is True
        )
        host_owned_observation = metadata.get("host_owned_observation") is True
        local_evidence = (
            canonical
            or host_owned_observation
            or await self._has_local_evidence(hit, runtime)
        )
        authority = reclassify_provider_authority(
            hit.source_type,
            hit.authority_hint,
            canonical_record=canonical,
            local_evidence=local_evidence,
        )
        status = normalized_status
        if (
            not canonical
            and not host_owned_observation
            and enum_value(status) == MemoryStatus.VERIFIED.value
        ):
            status = MemoryStatus.CANDIDATE
        if (
            not canonical
            and not host_owned_observation
            and enum_value(status) == MemoryStatus.ACTIVE.value
        ):
            # A remote provider can suggest an active result, but it cannot
            # turn that suggestion into a trusted lifecycle transition.
            status = MemoryStatus.CANDIDATE
        metadata["broker_authority"] = authority.value
        metadata["broker_admitted"] = True
        metadata["provider_status_hint"] = enum_value(hit.status)
        metadata["local_evidence_validated"] = local_evidence
        return replace(
            hit,
            provider_metadata=metadata,
            authority_hint=authority.value,
            status=status,
        )

    async def _has_local_evidence(
        self,
        hit: MemoryHit,
        runtime: RuntimeMemoryContext,
    ) -> bool:
        """Validate one bounded set of provider-reported event references."""

        event_ids = list(hit.event_ids)
        event_ids.extend(ref.event_id for ref in hit.evidence_refs if ref.event_id)
        for event_id in tuple(dict.fromkeys(value for value in event_ids if value))[:32]:
            row = await self.ledger.get(str(event_id), runtime)
            if row is None:
                continue
            row_session = str(row.get("session_id") or "")
            hit_source = enum_value(hit.source_type or SourceType.PROVIDER)
            if (
                str(row.get("principal_id")) == runtime.principal_id
                and str(row.get("project_id")) == runtime.project_id
                and (not runtime.session_id or not row_session or row_session == runtime.session_id)
                and str(row.get("source_type")) == hit_source
            ):
                return True
        return False

    async def _bind_candidate_authority(
        self,
        candidate: MemoryCandidate,
        runtime: RuntimeMemoryContext,
    ) -> MemoryCandidate:
        """Downgrade source claims that lack matching local provenance.

        Candidate callers may propose a useful claim, but a string-valued
        ``authority`` is never enough to mint trust.  USER/TOOL/REPOSITORY
        authority survives only when one of the candidate's event references
        is a scoped local event of the corresponding kind.  Invalid claims
        are retained as inferred evidence so AML/provider integrations do not
        lose data, while their requested authority cannot cross the boundary.
        """

        requested = enum_value(candidate.authority)
        required = {
            MemoryAuthority.USER_STATED.value: {
                (SourceType.USER.value, MemoryEventType.USER_MESSAGE.value),
            },
            MemoryAuthority.TOOL_OBSERVED.value: {
                (SourceType.TOOL.value, MemoryEventType.TOOL_CALL.value),
                (SourceType.TOOL.value, MemoryEventType.TOOL_RESULT.value),
            },
            MemoryAuthority.REPOSITORY_OBSERVED.value: {
                (SourceType.REPOSITORY.value, MemoryEventType.FILE_OBSERVED.value),
                (SourceType.REPOSITORY.value, MemoryEventType.PATCH_APPLIED.value),
                (SourceType.REPOSITORY.value, MemoryEventType.COMMIT_OBSERVED.value),
            },
        }.get(requested)
        if required is None:
            return candidate
        references = list(candidate.source_event_ids)
        references.extend(
            ref.event_id for ref in candidate.evidence_refs if ref.event_id
        )
        for event_id in tuple(dict.fromkeys(value for value in references if value))[:32]:
            row = await self.ledger.get(str(event_id), runtime)
            if row is None:
                continue
            if (
                str(row.get("source_type")),
                str(row.get("event_type")),
            ) in required:
                return candidate
        return replace(
            candidate,
            authority=MemoryAuthority.AGENT_INFERRED,
            verification_proof=None,
        )

    async def _supersession_targets(
        self,
        candidate: MemoryCandidate,
        runtime: RuntimeMemoryContext,
        *,
        authority: MemoryAuthority,
        status: MemoryStatus,
    ) -> tuple[tuple[str, ...], str | None]:
        """Resolve current same-key rows and apply Broker policy only."""

        if not candidate.key or status in {
            MemoryStatus.CANDIDATE,
            MemoryStatus.QUARANTINED,
            MemoryStatus.REJECTED,
        }:
            return (), None
        getter = _async_method(self.provider, "get_current")
        if getter is None:
            return (), "provider_cannot_prove_current_identity"
        existing = await getter(
            runtime,
            scope=candidate.scope,
            key=candidate.key,
            namespace=candidate.namespace,
            session_id=candidate.session_id,
        )
        if not isinstance(existing, MemoryHit):
            return (), None
        existing = await self._normalize_hit(existing, runtime)
        if existing is None or not scope_matches(existing, runtime):
            return (), None
        decision = self.supersession_policy.decide(
            existing,
            candidate_authority=authority,
            candidate_status=status,
            user_correction=bool(candidate.preconditions.get("user_correction", False)),
        )
        if decision.allowed and existing.memory_id:
            return (existing.memory_id,), None
        return (), decision.reason

    @staticmethod
    def _validate_candidate_scope(
        candidate: MemoryCandidate,
        runtime: RuntimeMemoryContext,
    ) -> None:
        if candidate.namespace == "session" and candidate.session_id != runtime.session_id:
            raise ValueError("session memory candidate is outside runtime session")
        if candidate.namespace not in {"private", "session", "project", "shared"}:
            raise ValueError("unsupported memory namespace")

    @staticmethod
    def _candidate_source_type(candidate: MemoryCandidate) -> SourceType:
        authority = enum_value(candidate.authority)
        if authority == MemoryAuthority.USER_STATED.value:
            return SourceType.USER
        if authority == MemoryAuthority.TOOL_OBSERVED.value:
            return SourceType.TOOL
        if authority == MemoryAuthority.REPOSITORY_OBSERVED.value:
            return SourceType.REPOSITORY
        if authority == MemoryAuthority.EXTERNAL_UNTRUSTED.value:
            return SourceType.EXTERNAL
        if authority == MemoryAuthority.VERIFICATION_CONFIRMED.value:
            return SourceType.VERIFICATION
        return SourceType.PROVIDER

    @staticmethod
    def _admitted_authority(
        candidate: MemoryCandidate,
        verified: bool,
    ) -> MemoryAuthority:
        requested = enum_value(candidate.authority)
        if requested == MemoryAuthority.VERIFICATION_CONFIRMED.value and not verified:
            return MemoryAuthority.AGENT_INFERRED
        try:
            return MemoryAuthority(requested)
        except ValueError:
            return MemoryAuthority.AGENT_INFERRED

    @staticmethod
    def _decision(
        accepted: bool,
        status: MemoryStatus,
        reason: str,
        *,
        memory_id: str | None = None,
        event_id: str | None = None,
    ) -> MemoryDecision:
        return MemoryDecision(accepted, status, reason, memory_id, event_id)


class _KeyBudget:
    """Small internal budget for provider-agnostic exact-key fallback."""

    max_hits = 32


def _hash_query(query: str) -> str:
    import hashlib

    return hashlib.sha256(query.encode("utf-8")).hexdigest()


def _candidate_size(candidate: MemoryCandidate) -> int:
    """Bound the whole candidate, not only the human-readable claim."""

    payload = {
        "claim": candidate.claim,
        "source_event_ids": candidate.source_event_ids,
        "evidence_refs": [
            {
                "source_type": enum_value(ref.source_type),
                "source_ref": ref.source_ref,
                "event_id": ref.event_id,
                "verification_run_id": ref.verification_run_id,
                "commit_sha": ref.commit_sha,
            }
            for ref in candidate.evidence_refs
        ],
        "preconditions": dict(candidate.preconditions),
        "environment": dict(candidate.environment),
        "source_kind": enum_value(candidate.source_kind) if candidate.source_kind else None,
        "provenance": dict(candidate.provenance),
    }
    return len(json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8"))


def _hit_sort_key(hit: MemoryHit) -> tuple[float, int, float, float, str]:
    authority_rank = {
        MemoryAuthority.SYSTEM_POLICY.value: 5,
        MemoryAuthority.VERIFICATION_CONFIRMED.value: 4,
        MemoryAuthority.USER_STATED.value: 3,
        MemoryAuthority.TOOL_OBSERVED.value: 2,
        MemoryAuthority.REPOSITORY_OBSERVED.value: 1,
        MemoryAuthority.AGENT_INFERRED.value: 0,
        MemoryAuthority.EXTERNAL_UNTRUSTED.value: -1,
    }.get(enum_value(hit.authority_hint or ""), 0)
    confidence = float(hit.confidence_hint or 0.0)
    valid_from = hit.valid_from.timestamp() if hit.valid_from is not None else float("-inf")
    rrf_score = float(hit.provider_metadata.get("rrf_score", 0.0) or 0.0)
    # Relevance is the primary ordering signal.  Authority is a bounded
    # rerank bonus and never a categorical first-place override for an
    # unrelated result; admission/status gates remain separate security
    # decisions.
    combined_score = rrf_score + (authority_rank * 0.0005) + (confidence * 0.0001)
    return (-combined_score, -authority_rank, -confidence, -valid_from, hit.memory_id or "")


def _fuse_hits(hits: list[MemoryHit], *, k: int = 60) -> list[MemoryHit]:
    """Fuse memory and CodeGraph rankings with bounded reciprocal rank."""

    if not hits:
        return []
    scores: dict[str, float] = {}
    for position, hit in enumerate(hits, start=1):
        rank = hit.source_rank if hit.source_rank > 0 else position
        identity = hit.memory_id or f"{hit.provider_id}:{hit.external_id}:{hit.content}"
        scores[identity] = scores.get(identity, 0.0) + 1.0 / (k + rank)
    fused: list[MemoryHit] = []
    for hit in hits:
        identity = hit.memory_id or f"{hit.provider_id}:{hit.external_id}:{hit.content}"
        metadata = dict(hit.provider_metadata)
        metadata["rrf_score"] = scores[identity]
        features = dict(hit.retrieval_features)
        features["rrf_score"] = scores[identity]
        fused.append(
            replace(
                hit,
                provider_metadata=metadata,
                retrieval_features=features,
            )
        )
    return fused


def _async_method(owner: object, name: str) -> Callable[..., Awaitable[Any]] | None:
    """Return an optional provider extension with an explicit async type."""

    method = getattr(owner, name, None)
    if not callable(method):
        return None
    return cast(Callable[..., Awaitable[Any]], method)


def _partition_hits(hits: list[MemoryHit]) -> tuple[list[MemoryHit], list[MemoryHit], list[MemoryHit]]:
    primary: list[MemoryHit] = []
    supporting: list[MemoryHit] = []
    conflicts: list[MemoryHit] = []
    by_key: dict[tuple[str, str], MemoryHit] = {}
    for hit in hits:
        key = (hit.scope, hit.key or hit.memory_id or hit.content)
        previous = by_key.get(key)
        if previous is None:
            by_key[key] = hit
            primary.append(hit)
            continue
        if previous.content != hit.content:
            conflicts.append(hit)
        else:
            supporting.append(hit)
    return primary, supporting, conflicts


def _latest_valid(hits: list[MemoryHit]) -> MemoryHit | None:
    if not hits:
        return None
    return max(
        hits,
        key=lambda hit: hit.valid_from or datetime.min.replace(tzinfo=UTC),
    )


__all__ = ["MemoryBroker"]
