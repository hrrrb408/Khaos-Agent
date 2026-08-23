"""Non-bypassable Memory V2 Broker.

The Broker is the only component allowed to turn provider output into
model-visible memory.  It binds scope from the runtime, reclassifies provider
authority, applies applicability and temporal gates, and records every
decision.  Providers remain replaceable evidence engines below this boundary.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Sequence
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any

from khaos.memory.core.authority import VerificationAuthority
from khaos.memory.core.contracts import (
    EvidenceResolution,
    ForgetResult,
    MemoryAuthority,
    MemoryCandidate,
    MemoryDecision,
    MemoryEvent,
    MemoryEventType,
    MemoryForgetRequest,
    MemoryHit,
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
    applicability_matches,
    candidate_status,
    reclassify_provider_authority,
    scope_matches,
    screen_text,
    temporal_matches,
    usage_allows_injection,
)
from khaos.memory.ledger import SqliteEventLedger

logger = logging.getLogger(__name__)


class MemoryBroker:
    """Admission, provenance, retrieval, and forget authority for memory."""

    def __init__(
        self,
        provider: MemoryProvider,
        ledger: SqliteEventLedger,
        *,
        policy: MemoryPolicy | None = None,
        verification_authority: VerificationAuthority | None = None,
    ) -> None:
        self.provider = provider
        self.ledger = ledger
        self.policy = policy or MemoryPolicy()
        self.verification_authority = verification_authority or VerificationAuthority()

    async def record_event(self, event: MemoryEvent) -> str:
        """Append a canonical event before any derived-memory write."""

        return await self.ledger.append(event)

    async def propose_memory(
        self,
        candidate: MemoryCandidate,
        runtime: RuntimeMemoryContext,
    ) -> MemoryDecision:
        """Screen, persist, and audit one derived-memory proposal."""

        self._validate_candidate_scope(candidate, runtime)
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
            and self.verification_authority.validate(
                candidate,
                token=candidate.verification_proof,
                verification_run_id=candidate.verification_run_id,
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

        admitted = MemoryWriteRequest(
            candidate=candidate,
            runtime=runtime,
            status=status,
            authority=authority,
            provider_id=self.provider.provider_id,
            candidate_event_id=candidate_event.event_id,
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

        if result.superseded_memory_ids:
            await self._append_state_event(
                MemoryEventType.MEMORY_SUPERSEDED,
                runtime,
                result.memory_id,
                result.superseded_memory_ids,
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
            detail={"status": status.value, "reason": reason},
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

        if not isinstance(query, str) or len(query) > self.policy.max_search_query_length:
            raise ValueError("memory search query is missing or too long")
        limit = min(
            max(int(getattr(budget, "max_hits", 32)), 0),
            self.policy.max_search_hits,
        )
        if limit == 0:
            return EvidenceResolution(())
        request = MemorySearchRequest(
            query=query,
            runtime=runtime,
            limit=limit,
            include_historical=include_historical,
        )
        await self._audit(
            "MEMORY_SEARCH_REQUESTED",
            runtime,
            detail={"query_hash": _hash_query(query), "limit": limit},
        )
        try:
            raw_hits = await self.provider.search(request)
        except Exception as exc:
            logger.exception("memory provider search failed")
            await self._audit(
                "MEMORY_PROVIDER_FAILED",
                runtime,
                detail={"operation": "search", "error": type(exc).__name__},
            )
            return EvidenceResolution((), provider_error=type(exc).__name__)
        if not isinstance(raw_hits, Sequence) or isinstance(raw_hits, (str, bytes)):
            await self._audit(
                "MEMORY_PROVIDER_FAILED",
                runtime,
                detail={"operation": "search", "error": "malformed_result"},
            )
            return EvidenceResolution((), provider_error="malformed_result")

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
            )
        except Exception as exc:
            logger.exception("memory revocation ledger read failed")
            return EvidenceResolution((), provider_error=type(exc).__name__)
        for raw_hit in bounded_raw_hits:
            try:
                normalized = self._normalize_hit(raw_hit)
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

        accepted.sort(key=_hit_sort_key)
        primary, supporting, conflicts = _partition_hits(accepted)
        latest = _latest_valid(primary or supporting)
        if accepted and hasattr(self.provider, "record_retrieval"):
            try:
                await self.provider.record_retrieval(  # type: ignore[attr-defined]
                    [hit.memory_id for hit in accepted if hit.memory_id],
                    runtime,
                )
            except Exception:
                logger.warning("memory retrieval statistics update failed", exc_info=True)
        if accepted and hasattr(self.provider, "record_application"):
            try:
                await self.provider.record_application(  # type: ignore[attr-defined]
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
        return EvidenceResolution(
            tuple(primary),
            tuple(supporting),
            tuple(conflicts),
            latest_valid_fact=latest,
        )

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
        # Record intent before mutating derived storage.  A crash after this
        # append but before provider deletion remains recoverable and fail
        # closed: the next search/rebuild sees the revocation marker.
        for memory_id in target_ids:
            await self._append_state_event(
                MemoryEventType.MEMORY_REVOKED,
                runtime,
                memory_id,
                (),
                detail={"forget_mode": request.mode},
            )
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

    async def _owned_forget_targets(
        self,
        request: MemoryForgetRequest,
    ) -> tuple[str, ...]:
        """Return selectors proven to be in the provider's runtime scope."""

        getter = getattr(self.provider, "get_by_id", None)
        if not callable(getter):
            return request.memory_ids
        owned: list[str] = []
        for memory_id in request.memory_ids:
            raw_hit = await getter(request.runtime, memory_id)
            if not isinstance(raw_hit, MemoryHit):
                continue
            if raw_hit.memory_id != memory_id or not scope_matches(raw_hit, request.runtime):
                continue
            owned.append(memory_id)
        return tuple(owned)

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

        getter = getattr(self.provider, "get_current", None)
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
        normalized = self._normalize_hit(raw_hit)
        if normalized is None:
            return None
        if not scope_matches(normalized, runtime):
            return None
        if normalized.memory_id:
            try:
                if await self._is_revoked(normalized.memory_id, runtime):
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
        getter = getattr(self.provider, "get_by_id", None)
        if not callable(getter):
            return None
        raw_hit = await getter(runtime, memory_id)
        if raw_hit is None:
            return None
        normalized = self._normalize_hit(raw_hit)
        if normalized is None or not scope_matches(normalized, runtime):
            return None
        if await self._is_revoked(memory_id, runtime):
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

    async def rebuild(self) -> int:
        """Rebuild provider indexes from canonical tables when supported."""

        rebuild = getattr(self.provider, "rebuild_indexes", None)
        if not callable(rebuild):
            raise TypeError("provider does not support index rebuild")
        return int(await rebuild())

    async def rebuild_from_ledger(
        self,
        runtime: RuntimeMemoryContext,
        *,
        limit: int = 10_000,
    ) -> int:
        """Replay Broker candidate events into a provider's derived tables."""

        if limit <= 0 or limit > 100_000:
            raise ValueError("memory rebuild limit must be between 1 and 100000")
        replay = getattr(self.provider, "rebuild_from_events", None)
        if not callable(replay):
            raise TypeError("provider does not support ledger replay")
        events = await self.ledger.list(
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
        )
        count = int(await replay(events))
        candidate_event_count = sum(
            1
            for event in events
            if event.get("event_type") == MemoryEventType.MEMORY_CANDIDATE_CREATED.value
        )
        await self._audit(
            "MEMORY_REBUILT_FROM_LEDGER",
            runtime,
            detail={
                "ledger_events": len(events),
                "candidate_events": candidate_event_count,
                "replayed": count,
            },
        )
        return count

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
        recorder = getattr(self.provider, "record_audit", None)
        if callable(recorder):
            await recorder(
                action=action,
                runtime=runtime,
                memory_id=memory_id,
                detail=detail,
            )

    async def _revoked_ids(
        self,
        runtime: RuntimeMemoryContext,
        memory_ids: Sequence[str],
    ) -> set[str]:
        """Read bounded revocation markers before admitting provider hits."""

        resolver = getattr(self.ledger, "revoked_ids", None)
        if callable(resolver):
            return set(await resolver(runtime, list(memory_ids)))
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

    def _normalize_hit(self, hit: MemoryHit) -> MemoryHit | None:
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
        canonical = bool(
            getattr(self.provider, "trusted_canonical", False)
            and metadata.get("canonical_record") is True
        )
        authority = reclassify_provider_authority(
            hit.source_type,
            hit.authority_hint,
            canonical_record=canonical,
        )
        metadata["broker_authority"] = authority.value
        metadata["broker_admitted"] = True
        return replace(
            hit,
            provider_metadata=metadata,
            authority_hint=authority.value,
        )

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
    }
    return len(json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8"))


def _hit_sort_key(hit: MemoryHit) -> tuple[int, float, float, str]:
    authority_rank = {
        MemoryAuthority.SYSTEM_POLICY.value: 5,
        MemoryAuthority.VERIFICATION_CONFIRMED.value: 4,
        MemoryAuthority.USER_STATED.value: 3,
        MemoryAuthority.TOOL_OBSERVED.value: 2,
        MemoryAuthority.REPOSITORY_OBSERVED.value: 1,
        MemoryAuthority.AGENT_INFERRED.value: 0,
        MemoryAuthority.EXTERNAL_UNTRUSTED.value: -1,
    }.get(enum_value(hit.authority_hint), 0)
    confidence = float(hit.confidence_hint or 0.0)
    valid_from = hit.valid_from.timestamp() if hit.valid_from is not None else float("-inf")
    return (-authority_rank, -confidence, -valid_from, hit.memory_id or "")


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
