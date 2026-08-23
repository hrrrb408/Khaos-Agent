"""Broker-backed adapter for AML-style add/search memory APIs.

AML integrations are treated as untrusted callers.  They can submit bounded
candidate data and request retrieval, but they never receive a provider
handle, a raw database connection, or authority to choose the effective
scope.  Every operation is translated into the MemoryBroker contract.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from khaos.memory.core import MemoryBroker
from khaos.memory.core.contracts import (
    EvidenceRef,
    MemoryAuthority,
    MemoryBudget,
    MemoryCandidate,
    MemoryDecision,
    MemoryType,
    RuntimeMemoryContext,
    Sensitivity,
    SourceType,
    UsagePolicy,
    enum_value,
)


class AMLAdapterError(ValueError):
    """Raised when an AML request cannot be translated safely."""


class MemoryAMLAdapter:
    """Expose bounded ``add``/``search``/``forget`` methods over the Broker."""

    def __init__(self, broker: MemoryBroker, *, max_batch: int = 128) -> None:
        if max_batch <= 0 or max_batch > 1024:
            raise AMLAdapterError("max_batch must be between 1 and 1024")
        self._broker = broker
        self._max_batch = max_batch

    async def add(
        self,
        item: Mapping[str, Any],
        runtime: RuntimeMemoryContext,
    ) -> MemoryDecision:
        """Translate one AML item into a Broker-admitted candidate."""

        return await self._broker.propose_memory(self._candidate(item), runtime)

    async def add_many(
        self,
        items: Iterable[Mapping[str, Any]],
        runtime: RuntimeMemoryContext,
    ) -> tuple[MemoryDecision, ...]:
        """Add a bounded batch while preserving item order and decisions."""

        bounded = list(items)
        if len(bounded) > self._max_batch:
            raise AMLAdapterError("AML add batch is oversized")
        decisions: list[MemoryDecision] = []
        for item in bounded:
            decisions.append(await self.add(item, runtime))
        return tuple(decisions)

    async def search(
        self,
        query: str,
        runtime: RuntimeMemoryContext,
        *,
        limit: int = 32,
        include_historical: bool = False,
    ) -> dict[str, Any]:
        """Return a stable AML response built from Broker evidence."""

        if limit <= 0 or limit > 256:
            raise AMLAdapterError("AML search limit is outside the bounded range")
        resolution = await self._broker.search(
            query,
            runtime,
            MemoryBudget(max_hits=limit),
            include_historical=include_historical,
        )
        return {
            "results": [_hit_mapping(hit) for hit in resolution.primary_hits],
            "supporting": [_hit_mapping(hit) for hit in resolution.supporting_hits],
            "conflicts": [_hit_mapping(hit) for hit in resolution.conflicts],
            "missing_requirements": list(resolution.missing_requirements),
            "latest_valid_fact": (
                _hit_mapping(resolution.latest_valid_fact)
                if resolution.latest_valid_fact is not None
                else None
            ),
            "provider_error": resolution.provider_error,
        }

    async def forget(
        self,
        memory_ids: Iterable[str],
        runtime: RuntimeMemoryContext,
        *,
        mode: str = "soft",
    ) -> dict[str, Any]:
        """Forget through the Broker's ownership and audit gates."""

        ids = tuple(memory_ids)
        if len(ids) > self._max_batch:
            raise AMLAdapterError("AML forget batch is oversized")
        result = await self._broker.forget(ids, runtime, mode=mode)
        return {"forgotten_ids": list(result.forgotten_ids), "mode": result.mode}

    def _candidate(self, item: Mapping[str, Any]) -> MemoryCandidate:
        if not isinstance(item, Mapping):
            raise AMLAdapterError("AML memory item must be an object")
        claim = item.get("claim", item.get("content", item.get("value")))
        if not isinstance(claim, str) or not claim.strip():
            raise AMLAdapterError("AML memory item requires a non-empty claim")
        raw_refs = item.get("evidence_refs", item.get("evidence", ()))
        if not isinstance(raw_refs, (list, tuple)):
            raise AMLAdapterError("AML evidence_refs must be a list")
        refs = tuple(_evidence_ref(value) for value in raw_refs)
        source_event_ids = item.get("source_event_ids", ())
        if not isinstance(source_event_ids, (list, tuple)):
            raise AMLAdapterError("AML source_event_ids must be a list")
        authority = str(item.get("authority", MemoryAuthority.EXTERNAL_UNTRUSTED.value))
        memory_type = str(item.get("memory_type", MemoryType.PROJECT_FACT.value))
        try:
            MemoryAuthority(authority)
            MemoryType(memory_type)
        except ValueError as exc:
            raise AMLAdapterError("AML authority or memory_type is invalid") from exc
        try:
            confidence = float(item.get("confidence", 0.35))
        except (TypeError, ValueError) as exc:
            raise AMLAdapterError("AML confidence must be numeric") from exc
        try:
            sensitivity = Sensitivity(str(item.get("sensitivity", Sensitivity.INTERNAL.value)))
            usage_policy = UsagePolicy(
                str(item.get("usage_policy", UsagePolicy.PROJECT_ONLY.value))
            )
        except ValueError as exc:
            raise AMLAdapterError("AML sensitivity or usage_policy is invalid") from exc
        preconditions = item.get("preconditions", {})
        environment = item.get("environment", {})
        if not isinstance(preconditions, Mapping) or not isinstance(environment, Mapping):
            raise AMLAdapterError("AML preconditions and environment must be objects")
        scope = str(item.get("scope", "global"))
        if not scope or len(scope) > 128:
            raise AMLAdapterError("AML scope is empty or oversized")
        return MemoryCandidate(
            memory_type=memory_type,
            claim=claim,
            authority=authority,
            confidence=confidence,
            source_event_ids=tuple(str(value) for value in source_event_ids),
            evidence_refs=refs,
            key=str(item["key"]) if item.get("key") is not None else None,
            scope=scope,
            namespace=str(item.get("namespace", "private")),
            session_id=(
                str(item["session_id"]) if item.get("session_id") is not None else None
            ),
            preconditions=dict(preconditions),
            environment=dict(environment),
            sensitivity=sensitivity,
            usage_policy=usage_policy,
        )


def _evidence_ref(value: Any) -> EvidenceRef:
    if isinstance(value, str):
        return EvidenceRef(SourceType.EXTERNAL, value[:1024])
    if not isinstance(value, Mapping):
        raise AMLAdapterError("AML evidence reference must be a string or object")
    source_ref = value.get("source_ref", value.get("ref"))
    if not isinstance(source_ref, str) or not source_ref.strip():
        raise AMLAdapterError("AML evidence reference requires source_ref")
    return EvidenceRef(
        source_type=str(value.get("source_type", SourceType.EXTERNAL.value)),
        source_ref=source_ref[:1024],
        event_id=(str(value["event_id"]) if value.get("event_id") else None),
        verification_run_id=(
            str(value["verification_run_id"])
            if value.get("verification_run_id")
            else None
        ),
        commit_sha=str(value["commit_sha"]) if value.get("commit_sha") else None,
    )


def _hit_mapping(hit: Any) -> dict[str, Any]:
    return {
        "id": hit.memory_id or hit.external_id,
        "content": hit.content,
        "memory_type": enum_value(hit.memory_type),
        "status": enum_value(hit.status),
        "scope": hit.scope,
        "namespace": hit.namespace,
        "authority": hit.authority_hint,
        "confidence": hit.confidence_hint,
        "source_type": enum_value(hit.source_type) if hit.source_type else None,
        "source_ref": hit.source_ref,
        "event_ids": list(hit.event_ids),
        "metadata": dict(hit.provider_metadata),
    }


async def aml_add(
    broker: MemoryBroker,
    item: Mapping[str, Any],
    runtime: RuntimeMemoryContext,
) -> MemoryDecision:
    """Add one item through a short-lived Broker-backed AML adapter."""

    return await MemoryAMLAdapter(broker).add(item, runtime)


async def aml_search(
    broker: MemoryBroker,
    query: str,
    runtime: RuntimeMemoryContext,
    *,
    limit: int = 32,
    include_historical: bool = False,
) -> dict[str, Any]:
    """Search through the same bounded AML adapter contract."""

    return await MemoryAMLAdapter(broker).search(
        query,
        runtime,
        limit=limit,
        include_historical=include_historical,
    )


__all__ = ["AMLAdapterError", "MemoryAMLAdapter", "aml_add", "aml_search"]
