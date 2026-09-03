"""Deterministic de-duplication, overlap merging, and bounded eviction."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import replace

from khaos.coding.context_engine.contracts import (
    MAX_CONTEXT_ITEM_BYTES,
    ContextItem,
    ContextItemKind,
    ContextLayer,
    ContextRequirements,
    ContextSelection,
)
from khaos.security.protocol_boundary import canonical_digest


class ContextSelector:
    """Select the highest-value bounded set with stable tie-breaking."""

    def select(
        self,
        candidates: Iterable[ContextItem],
        requirements: ContextRequirements,
    ) -> ContextSelection:
        normalized = self._normalize(candidates, requirements)
        required = [item for item in normalized if self._is_required(item, requirements)]
        optional = [item for item in normalized if item not in required]
        required.sort(key=lambda item: self._sort_key(item, requirements))
        optional.sort(key=lambda item: self._sort_key(item, requirements))

        selected: list[ContextItem] = []
        evicted: list[ContextItem] = []
        compressed: list[ContextItem] = []
        used_tokens = 0
        used_bytes = 0
        layer_tokens = {layer.value: 0 for layer in ContextLayer if layer.name == layer.value}
        layer_bytes = {layer.value: 0 for layer in ContextLayer if layer.name == layer.value}
        truncated_count = 0

        # Required items are admitted first.  L0 is never silently dropped;
        # the normal runtime keeps it pre-bounded, while the explicit
        # ``partial`` accounting remains the service's responsibility if a
        # caller supplies an impossible budget.
        for item in required:
            admitted, bounded = self._admit(
                item,
                requirements,
                used_tokens=used_tokens,
                used_bytes=used_bytes,
                layer_tokens=layer_tokens,
                layer_bytes=layer_bytes,
                required=True,
            )
            if admitted:
                selected.append(bounded)
                if bounded.truncated:
                    truncated_count += 1
                    compressed.append(bounded)
                used_tokens += bounded.estimated_tokens
                used_bytes += bounded.estimated_bytes
                layer_tokens[bounded.layer.value] += bounded.estimated_tokens
                layer_bytes[bounded.layer.value] += bounded.estimated_bytes
            else:
                # Keep only L0 if a hostile/malformed budget would otherwise
                # remove policy. Other required items are represented as an
                # eviction and can be re-requested on the next build.
                if item.layer is ContextLayer.L0:
                    selected.append(item)
                    used_tokens += item.estimated_tokens
                    used_bytes += item.estimated_bytes
                    layer_tokens[item.layer.value] += item.estimated_tokens
                    layer_bytes[item.layer.value] += item.estimated_bytes
                else:
                    evicted.append(item)

        for item in optional:
            if len(selected) >= requirements.max_items:
                evicted.append(item)
                continue
            admitted, bounded = self._admit(
                item,
                requirements,
                used_tokens=used_tokens,
                used_bytes=used_bytes,
                layer_tokens=layer_tokens,
                layer_bytes=layer_bytes,
                required=False,
            )
            if not admitted:
                evicted.append(item)
                continue
            selected.append(bounded)
            if bounded.truncated:
                truncated_count += 1
                compressed.append(bounded)
            used_tokens += bounded.estimated_tokens
            used_bytes += bounded.estimated_bytes
            layer_tokens[bounded.layer.value] += bounded.estimated_tokens
            layer_bytes[bounded.layer.value] += bounded.estimated_bytes

        # The provider-facing order follows the lifecycle layers first, then
        # preserves each layer's deterministic event sequence.  This keeps
        # L0/L1 stable at the front even when a caller supplied arbitrary
        # sequence values for lower-layer evidence.
        selected.sort(key=lambda item: (item.layer.rank, item.sequence, item.item_id))
        return ContextSelection(
            selected=tuple(selected),
            evicted=tuple(evicted),
            compressed=tuple(compressed),
            truncated_count=truncated_count,
            total_tokens=used_tokens,
            total_bytes=used_bytes,
            layer_tokens=dict(layer_tokens),
            layer_bytes=dict(layer_bytes),
        )

    def _normalize(
        self,
        candidates: Iterable[ContextItem],
        requirements: ContextRequirements,
    ) -> list[ContextItem]:
        values = [item for item in candidates if type(item) is ContextItem]
        by_identity: dict[tuple[object, ...], ContextItem] = {}
        for item in values:
            if requirements.workspace_id:
                if item.workspace_id not in {"", requirements.workspace_id}:
                    continue
                if (
                    item.source.value == "repo_intelligence"
                    and not item.workspace_id
                ):
                    continue
            if requirements.generation and item.generation not in {
                None,
                requirements.generation,
            }:
                continue
            if item.kind is ContextItemKind.MEMORY and not requirements.include_memory:
                continue
            if item.source.value == "repo_intelligence" and not requirements.include_repo:
                continue
            if item.kind is ContextItemKind.DIAGNOSTIC and not requirements.include_diagnostics:
                continue
            candidate = item
            if item.kind in requirements.required_kinds and not item.required:
                candidate = replace(candidate, required=True)
            if item.kind in requirements.preferred_kinds:
                candidate = replace(candidate, priority=min(1000, candidate.priority + 15))
            key = candidate.identity_key
            existing = by_identity.get(key)
            if existing is None or self._sort_key(candidate, requirements) < self._sort_key(existing, requirements):
                by_identity[key] = candidate

        # Merge overlapping regions from the same generation. This is a
        # presentation optimization only; it never combines different trust
        # or provenance domains.
        merged: list[ContextItem] = []
        for item in sorted(by_identity.values(), key=lambda value: self._sort_key(value, requirements)):
            if item.kind is not ContextItemKind.FILE_REGION or item.path is None:
                merged.append(item)
                continue
            overlap_indices = [
                index
                for index, existing in enumerate(merged)
                if existing.kind is ContextItemKind.FILE_REGION
                and existing.path == item.path
                and existing.generation == item.generation
                and existing.source is item.source
                and existing.trust is item.trust
                and _ranges_overlap(existing, item)
            ]
            if not overlap_indices:
                merged.append(item)
            else:
                merged_item = item
                for overlap_index in reversed(overlap_indices):
                    merged_item = _merge_regions(merged[overlap_index], merged_item)
                    merged.pop(overlap_index)
                merged.append(merged_item)
        return merged

    @staticmethod
    def _is_required(item: ContextItem, requirements: ContextRequirements) -> bool:
        return item.layer is ContextLayer.L0 or item.required or item.pinned or item.kind in requirements.required_kinds

    @staticmethod
    def _sort_key(item: ContextItem, requirements: ContextRequirements) -> tuple[object, ...]:
        target_match = 0
        if item.path and item.path in requirements.target_files:
            target_match = 1
        if item.symbol and item.symbol in requirements.target_symbols:
            target_match = 1
        if item.path and item.path in requirements.changed_files:
            target_match = 1
        return (
            0 if ContextSelector._is_required(item, requirements) else 1,
            -target_match,
            -item.priority,
            item.layer.rank,
            item.kind.value,
            item.path or "",
            item.symbol or "",
            item.region_start if item.region_start is not None else -1,
            item.sequence,
            item.digest,
            item.item_id,
        )

    @staticmethod
    def _admit(
        item: ContextItem,
        requirements: ContextRequirements,
        *,
        used_tokens: int,
        used_bytes: int,
        layer_tokens: dict[str, int],
        layer_bytes: dict[str, int],
        required: bool,
    ) -> tuple[bool, ContextItem]:
        budget = requirements.budget
        remaining_total_tokens = budget.available_tokens - used_tokens
        remaining_total_bytes = budget.available_bytes - used_bytes
        remaining_layer_tokens = budget.layer_tokens(item.layer) - layer_tokens[item.layer.value]
        remaining_layer_bytes = budget.layer_bytes(item.layer) - layer_bytes[item.layer.value]
        max_tokens = min(remaining_total_tokens, remaining_layer_tokens)
        max_bytes = min(remaining_total_bytes, remaining_layer_bytes)
        if item.layer is ContextLayer.L0 and required:
            max_tokens = max(max_tokens, item.estimated_tokens)
            max_bytes = max(max_bytes, item.estimated_bytes)
        if item.estimated_tokens <= max_tokens and item.estimated_bytes <= max_bytes:
            return True, item
        if max_tokens <= 0 or max_bytes <= 0:
            return False, item
        bounded = item.truncated_to(max_bytes=max_bytes, max_tokens=max_tokens)
        if bounded.estimated_tokens > max_tokens or bounded.estimated_bytes > max_bytes:
            return False, item
        return True, bounded


def _ranges_overlap(left: ContextItem, right: ContextItem) -> bool:
    if left.region_start is None or left.region_end is None or right.region_start is None or right.region_end is None:
        return left.digest == right.digest
    return left.region_start <= right.region_end and right.region_start <= left.region_end


def _merge_regions(left: ContextItem, right: ContextItem) -> ContextItem:
    start_values = [value for value in (left.region_start, right.region_start) if value is not None]
    end_values = [value for value in (left.region_end, right.region_end) if value is not None]
    payload = left.payload
    if right.payload and right.payload not in payload:
        payload = f"{payload}\n{right.payload}" if payload else right.payload
    payload_truncated = False
    if len(payload.encode("utf-8")) > MAX_CONTEXT_ITEM_BYTES:
        payload = payload.encode("utf-8")[:MAX_CONTEXT_ITEM_BYTES].decode(
            "utf-8", errors="ignore"
        )
        payload_truncated = True
    merged_digest = (
        left.digest
        if left.digest == right.digest
        else canonical_digest({"left": left.digest, "right": right.digest})
    )
    return ContextItem(
        kind=left.kind,
        payload=payload,
        layer=left.layer,
        source=left.source,
        trust=left.trust,
        workspace_id=left.workspace_id,
        generation=left.generation,
        priority=max(left.priority, right.priority),
        item_id=min(left.item_id, right.item_id),
        required=left.required or right.required,
        pinned=left.pinned or right.pinned,
        truncated=left.truncated or right.truncated or payload_truncated,
        compressed=left.compressed or right.compressed,
        path=left.path,
        symbol=left.symbol or right.symbol,
        region_start=min(start_values) if start_values else None,
        region_end=max(end_values) if end_values else None,
        sequence=min(left.sequence, right.sequence),
        digest=merged_digest,
        metadata={**dict(left.metadata), **dict(right.metadata), "overlap_merged": True},
    )
