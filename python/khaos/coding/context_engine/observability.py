"""Bounded metadata projection for one Context Engine selection.

This module observes the exact selector result already used to build the
provider messages.  It never reads a context payload and never re-runs the
selector.  Its output is safe for Trace v2 and qualification artifacts.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable, Mapping
from typing import Final

from khaos.coding.context_engine.contracts import (
    ContextItemKind,
    ContextLayer,
    ContextSource,
)
from khaos.coding.intelligence.context import normalize_relative_path
from khaos.coding.planning.safe_identifiers import (
    SafeWorkspaceRelativePath,
    UnsafePersistedIdentifier,
)
from khaos.security.protocol_boundary import canonical_digest, canonical_json_bytes

CONTEXT_SELECTION_OBSERVABILITY_SCHEMA_VERSION: Final[int] = 1
MAX_CONTEXT_SELECTION_ITEMS: Final[int] = 128
MAX_CONTEXT_SYMBOLS_PER_ITEM: Final[int] = 16
MAX_CONTEXT_SYMBOL_BYTES: Final[int] = 256
MAX_CONTEXT_PATH_BYTES: Final[int] = 512
MAX_CONTEXT_ITEM_ID_BYTES: Final[int] = 256
MAX_CONTEXT_ITEM_BYTES: Final[int] = 256 * 1024
MAX_CONTEXT_SELECTION_PROJECTION_BYTES: Final[int] = 192 * 1024

_IDENTIFIER_EXTRA = frozenset("_-.:/@$<>[]")
_CONTROL_OR_FORMAT = re.compile(r"[\x00-\x1f\x7f]|[\u0080-\u009f]")
_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:")
_SECRET_LIKE = re.compile(
    r"(?ix)"
    r"(?:authorization\s*[:=]\s*bearer\s+\S+)"
    r"|(?:(?:api[_ -]?key|access[_ -]?token|refresh[_ -]?token|"
    r"password|secret|private[_ -]?key|token)\s*[:=]\s*\S+)"
    r"|(?:\b(?:sk|rk|ghp|github_pat|xox[baprs]-|AIza)[A-Za-z0-9_-]{8,})"
)
_CANONICAL_KINDS = frozenset(item.value for item in ContextItemKind)
_CANONICAL_SOURCES = frozenset(item.value for item in ContextSource)
_CANONICAL_LAYERS = frozenset(item.value for item in ContextLayer)
_HIDDEN_PATH_PARTS = frozenset(
    {".oracle-hidden", "oracle", "gold", "golden", "expected", "hidden", "reference", "solution"}
)
_HIDDEN_IDENTIFIER_MARKERS = frozenset(
    {
        "oracle",
        "gold",
        "golden",
        "expected",
        "hidden",
        "reference",
        "secret",
        "answer",
        "solution",
    }
)


def project_context_selection(selection: object) -> dict[str, object]:
    """Return ordered, payload-free metadata for one selector result."""

    selected = _sequence(getattr(selection, "selected", ()))
    evicted = _sequence(getattr(selection, "evicted", ()))
    compressed = _sequence(getattr(selection, "compressed", ()))
    compressed_ids = {
        _item_identity(item) for item in compressed
    }
    rows: list[dict[str, object]] = []
    for ordinal, item in enumerate(selected):
        if len(rows) >= MAX_CONTEXT_SELECTION_ITEMS:
            break
        rows.append(
            _project_item(
                item,
                selection_ordinal=ordinal,
                eviction_ordinal=None,
                selected=True,
                evicted=False,
                compressed=_item_identity(item) in compressed_ids,
            )
        )
    for eviction_ordinal, item in enumerate(evicted):
        if len(rows) >= MAX_CONTEXT_SELECTION_ITEMS:
            break
        rows.append(
            _project_item(
                item,
                selection_ordinal=None,
                eviction_ordinal=eviction_ordinal,
                selected=False,
                evicted=True,
                compressed=_item_identity(item) in compressed_ids,
            )
        )

    original_count = len(selected) + len(evicted)
    rows = _fit_rows_to_bound(rows)
    persisted_count = len(rows)
    projection_truncated = persisted_count < original_count
    digest = canonical_digest(
        {
            "schema_version": CONTEXT_SELECTION_OBSERVABILITY_SCHEMA_VERSION,
            "selected_count": len(selected),
            "evicted_count": len(evicted),
            "compressed_count": len(compressed),
            "projection_truncated": projection_truncated,
            "items": rows,
        }
    )
    repository_paths = sorted(
        {
            path
            for row in rows
            if row["selected"] is True
            and row["source_channel"] == "automatic_repo_context"
            and isinstance((path := row.get("path")), str)
            and not path.startswith("workspace:")
        }
    )
    return {
        "context_selection_observability_schema_version": (
            CONTEXT_SELECTION_OBSERVABILITY_SCHEMA_VERSION
        ),
        "context_selection_detail_status": "AVAILABLE",
        "selection_digest": digest,
        "selection_items": rows,
        "selection_items_original_count": original_count,
        "selection_items_persisted_count": persisted_count,
        "selection_items_projection_truncated": projection_truncated,
        "selected_repository_paths": repository_paths,
        "automatic_repo_items_selected": sum(
            1
            for item in selected
            if _canonical_enum(
                getattr(item, "source", None),
                allowed=_CANONICAL_SOURCES,
                fallback="other",
            )
            == ContextSource.REPO_INTELLIGENCE.value
        ),
        "tool_acquired_items_selected": sum(
            1
            for item in selected
            if _canonical_enum(
                getattr(item, "source", None),
                allowed=_CANONICAL_SOURCES,
                fallback="other",
            )
            == ContextSource.TOOL.value
        ),
        "non_repository_items_selected": max(
            0,
            len(selected)
            - sum(
                1
                for item in selected
                if _canonical_enum(
                    getattr(item, "source", None),
                    allowed=_CANONICAL_SOURCES,
                    fallback="other",
                )
                in {
                    ContextSource.REPO_INTELLIGENCE.value,
                    ContextSource.TOOL.value,
                }
            ),
        ),
    }


def _project_item(
    item: object,
    *,
    selection_ordinal: int | None,
    eviction_ordinal: int | None,
    selected: bool,
    evicted: bool,
    compressed: bool,
) -> dict[str, object]:
    kind = _canonical_enum(
        getattr(item, "kind", None),
        allowed=_CANONICAL_KINDS,
        fallback="other",
    )
    source = _canonical_enum(
        getattr(item, "source", None),
        allowed=_CANONICAL_SOURCES,
        fallback="other",
    )
    path, path_redacted = _safe_path(getattr(item, "path", None))
    symbols, symbol_count, symbols_redacted, symbols_truncated = _safe_symbols(item, kind)
    metadata = getattr(item, "metadata", {})
    metadata = metadata if isinstance(metadata, Mapping) else {}
    relation_count = _bounded_count(
        metadata.get("relation_count", metadata.get("relations_count")),
        maximum=256,
    )
    evidence_count = _bounded_count(
        metadata.get(
            "evidence_record_count",
            metadata.get("evidence_count", metadata.get("evidence_records_count")),
        ),
        maximum=256,
    )
    return {
        "selection_ordinal": selection_ordinal,
        "eviction_ordinal": eviction_ordinal,
        "selected": selected,
        "evicted": evicted,
        "item_id": _safe_item_id(getattr(item, "item_id", None)),
        "item_kind": kind,
        "source": source,
        "source_channel": _source_channel(source, kind),
        "layer": _canonical_enum(
            getattr(item, "layer", None),
            allowed=_CANONICAL_LAYERS,
            fallback="other",
        ),
        "path": path,
        "path_redacted": path_redacted,
        "symbols": symbols,
        "symbol_count": symbol_count,
        "symbols_redacted": symbols_redacted,
        "symbols_projection_truncated": symbols_truncated,
        "relation_count": relation_count,
        "evidence_record_count": evidence_count,
        "safe_item_digest": _safe_digest(getattr(item, "digest", None)),
        "byte_count": _bounded_count(
            getattr(item, "byte_count", getattr(item, "byte_size", None)),
            maximum=MAX_CONTEXT_ITEM_BYTES,
        ),
        "token_estimate": _bounded_count(
            getattr(item, "token_count", getattr(item, "token_cost", None)),
            maximum=MAX_CONTEXT_ITEM_BYTES,
        ),
        "truncated": _bool(getattr(item, "truncated", False)),
        "compressed": _bool(getattr(item, "compressed", False)) or compressed,
    }


def _fit_rows_to_bound(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    """Keep the complete projection under a finite metadata budget."""

    while rows:
        encoded = canonical_json_bytes(rows)
        if len(encoded) <= MAX_CONTEXT_SELECTION_PROJECTION_BYTES:
            return rows
        rows.pop()
    return rows


def _safe_path(value: object) -> tuple[str | None, bool]:
    if value is None:
        return None, False
    if not isinstance(value, str):
        return "workspace:unsafe", True
    if (
        not value
        or len(value.encode("utf-8", errors="replace")) > MAX_CONTEXT_PATH_BYTES
        or _CONTROL_OR_FORMAT.search(value) is not None
        or "\\" in value
        or _WINDOWS_DRIVE.match(value) is not None
        or value != unicodedata.normalize("NFC", value)
    ):
        return "workspace:unsafe", True
    try:
        normalized = normalize_relative_path(value, label="context.path")
        SafeWorkspaceRelativePath.parse(normalized)
    except (TypeError, ValueError, UnsafePersistedIdentifier):
        return "workspace:unsafe", True
    if any(part.casefold() in _HIDDEN_PATH_PARTS for part in normalized.split("/")):
        return "workspace:unsafe", True
    if _SECRET_LIKE.search(normalized) is not None:
        return "workspace:unsafe", True
    return normalized, False


def _safe_symbols(item: object, kind: str) -> tuple[list[str], int | None, bool, bool]:
    metadata = getattr(item, "metadata", {})
    metadata = metadata if isinstance(metadata, Mapping) else {}
    raw_values: list[object] = []
    symbol = getattr(item, "symbol", None)
    if symbol is not None:
        raw_values.append(symbol)
    extra = metadata.get("symbols")
    raw_values_truncated = False
    if isinstance(extra, (list, tuple)):
        raw_values.extend(extra[: MAX_CONTEXT_SYMBOLS_PER_ITEM + 1])
        raw_values_truncated = len(extra) > MAX_CONTEXT_SYMBOLS_PER_ITEM
    original_count = _bounded_count(metadata.get("symbol_count"), maximum=256)
    if original_count is None and raw_values:
        original_count = len(raw_values)
    projected: list[str] = []
    redacted = False
    for value in raw_values[:MAX_CONTEXT_SYMBOLS_PER_ITEM]:
        safe, was_redacted = _safe_identifier(value, "[REDACTED_SYMBOL]")
        projected.append(safe)
        redacted = redacted or was_redacted
    truncated = raw_values_truncated or len(raw_values) > len(projected)
    if original_count is not None and original_count > len(projected):
        truncated = True
    if original_count is None and kind == ContextItemKind.SYMBOL.value and raw_values:
        original_count = 1
    return projected, original_count, redacted, truncated


def _safe_identifier(value: object, sentinel: str) -> tuple[str, bool]:
    if not isinstance(value, str):
        return sentinel, True
    normalized = unicodedata.normalize("NFKC", value).strip()
    if (
        not normalized
        or len(normalized.encode("utf-8", errors="replace")) > MAX_CONTEXT_SYMBOL_BYTES
        or _CONTROL_OR_FORMAT.search(normalized) is not None
        or _SECRET_LIKE.search(normalized) is not None
        or any(
            not (character.isalnum() or character in _IDENTIFIER_EXTRA)
            for character in normalized
        )
        or any(character.isspace() for character in normalized)
    ):
        return sentinel, True
    return normalized, False


def _safe_item_id(value: object) -> str:
    safe, redacted = _safe_identifier(value, "item:unsafe")
    if redacted or any(marker in safe.casefold() for marker in _HIDDEN_IDENTIFIER_MARKERS):
        return "item:unsafe"
    if len(safe.encode("utf-8", errors="replace")) > MAX_CONTEXT_ITEM_ID_BYTES:
        return "item:unsafe"
    return safe


def _safe_digest(value: object) -> str | None:
    if (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    ):
        return value
    return None


def _bounded_count(value: object, *, maximum: int) -> int | None:
    if type(value) is int and 0 <= value <= maximum:
        return value
    return None


def _bool(value: object) -> bool:
    return value if type(value) is bool else False


def _sequence(value: object) -> tuple[object, ...]:
    if isinstance(value, (list, tuple)):
        return tuple(value)
    if isinstance(value, Iterable) and not isinstance(value, (str, bytes, Mapping)):
        # Typed ContextSelection uses bounded tuples.  A defensive adapter or
        # test double may expose an arbitrary iterator; probe only one item
        # beyond the durable projection bound so telemetry cannot consume an
        # unbounded stream.
        result: list[object] = []
        iterator = iter(value)
        for _ in range(MAX_CONTEXT_SELECTION_ITEMS + 1):
            try:
                result.append(next(iterator))
            except StopIteration:
                break
        return tuple(result)
    return ()


def _item_identity(item: object) -> str:
    value = getattr(item, "item_id", None)
    return value if isinstance(value, str) else f"object:{id(item)}"


def _enum_value(value: object) -> str | None:
    raw = getattr(value, "value", value)
    return raw if isinstance(raw, str) and raw else None


def _canonical_enum(value: object, *, allowed: frozenset[str], fallback: str) -> str:
    raw = _enum_value(value)
    return raw if raw in allowed else fallback


def _source_channel(source: str, kind: str) -> str:
    if source == ContextSource.REPO_INTELLIGENCE.value:
        return "automatic_repo_context"
    if source == ContextSource.TOOL.value:
        return "tool_acquired_context"
    if source in {ContextSource.CONVERSATION.value, ContextSource.MEMORY.value}:
        return "history"
    if source in {
        ContextSource.SYSTEM.value,
        ContextSource.PROJECT.value,
        ContextSource.RUNTIME.value,
        ContextSource.EDIT_TRANSACTION.value,
        ContextSource.VERIFICATION.value,
    }:
        return "task_context"
    if kind in {
        ContextItemKind.GOAL.value,
        ContextItemKind.PLAN.value,
        ContextItemKind.PLAN_STEP.value,
        ContextItemKind.TASK_STATE.value,
    }:
        return "task_context"
    return "other"


__all__ = [
    "CONTEXT_SELECTION_OBSERVABILITY_SCHEMA_VERSION",
    "MAX_CONTEXT_ITEM_BYTES",
    "MAX_CONTEXT_ITEM_ID_BYTES",
    "MAX_CONTEXT_PATH_BYTES",
    "MAX_CONTEXT_SELECTION_ITEMS",
    "MAX_CONTEXT_SELECTION_PROJECTION_BYTES",
    "MAX_CONTEXT_SYMBOLS_PER_ITEM",
    "MAX_CONTEXT_SYMBOL_BYTES",
    "project_context_selection",
]
