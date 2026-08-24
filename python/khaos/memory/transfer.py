"""Scope-preserving canonical Memory V2 export and import."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import tempfile
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from khaos.memory.core.broker import MemoryBroker
from khaos.memory.core.contracts import (
    MemoryEvent,
    MemoryEventType,
    RuntimeMemoryContext,
    canonical_json,
)
from khaos.memory.projection import stable_memory_id


class MemoryTransferError(ValueError):
    """Raised when an export/import package is invalid or out of scope."""


MAX_TRANSFER_BYTES = 256 * 1024 * 1024
MAX_TRANSFER_EVENTS = 100_000
MAX_TRANSFER_ROWS = 200_000


class MemoryTransferService:
    """Export canonical evidence and rebuild derived state after import."""

    def __init__(self, broker: MemoryBroker) -> None:
        self._broker = broker

    async def export(
        self,
        runtime: RuntimeMemoryContext,
        path: Path,
        *,
        include_derived: bool = True,
        limit: int = MAX_TRANSFER_ROWS,
    ) -> dict[str, Any]:
        """Write a digest-bound JSON package through an atomic replace."""

        if limit <= 0 or limit > MAX_TRANSFER_ROWS:
            raise MemoryTransferError("export limit is outside the bounded range")
        payload = await self._collect(runtime, include_derived=include_derived, limit=limit)
        encoded = _encode_package(payload)
        if len(encoded) > MAX_TRANSFER_BYTES:
            raise MemoryTransferError("export package exceeds the maximum size")
        await asyncio.to_thread(_atomic_write, path, encoded)
        return {
            "path": str(path),
            "bytes": len(encoded),
            "events": len(payload["events"]),
            "nodes": len(payload.get("memory_nodes", [])),
            "digest": payload["digest"],
        }

    async def import_package(
        self,
        runtime: RuntimeMemoryContext,
        path: Path,
        *,
        rebuild: bool = True,
    ) -> dict[str, Any]:
        """Validate a package, append only in-scope events, and rebuild."""

        raw = await asyncio.to_thread(_read_bounded, path, MAX_TRANSFER_BYTES)
        try:
            package = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise MemoryTransferError("import package is not valid UTF-8 JSON") from exc
        _validate_package(package)
        if package["scope"]["project_id"] != runtime.project_id:
            raise MemoryTransferError("import package belongs to a different project")
        if package["scope"]["principal_id"] != runtime.principal_id:
            raise MemoryTransferError("import package belongs to a different principal")
        _validate_import_scope(package, runtime)
        events = package["events"]
        if len(events) > MAX_TRANSFER_EVENTS:
            raise MemoryTransferError("import package contains too many events")
        imported = 0
        for raw_event in events:
            if (
                raw_event.get("payload_redacted") is True
                and str(raw_event.get("event_type")) == "MEMORY_CANDIDATE_CREATED"
            ):
                # A compliance-redacted candidate has intentionally lost its
                # claim.  The corresponding revoke/tombstone event remains
                # canonical; importing an empty candidate would turn privacy
                # deletion into a malformed replay failure.
                continue
            event = _event_from_mapping(raw_event)
            if (
                event.project_id != runtime.project_id
                or event.principal_id not in {runtime.principal_id, ""}
            ):
                raise MemoryTransferError("import event escaped the package scope")
            await self._broker.record_event(event)
            imported += 1
        replayed = 0
        if rebuild:
            # ``limit`` is a bounded page size in the replay API, never the
            # total package size.  Keeping the page within the Broker's
            # contract still replays every imported event through the stable
            # cursor loop.
            replayed = await self._broker.rebuild_from_ledger(runtime, limit=10_000)
        return {
            "path": str(path),
            "imported_events": imported,
            "replayed_nodes": replayed,
            "digest": package["digest"],
        }

    async def _collect(
        self,
        runtime: RuntimeMemoryContext,
        *,
        include_derived: bool,
        limit: int,
    ) -> dict[str, Any]:
        db = self._broker.ledger.database
        async with db.read_connection() as conn:
            scope_clause = (
                "project_id = ? AND "
                "(principal_id = ? OR principal_id = '') AND "
                "(session_id = ? OR session_id = '')"
            )
            scope_params = (
                runtime.project_id,
                runtime.principal_id,
                runtime.session_id or "",
            )
            events = await (
                await conn.execute(
                    "SELECT e.event_id, e.event_type, e.principal_id, e.project_id, "
                    "e.session_id, e.task_id, e.workspace_id, e.repo_id, e.branch, "
                    "e.commit_sha, e.source_type, e.source_ref, e.occurred_at, "
                    "e.observed_at, e.recorded_at, "
                    "CASE WHEN t.event_id IS NULL THEN e.payload_json ELSE '{}' END "
                    "AS payload_json, "
                    "CASE WHEN t.event_id IS NULL THEN e.payload_hash ELSE "
                    "'" + hashlib.sha256(b"{}").hexdigest() + "' END AS payload_hash, "
                    "e.trust_hint, e.sensitivity, "
                    "CASE WHEN t.event_id IS NULL THEN 0 ELSE 1 END AS payload_redacted "
                    "FROM memory_events e LEFT JOIN memory_privacy_tombstones t "
                    "ON t.event_id = e.event_id AND t.project_id = e.project_id "
                    "AND ("
                    "(t.principal_id = ? AND (t.session_id = e.session_id OR t.session_id = '')) "
                    "OR (t.principal_id = '' AND t.session_id = '')"
                    ") WHERE "
                    + scope_clause.replace("project_id", "e.project_id")
                    .replace("principal_id", "e.principal_id")
                    .replace("session_id", "e.session_id")
                    + " ORDER BY e.recorded_at, e.event_id LIMIT ?",
                    (
                        runtime.principal_id,
                        *scope_params,
                        min(limit, MAX_TRANSFER_EVENTS),
                    ),
                )
            ).fetchall()
            package: dict[str, Any] = {
                "format": "khaos-memory-v2",
                "version": 1,
                "scope": {
                    "principal_id": runtime.principal_id,
                    "project_id": runtime.project_id,
                    "session_id": runtime.session_id,
                },
                "created_at": datetime.now(UTC).isoformat(),
                "events": [dict(row) for row in events],
            }
            if include_derived:
                nodes = await (
                    await conn.execute(
                        "SELECT * FROM memory_nodes WHERE " + scope_clause +
                        " ORDER BY updated_at, memory_id LIMIT ?",
                        (*scope_params, limit),
                    )
                ).fetchall()
                node_ids = [str(row["memory_id"]) for row in nodes]
                package["memory_nodes"] = [dict(row) for row in nodes]
                if node_ids:
                    placeholders = ",".join("?" for _ in node_ids)
                    evidence = await (
                        await conn.execute(
                            "SELECT * FROM memory_evidence WHERE memory_id IN ("
                            + placeholders
                            + ") AND project_id = ? AND (principal_id = ? OR principal_id = '') LIMIT ?",
                            (*node_ids, runtime.project_id, runtime.principal_id, limit),
                        )
                    ).fetchall()
                    edges = await (
                        await conn.execute(
                            "SELECT * FROM memory_edges WHERE project_id = ? "
                            "AND (principal_id = ? OR principal_id = '') LIMIT ?",
                            (runtime.project_id, runtime.principal_id, limit),
                        )
                    ).fetchall()
                    entities = await (
                        await conn.execute(
                            "SELECT * FROM memory_entities WHERE project_id = ? "
                            "AND (principal_id = ? OR principal_id = '') LIMIT ?",
                            (runtime.project_id, runtime.principal_id, limit),
                        )
                    ).fetchall()
                    visible_node_ids = set(node_ids)
                    visible_entity_ids = {str(row["entity_id"]) for row in entities}
                    filtered_edges = [
                        dict(row)
                        for row in edges
                        if _edge_is_visible(
                            row,
                            visible_node_ids=visible_node_ids,
                            visible_entity_ids=visible_entity_ids,
                        )
                    ]
                    package["memory_evidence"] = [dict(row) for row in evidence]
                    package["memory_edges"] = filtered_edges
                    package["memory_entities"] = [dict(row) for row in entities]
                else:
                    package["memory_evidence"] = []
                    package["memory_edges"] = []
                    package["memory_entities"] = []
            digest_payload = dict(package)
            package["digest"] = _digest(digest_payload)
            return package


def _event_from_mapping(raw: Mapping[str, Any]) -> MemoryEvent:
    required = {
        "event_id",
        "event_type",
        "principal_id",
        "project_id",
        "occurred_at",
        "payload_json",
        "payload_hash",
        "source_type",
        "trust_hint",
        "sensitivity",
    }
    if not required.issubset(raw):
        raise MemoryTransferError("import event is missing required fields")
    try:
        payload = json.loads(str(raw["payload_json"]))
    except json.JSONDecodeError as exc:
        raise MemoryTransferError("import event payload is invalid JSON") from exc
    if not isinstance(payload, Mapping):
        raise MemoryTransferError("import event payload must be an object")
    return MemoryEvent(
        event_id=str(raw["event_id"]),
        event_type=str(raw["event_type"]),
        principal_id=str(raw["principal_id"]),
        project_id=str(raw["project_id"]),
        session_id=_none_if_empty(raw.get("session_id")),
        task_id=_none_if_empty(raw.get("task_id")),
        workspace_id=_none_if_empty(raw.get("workspace_id")),
        repo_id=_none_if_empty(raw.get("repo_id")),
        branch=_none_if_empty(raw.get("branch")),
        commit_sha=_none_if_empty(raw.get("commit_sha")),
        source_type=str(raw["source_type"]),
        source_ref=_none_if_empty(raw.get("source_ref")),
        occurred_at=datetime.fromisoformat(str(raw["occurred_at"])),
        observed_at=datetime.fromisoformat(str(raw.get("observed_at", raw["occurred_at"]))),
        recorded_at=datetime.fromisoformat(str(raw.get("recorded_at", raw["occurred_at"]))),
        payload=payload,
        payload_hash=str(raw["payload_hash"]),
        trust_hint=str(raw["trust_hint"]),
        sensitivity=str(raw["sensitivity"]),
    )


def _none_if_empty(value: Any) -> str | None:
    return str(value) if value not in (None, "") else None


def _validate_package(package: Any) -> None:
    if not isinstance(package, dict):
        raise MemoryTransferError("import package root must be an object")
    if package.get("format") != "khaos-memory-v2" or package.get("version") != 1:
        raise MemoryTransferError("unsupported memory package format")
    if not isinstance(package.get("scope"), dict):
        raise MemoryTransferError("import package has no scope")
    if not isinstance(package.get("events"), list):
        raise MemoryTransferError("import package has no event list")
    for key in (
        "events",
        "memory_nodes",
        "memory_evidence",
        "memory_edges",
        "memory_entities",
    ):
        value = package.get(key, [])
        if not isinstance(value, list) or len(value) > MAX_TRANSFER_ROWS:
            raise MemoryTransferError(f"import package field {key} is oversized")
    supplied = package.get("digest")
    if not isinstance(supplied, str) or supplied != _digest({key: value for key, value in package.items() if key != "digest"}):
        raise MemoryTransferError("import package digest mismatch")


def _validate_import_scope(
    package: Mapping[str, Any],
    runtime: RuntimeMemoryContext,
) -> None:
    """Validate every canonical/derived row before appending any event."""

    scope = package["scope"]
    if scope.get("session_id") not in {None, "", runtime.session_id}:
        raise MemoryTransferError("import package belongs to a different session")
    nodes = package.get("memory_nodes", [])
    node_ids = {str(row.get("memory_id")) for row in nodes}
    entity_ids = {str(row.get("entity_id")) for row in package.get("memory_entities", [])}
    event_ids = {
        str(event.get("event_id"))
        for event in package.get("events", [])
        if event.get("event_id")
    }
    candidate_ids = {
        stable_memory_id(str(event.get("event_id")))
        for event in package.get("events", [])
        if str(event.get("event_type")) == MemoryEventType.MEMORY_CANDIDATE_CREATED.value
        and event.get("event_id")
    }
    known_memory_ids = node_ids | candidate_ids
    for event in package.get("events", []):
        _validate_row_identity(event, runtime, "event")
        event_type = str(event.get("event_type"))
        if event_type not in {
            MemoryEventType.MEMORY_PROMOTED.value,
            MemoryEventType.MEMORY_SUPERSEDED.value,
            MemoryEventType.MEMORY_REVOKED.value,
        }:
            continue
        try:
            payload = json.loads(str(event.get("payload_json", "{}")))
        except json.JSONDecodeError as exc:
            raise MemoryTransferError("import lifecycle event payload is invalid JSON") from exc
        if not isinstance(payload, Mapping):
            raise MemoryTransferError("import lifecycle event payload must be an object")
        memory_id = payload.get("memory_id")
        if not isinstance(memory_id, str) or not memory_id or memory_id not in known_memory_ids:
            raise MemoryTransferError("import lifecycle event references an invisible memory")
        related_ids = payload.get("related_ids", ())
        if not isinstance(related_ids, (list, tuple)) or len(related_ids) > 256:
            raise MemoryTransferError("import lifecycle related ids are malformed")
        related_allowlist = event_ids if event_type == MemoryEventType.MEMORY_PROMOTED.value else known_memory_ids
        if any(
            not isinstance(related_id, str) or not related_id or related_id not in related_allowlist
            for related_id in related_ids
        ):
            raise MemoryTransferError("import lifecycle event references an invisible related memory")
    for node in nodes:
        _validate_row_identity(node, runtime, "memory node")
        namespace = str(node.get("namespace", ""))
        principal = str(node.get("principal_id", ""))
        session = str(node.get("session_id", ""))
        if namespace in {"private", "session"} and principal != runtime.principal_id:
            raise MemoryTransferError("import private node escaped principal scope")
        if namespace == "session" and session != (runtime.session_id or ""):
            raise MemoryTransferError("import session node escaped session scope")
        if namespace in {"project", "shared"} and principal not in {"", runtime.principal_id}:
            raise MemoryTransferError("import shared node has foreign principal")
    for evidence in package.get("memory_evidence", []):
        _validate_row_identity(evidence, runtime, "memory evidence")
        if str(evidence.get("memory_id")) not in node_ids:
            raise MemoryTransferError("import evidence references an invisible node")
    for entity in package.get("memory_entities", []):
        _validate_row_identity(entity, runtime, "memory entity")
        if str(entity.get("entity_id")) not in entity_ids:
            raise MemoryTransferError("import entity identity is malformed")
    for edge in package.get("memory_edges", []):
        _validate_row_identity(edge, runtime, "memory edge")
        if not _edge_is_visible(
            edge,
            visible_node_ids=node_ids,
            visible_entity_ids=entity_ids,
        ):
            raise MemoryTransferError("import edge references an invisible endpoint")


def _validate_row_identity(
    row: Mapping[str, Any],
    runtime: RuntimeMemoryContext,
    label: str,
) -> None:
    if str(row.get("project_id", "")) != runtime.project_id:
        raise MemoryTransferError(f"import {label} escaped project scope")
    principal = str(row.get("principal_id", ""))
    if principal not in {"", runtime.principal_id}:
        raise MemoryTransferError(f"import {label} escaped principal scope")
    session = str(row.get("session_id", ""))
    if session not in {"", runtime.session_id or ""}:
        raise MemoryTransferError(f"import {label} escaped session scope")


def _edge_is_visible(
    row: Mapping[str, Any],
    *,
    visible_node_ids: set[str],
    visible_entity_ids: set[str],
) -> bool:
    for kind_key, id_key in (("from_kind", "from_id"), ("to_kind", "to_id")):
        kind = str(row.get(kind_key, ""))
        target = str(row.get(id_key, ""))
        if kind == "memory" and target not in visible_node_ids:
            return False
        if kind == "entity" and target not in visible_entity_ids:
            return False
    return True


def _digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _encode_package(package: Mapping[str, Any]) -> bytes:
    return (canonical_json(package) + "\n").encode("utf-8")


def _read_bounded(path: Path, maximum: int) -> bytes:
    """Read an import package without allocating beyond its hard byte bound."""

    if maximum <= 0:
        raise MemoryTransferError("import package bound must be positive")
    chunks: list[bytes] = []
    total = 0
    try:
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(min(64 * 1024, maximum - total + 1))
                if not chunk:
                    break
                total += len(chunk)
                if total > maximum:
                    raise MemoryTransferError("import package exceeds the maximum size")
                chunks.append(chunk)
    except FileNotFoundError as exc:
        raise MemoryTransferError(f"import package does not exist: {path}") from exc
    except OSError as exc:
        raise MemoryTransferError("import package cannot be read") from exc
    return b"".join(chunks)


def _atomic_write(path: Path, payload: bytes) -> None:
    target = path.expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


__all__ = ["MemoryTransferError", "MemoryTransferService"]
