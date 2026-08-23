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

from khaos.memory.core.contracts import (
    MemoryEvent,
    RuntimeMemoryContext,
    canonical_json,
)
from khaos.memory.core.broker import MemoryBroker


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
        events = package["events"]
        if len(events) > MAX_TRANSFER_EVENTS:
            raise MemoryTransferError("import package contains too many events")
        imported = 0
        for raw_event in events:
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
            replayed = await self._broker.rebuild_from_ledger(runtime, limit=MAX_TRANSFER_EVENTS)
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
                "(principal_id = ? OR principal_id = '' OR ? = '')"
            )
            scope_params = (runtime.project_id, runtime.principal_id, runtime.principal_id)
            events = await (
                await conn.execute(
                    "SELECT * FROM memory_events WHERE " + scope_clause +
                    " ORDER BY recorded_at, event_id LIMIT ?",
                    (*scope_params, min(limit, MAX_TRANSFER_EVENTS)),
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
                            + placeholders + ") LIMIT ?",
                            (*node_ids, limit),
                        )
                    ).fetchall()
                    edges = await (
                        await conn.execute(
                            "SELECT * FROM memory_edges WHERE project_id = ? LIMIT ?",
                            (runtime.project_id, limit),
                        )
                    ).fetchall()
                    package["memory_evidence"] = [dict(row) for row in evidence]
                    package["memory_edges"] = [dict(row) for row in edges]
                else:
                    package["memory_evidence"] = []
                    package["memory_edges"] = []
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
    for key in ("events", "memory_nodes", "memory_evidence", "memory_edges"):
        value = package.get(key, [])
        if not isinstance(value, list) or len(value) > MAX_TRANSFER_ROWS:
            raise MemoryTransferError(f"import package field {key} is oversized")
    supplied = package.get("digest")
    if not isinstance(supplied, str) or supplied != _digest({key: value for key, value in package.items() if key != "digest"}):
        raise MemoryTransferError("import package digest mismatch")


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
