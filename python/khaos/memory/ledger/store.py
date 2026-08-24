"""Canonical append-only event ledger backed by the shared SQLite owner."""

from __future__ import annotations

import sqlite3
from collections.abc import Sequence
from typing import Any

from khaos.memory.core.contracts import (
    MemoryEvent,
    RuntimeMemoryContext,
    as_utc,
    enum_value,
    payload_digest,
)


class EventLedgerError(RuntimeError):
    """Raised when an event cannot be appended without losing provenance."""


class SqliteEventLedger:
    """Append and scope-filter canonical events through a Database port."""

    def __init__(self, db: Any) -> None:
        self._db = db

    @property
    def database(self) -> Any:
        """Expose the injected database for composition, never for callers."""

        return self._db

    async def append(self, event: MemoryEvent) -> str:
        """Append one event, treating an identical event id as idempotent."""

        payload_json = _json(event.payload)
        recorded_at = as_utc(event.recorded_at or event.occurred_at).isoformat()
        async with self._db.transaction() as conn:
            cursor = await conn.execute(
                "SELECT payload_hash, principal_id, project_id FROM memory_events "
                "WHERE event_id = ?",
                (event.event_id,),
            )
            existing = await cursor.fetchone()
            if existing is not None:
                if (
                    str(existing["payload_hash"]) != event.payload_hash
                    or str(existing["principal_id"]) != event.principal_id
                    or str(existing["project_id"]) != event.project_id
                ):
                    raise EventLedgerError(
                        "event_id collision with different scope or payload"
                    )
                return event.event_id
            await conn.execute(
                """
                INSERT INTO memory_events (
                    event_id, event_type, principal_id, project_id, session_id,
                    task_id, workspace_id, repo_id, branch, commit_sha,
                    source_type, source_ref, occurred_at, observed_at,
                    recorded_at, payload_json, payload_hash, trust_hint,
                    sensitivity
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    enum_value(event.event_type),
                    event.principal_id,
                    event.project_id,
                    event.session_id or "",
                    event.task_id or "",
                    event.workspace_id or "",
                    event.repo_id or "",
                    event.branch or "",
                    event.commit_sha or "",
                    enum_value(event.source_type),
                    event.source_ref or "",
                    as_utc(event.occurred_at).isoformat(),
                    as_utc(event.observed_at or event.occurred_at).isoformat(),
                    recorded_at,
                    payload_json,
                    event.payload_hash,
                    enum_value(event.trust_hint),
                    enum_value(event.sensitivity),
                ),
            )
        return event.event_id

    async def get(self, event_id: str, runtime: RuntimeMemoryContext) -> dict[str, Any] | None:
        """Read one event only inside the caller's project/principal scope."""

        async with self._db.read_connection() as conn:
            cursor = await conn.execute(
                "SELECT * FROM memory_events "
                "WHERE event_id = ? AND project_id = ? AND principal_id = ?",
                (event_id, runtime.project_id, runtime.principal_id),
            )
            row = await cursor.fetchone()
            if row is None:
                return None
            value = dict(row)
            return await self._redact_if_tombstoned(value, runtime)

    async def list(
        self,
        runtime: RuntimeMemoryContext,
        *,
        event_types: Sequence[str] | None = None,
        limit: int = 100,
        include_all_sessions: bool = False,
        include_all_principals: bool = False,
        after_recorded_at: str | None = None,
        after_event_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """List one stable cursor page in recorded order.

        ``after_recorded_at`` + ``after_event_id`` is a strict lexicographic
        cursor.  It is intentionally not an offset: inserting or deleting a
        derived row cannot make a rebuild skip or repeat a canonical event.
        """

        if limit <= 0 or limit > 10_000:
            raise ValueError("event ledger page size must be between 1 and 10000")
        clauses = ["project_id = ?"]
        params: list[Any] = [runtime.project_id]
        if not include_all_principals:
            clauses.append("principal_id = ?")
            params.append(runtime.principal_id)
        if runtime.session_id is not None and not include_all_sessions:
            clauses.append("(session_id = ? OR session_id = '')")
            params.append(runtime.session_id)
        if event_types:
            if len(event_types) > 32:
                raise ValueError("event_types is oversized")
            placeholders = ",".join("?" for _ in event_types)
            clauses.append(f"event_type IN ({placeholders})")
            params.extend(event_types)
        if (after_recorded_at is None) != (after_event_id is None):
            raise ValueError("ledger cursor requires recorded_at and event_id together")
        if after_recorded_at is not None and after_event_id is not None:
            clauses.append(
                "(recorded_at > ? OR (recorded_at = ? AND event_id > ?))"
            )
            params.extend((after_recorded_at, after_recorded_at, after_event_id))
        params.append(limit)
        async with self._db.read_connection() as conn:
            cursor = await conn.execute(
                "SELECT * FROM memory_events WHERE "
                + " AND ".join(clauses)
                + " ORDER BY recorded_at, event_id LIMIT ?",
                tuple(params),
            )
            values = [dict(row) for row in await cursor.fetchall()]
            return [
                await self._redact_if_tombstoned(value, runtime)
                for value in values
            ]

    async def _redact_if_tombstoned(
        self,
        row: dict[str, Any],
        runtime: RuntimeMemoryContext,
    ) -> dict[str, Any]:
        """Return content-free event data after a compliance redaction."""

        event_id = str(row.get("event_id") or "")
        if not event_id:
            return row
        try:
            async with self._db.read_connection() as conn:
                tombstone = await (
                    await conn.execute(
                        "SELECT 1 FROM memory_privacy_tombstones "
                        "WHERE event_id = ? AND project_id = ? AND ("
                        "(principal_id = ? AND (session_id = ? OR session_id = '')) "
                        "OR (principal_id = '' AND session_id = '')"
                        ")",
                        (
                            event_id,
                            runtime.project_id,
                            runtime.principal_id,
                            runtime.session_id or "",
                        ),
                    )
                ).fetchone()
        except sqlite3.OperationalError as exc:
            # Older pre-v15 databases are migrated before production use; a
            # missing table here is retained as a compatibility read result.
            if "no such table: memory_privacy_tombstones" in str(exc).lower():
                return row
            raise
        if tombstone is None:
            return row
        redacted = dict(row)
        redacted["payload_json"] = "{}"
        redacted["payload_hash"] = payload_digest({})
        redacted["payload_redacted"] = True
        return redacted

    async def revoked_ids(
        self,
        runtime: RuntimeMemoryContext,
        memory_ids: Sequence[str],
        *,
        provider_id: str | None = None,
    ) -> set[str]:
        """Resolve ids against complete, provider-bound revocation identity."""

        if not memory_ids:
            return set()
        if len(memory_ids) > 256:
            raise ValueError("revocation lookup is oversized")
        patterns = [f'%"memory_id":"{memory_id}"%' for memory_id in memory_ids]
        async with self._db.read_connection() as conn:
            cursor = await conn.execute(
                "SELECT payload_json FROM memory_events "
                "WHERE project_id = ? "
                "AND event_type = 'MEMORY_REVOKED' "
                "AND ("
                + " OR ".join("payload_json LIKE ?" for _ in patterns)
                + ")",
                [runtime.project_id, *patterns],
            )
            rows = await cursor.fetchall()
        revoked: set[str] = set()
        for row in rows:
            payload = row["payload_json"]
            try:
                value = _parse_json(payload)
            except (TypeError, ValueError):
                continue
            memory_id = value.get("memory_id") if isinstance(value, dict) else None
            payload_project = value.get("project_id") if isinstance(value, dict) else None
            payload_principal = value.get("principal_id") if isinstance(value, dict) else None
            payload_session = value.get("session_id") if isinstance(value, dict) else None
            payload_provider = value.get("provider_id") if isinstance(value, dict) else None
            payload_namespace = value.get("namespace") if isinstance(value, dict) else None
            if (
                isinstance(memory_id, str)
                and payload_project == runtime.project_id
                and (not provider_id or payload_provider == provider_id)
                and payload_namespace in {"private", "session", "project", "shared"}
                and (
                    (
                        payload_namespace in {"project", "shared"}
                        and payload_principal == ""
                        and payload_session == ""
                    )
                    or (
                        payload_principal == runtime.principal_id
                        and payload_namespace != "session"
                    )
                    or (
                        payload_principal == runtime.principal_id
                        and payload_namespace == "session"
                        and payload_session == (runtime.session_id or "")
                    )
                )
            ):
                revoked.add(memory_id)
        return revoked


def _json(value: Any) -> str:
    """Canonical JSON helper kept local to the persistence adapter."""

    import json

    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _parse_json(value: Any) -> Any:
    import json

    return json.loads(str(value))


EventLedger = SqliteEventLedger


__all__ = ["EventLedger", "EventLedgerError", "SqliteEventLedger"]
