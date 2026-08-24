"""Khaos Native Memory V2 provider.

The native provider is intentionally boring: SQLite is the canonical local
store, FTS5 is a rebuildable index, and all authority/scope decisions are
made by :class:`MemoryBroker` before this module is called.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import sqlite3
import uuid
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any

from khaos.memory.core.contracts import (
    EvidenceRef,
    ForgetResult,
    MemoryAuthority,
    MemoryCandidate,
    MemoryCapabilities,
    MemoryEventType,
    MemoryForgetRequest,
    MemoryHit,
    MemorySearchRequest,
    MemoryStatus,
    MemoryWriteRequest,
    MemoryWriteResult,
    ProviderHealth,
    RelationCandidate,
    RuntimeMemoryContext,
    SourceType,
    enum_value,
    utc_now,
)
from khaos.memory.projection import MemoryProjectionReducer


class NativeMemoryProvider:
    """SQLite/FTS5 implementation of the MemoryProvider SPI."""

    provider_id = "khaos-native"
    trusted_canonical = True

    def __init__(self, db: Any) -> None:
        self._db = db
        self._started = True
        self._rebuild_lock = asyncio.Lock()
        self._rebuild_connection: ContextVar[Any | None] = ContextVar(
            "khaos_memory_rebuild_connection", default=None
        )

    @property
    def database(self) -> Any:
        """Return the injected database port for maintenance composition."""

        return self._db

    def capabilities(self) -> MemoryCapabilities:
        """Return capabilities supported without remote dependencies."""

        return MemoryCapabilities(
            exact_search=True,
            keyword_search=True,
            semantic_search=False,
            entity_linking=True,
            graph_traversal=False,
            temporal_search=True,
            historical_query=True,
            profile=False,
            bulk_import=True,
            forget=True,
            update=True,
            graph_expand=False,
            vector_search=False,
            export_data=True,
            import_data=True,
            compact=True,
            bulk_rebuild=True,
            stream_events=True,
        )

    async def install(self) -> None:
        """Native storage is installed by the shared database migration."""

    async def validate(self) -> None:
        """Ensure the canonical tables are available before mounting."""

        async with self._db.read_connection() as conn:
            row = await (
                await conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='memory_nodes'"
                )
            ).fetchone()
            if row is None:
                raise RuntimeError("memory V2 schema is not migrated")

    async def mount(self) -> None:
        """The shared Database owns the SQLite connection lifecycle."""

    async def start(self) -> None:
        self._started = True

    async def stop(self) -> None:
        self._started = False

    async def unmount(self) -> None:
        """No provider-local handles exist after the shared DB is closed."""

    async def health(self) -> ProviderHealth:
        """Check that the canonical tables are available."""

        if not self._started:
            return ProviderHealth(self.provider_id, False, "provider_stopped", "stopped")
        try:
            async with self._db.read_connection() as conn:
                await (await conn.execute("SELECT 1 FROM memory_events LIMIT 1")).fetchone()
            return ProviderHealth(self.provider_id, True, lifecycle="healthy")
        except Exception as exc:  # noqa: BLE001 - health must not escape
            return ProviderHealth(self.provider_id, False, type(exc).__name__, "failed")

    async def add(self, request: MemoryWriteRequest) -> MemoryWriteResult:
        """Persist a candidate as a new version, never overwriting content."""

        candidate = request.candidate
        runtime = request.runtime
        now = utc_now()
        valid_from = candidate.valid_from or now
        content_hash = hashlib.sha256(candidate.claim.encode("utf-8")).hexdigest()
        namespace = candidate.namespace
        principal_id = "" if namespace in {"project", "shared"} else runtime.principal_id
        session_id = candidate.session_id or (runtime.session_id if namespace == "session" else "")
        key = candidate.key or _derived_key(candidate.claim)
        memory_id = _stable_memory_id(request.candidate_event_id)
        applicability_json = _json(candidate.preconditions)
        environment_json = _json(candidate.environment)

        async with self._write_transaction() as conn:
            existing_cursor = await conn.execute(
                """
                SELECT memory_id, content_hash, status FROM memory_nodes
                WHERE project_id = ? AND namespace = ? AND principal_id = ?
                  AND session_id = ? AND memory_type = ? AND scope = ? AND key = ?
                  AND status IN ('ACTIVE', 'VERIFIED', 'CANDIDATE', 'QUARANTINED')
                ORDER BY valid_from DESC, created_at DESC
                LIMIT 1
                """,
                (
                    runtime.project_id,
                    namespace,
                    principal_id,
                    session_id,
                    enum_value(candidate.memory_type),
                    candidate.scope,
                    key,
                ),
            )
            existing = await existing_cursor.fetchone()
            if existing is not None and str(existing["content_hash"]) == content_hash:
                evidence_added = await self._insert_evidence(conn, request, str(existing["memory_id"]), now)
                await self._insert_entities_and_edges(conn, request, str(existing["memory_id"]), now)
                return MemoryWriteResult(
                    memory_id=str(existing["memory_id"]),
                    status=MemoryStatus(str(existing["status"])),
                    created=False,
                    evidence_added=evidence_added,
                )

            superseded_ids = tuple(dict.fromkeys(request.supersede_memory_ids))
            if existing is not None and not superseded_ids:
                # Same-key replacement is a Broker policy decision.  Keeping
                # the old node active is deliberate: unresolved conflicts
                # remain visible to the Broker as temporal alternatives.
                superseded_ids = ()
            if superseded_ids:
                placeholders = ",".join("?" for _ in superseded_ids)
                current_clauses, current_params = _scope_predicate(
                    runtime, include_historical=True
                )
                rows = await (
                    await conn.execute(
                        "SELECT memory_id FROM memory_nodes n WHERE memory_id IN ("
                        + placeholders
                        + ") AND "
                        + " AND ".join(current_clauses),
                        [*superseded_ids, *current_params],
                    )
                ).fetchall()
                owned_ids = {str(row["memory_id"]) for row in rows}
                if owned_ids != set(superseded_ids):
                    raise PermissionError("supersession target is outside provider scope")
                await conn.execute(
                    "UPDATE memory_nodes SET status = 'SUPERSEDED', valid_to = ?, "
                    "superseded_at = ?, superseded_by = ?, updated_at = ? "
                    "WHERE memory_id IN (" + placeholders + ")",
                    [
                        valid_from.astimezone(UTC).isoformat(),
                        now.astimezone(UTC).isoformat(),
                        memory_id,
                        now.astimezone(UTC).isoformat(),
                        *superseded_ids,
                    ],
                )

            await conn.execute(
                """
                INSERT INTO memory_nodes (
                    memory_id, memory_type, status, namespace, scope,
                    principal_id, project_id, session_id, key, content,
                    content_hash, authority, confidence, sensitivity,
                    usage_policy, applicability_json, environment_json,
                    valid_from, valid_to, superseded_by, created_at, updated_at,
                    provider_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    memory_id,
                    enum_value(candidate.memory_type),
                    enum_value(request.status),
                    namespace,
                    candidate.scope,
                    principal_id,
                    runtime.project_id,
                    session_id,
                    key,
                    candidate.claim,
                    content_hash,
                    enum_value(request.authority),
                    float(candidate.confidence),
                    enum_value(candidate.sensitivity),
                    enum_value(candidate.usage_policy),
                    applicability_json,
                    environment_json,
                    valid_from.astimezone(UTC).isoformat(),
                    candidate.valid_to.astimezone(UTC).isoformat() if candidate.valid_to else None,
                    None,
                    now.astimezone(UTC).isoformat(),
                    now.astimezone(UTC).isoformat(),
                    self.provider_id,
                ),
            )
            evidence_added = await self._insert_evidence(conn, request, memory_id, now)
            await self._insert_entities_and_edges(conn, request, memory_id, now)

        return MemoryWriteResult(
            memory_id=memory_id,
            status=request.status,
            superseded_memory_ids=superseded_ids,
            evidence_added=evidence_added,
        )

    async def search(self, request: MemorySearchRequest) -> list[MemoryHit]:
        """Search FTS5 inside the provider request's host-bound scope."""

        if request.limit <= 0:
            return []
        clauses, params = _scope_predicate(request.runtime, include_historical=request.include_historical)
        query = request.query.strip()
        async with self._db.read_connection() as conn:
            if query:
                safe_query = _fts_query(query)
                try:
                    cursor = await conn.execute(
                        """
                        SELECT n.*, bm25(f) AS retrieval_score FROM memory_nodes_fts_search f
                        JOIN memory_nodes_fts idx ON idx.rowid = f.rowid
                        JOIN memory_nodes n ON n.memory_id = idx.memory_id
                        WHERE f MATCH ? AND """
                        + " AND ".join(clauses)
                        + " ORDER BY bm25(f) LIMIT ?",
                        [safe_query, *params, request.limit],
                    )
                    rows = await cursor.fetchall()
                except sqlite3.OperationalError:
                    # FTS syntax is an index concern.  A malformed user query
                    # must not fail open or turn into SQL; bounded LIKE is a
                    # safe, slower fallback for the same scope.  Match terms
                    # independently so a harmless multi-term query does not
                    # become an accidental exact-phrase search.
                    terms = [term[:256] for term in query.split() if term][:32]
                    if not terms:
                        terms = [query[:256]]
                    like_clauses = [
                        "(n.key LIKE ? OR n.content LIKE ?)" for _ in terms
                    ]
                    like_params = [
                        value
                        for term in terms
                        for value in (f"%{term}%", f"%{term}%")
                    ]
                    cursor = await conn.execute(
                        "SELECT n.* FROM memory_nodes n WHERE ("
                        + " OR ".join(like_clauses)
                        + ") AND "
                        + " AND ".join(clauses)
                        + " ORDER BY n.updated_at DESC LIMIT ?",
                        [*like_params, *params, request.limit],
                    )
                    rows = await cursor.fetchall()
            else:
                cursor = await conn.execute(
                    "SELECT n.* FROM memory_nodes n WHERE "
                    + " AND ".join(clauses)
                    + " ORDER BY CASE n.status WHEN 'VERIFIED' THEN 0 WHEN 'ACTIVE' THEN 1 ELSE 2 END, "
                    "n.updated_at DESC LIMIT ?",
                    [*params, request.limit],
                )
                rows = await cursor.fetchall()
            return [await self._row_to_hit(conn, row) for row in rows]

    async def get_current(
        self,
        runtime: Any,
        *,
        scope: str,
        key: str,
        namespace: str = "private",
        session_id: str | None = None,
    ) -> MemoryHit | None:
        """Read the latest valid version for the compatibility RPC surface."""

        principal_id = "" if namespace in {"project", "shared"} else runtime.principal_id
        effective_session = session_id or (runtime.session_id if namespace == "session" else "")
        async with self._db.read_connection() as conn:
            cursor = await conn.execute(
                """
                SELECT * FROM memory_nodes
                WHERE project_id = ? AND namespace = ? AND principal_id = ?
                  AND session_id = ? AND scope = ? AND key = ?
                  AND status IN ('ACTIVE', 'VERIFIED')
                ORDER BY CASE authority
                    WHEN 'VERIFICATION_CONFIRMED' THEN 0
                    WHEN 'USER_STATED' THEN 1
                    WHEN 'TOOL_OBSERVED' THEN 2
                    WHEN 'REPOSITORY_OBSERVED' THEN 3
                    ELSE 4 END,
                    valid_from DESC, updated_at DESC LIMIT 1
                """,
                (
                    runtime.project_id,
                    namespace,
                    principal_id,
                    effective_session,
                    scope,
                    key,
                ),
            )
            row = await cursor.fetchone()
            return await self._row_to_hit(conn, row) if row is not None else None

    async def get_by_id(self, runtime: Any, memory_id: str) -> MemoryHit | None:
        """Read one canonical node for compatibility projections and UI."""

        clauses, params = _scope_predicate(runtime, include_historical=True)
        async with self._db.read_connection() as conn:
            cursor = await conn.execute(
                "SELECT n.* FROM memory_nodes n WHERE n.memory_id = ? AND "
                + " AND ".join(clauses),
                [memory_id, *params],
            )
            row = await cursor.fetchone()
            return await self._row_to_hit(conn, row) if row is not None else None

    async def get_source(self, runtime: Any, memory_id: str) -> dict[str, Any] | None:
        """Return the canonical node metadata for scoped provenance inspection."""

        clauses, params = _scope_predicate(runtime, include_historical=True)
        async with self._db.read_connection() as conn:
            row = await (
                await conn.execute(
                    "SELECT n.* FROM memory_nodes n WHERE n.memory_id = ? AND "
                    + " AND ".join(clauses),
                    [memory_id, *params],
                )
            ).fetchone()
            return dict(row) if row is not None else None

    async def get_evidence(self, runtime: Any, memory_id: str) -> list[dict[str, Any]]:
        """Return evidence rows only when their node is in the caller scope."""

        source = await self.get_source(runtime, memory_id)
        if source is None:
            return []
        async with self._db.read_connection() as conn:
            rows = await (
                await conn.execute(
                    "SELECT * FROM memory_evidence WHERE memory_id = ? "
                    "ORDER BY observed_at, evidence_id LIMIT 128",
                    (memory_id,),
                )
            ).fetchall()
            return [dict(row) for row in rows]

    async def record_observation(
        self,
        memory_id: str,
        runtime: Any,
        *,
        success: bool | None = None,
        contradiction: bool = False,
        user_confirmed: bool = False,
    ) -> bool:
        """Record outcome telemetry without making retrieval frequency trust."""

        clauses, params = _scope_predicate(runtime, include_historical=True)
        assignments: list[str] = []
        values: list[Any] = []
        if success is True:
            assignments.append("verified_success_count = verified_success_count + 1")
        elif success is False:
            assignments.append("verified_failure_count = verified_failure_count + 1")
        if contradiction:
            assignments.append("contradiction_count = contradiction_count + 1")
        if user_confirmed:
            assignments.append("user_confirm_count = user_confirm_count + 1")
        if not assignments:
            return False
        assignments.append("updated_at = ?")
        values.append(utc_now().astimezone(UTC).isoformat())
        async with self._db.transaction() as conn:
            cursor = await conn.execute(
                "UPDATE memory_nodes SET " + ", ".join(assignments) +
                " WHERE memory_id = ? AND " + " AND ".join(clauses),
                [*values, memory_id, *params],
            )
            return cursor.rowcount > 0

    async def promote(
        self,
        memory_id: str,
        runtime: Any,
        *,
        authority: str,
        status: MemoryStatus,
    ) -> bool:
        """Promote a scoped node after the Broker has validated the authority."""

        if status not in {MemoryStatus.ACTIVE, MemoryStatus.VERIFIED}:
            raise ValueError("promotion status must be ACTIVE or VERIFIED")
        clauses, params = _scope_predicate(runtime, include_historical=True)
        async with self._db.transaction() as conn:
            cursor = await conn.execute(
                "UPDATE memory_nodes SET status = ?, authority = ?, updated_at = ? "
                "WHERE memory_id = ? AND " + " AND ".join(clauses),
                (
                    status.value,
                    authority,
                    utc_now().astimezone(UTC).isoformat(),
                    memory_id,
                    *params,
                ),
            )
            return cursor.rowcount > 0

    async def compact(self, runtime: Any, *, limit: int = 256) -> int:
        """Remove only rejected derived rows; canonical events remain intact."""

        if limit <= 0 or limit > 10_000:
            raise ValueError("compact limit is outside the bounded range")
        clauses, params = _scope_predicate(runtime, include_historical=True)
        async with self._db.transaction() as conn:
            rows = await (
                await conn.execute(
                    "SELECT memory_id FROM memory_nodes WHERE status = 'REJECTED' AND "
                    + " AND ".join(clauses) + " LIMIT ?",
                    [*params, limit],
                )
            ).fetchall()
            for row in rows:
                memory_id = str(row["memory_id"])
                await conn.execute("DELETE FROM memory_evidence WHERE memory_id = ?", (memory_id,))
                await conn.execute("DELETE FROM memory_nodes WHERE memory_id = ?", (memory_id,))
            return len(rows)

    async def deduplicate_evidence(self, runtime: Any, *, limit: int = 1024) -> int:
        """Remove only duplicate derived evidence rows in the runtime scope."""

        if limit <= 0 or limit > 10_000:
            raise ValueError("evidence maintenance limit is outside the bounded range")
        clauses, params = _scope_predicate(runtime, include_historical=True, alias="n")
        async with self._db.transaction() as conn:
            duplicate_rows = await (
                await conn.execute(
                    "SELECT e.memory_id, e.evidence_type, e.source_ref, "
                    "COALESCE(e.event_id, '') AS event_key "
                    "FROM memory_evidence e JOIN memory_nodes n "
                    "ON n.memory_id = e.memory_id WHERE "
                    + " AND ".join(clauses)
                    + " GROUP BY e.memory_id, e.evidence_type, e.source_ref, event_key "
                    "HAVING COUNT(*) > 1 LIMIT ?",
                    [*params, limit],
                )
            ).fetchall()
            removed = 0
            for row in duplicate_rows:
                rows = await (
                    await conn.execute(
                        "SELECT evidence_id FROM memory_evidence WHERE memory_id = ? "
                        "AND evidence_type = ? AND source_ref = ? "
                        "AND COALESCE(event_id, '') = ? ORDER BY evidence_id",
                        (
                            row["memory_id"],
                            row["evidence_type"],
                            row["source_ref"],
                            row["event_key"],
                        ),
                    )
                ).fetchall()
                for duplicate in rows[1:]:
                    await conn.execute(
                        "DELETE FROM memory_evidence WHERE evidence_id = ?",
                        (duplicate["evidence_id"],),
                    )
                    removed += 1
                    if removed >= limit:
                        return removed
            return removed

    async def refresh_lifecycle(self, runtime: Any, *, limit: int = 10_000) -> dict[str, int]:
        """Record deterministic hot/warm/cold lifecycle tiers for maintenance."""

        if limit <= 0 or limit > 10_000:
            raise ValueError("lifecycle maintenance limit is outside the bounded range")
        clauses, params = _scope_predicate(runtime, include_historical=True, alias="n")
        async with self._db.transaction() as conn:
            rows = await (
                await conn.execute(
                    "SELECT n.status, n.retrieval_count, n.application_count "
                    "FROM memory_nodes n WHERE " + " AND ".join(clauses) + " LIMIT ?",
                    [*params, limit],
                )
            ).fetchall()
            tiers = {"hot": 0, "warm": 0, "cold": 0}
            for row in rows:
                status = str(row["status"])
                activity = int(row["retrieval_count"]) + int(row["application_count"])
                tier = "cold" if status in {"REVOKED", "SUPERSEDED"} else "hot" if activity >= 10 else "warm"
                tiers[tier] += 1
            now = utc_now().astimezone(UTC).isoformat()
            await conn.execute(
                "INSERT INTO memory_maintenance_state "
                "(principal_id, project_id, operation, cursor_json, status, updated_at, detail_json) "
                "VALUES (?, ?, 'lifecycle', '{}', 'COMPLETE', ?, ?) "
                "ON CONFLICT(principal_id, project_id, operation) DO UPDATE SET "
                "status=excluded.status, updated_at=excluded.updated_at, detail_json=excluded.detail_json",
                (
                    runtime.principal_id,
                    runtime.project_id,
                    now,
                    _json({"tiers": tiers, "rows": len(rows), "limit": limit}),
                ),
            )
            return tiers

    async def record_retrieval(
        self,
        memory_ids: list[str],
        runtime: Any,
    ) -> None:
        """Increment retrieval telemetry without changing trust/ranking."""

        if not memory_ids:
            return
        clauses, params = _scope_predicate(
            runtime,
            include_historical=True,
            alias="",
        )
        placeholders = ",".join("?" for _ in memory_ids)
        async with self._db.transaction() as conn:
            await conn.execute(
                "UPDATE memory_nodes SET retrieval_count = retrieval_count + 1 "
                "WHERE memory_id IN (" + placeholders + ") AND "
                + " AND ".join(clauses),
                [*memory_ids, *params],
            )

    async def record_application(
        self,
        memory_ids: list[str],
        runtime: Any,
    ) -> None:
        """Increment prompt-application telemetry without changing ranking."""

        if not memory_ids:
            return
        clauses, params = _scope_predicate(
            runtime,
            include_historical=True,
            alias="",
        )
        placeholders = ",".join("?" for _ in memory_ids)
        async with self._db.transaction() as conn:
            await conn.execute(
                "UPDATE memory_nodes SET application_count = application_count + 1 "
                "WHERE memory_id IN (" + placeholders + ") AND "
                + " AND ".join(clauses),
                [*memory_ids, *params],
            )

    async def forget(self, request: MemoryForgetRequest) -> ForgetResult:
        """Soft-revoke or hard-remove only rows in the caller's scope."""

        if len(request.memory_ids) > 100:
            raise ValueError("forget request is oversized")
        forgotten: list[str] = []
        clauses, params = _scope_predicate(request.runtime, include_historical=True)
        now = utc_now().astimezone(UTC).isoformat()
        async with self._db.transaction() as conn:
            for memory_id in request.memory_ids:
                cursor = await conn.execute(
                    "SELECT memory_id, namespace, scope, principal_id, session_id "
                    "FROM memory_nodes n WHERE memory_id = ? AND "
                    + " AND ".join(clauses),
                    [memory_id, *params],
                )
                row = await cursor.fetchone()
                if row is None:
                    continue
                if request.namespace is not None and str(row["namespace"]) != request.namespace:
                    continue
                if request.scope is not None and str(row["scope"]) != request.scope:
                    continue
                if request.mode == "soft":
                    await conn.execute(
                        "UPDATE memory_nodes SET status='REVOKED', valid_to=?, updated_at=? "
                        "WHERE memory_id = ?",
                        (now, now, memory_id),
                    )
                else:
                    # Hard and compliance forget must remove every derived
                    # object that can retain the node's content or identity.
                    # The append-only event ledger is intentionally not
                    # mutated; compliance callers get a content-free audit
                    # tombstone below and the Broker never exposes the raw
                    # event through memory retrieval.
                    evidence_rows = await (
                        await conn.execute(
                            "SELECT event_id FROM memory_evidence WHERE memory_id = ?",
                            (memory_id,),
                        )
                    ).fetchall()
                    await conn.execute(
                        "DELETE FROM memory_edges WHERE "
                        "(from_kind = 'memory' AND from_id = ?) OR "
                        "(to_kind = 'memory' AND to_id = ?)",
                        (memory_id, memory_id),
                    )
                    await conn.execute(
                        "DELETE FROM memory_evidence WHERE memory_id = ?", (memory_id,)
                    )
                    await conn.execute(
                        "DELETE FROM memory_nodes WHERE memory_id = ?", (memory_id,)
                    )
                    if request.mode == "compliance":
                        identity_principal = (
                            ""
                            if str(row["namespace"]) in {"project", "shared"}
                            else request.runtime.principal_id
                        )
                        identity_session = (
                            str(row["session_id"])
                            if str(row["namespace"]) == "session"
                            else ""
                        )
                        for evidence_row in evidence_rows:
                            event_id = str(evidence_row["event_id"] or "")
                            if event_id:
                                await conn.execute(
                                    "INSERT OR IGNORE INTO memory_privacy_tombstones ("
                                    "memory_id, provider_id, namespace, event_id, principal_id, "
                                    "project_id, session_id, created_at"
                                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                                    (
                                        memory_id,
                                        self.provider_id,
                                        str(row["namespace"]),
                                        event_id,
                                        identity_principal,
                                        request.runtime.project_id,
                                        identity_session,
                                        now,
                                    ),
                                )
                        await conn.execute(
                            "INSERT INTO memory_audit ("
                            "action, memory_id, provider_id, principal_id, "
                            "project_id, session_id, detail_json, created_at"
                            ") VALUES (?, '', ?, ?, ?, ?, ?, ?)",
                            (
                                "MEMORY_COMPLIANCE_TOMBSTONE",
                                self.provider_id,
                                request.runtime.principal_id,
                                request.runtime.project_id,
                                request.runtime.session_id or "",
                                _json({"forgotten": True}),
                                now,
                            ),
                        )
                forgotten.append(memory_id)
        return ForgetResult(tuple(forgotten), request.mode)

    async def record_audit(
        self,
        *,
        action: str,
        runtime: Any,
        memory_id: str = "",
        detail: Mapping[str, Any] | None = None,
    ) -> None:
        """Write a bounded decision audit record."""

        async with self._db.transaction() as conn:
            await conn.execute(
                """
                INSERT INTO memory_audit (
                    action, memory_id, provider_id, principal_id, project_id,
                    session_id, detail_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    action,
                    memory_id,
                    self.provider_id,
                    runtime.principal_id,
                    runtime.project_id,
                    runtime.session_id or "",
                    _json(detail or {}),
                    utc_now().astimezone(UTC).isoformat(),
                ),
            )

    async def rebuild_indexes(self) -> int:
        """Rebuild FTS from canonical ``memory_nodes`` rows."""

        async with self._write_transaction() as conn:
            return await self._rebuild_indexes_on_connection(conn)

    async def rebuild_from_events(
        self,
        events: list[Mapping[str, Any]],
    ) -> int:
        """Replay admitted candidate events into derived canonical tables.

        The event ledger is the durable recovery input.  This method does not
        re-run extraction or policy: each event already records the Broker's
        admitted status and authority, so replay only reconstructs provider
        state.  A malformed event is skipped and left available for the
        maintenance report rather than being interpreted permissively.
        """

        project_ids = {
            str(event.get("project_id", ""))
            for event in events
            if str(event.get("project_id", ""))
        }
        if not project_ids:
            return 0

        # The broker fences retrieval while this lock is held.  More
        # importantly, the provider keeps the clear/replay/index rebuild in
        # one SQLite transaction.  A malformed event or a database failure
        # therefore rolls the projection back to the last complete state.
        async with self._rebuild_lock, self._db.transaction() as conn:
            token = self._rebuild_connection.set(conn)
            try:
                reducer = MemoryProjectionReducer()
                reducer.replay(events)
                placeholders = ",".join("?" for _ in project_ids)
                await conn.execute(
                    "DELETE FROM memory_edges WHERE project_id IN (" + placeholders + ")",
                    tuple(project_ids),
                )
                await conn.execute(
                    "DELETE FROM memory_entities WHERE project_id IN (" + placeholders + ")",
                    tuple(project_ids),
                )
                await conn.execute(
                    "DELETE FROM memory_evidence WHERE project_id IN (" + placeholders + ")",
                    tuple(project_ids),
                )
                await conn.execute(
                    "DELETE FROM memory_nodes WHERE project_id IN (" + placeholders + ")",
                    tuple(project_ids),
                )

                replayed = 0
                candidate_events = [
                    event
                    for event in events
                    if str(event.get("event_type"))
                    == MemoryEventType.MEMORY_CANDIDATE_CREATED.value
                ]
                invalid_events: list[str] = []
                for event in candidate_events:
                    payload = _loads(str(event.get("payload_json", "{}")))
                    if event.get("payload_redacted") is True:
                        continue
                    request = _replay_request(event, payload, self.provider_id)
                    if request is None:
                        invalid_events.append(str(event.get("event_id") or ""))
                        continue
                    if request.status is MemoryStatus.REJECTED:
                        continue
                    await self.add(request)
                    replayed += 1
                if reducer.invalid_event_ids or invalid_events:
                    invalid = [
                        value
                        for value in (*reducer.invalid_event_ids, *invalid_events)
                        if value
                    ]
                    raise RuntimeError(
                        "memory projection replay contains invalid events: "
                        + ",".join(invalid[:16])
                    )
                for record in reducer.records:
                    await conn.execute(
                        "UPDATE memory_nodes SET status = ?, authority = ?, "
                        "valid_to = COALESCE(?, valid_to), "
                        "superseded_by = CASE WHEN ? <> '' THEN ? ELSE superseded_by END, "
                        "updated_at = COALESCE(?, updated_at) WHERE memory_id = ?",
                        (
                            record.status,
                            record.authority,
                            record.valid_to,
                            record.superseded_by,
                            record.superseded_by,
                            record.valid_to,
                            record.memory_id,
                        ),
                    )
                if reducer.deleted_ids:
                    deleted = tuple(reducer.deleted_ids)
                    delete_placeholders = ",".join("?" for _ in deleted)
                    await conn.execute(
                        "DELETE FROM memory_edges WHERE (from_kind = 'memory' AND from_id IN ("
                        + delete_placeholders
                        + ")) OR (to_kind = 'memory' AND to_id IN ("
                        + delete_placeholders
                        + "))",
                        (*deleted, *deleted),
                    )
                    await conn.execute(
                        "DELETE FROM memory_evidence WHERE memory_id IN ("
                        + delete_placeholders
                        + ")",
                        deleted,
                    )
                    await conn.execute(
                        "DELETE FROM memory_nodes WHERE memory_id IN ("
                        + delete_placeholders
                        + ")",
                        deleted,
                    )
                node_count = await self._rebuild_indexes_on_connection(conn)
                cursor_recorded_at, cursor_event_id = max(
                    (
                        (
                            str(event.get("recorded_at", "")),
                            str(event.get("event_id", "")),
                        )
                        for event in events
                    ),
                    default=("", ""),
                )
                await self._record_projection_generation(
                    conn,
                    project_ids=project_ids,
                    event_count=len(events),
                    node_count=node_count,
                    cursor_recorded_at=cursor_recorded_at,
                    cursor_event_id=cursor_event_id,
                )
            finally:
                self._rebuild_connection.reset(token)
        return replayed

    async def _replay_revocation(
        self,
        conn: Any,
        memory_id: str,
        mode: str,
        occurred_at: str,
    ) -> None:
        """Replay a forget event after candidate materialization."""

        if not memory_id:
            return
        if mode == "soft":
            await conn.execute(
                "UPDATE memory_nodes SET status='REVOKED', valid_to=?, updated_at=? "
                "WHERE memory_id = ?",
                (occurred_at, occurred_at, memory_id),
            )
            return
        await conn.execute(
            "DELETE FROM memory_edges WHERE "
            "(from_kind = 'memory' AND from_id = ?) OR "
            "(to_kind = 'memory' AND to_id = ?)",
            (memory_id, memory_id),
        )
        await conn.execute(
            "DELETE FROM memory_evidence WHERE memory_id = ?", (memory_id,)
        )
        await conn.execute("DELETE FROM memory_nodes WHERE memory_id = ?", (memory_id,))

    async def _replay_supersession(
        self,
        conn: Any,
        memory_id: str,
        related_ids: tuple[str, ...],
        occurred_at: str,
    ) -> None:
        """Replay an explicit supersession marker for older versions."""

        if not memory_id or not related_ids:
            return
        for related_id in related_ids:
            await conn.execute(
                "UPDATE memory_nodes SET status='SUPERSEDED', valid_to=?, "
                "superseded_at=?, superseded_by=?, updated_at=? WHERE memory_id = ?",
                (occurred_at, occurred_at, memory_id, occurred_at, related_id),
            )

    @asynccontextmanager
    async def _write_transaction(self) -> AsyncIterator[Any]:
        """Serialize provider writes and reuse the rebuild transaction."""

        connection = self._rebuild_connection.get()
        if connection is not None:
            yield connection
            return
        async with self._rebuild_lock, self._db.transaction() as connection:
            yield connection

    async def _rebuild_indexes_on_connection(self, conn: Any) -> int:
        """Rebuild FTS using an already-open atomic write connection."""

        await conn.execute("DELETE FROM memory_nodes_fts_search")
        await conn.execute("DELETE FROM memory_nodes_fts")
        cursor = await conn.execute(
            "SELECT memory_id, key, content, memory_type, applicability_json FROM memory_nodes"
        )
        rows = await cursor.fetchall()
        for row in rows:
            await conn.execute(
                "INSERT INTO memory_nodes_fts "
                "(memory_id, key, content, memory_type, applicability) VALUES (?, ?, ?, ?, ?)",
                (
                    row["memory_id"],
                    row["key"],
                    row["content"],
                    row["memory_type"],
                    row["applicability_json"],
                ),
            )
            await conn.execute(
                "INSERT INTO memory_nodes_fts_search "
                "(rowid, memory_id, key, content, memory_type, applicability) "
                "SELECT rowid, memory_id, key, content, memory_type, applicability "
                "FROM memory_nodes_fts WHERE memory_id = ?",
                (row["memory_id"],),
            )
        return len(rows)

    async def _record_projection_generation(
        self,
        conn: Any,
        *,
        project_ids: set[str],
        event_count: int,
        node_count: int,
        cursor_recorded_at: str,
        cursor_event_id: str,
    ) -> None:
        """Commit a complete projection generation with its cursor metadata."""

        now = utc_now().astimezone(UTC).isoformat()
        row = await (
            await conn.execute(
                "SELECT COALESCE(MAX(generation), 0) AS generation "
                "FROM memory_projection_generations WHERE provider_id = ?",
                (self.provider_id,),
            )
        ).fetchone()
        generation = int(row["generation"] if row is not None else 0) + 1
        for project_id in project_ids:
            await conn.execute(
                "INSERT INTO memory_projection_generations "
                "(provider_id, generation, project_id, principal_id, status, event_count, "
                "node_count, started_at, finished_at) VALUES (?, ?, ?, ?, 'COMPLETE', ?, ?, ?, ?)",
                (
                    self.provider_id,
                    generation,
                    project_id,
                    "*",
                    event_count,
                    node_count,
                    now,
                    now,
                ),
            )
            await conn.execute(
                "INSERT INTO memory_projection_state "
                "(provider_id, active_generation, lifecycle_state, cursor_recorded_at, "
                "cursor_event_id, updated_at) VALUES (?, ?, 'ACTIVE', ?, ?, ?) "
                "ON CONFLICT(provider_id) DO UPDATE SET active_generation=excluded.active_generation, "
                "lifecycle_state=excluded.lifecycle_state, cursor_recorded_at=excluded.cursor_recorded_at, "
                "cursor_event_id=excluded.cursor_event_id, updated_at=excluded.updated_at",
                (self.provider_id, generation, cursor_recorded_at, cursor_event_id, now),
            )

    async def verify_indexes(self) -> dict[str, int | bool]:
        """Return bounded consistency counts for maintenance health checks."""

        async with self._db.read_connection() as conn:
            counts: dict[str, int] = {}
            for name, table in (
                ("memory_nodes", "memory_nodes"),
                ("memory_nodes_fts", "memory_nodes_fts"),
                ("memory_nodes_fts_search", "memory_nodes_fts_search"),
            ):
                cursor = await conn.execute(f"SELECT COUNT(*) AS count FROM {table}")
                row = await cursor.fetchone()
                counts[name] = int(row["count"] if row is not None else 0)
        counts["consistent"] = (
            counts["memory_nodes"]
            == counts["memory_nodes_fts"]
            == counts["memory_nodes_fts_search"]
        )
        return counts

    async def _insert_evidence(
        self,
        conn: Any,
        request: MemoryWriteRequest,
        memory_id: str,
        now: datetime,
    ) -> int:
        refs = list(request.candidate.evidence_refs)
        refs.extend(
            EvidenceRef(SourceType.SYSTEM, event_id, event_id=event_id)
            for event_id in request.candidate.source_event_ids
            if not any(ref.event_id == event_id for ref in refs)
        )
        if request.candidate_event_id and not any(
            ref.event_id == request.candidate_event_id for ref in refs
        ):
            refs.append(
                EvidenceRef(
                    SourceType.SYSTEM,
                    request.candidate_event_id,
                    event_id=request.candidate_event_id,
                )
            )
        if not refs:
            refs.append(EvidenceRef(SourceType.SYSTEM, f"candidate:{memory_id}"))
        inserted = 0
        for ref in refs:
            source_ref = ref.source_ref[:1024]
            metadata = {
                "candidate_event": bool(
                    request.candidate_event_id
                    and ref.event_id == request.candidate_event_id
                )
            }
            cursor = await conn.execute(
                """
                INSERT OR IGNORE INTO memory_evidence (
                    evidence_id, memory_id, evidence_type, source_ref, event_id,
                    task_id, turn_id, tool_call_id, workspace_id, commit_sha,
                    verification_run_id, observed_at, valid_from, valid_to,
                    principal_id, project_id, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    uuid.uuid4().hex,
                    memory_id,
                    enum_value(ref.source_type),
                    source_ref,
                    ref.event_id,
                    None,
                    None,
                    None,
                    None,
                    ref.commit_sha,
                    ref.verification_run_id,
                    now.astimezone(UTC).isoformat(),
                    None,
                    None,
                    request.runtime.principal_id,
                    request.runtime.project_id,
                    _json(metadata),
                ),
            )
            inserted += max(0, int(cursor.rowcount))
        return inserted

    async def _insert_entities_and_edges(
        self,
        conn: Any,
        request: MemoryWriteRequest,
        memory_id: str,
        now: datetime,
    ) -> None:
        for entity in request.candidate.entities:
            entity_id = entity.entity_id or _entity_id(
                request.runtime.project_id,
                entity.entity_type,
                entity.canonical_name,
            )
            await conn.execute(
                """
                INSERT INTO memory_entities (
                    entity_id, entity_type, canonical_name, principal_id,
                    project_id, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(project_id, entity_type, canonical_name) DO UPDATE SET
                    updated_at = excluded.updated_at
                """,
                (
                    entity_id,
                    entity.entity_type,
                    entity.canonical_name,
                    request.runtime.principal_id,
                    request.runtime.project_id,
                    now.astimezone(UTC).isoformat(),
                    now.astimezone(UTC).isoformat(),
                ),
            )
        for relation in request.candidate.relations:
            await conn.execute(
                """
                INSERT OR IGNORE INTO memory_edges (
                    edge_id, from_kind, from_id, relation, to_kind, to_id,
                    principal_id, project_id, authority, confidence, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    uuid.uuid4().hex,
                    "memory",
                    memory_id,
                    relation.relation,
                    relation.target_kind,
                    relation.target_id,
                    request.runtime.principal_id,
                    request.runtime.project_id,
                    enum_value(request.authority),
                    float(relation.confidence),
                    now.astimezone(UTC).isoformat(),
                ),
            )

    async def _row_to_hit(self, conn: Any, row: Any) -> MemoryHit:
        evidence_cursor = await conn.execute(
            "SELECT event_id, evidence_type, source_ref, metadata_json FROM memory_evidence "
            "WHERE memory_id = ? ORDER BY observed_at LIMIT 32",
            (row["memory_id"],),
        )
        evidence_rows = await evidence_cursor.fetchall()
        event_ids = tuple(
            str(item["event_id"])
            for item in evidence_rows
            if item["event_id"] and not _is_private_candidate_evidence(item)
        )
        source_ref = str(evidence_rows[0]["source_ref"]) if evidence_rows else None
        source_type = _source_for_authority(str(row["authority"]))
        row_keys = set(row.keys()) if hasattr(row, "keys") else set()
        raw_score = (
            float(row["retrieval_score"])
            if "retrieval_score" in row_keys and row["retrieval_score"] is not None
            else None
        )
        return MemoryHit(
            provider_id=self.provider_id,
            external_id=str(row["memory_id"]),
            memory_id=str(row["memory_id"]),
            content=str(row["content"]),
            raw_score=raw_score,
            source_type=source_type,
            source_ref=source_ref,
            provider_metadata={
                "canonical_record": True,
                "broker_authority": str(row["authority"]),
                "superseded_by": str(row["superseded_by"] or ""),
                "superseded_at": str(row["superseded_at"] or ""),
                "retrieval_count": int(row["retrieval_count"]),
                "application_count": int(row["application_count"]),
                "verified_success_count": int(row["verified_success_count"]),
                "verified_failure_count": int(row["verified_failure_count"]),
                "contradiction_count": int(row["contradiction_count"]),
                "user_confirm_count": int(row["user_confirm_count"]),
            },
            authority_hint=str(row["authority"]),
            confidence_hint=float(row["confidence"]),
            memory_type=str(row["memory_type"]),
            status=str(row["status"]),
            principal_id=str(row["principal_id"]),
            project_id=str(row["project_id"]),
            namespace=str(row["namespace"]),
            scope=str(row["scope"]),
            session_id=str(row["session_id"]) or None,
            key=str(row["key"]) or None,
            sensitivity=str(row["sensitivity"]),
            usage_policy=str(row["usage_policy"]),
            valid_from=_parse_datetime(row["valid_from"]),
            valid_to=_parse_datetime(row["valid_to"]),
            applicability=_loads(row["applicability_json"]),
            environment=_loads(row["environment_json"]),
            event_ids=event_ids,
            evidence_refs=tuple(
                EvidenceRef(
                    source_type=str(item["evidence_type"]),
                    source_ref=str(item["source_ref"]),
                    event_id=str(item["event_id"]) if item["event_id"] else None,
                )
                for item in evidence_rows
            ),
            source_rank=0,
            source_kind="memory",
            retrieval_features={"bm25": raw_score} if raw_score is not None else {},
        )


def _scope_predicate(
    runtime: Any,
    *,
    include_historical: bool,
    alias: str = "n",
) -> tuple[list[str], list[Any]]:
    prefix = f"{alias}." if alias else ""
    clauses = [f"{prefix}project_id = ?"]
    params: list[Any] = [runtime.project_id]
    if runtime.session_id is not None:
        clauses.append(f"({prefix}session_id = ? OR {prefix}session_id = '')")
        params.append(runtime.session_id)
    clauses.append(
        f"({prefix}namespace IN ('shared', 'project') AND {prefix}principal_id = '' "
        f"OR {prefix}namespace IN ('private', 'session') AND {prefix}principal_id = ?)"
    )
    params.append(runtime.principal_id)
    if runtime.session_id is None:
        clauses.append(f"{prefix}namespace <> 'session'")
    if include_historical:
        clauses.append(f"{prefix}status NOT IN ('REVOKED', 'REJECTED')")
    else:
        clauses.append(f"{prefix}status IN ('ACTIVE', 'VERIFIED')")
    return clauses, params


def _fts_query(query: str) -> str:
    terms = [term.replace('"', "") for term in query.split() if term]
    if not terms:
        return '""'
    return " OR ".join(f'"{term[:128]}"' for term in terms[:32])


def _derived_key(claim: str) -> str:
    return f"claim:{hashlib.sha256(claim.encode('utf-8')).hexdigest()[:24]}"


def _entity_id(project_id: str, entity_type: str, name: str) -> str:
    return hashlib.sha256(
        f"{project_id}:{entity_type}:{name.casefold()}".encode()
    ).hexdigest()[:32]


def _source_for_authority(authority: str) -> SourceType:
    if authority == MemoryAuthority.USER_STATED.value:
        return SourceType.USER
    if authority == MemoryAuthority.TOOL_OBSERVED.value:
        return SourceType.TOOL
    if authority == MemoryAuthority.VERIFICATION_CONFIRMED.value:
        return SourceType.VERIFICATION
    if authority == MemoryAuthority.REPOSITORY_OBSERVED.value:
        return SourceType.REPOSITORY
    if authority == MemoryAuthority.EXTERNAL_UNTRUSTED.value:
        return SourceType.EXTERNAL
    if authority == MemoryAuthority.SYSTEM_POLICY.value:
        return SourceType.SYSTEM
    return SourceType.PROVIDER


def _parse_datetime(value: Any) -> datetime | None:
    if not value:
        return None
    parsed = datetime.fromisoformat(str(value))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _loads(value: Any) -> dict[str, Any]:
    try:
        parsed = json.loads(str(value))
    except (TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _is_private_candidate_evidence(row: Any) -> bool:
    """Hide the Broker's internal candidate event from public event_ids."""

    metadata = _loads(row["metadata_json"] if row["metadata_json"] is not None else "{}")
    return metadata.get("candidate_event") is True


def _replay_request(
    event: Mapping[str, Any],
    payload: Mapping[str, Any],
    provider_id: str,
) -> MemoryWriteRequest | None:
    """Decode one Broker candidate event without trusting missing fields."""

    try:
        status = MemoryStatus(str(payload["status"]))
        authority = MemoryAuthority(str(payload["admitted_authority"]))
        runtime = RuntimeMemoryContext(
            principal_id=str(event["principal_id"]),
            project_id=str(event["project_id"]),
            session_id=_optional_text(event.get("session_id")),
            task_id=_optional_text(event.get("task_id")),
            workspace_id=_optional_text(event.get("workspace_id")),
            mode=str(payload.get("mode") or payload.get("scope") or "global"),
            environment_fingerprint=str(payload.get("environment_fingerprint", "")),
            repo_id=_optional_text(event.get("repo_id")),
            commit_sha=_optional_text(event.get("commit_sha")),
            branch=_optional_text(event.get("branch")),
            environment=(
                dict(payload["runtime_environment"])
                if isinstance(payload.get("runtime_environment"), Mapping)
                else {}
            ),
        )
        candidate = MemoryCandidate(
            memory_type=str(payload["memory_type"]),
            claim=str(payload["claim"]),
            authority=authority,
            confidence=float(payload["confidence"]),
            source_event_ids=tuple(str(item) for item in payload.get("source_event_ids", ())),
            evidence_refs=tuple(
                _evidence_from_payload(item)
                for item in payload.get("evidence_refs", ())
                if isinstance(item, Mapping)
            ),
            entities=tuple(
                _entity_from_payload(item)
                for item in payload.get("entities", ())
                if isinstance(item, Mapping)
            ),
            relations=tuple(
                RelationCandidate(
                    relation=str(item["relation"]),
                    target_kind=str(item["target_kind"]),
                    target_id=str(item["target_id"]),
                    confidence=float(item.get("confidence", 0.5)),
                )
                for item in payload.get("relations", ())
                if isinstance(item, Mapping)
            ),
            key=str(payload.get("key") or "") or None,
            scope=str(payload.get("scope") or "global"),
            namespace=str(payload.get("namespace") or "private"),
            session_id=_optional_text(payload.get("session_id")),
            valid_from=_parse_datetime(payload.get("valid_from")),
            valid_to=_parse_datetime(payload.get("valid_to")),
            preconditions=(
                dict(payload["preconditions"])
                if isinstance(payload.get("preconditions"), Mapping)
                else {}
            ),
            environment=(
                dict(payload["environment"])
                if isinstance(payload.get("environment"), Mapping)
                else {}
            ),
            sensitivity=str(payload.get("sensitivity") or "INTERNAL"),
            usage_policy=str(payload.get("usage_policy") or "PROJECT_ONLY"),
            verification_run_id=_optional_text(payload.get("verification_run_id")),
            verification_result_digest=_optional_text(
                payload.get("verification_result_digest")
            ),
        )
    except (KeyError, TypeError, ValueError):
        return None
    return MemoryWriteRequest(
        candidate=candidate,
        runtime=runtime,
        status=status,
        authority=authority,
        provider_id=provider_id,
        candidate_event_id=str(event.get("event_id") or "") or None,
    )


def _optional_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text or None


def _stable_memory_id(candidate_event_id: str | None) -> str:
    """Use a replay-stable id for Broker-admitted candidates."""

    if candidate_event_id:
        return hashlib.sha256(f"khaos-memory:{candidate_event_id}".encode()).hexdigest()[:32]
    return uuid.uuid4().hex


def _evidence_from_payload(value: Mapping[str, Any]) -> EvidenceRef:
    return EvidenceRef(
        source_type=str(value["source_type"]),
        source_ref=str(value["source_ref"]),
        event_id=_optional_text(value.get("event_id")),
        verification_run_id=_optional_text(value.get("verification_run_id")),
        commit_sha=_optional_text(value.get("commit_sha")),
    )


def _entity_from_payload(value: Mapping[str, Any]) -> Any:
    from khaos.memory.core.contracts import EntityRef

    return EntityRef(
        entity_type=str(value["entity_type"]),
        canonical_name=str(value["canonical_name"]),
        entity_id=_optional_text(value.get("entity_id")),
    )


__all__ = ["NativeMemoryProvider"]
