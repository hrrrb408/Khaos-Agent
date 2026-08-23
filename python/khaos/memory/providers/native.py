"""Khaos Native Memory V2 provider.

The native provider is intentionally boring: SQLite is the canonical local
store, FTS5 is a rebuildable index, and all authority/scope decisions are
made by :class:`MemoryBroker` before this module is called.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from collections.abc import Mapping
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


class NativeMemoryProvider:
    """SQLite/FTS5 implementation of the MemoryProvider SPI."""

    provider_id = "khaos-native"
    trusted_canonical = True

    def __init__(self, db: Any) -> None:
        self._db = db

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
            bulk_import=False,
            forget=True,
        )

    async def health(self) -> ProviderHealth:
        """Check that the canonical tables are available."""

        try:
            async with self._db.read_connection() as conn:
                await (await conn.execute("SELECT 1 FROM memory_events LIMIT 1")).fetchone()
            return ProviderHealth(self.provider_id, True)
        except Exception as exc:  # noqa: BLE001 - health must not escape
            return ProviderHealth(self.provider_id, False, type(exc).__name__)

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

        async with self._db.transaction() as conn:
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
                return MemoryWriteResult(
                    memory_id=str(existing["memory_id"]),
                    status=MemoryStatus(str(existing["status"])),
                    created=False,
                )

            if existing is not None:
                await conn.execute(
                    """
                    UPDATE memory_nodes
                    SET status = 'SUPERSEDED', valid_to = ?, superseded_by = ?,
                        updated_at = ?
                    WHERE memory_id = ?
                    """,
                    (
                        valid_from.astimezone(UTC).isoformat(),
                        memory_id,
                        now.astimezone(UTC).isoformat(),
                        str(existing["memory_id"]),
                    ),
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
            await self._insert_evidence(conn, request, memory_id, now)
            await self._insert_entities_and_edges(conn, request, memory_id, now)

        return MemoryWriteResult(
            memory_id=memory_id,
            status=request.status,
            superseded_memory_ids=(str(existing["memory_id"]),) if existing is not None else (),
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
                        SELECT n.* FROM memory_nodes_fts_search f
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
                    # safe, slower fallback for the same scope.
                    like = f"%{query[:256]}%"
                    cursor = await conn.execute(
                        "SELECT n.* FROM memory_nodes n WHERE (n.key LIKE ? OR n.content LIKE ?) AND "
                        + " AND ".join(clauses)
                        + " ORDER BY n.updated_at DESC LIMIT ?",
                        [like, like, *params, request.limit],
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
                ORDER BY valid_from DESC, updated_at DESC LIMIT 1
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
                    "SELECT memory_id FROM memory_nodes n WHERE memory_id = ? AND "
                    + " AND ".join(clauses),
                    [memory_id, *params],
                )
                row = await cursor.fetchone()
                if row is None:
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

        async with self._db.transaction() as conn:
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

        async with self._db.transaction() as conn:
            await conn.execute("DELETE FROM memory_edges")
            await conn.execute("DELETE FROM memory_entities")
            await conn.execute("DELETE FROM memory_evidence")
            await conn.execute("DELETE FROM memory_nodes")

        replayed = 0
        candidate_events = [
            event
            for event in events
            if str(event.get("event_type")) == MemoryEventType.MEMORY_CANDIDATE_CREATED.value
        ]
        for event in candidate_events:
            payload = _loads(str(event.get("payload_json", "{}")))
            request = _replay_request(event, payload, self.provider_id)
            if request is None or request.status is MemoryStatus.REJECTED:
                continue
            await self.add(request)
            replayed += 1
        for event in events:
            event_type = str(event.get("event_type"))
            if event_type == MemoryEventType.MEMORY_REVOKED.value:
                payload = _loads(str(event.get("payload_json", "{}")))
                await self._replay_revocation(
                    str(payload.get("memory_id", "")),
                    str(payload.get("forget_mode", "soft")),
                    str(event.get("occurred_at", "")),
                )
            elif event_type == MemoryEventType.MEMORY_SUPERSEDED.value:
                payload = _loads(str(event.get("payload_json", "{}")))
                await self._replay_supersession(
                    str(payload.get("memory_id", "")),
                    tuple(str(item) for item in payload.get("related_ids", ())),
                    str(event.get("occurred_at", "")),
                )
        await self.rebuild_indexes()
        return replayed

    async def _replay_revocation(
        self,
        memory_id: str,
        mode: str,
        occurred_at: str,
    ) -> None:
        """Replay a forget event after candidate materialization."""

        if not memory_id:
            return
        async with self._db.transaction() as conn:
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
        memory_id: str,
        related_ids: tuple[str, ...],
        occurred_at: str,
    ) -> None:
        """Replay an explicit supersession marker for older versions."""

        if not memory_id or not related_ids:
            return
        async with self._db.transaction() as conn:
            for related_id in related_ids:
                await conn.execute(
                    "UPDATE memory_nodes SET status='SUPERSEDED', valid_to=?, "
                    "superseded_by=?, updated_at=? WHERE memory_id = ?",
                    (occurred_at, memory_id, occurred_at, related_id),
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
    ) -> None:
        refs = list(request.candidate.evidence_refs)
        refs.extend(
            EvidenceRef(SourceType.SYSTEM, event_id, event_id=event_id)
            for event_id in request.candidate.source_event_ids
            if not any(ref.event_id == event_id for ref in refs)
        )
        if not refs:
            refs.append(EvidenceRef(SourceType.SYSTEM, f"candidate:{memory_id}"))
        for ref in refs:
            source_ref = ref.source_ref[:1024]
            await conn.execute(
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
                    "{}",
                ),
            )

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
            "SELECT event_id, evidence_type, source_ref FROM memory_evidence "
            "WHERE memory_id = ? ORDER BY observed_at LIMIT 32",
            (row["memory_id"],),
        )
        evidence_rows = await evidence_cursor.fetchall()
        event_ids = tuple(
            str(item["event_id"]) for item in evidence_rows if item["event_id"]
        )
        source_ref = str(evidence_rows[0]["source_ref"]) if evidence_rows else None
        source_type = _source_for_authority(str(row["authority"]))
        return MemoryHit(
            provider_id=self.provider_id,
            external_id=str(row["memory_id"]),
            memory_id=str(row["memory_id"]),
            content=str(row["content"]),
            raw_score=None,
            source_type=source_type,
            source_ref=source_ref,
            provider_metadata={
                "canonical_record": True,
                "broker_authority": str(row["authority"]),
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
    return SourceType.SYSTEM


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
