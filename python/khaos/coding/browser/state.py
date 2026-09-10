"""Durable, metadata-only browser/app lifecycle journal.

The journal is a recovery projection.  It deliberately stores typed payloads
and digests, never live browser objects, page text, credentials, argv values,
or downloaded bytes.  Existing task/workspace/approval/verification owners
remain authoritative for their respective decisions.
"""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import Mapping
from typing import Any

from khaos.security.protocol_boundary import canonical_digest, canonical_json_bytes

_FORBIDDEN_METADATA_KEYS = frozenset(
    {
        "content",
        "text",
        "html",
        "body",
        "page_text",
        "dom",
        "aria",
        "semantic_text",
        "accessibility",
        "console",
        "network",
        "output",
        "stdout",
        "stderr",
        "argv",
        "environment",
        "value",
    }
)
_SECRET_KEY_PARTS = frozenset(
    {"authorization", "api_key", "apikey", "cookie", "credential", "password", "secret", "token"}
)


class BrowserStateJournalError(RuntimeError):
    """The durable browser recovery projection cannot be updated safely."""


class BrowserStateRepository:
    """Persist bounded browser/app identity and append-only lifecycle facts."""

    MAX_PAYLOAD_BYTES = 64 * 1024
    MAX_TEXT_BYTES = 2048

    def __init__(self, database: Any) -> None:
        if database is None:
            raise ValueError("BrowserStateRepository requires a database")
        self.database = database

    async def record(
        self,
        *,
        resource_id: str,
        resource_kind: str,
        task_id: str,
        workspace_id: str,
        workspace_generation: int,
        principal_id: str,
        project_id: str,
        event_type: str,
        lifecycle_state: str,
        payload: Mapping[str, object],
        quarantine_reason: str = "",
    ) -> str:
        values = {
            "resource_id": resource_id,
            "resource_kind": resource_kind,
            "task_id": task_id,
            "workspace_id": workspace_id,
            "principal_id": principal_id,
            "project_id": project_id,
            "event_type": event_type,
            "lifecycle_state": lifecycle_state,
            "quarantine_reason": quarantine_reason,
        }
        for label, value in values.items():
            if (
                type(value) is not str
                or (label != "quarantine_reason" and not value)
                or len(value.encode("utf-8")) > self.MAX_TEXT_BYTES
                or "\x00" in value
            ):
                raise BrowserStateJournalError(f"{label} is malformed")
        if type(workspace_generation) is not int or workspace_generation < 0:
            raise BrowserStateJournalError("workspace generation is invalid")
        _validate_metadata_payload(payload)
        try:
            payload_json = canonical_json_bytes(dict(payload)).decode("utf-8")
        except Exception as exc:
            raise BrowserStateJournalError("browser journal payload is not JSON-safe") from exc
        if len(payload_json.encode("utf-8")) > self.MAX_PAYLOAD_BYTES:
            raise BrowserStateJournalError("browser journal payload exceeds its bound")
        payload_digest = canonical_digest(dict(payload))
        event_digest = canonical_digest(
            {
                "event_id": uuid.uuid4().hex,
                "resource_id": resource_id,
                "resource_kind": resource_kind,
                "task_id": task_id,
                "workspace_id": workspace_id,
                "workspace_generation": workspace_generation,
                "principal_id": principal_id,
                "project_id": project_id,
                "event_type": event_type,
                "lifecycle_state": lifecycle_state,
                "payload_digest": payload_digest,
            }
        )
        now = str(time.time())
        try:
            async with self.database.transaction() as conn:
                await conn.execute(
                    """
                    INSERT INTO browser_resource_state (
                        resource_id, resource_kind, task_id, workspace_id,
                        workspace_generation, principal_id, project_id,
                        lifecycle_state, payload_json, payload_digest,
                        quarantine_reason, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(resource_id) DO UPDATE SET
                        resource_kind = excluded.resource_kind,
                        task_id = excluded.task_id,
                        workspace_id = excluded.workspace_id,
                        workspace_generation = excluded.workspace_generation,
                        principal_id = excluded.principal_id,
                        project_id = excluded.project_id,
                        lifecycle_state = excluded.lifecycle_state,
                        payload_json = excluded.payload_json,
                        payload_digest = excluded.payload_digest,
                        quarantine_reason = excluded.quarantine_reason,
                        updated_at = excluded.updated_at
                    """,
                    (
                        resource_id,
                        resource_kind,
                        task_id,
                        workspace_id,
                        workspace_generation,
                        principal_id,
                        project_id,
                        lifecycle_state,
                        payload_json,
                        payload_digest,
                        quarantine_reason,
                        now,
                        now,
                    ),
                )
                await conn.execute(
                    """
                    INSERT INTO browser_resource_events (
                        resource_id, resource_kind, task_id, workspace_id,
                        workspace_generation, principal_id, project_id,
                        event_type, lifecycle_state, payload_json,
                        payload_digest, event_digest, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        resource_id,
                        resource_kind,
                        task_id,
                        workspace_id,
                        workspace_generation,
                        principal_id,
                        project_id,
                        event_type,
                        lifecycle_state,
                        payload_json,
                        payload_digest,
                        event_digest,
                        now,
                    ),
                )
        except Exception as exc:
            raise BrowserStateJournalError("browser journal write failed") from exc
        return event_digest

    async def list_live_resources(
        self, *, principal_id: str, project_id: str
    ) -> tuple[dict[str, object], ...]:
        """Return non-terminal rows for explicit restart reconciliation."""
        try:
            async with self.database.read_connection() as conn:
                cursor = await conn.execute(
                    """
                    SELECT resource_id, resource_kind, task_id, workspace_id,
                           workspace_generation, principal_id, project_id,
                           lifecycle_state, payload_json, payload_digest,
                           quarantine_reason, created_at, updated_at
                    FROM browser_resource_state
                    WHERE principal_id = ? AND project_id = ?
                      AND resource_kind IN ('app', 'session')
                      AND lifecycle_state NOT IN ('stopped', 'stale')
                    ORDER BY updated_at, resource_id
                    """,
                    (principal_id, project_id),
                )
                rows = await cursor.fetchall()
        except Exception as exc:
            raise BrowserStateJournalError("browser journal read failed") from exc
        values: list[dict[str, object]] = []
        for row in rows:
            try:
                payload = json.loads(str(row["payload_json"]))
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                raise BrowserStateJournalError("browser journal row is malformed") from exc
            if not isinstance(payload, dict):
                raise BrowserStateJournalError("browser journal payload is not an object")
            _validate_metadata_payload(payload)
            payload_digest = str(row["payload_digest"])
            if canonical_digest(payload) != payload_digest:
                raise BrowserStateJournalError("browser journal payload digest is invalid")
            values.append(
                {
                    "resource_id": str(row["resource_id"]),
                    "resource_kind": str(row["resource_kind"]),
                    "task_id": str(row["task_id"]),
                    "workspace_id": str(row["workspace_id"]),
                    "workspace_generation": int(row["workspace_generation"]),
                    "principal_id": str(row["principal_id"]),
                    "project_id": str(row["project_id"]),
                    "lifecycle_state": str(row["lifecycle_state"]),
                    "payload": payload,
                    "payload_digest": payload_digest,
                    "quarantine_reason": str(row["quarantine_reason"]),
                }
            )
        return tuple(values)


def _validate_metadata_payload(value: object, *, path: str = "payload") -> None:
    """Reject source-shaped or credential-shaped values at the durable boundary."""
    if isinstance(value, Mapping):
        for key, child in value.items():
            if type(key) is not str:
                raise BrowserStateJournalError(f"{path} contains a non-text key")
            folded = key.casefold().replace("-", "_")
            if folded in _FORBIDDEN_METADATA_KEYS or any(
                part in folded for part in _SECRET_KEY_PARTS
            ):
                raise BrowserStateJournalError(
                    f"{path} contains non-metadata field {key!r}"
                )
            _validate_metadata_payload(child, path=f"{path}.{key}")
        return
    if isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            _validate_metadata_payload(child, path=f"{path}[{index}]")
        return
    if isinstance(value, (str, int, float, bool)) or value is None:
        return
    raise BrowserStateJournalError(f"{path} is not JSON-compatible")


__all__ = ["BrowserStateJournalError", "BrowserStateRepository"]
