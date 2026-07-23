"""Export audit logs to JSON/CSV for external analysis.

Three export shapes are supported:

* ``export_audit_json``  — JSON Lines (one record per line), good for piping
  into log shippers or jq.
* ``export_audit_csv``   — flat CSV for spreadsheets / quick review.
* ``export_security_events`` — the subset of records whose ``action`` starts
  with ``security:`` (command_blocked, path_denied, network_blocked,
  sandbox_violation, …), for incident review.

All exports accept a ``since`` ISO-timestamp filter and return the number of
records written.
"""

from __future__ import annotations

import asyncio
import csv
import json
import logging
from pathlib import Path
from typing import Any

from khaos.audit.logger import AuditEntry

logger = logging.getLogger(__name__)

# A high cap so exports are not silently truncated by the default query limit.
EXPORT_LIMIT = 100_000


async def _fetch_rows(
    db, since: str | None, *, result: str | None = None, project_id: str | None = None,
) -> list[dict[str, Any]]:
    """Fetch raw audit rows, optionally filtered by since/result/project."""
    kwargs: dict[str, Any] = {"limit": EXPORT_LIMIT}
    if since is not None:
        kwargs["since"] = since
    if result is not None:
        kwargs["result"] = result
    if project_id is not None:
        kwargs["project_id"] = project_id
    return await db.query_audit_logs(**kwargs)


def _row_to_exportable(row: dict[str, Any]) -> dict[str, Any]:
    """Normalize one raw DB row into an exportable dict (parses detail JSON)."""
    entry = AuditEntry.from_row(row)
    data = entry.to_dict()
    # created_at may be None for very recent inserts; normalise to "".
    data["created_at"] = data.get("created_at") or ""
    return data


async def export_audit_json(
    db, output_path: str, since: str | None = None, *, project_id: str | None = None,
) -> int:
    """导出审计日志为 JSON Lines 文件。

    每行一个 JSON 对象。返回导出的记录数。

    H-03 (round-4 review): ``project_id`` scopes the export to one
    project's audit trail on shared DBs.  ``None`` (default) is the
    admin opt-in that exports every project.
    """
    rows = await _fetch_rows(db, since, project_id=project_id)
    records = [_row_to_exportable(row) for row in rows]
    # Write off-loop: synchronous file I/O inside an async function that just
    # awaited an aiosqlite query can deadlock aiosqlite's worker thread on
    # event-loop teardown (observed under pytest-asyncio). Offloading to a
    # worker thread breaks the interaction.
    count = await asyncio.to_thread(_write_jsonl, output_path, records)
    logger.info("exported %d audit rows to %s (jsonl)", count, output_path)
    return count


async def export_audit_csv(
    db, output_path: str, since: str | None = None, *, project_id: str | None = None,
) -> int:
    """导出审计日志为 CSV 文件。

    ``detail`` 列以 JSON 字符串形式写入。返回导出的记录数。

    H-03 (round-4 review): ``project_id`` scopes the export to one
    project's audit trail on shared DBs.  ``None`` (default) is the
    admin opt-in that exports every project.
    """
    rows = await _fetch_rows(db, since, project_id=project_id)
    records = [_row_to_exportable(row) for row in rows]
    count = await asyncio.to_thread(_write_csv, output_path, records)
    logger.info("exported %d audit rows to %s (csv)", count, output_path)
    return count


async def export_security_events(
    db, output_path: str, *, project_id: str | None = None,
) -> int:
    """仅导出安全相关事件（action 以 ``security:`` 开头）。

    Output is JSON Lines. Returns the number of exported records.

    H-03 (round-4 review): ``project_id`` scopes the export to one
    project's security events on shared DBs.  ``None`` (default) is the
    admin opt-in that exports every project.
    """
    rows = await _fetch_rows(db, since=None, project_id=project_id)
    records = [
        _row_to_exportable(row)
        for row in rows
        if str(row.get("action", "")).startswith("security:")
    ]
    count = await asyncio.to_thread(_write_jsonl, output_path, records)
    logger.info("exported %d security-event rows to %s (jsonl)", count, output_path)
    return count


def _write_jsonl(output_path: str, records: list[dict[str, Any]]) -> int:
    """Synchronously write records as JSON Lines. Called off-loop."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        for data in records:
            handle.write(json.dumps(data, ensure_ascii=False) + "\n")
    return len(records)


def _write_csv(output_path: str, records: list[dict[str, Any]]) -> int:
    """Synchronously write records as CSV. Called off-loop."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["id", "created_at", "action", "target", "result", "session_id", "detail"]
    with open(path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for data in records:
            writer.writerow(
                {
                    "id": data.get("id", ""),
                    "created_at": data.get("created_at", ""),
                    "action": data.get("action", ""),
                    "target": data.get("target", ""),
                    "result": data.get("result", ""),
                    "session_id": data.get("session_id") or "",
                    "detail": json.dumps(data.get("detail", {}), ensure_ascii=False),
                }
            )
    return len(records)
