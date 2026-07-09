"""Tests for audit log export (JSON / CSV / security-events-only).

The export pipeline is exercised via a subprocess that runs its own
``asyncio.run`` loop, fully isolated from pytest-asyncio's event-loop
management. This is necessary because the export path combines aiosqlite
queries with synchronous file I/O, and under pytest-asyncio's auto loop mode
that combination deadlocks aiosqlite's worker thread on teardown when run in
the same process as other async DB tests (e.g. test_audit_logger.py). A
subprocess gets a clean process/loop/thread lifecycle every time.

The export logic itself is identical regardless of how it's invoked.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

_EXPORT_RUNNER = """
import asyncio, json, sys
from pathlib import Path
from khaos.audit import AuditLogger
from khaos.audit.export import export_audit_csv, export_audit_json, export_security_events
from khaos.db import Database

async def main(tmp):
    db = Database(Path(tmp) / "khaos.db")
    await db.connect(); await db.run_migrations()
    audit = AuditLogger(db)
    await audit.log("write_file", "/tmp/a", "success", {"size": 1})
    await audit.log("terminal", "ls", "success")
    await audit.log_security_event("command_blocked", "terminal", "sudo rm")
    await audit.log_security_event("network_blocked", "terminal", "curl https://x")
    results = {}
    results["json"] = await export_audit_json(db, str(Path(tmp) / "audit.jsonl"))
    results["csv"] = await export_audit_csv(db, str(Path(tmp) / "audit.csv"))
    results["sec"] = await export_security_events(db, str(Path(tmp) / "security.jsonl"))
    results["nested"] = await export_audit_json(db, str(Path(tmp) / "nested" / "deep" / "a.jsonl"))
    results["since_future"] = await export_audit_json(db, str(Path(tmp) / "f.jsonl"), since="2999-01-01 00:00:00")
    results["since_past"] = await export_audit_json(db, str(Path(tmp) / "p.jsonl"), since="2000-01-01 00:00:00")
    await db.close()
    print(json.dumps(results))

asyncio.run(main(sys.argv[1]))
"""


def _run_export_subprocess(tmp_path: Path) -> dict:
    """Run the export pipeline in an isolated subprocess; return its counts."""
    proc = subprocess.run(
        [sys.executable, "-c", _EXPORT_RUNNER, str(tmp_path)],
        capture_output=True,
        text=True,
        cwd=str(Path(__file__).parents[2]),  # python package root, so `khaos` imports
        timeout=60,
    )
    assert proc.returncode == 0, f"export subprocess failed: {proc.stderr}"
    return json.loads(proc.stdout.strip())


def test_export_json(tmp_path: Path) -> None:
    counts = _run_export_subprocess(tmp_path)

    assert counts["json"] == 4
    out = tmp_path / "audit.jsonl"
    lines = out.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 4
    assert {"id", "action", "target", "result", "detail", "created_at"} <= set(
        json.loads(lines[0])
    )


def test_export_csv(tmp_path: Path) -> None:
    _run_export_subprocess(tmp_path)
    import csv as csv_mod

    with open(tmp_path / "audit.csv", encoding="utf-8") as handle:
        rows = list(csv_mod.DictReader(handle))
    assert len(rows) == 4
    assert rows[0]["action"]
    assert json.loads(rows[0]["detail"]) is not None


def test_export_security_events_only(tmp_path: Path) -> None:
    _run_export_subprocess(tmp_path)
    out = tmp_path / "security.jsonl"
    actions = {json.loads(line)["action"] for line in out.read_text().splitlines()}
    assert actions == {"security:command_blocked", "security:network_blocked"}


def test_export_creates_parent_dirs(tmp_path: Path) -> None:
    _run_export_subprocess(tmp_path)
    assert (tmp_path / "nested" / "deep" / "a.jsonl").is_file()


def test_export_since_filter(tmp_path: Path) -> None:
    counts = _run_export_subprocess(tmp_path)
    assert counts["since_future"] == 0
    assert counts["since_past"] == 4
