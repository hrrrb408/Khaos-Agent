"""M4 Batch 3.1.16A-5-1b — Project Identity Write-Path + Drift Detection.

Acceptance tests for the write-path stamping and RPC drift detection
introduced by A-5-1b (built on top of the A-5-1a schema closure).

A-5-1a added the ``project_id`` column to 8 tables (schema-only).
A-5-1b stamps the live ``project_id`` on every write path and adds
fail-closed drift detection at the RPC dispatcher.

Verifies:
  1. AuditLogger stamps ``project_id`` on every audit row.
  2. AuditLogger default ``project_id=''`` (legacy compat).
  3. MemoryStore stamps ``project_id`` on every upserted memory.
  4. TaskManager stamps ``project_id`` on every persisted coding task.
  5. AgentLoop stamps ``project_id`` on every persisted message.
  6. TurnCoordinator.start stamps ``project_id`` on agent_turns rows.
  7. PermissionEngine.audit() stamps ``project_id`` on audit_log rows.
  8. Owner-preserving ON CONFLICT: re-log with different project_id
     does NOT re-stamp audit_log.project_id.
  9. Owner-preserving ON CONFLICT: re-set memory with different
     project_id does NOT re-stamp memories.project_id.
 10. RPC dispatcher rejects ``project_drift`` when payload project_id
     != server-bound project_id (fail-closed).
 11. RPC dispatcher accepts matching payload project_id.
 12. RPC dispatcher accepts empty payload project_id (backward compat
     with older Gateways).
 13. orchestrator_tools.spawn_subagent passes ``project_id`` to the
     constructed SubAgentTask.
 14. orchestrator_tools.execute_plan stamps ``project_id`` on every
     task in the plan (mirroring principal_id stamping).
 15. SubAgentService.spawn sets ``project_id`` from ``ctx.project_id``.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import sqlite3
import time
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from khaos.agent.core import AgentConfig, AgentLoop, Message
from khaos.agent.events import TurnCoordinator
from khaos.audit import AuditLogger
from khaos.coding.task_manager import TaskManager
from khaos.db import Database
from khaos.db.state_root import project_id as compute_project_id
from khaos.grpc_server import (
    AgentService,
    GatewayRPCAuthenticator,
    serve_json_lines,
)
from khaos.memory import Memory, MemoryConfidence, MemoryScope, MemoryStore
from khaos.permissions import PermissionEngine
from khaos.runtime import RequestContext
from khaos.scheduler import ScheduleConfig
from khaos.subagents.service import SubAgentService
from khaos.subagents.spawner import SubAgentTask
from khaos.tools import orchestrator_tools
from khaos.tools.orchestrator_tools import (
    execute_plan,
    init_orchestrator,
    spawn_subagent,
)


# ─────────────────────────────── helpers ────────────────────────────────


PROJECT_ID_A = "a" * 32  # 32-char hex (matches sha256[:32] format)
PROJECT_ID_B = "b" * 32


async def _make_db(path: Path) -> Database:
    """Open a fresh Database with migrations applied."""
    db = Database(path)
    await db.connect()
    await db.run_migrations()
    return db


async def _fetch_project_id(db: Database, table: str, where: str = "") -> str | None:
    """Fetch the ``project_id`` column from the first row of ``table``."""
    conn = await db._require_conn()
    sql = f"SELECT project_id FROM {table}"
    if where:
        sql += f" WHERE {where}"
    sql += " LIMIT 1"
    cursor = await conn.execute(sql)
    row = await cursor.fetchone()
    await cursor.close()
    return row[0] if row else None


def _signed_rpc_request(
    method: str,
    payload: dict,
    *,
    nonce: str = "n" * 32,
    capability: str = "c" * 48,
):
    """Build a Gateway-signed JSON-line RPC request (mirrors production)."""
    issued_at = int(time.time())
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")
    digest = hashlib.sha256(canonical).hexdigest()
    principal = str(payload.get("principal_id") or "gateway")
    signed = f"{method}\n{nonce}\n{issued_at}\n{principal}\n{digest}".encode()
    method_key = hmac.new(
        capability.encode(),
        f"khaos-rpc-method-v1\n{method}".encode(),
        hashlib.sha256,
    ).digest()
    return {
        "method": method,
        "payload": payload,
        "auth": {
            "nonce": nonce,
            "issued_at": issued_at,
            "principal_id": principal,
            "payload_digest": digest,
            "mac": hmac.new(method_key, signed, hashlib.sha256).hexdigest(),
        },
    }


# ────────────────────────── AuditLogger stamping ────────────────────────


async def test_acceptance_1_audit_logger_stamps_project_id(tmp_path):
    """A5-1b #1: AuditLogger constructed with project_id stamps it on rows."""
    db = await _make_db(tmp_path / "khaos.db")
    try:
        await db.create_session(
            "s1", "office", principal_id="u1", project_id=PROJECT_ID_A,
        )
        audit = AuditLogger(db, principal_id="u1", project_id=PROJECT_ID_A)
        await audit.log("write_file", "/tmp/x", "success", {"size": 42}, session_id="s1")
        stamped = await _fetch_project_id(db, "audit_log", "action='write_file'")
        assert stamped == PROJECT_ID_A
    finally:
        await db.close()


async def test_acceptance_2_audit_logger_default_empty_project_id(tmp_path):
    """A5-1b #2: AuditLogger default project_id='' (legacy compat)."""
    db = await _make_db(tmp_path / "khaos.db")
    try:
        await db.create_session("s1", "office", principal_id="u1")
        audit = AuditLogger(db, principal_id="u1")  # no project_id
        await audit.log("terminal", "ls", "success", session_id="s1")
        stamped = await _fetch_project_id(db, "audit_log", "action='terminal'")
        assert stamped == ""
    finally:
        await db.close()


# ────────────────────────── MemoryStore stamping ────────────────────────


async def test_acceptance_3_memory_store_stamps_project_id(tmp_path):
    """A5-1b #3: MemoryStore constructed with project_id stamps it on rows."""
    db = await _make_db(tmp_path / "khaos.db")
    try:
        store = MemoryStore(db, principal_id="u1", project_id=PROJECT_ID_A)
        memory = Memory(
            id=None, scope=MemoryScope.GLOBAL, key="k1", value="v1",
            confidence=MemoryConfidence.MEDIUM,
        )
        await store.set(memory, namespace="private")
        stamped = await _fetch_project_id(db, "memories", "key='k1'")
        assert stamped == PROJECT_ID_A
    finally:
        await db.close()


# ────────────────────────── TaskManager stamping ────────────────────────


async def test_acceptance_4_task_manager_stamps_project_id(tmp_path):
    """A5-1b #4: TaskManager constructed with project_id stamps it on rows."""
    db = await _make_db(tmp_path / "khaos.db")
    try:
        manager = TaskManager(db=db, principal_id="u1", project_id=PROJECT_ID_A)
        task = await manager.create("goal: build feature X")
        stamped = await _fetch_project_id(db, "coding_tasks", f"id='{task.id}'")
        assert stamped == PROJECT_ID_A
    finally:
        await db.close()


# ────────────────────────── AgentLoop stamping ──────────────────────────


async def test_acceptance_5_agent_loop_stamps_project_id_on_messages(tmp_path):
    """A5-1b #5: AgentLoop stamps project_id on every persisted message."""
    db = await _make_db(tmp_path / "khaos.db")
    try:
        await db.create_session("s1", "office", principal_id="u1", project_id=PROJECT_ID_A)
        # Build a minimal AgentLoop with project_id bound.  We bypass
        # build_runtime and construct the loop directly so the test
        # focuses on the stamping contract, not the full wiring.
        loop = AgentLoop(
            AgentConfig(),
            MagicMock(),  # mode_manager
            MagicMock(),  # router
            db,
            principal_id="u1",
            project_id=PROJECT_ID_A,
        )
        msg = Message(role="user", content="hello", token_count=5)
        await loop._persist_message("s1", msg)
        stamped = await _fetch_project_id(db, "messages", "content='hello'")
        assert stamped == PROJECT_ID_A
    finally:
        await db.close()


# ──────────────────────── TurnCoordinator stamping ──────────────────────


async def test_acceptance_6_turn_coordinator_stamps_project_id(tmp_path):
    """A5-1b #6: TurnCoordinator.start stamps project_id on agent_turns."""
    db = await _make_db(tmp_path / "khaos.db")
    try:
        await db.create_session("s1", "office", principal_id="u1", project_id=PROJECT_ID_A)
        coordinator = await TurnCoordinator.start(
            db,
            session_id="s1",
            task_id=None,
            principal_id="u1",
            project_id=PROJECT_ID_A,
        )
        stamped = await _fetch_project_id(db, "agent_turns", f"turn_id='{coordinator.turn_id}'")
        assert stamped == PROJECT_ID_A
    finally:
        await db.close()


# ──────────────────────── PermissionEngine stamping ─────────────────────


async def test_acceptance_7_permission_engine_audit_stamps_project_id(tmp_path):
    """A5-1b #7: PermissionEngine.audit() stamps project_id on audit_log."""
    db = await _make_db(tmp_path / "khaos.db")
    try:
        await db.create_session("s1", "office", principal_id="u1", project_id=PROJECT_ID_A)
        engine = PermissionEngine(
            db,
            principal_id="u1",
            project_id=PROJECT_ID_A,
            policy_digest="digest-xyz",
            runtime_id="rt-1",
        )
        await engine.audit(
            "write_file", "/tmp/x", "success",
            detail={"risk_level": "safe"}, session_id="s1",
        )
        stamped = await _fetch_project_id(db, "audit_log", "action='write_file'")
        assert stamped == PROJECT_ID_A
    finally:
        await db.close()


# ─────────────── Owner-preserving INSERT (audit_log) ────────────────


async def test_acceptance_8_audit_log_owner_preserving_on_conflict(tmp_path):
    """A5-1b #8: re-log with different project_id does NOT re-stamp.

    ``audit_log`` uses a plain INSERT (no ON CONFLICT clause) — each
    ``log()`` call appends a new row.  This test verifies the FIRST
    row keeps its original ``project_id`` stamp even after a second
    ``log()`` call from a different project context.  Both rows exist
    in the table; the first is bound to PROJECT_ID_A and cannot be
    re-stamped by the second call.
    """
    db = await _make_db(tmp_path / "khaos.db")
    try:
        await db.create_session("s1", "office", principal_id="u1", project_id=PROJECT_ID_A)
        # First write: stamps PROJECT_ID_A.
        audit_a = AuditLogger(db, principal_id="u1", project_id=PROJECT_ID_A)
        await audit_a.log("write_file", "/tmp/x", "success", session_id="s1")
        # Second write from a different project: must NOT overwrite.
        audit_b = AuditLogger(db, principal_id="u1", project_id=PROJECT_ID_B)
        await audit_b.log("write_file", "/tmp/x", "success", session_id="s1")
        rows = await _fetch_project_id(db, "audit_log", "action='write_file'")
        # The first row's project_id is preserved (owner-preserving).
        # NOTE: audit_log typically appends (no ON CONFLICT), so this
        # test verifies the FIRST row keeps its original stamp even
        # after a second log call.  Both rows exist; the first has A.
        conn = await db._require_conn()
        cursor = await conn.execute(
            "SELECT project_id FROM audit_log WHERE action='write_file' ORDER BY id ASC LIMIT 1"
        )
        first_row = await cursor.fetchone()
        await cursor.close()
        assert first_row[0] == PROJECT_ID_A
    finally:
        await db.close()


# ─────────────── Owner-preserving ON CONFLICT (memories) ────────────────


async def test_acceptance_9_memories_project_id_isolation_on_conflict(tmp_path):
    """A5-1b #9 (F-02): re-set memory with different project_id creates a
    DISTINCT row, not an owner-preserving overwrite.

    Pre-F-02 the ``memories`` UNIQUE key was
    ``(namespace, principal_id, session_id, scope, key)``; ``project_id``
    was a plain column and ``ON CONFLICT`` did NOT touch it.  Two
    projects sharing a state DB would collide on the same row.

    F-02 (third-round review) makes ``project_id`` part of the UNIQUE
    key.  Project B's upsert of the same key now creates its own row;
    project A's row is untouched.  Each project reads its own value.
    """
    db = await _make_db(tmp_path / "khaos.db")
    try:
        # First write: stamps PROJECT_ID_A, value "v1".
        store_a = MemoryStore(db, principal_id="u1", project_id=PROJECT_ID_A)
        memory_a = Memory(
            id=None, scope=MemoryScope.GLOBAL, key="shared-key", value="v1",
            confidence=MemoryConfidence.MEDIUM,
        )
        await store_a.set(memory_a, namespace="private")
        # Second write with different project_id: must create a new row.
        store_b = MemoryStore(db, principal_id="u1", project_id=PROJECT_ID_B)
        memory_b = Memory(
            id=None, scope=MemoryScope.GLOBAL, key="shared-key", value="v2",
            confidence=MemoryConfidence.MEDIUM,
        )
        await store_b.set(memory_b, namespace="private")
        # Each project reads its own value.
        got_a = await store_a.get(MemoryScope.GLOBAL, "shared-key", namespace="private")
        got_b = await store_b.get(MemoryScope.GLOBAL, "shared-key", namespace="private")
        assert got_a is not None and got_a.value == "v1"
        assert got_b is not None and got_b.value == "v2"
        # Two distinct rows exist in the DB.
        conn = await db._require_conn()
        cursor = await conn.execute(
            "SELECT project_id, value FROM memories "
            "WHERE key = 'shared-key' ORDER BY project_id"
        )
        rows = await cursor.fetchall()
        assert len(rows) == 2
        assert rows[0][0] == PROJECT_ID_A
        assert rows[0][1] == "v1"
        assert rows[1][0] == PROJECT_ID_B
        assert rows[1][1] == "v2"
    finally:
        await db.close()


# ──────────────────── RPC drift detection (reject) ──────────────────────


@pytest.mark.skipif(os.name == "nt", reason="Unix server lifecycle requires UDS")
async def test_acceptance_10_rpc_rejects_project_drift(tmp_path):
    """A5-1b #10: RPC dispatcher rejects ``project_drift`` (fail-closed).

    The server boots under ``project_root=tmp_path`` (computing
    ``_bound_project_id = compute_project_id(tmp_path)``).  A request
    that claims a different ``project_id`` in the payload is rejected
    with ``{"error": "project_drift"}`` BEFORE any service method runs.
    """
    (tmp_path / "prompts").mkdir()
    (tmp_path / "prompts" / "office.md").write_text("office", encoding="utf-8")
    (tmp_path / "prompts" / "coding.md").write_text("coding", encoding="utf-8")

    socket_parent = Path("/tmp") / f"drift-reject-{uuid.uuid4().hex[:10]}"
    socket_parent.mkdir(mode=0o700)
    socket_path = socket_parent / "agent.sock"
    server_task = asyncio.create_task(
        serve_json_lines(
            str(socket_path), str(tmp_path / "khaos.db"),
            project_root=tmp_path, gateway_capability="c" * 48,
        )
    )
    try:
        for _ in range(200):
            if socket_path.exists() or server_task.done():
                break
            await asyncio.sleep(0.01)
        if server_task.done():
            try:
                await server_task
            except (PermissionError, OSError) as exc:
                pytest.skip(f"sandbox does not allow lifecycle UDS: {exc}")
        try:
            reader, writer = await asyncio.open_unix_connection(str(socket_path))
        except (PermissionError, OSError) as exc:
            pytest.skip(f"sandbox does not allow lifecycle UDS: {exc}")

        # Claim a project_id that differs from the server's bound value.
        request = _signed_rpc_request(
            "TaskService.List",
            {"project_id": "deadbeef" * 8, "principal_id": "gateway"},
        )
        writer.write((json.dumps(request) + "\n").encode("utf-8"))
        await writer.drain()
        response = json.loads((await reader.readline()).decode("utf-8"))
        assert response.get("error") == "project_drift"
        assert "does not match server-bound project_id" in response.get("message", "")
        writer.close()
        try:
            await writer.wait_closed()
        except (asyncio.TimeoutError, ConnectionError, OSError):
            pass
    finally:
        server_task.cancel()
        try:
            await server_task
        except (asyncio.CancelledError, OSError, PermissionError):
            pass
        if socket_parent.exists():
            socket_parent.rmdir()


# ──────────────── RPC drift detection (accept matching) ─────────────────


@pytest.mark.skipif(os.name == "nt", reason="Unix server lifecycle requires UDS")
async def test_acceptance_11_rpc_accepts_matching_project_id(tmp_path):
    """A5-1b #11: RPC dispatcher accepts payload project_id == bound."""
    (tmp_path / "prompts").mkdir()
    (tmp_path / "prompts" / "office.md").write_text("office", encoding="utf-8")
    (tmp_path / "prompts" / "coding.md").write_text("coding", encoding="utf-8")

    socket_parent = Path("/tmp") / f"drift-match-{uuid.uuid4().hex[:10]}"
    socket_parent.mkdir(mode=0o700)
    socket_path = socket_parent / "agent.sock"
    server_task = asyncio.create_task(
        serve_json_lines(
            str(socket_path), str(tmp_path / "khaos.db"),
            project_root=tmp_path, gateway_capability="c" * 48,
        )
    )
    try:
        for _ in range(200):
            if socket_path.exists() or server_task.done():
                break
            await asyncio.sleep(0.01)
        if server_task.done():
            try:
                await server_task
            except (PermissionError, OSError) as exc:
                pytest.skip(f"sandbox does not allow lifecycle UDS: {exc}")
        try:
            reader, writer = await asyncio.open_unix_connection(str(socket_path))
        except (PermissionError, OSError) as exc:
            pytest.skip(f"sandbox does not allow lifecycle UDS: {exc}")

        # Claim the SAME project_id the server booted under.
        bound_pid = compute_project_id(tmp_path)
        request = _signed_rpc_request(
            "ChannelService.List",
            {"project_id": bound_pid, "principal_id": "gateway"},
        )
        writer.write((json.dumps(request) + "\n").encode("utf-8"))
        await writer.drain()
        response = json.loads((await reader.readline()).decode("utf-8"))
        # No drift error — a normal service response (channels list).
        assert "error" not in response
        assert isinstance(response.get("channels"), list)
        writer.close()
        try:
            await writer.wait_closed()
        except (asyncio.TimeoutError, ConnectionError, OSError):
            pass
    finally:
        server_task.cancel()
        try:
            await server_task
        except (asyncio.CancelledError, OSError, PermissionError):
            pass
        if socket_parent.exists():
            socket_parent.rmdir()


# ──────────────── RPC drift detection (accept empty) ────────────────────


@pytest.mark.skipif(os.name == "nt", reason="Unix server lifecycle requires UDS")
async def test_acceptance_12_rpc_accepts_empty_project_id(tmp_path):
    """A5-1b #12: RPC dispatcher accepts empty payload project_id (backward compat).

    Older Gateways that don't send ``project_id`` in the payload are
    accepted — ``ctx.project_id`` remains the server-bound value, and
    the request proceeds normally.
    """
    (tmp_path / "prompts").mkdir()
    (tmp_path / "prompts" / "office.md").write_text("office", encoding="utf-8")
    (tmp_path / "prompts" / "coding.md").write_text("coding", encoding="utf-8")

    socket_parent = Path("/tmp") / f"drift-empty-{uuid.uuid4().hex[:10]}"
    socket_parent.mkdir(mode=0o700)
    socket_path = socket_parent / "agent.sock"
    server_task = asyncio.create_task(
        serve_json_lines(
            str(socket_path), str(tmp_path / "khaos.db"),
            project_root=tmp_path, gateway_capability="c" * 48,
        )
    )
    try:
        for _ in range(200):
            if socket_path.exists() or server_task.done():
                break
            await asyncio.sleep(0.01)
        if server_task.done():
            try:
                await server_task
            except (PermissionError, OSError) as exc:
                pytest.skip(f"sandbox does not allow lifecycle UDS: {exc}")
        try:
            reader, writer = await asyncio.open_unix_connection(str(socket_path))
        except (PermissionError, OSError) as exc:
            pytest.skip(f"sandbox does not allow lifecycle UDS: {exc}")

        # No project_id in payload — backward compat.
        request = _signed_rpc_request("ChannelService.List", {})
        writer.write((json.dumps(request) + "\n").encode("utf-8"))
        await writer.drain()
        response = json.loads((await reader.readline()).decode("utf-8"))
        assert "error" not in response
        assert isinstance(response.get("channels"), list)
        writer.close()
        try:
            await writer.wait_closed()
        except (asyncio.TimeoutError, ConnectionError, OSError):
            pass
    finally:
        server_task.cancel()
        try:
            await server_task
        except (asyncio.CancelledError, OSError, PermissionError):
            pass
        if socket_parent.exists():
            socket_parent.rmdir()


# ──────────────── orchestrator_tools.spawn_subagent ─────────────────────


async def test_acceptance_13_spawn_subagent_passes_project_id(tmp_path):
    """A5-1b #13: spawn_subagent stamps project_id on the SubAgentTask."""
    captured_tasks: list[SubAgentTask] = []

    async def capturing_spawn(task):
        captured_tasks.append(task)
        task.status = "completed"
        task.result = "ok"
        return task

    spawner = MagicMock()
    spawner.spawn = AsyncMock(side_effect=capturing_spawn)
    init_orchestrator(spawner, MagicMock())
    try:
        result = await spawn_subagent(
            goal="g", principal_id="u1", project_id=PROJECT_ID_A,
        )
        assert result["ok"] is True
        assert len(captured_tasks) == 1
        assert captured_tasks[0].project_id == PROJECT_ID_A
        assert captured_tasks[0].principal_id == "u1"
    finally:
        orchestrator_tools._spawner = None
        orchestrator_tools._runner = None


# ──────────────── orchestrator_tools.execute_plan ───────────────────────


async def test_acceptance_14_execute_plan_stamps_project_id(tmp_path):
    """A5-1b #14: execute_plan stamps project_id on every task in the plan."""
    captured_tasks: list[SubAgentTask] = []

    async def completing_spawn(task):
        captured_tasks.append(task)
        task.status = "completed"
        task.result = f"done:{task.goal}"
        return task

    spawner = MagicMock()
    spawner.spawn = AsyncMock(side_effect=completing_spawn)
    spawner.wait_all = AsyncMock(return_value=[])
    init_orchestrator(spawner, MagicMock())
    try:
        plan_json = json.dumps({
            "description": "parallel",
            "tasks": [{"goal": "a"}, {"goal": "b"}, {"goal": "c"}],
        })
        result = await execute_plan(
            plan_json, principal_id="u1", project_id=PROJECT_ID_A,
        )
        assert result["ok"] is True
        assert result["total"] == 3
        assert len(captured_tasks) == 3
        # Every task in the plan inherits project_id from the caller.
        for task in captured_tasks:
            assert task.project_id == PROJECT_ID_A
            assert task.principal_id == "u1"
    finally:
        orchestrator_tools._spawner = None
        orchestrator_tools._runner = None


# ──────────────────── SubAgentService.spawn ─────────────────────────────


async def test_acceptance_15_subagent_service_spawn_uses_ctx_project_id(tmp_path):
    """A5-1b #15: SubAgentService.spawn sets project_id from ctx.project_id."""
    db = await _make_db(tmp_path / "khaos.db")
    try:
        captured_tasks: list[SubAgentTask] = []

        async def capturing_spawn(task):
            captured_tasks.append(task)
            task.status = "completed"
            return task

        spawner = MagicMock()
        spawner.spawn = AsyncMock(side_effect=capturing_spawn)
        service = SubAgentService(spawner, runner=None)

        ctx = RequestContext(
            principal_id="u1",
            session_id="sess-1",
            source_transport="test",
            project_id=PROJECT_ID_A,
        )
        payload = {"goal": "build feature", "tools": ["read_file"], "timeout": 60}
        result = await service.handle_spawn(ctx, payload)

        assert result["ok"] is True
        assert len(captured_tasks) == 1
        assert captured_tasks[0].project_id == PROJECT_ID_A
        assert captured_tasks[0].principal_id == "u1"
    finally:
        await db.close()


# ─────────── coding_tasks RE-STAMPING ON CONFLICT (inverse) ────────────


async def test_acceptance_16_coding_tasks_re_stamps_project_id_on_conflict(tmp_path):
    """A5-1b #16: ``coding_tasks`` DOES re-stamp project_id on conflict.

    Unlike ``sessions`` / ``messages`` / ``memories`` / ``audit_log`` /
    ``session_bookmarks`` (owner-preserving — ``ON CONFLICT`` does NOT
    touch ``project_id``), ``coding_tasks`` DOES update both
    ``principal_id`` and ``project_id`` on conflict.  Rationale: a
    coding task's lifecycle is tied to the runtime that owns it, so a
    re-attach by the same principal under a different project context
    (e.g. after a ``project_root`` move) is a legitimate lifecycle
    event that re-binds ownership.

    This test verifies the inverse policy:
      1. ``upsert_coding_task`` with ``project_id=A`` → row stamped A.
      2. ``upsert_coding_task`` (same task id) with ``project_id=B``
         → row RE-STAMPED to B (not owner-preserving).
    """
    db = await _make_db(tmp_path / "khaos.db")
    try:
        task_dict = {
            "id": "task-rebind-1",
            "goal": "build feature",
            "status": "in_progress",
            "created_at": "2026-07-21T00:00:00Z",
            "updated_at": "2026-07-21T00:00:00Z",
        }
        # First upsert: stamps PROJECT_ID_A.
        await db.upsert_coding_task(
            task_dict, principal_id="u1", project_id=PROJECT_ID_A,
        )
        stamped_a = await _fetch_project_id(db, "coding_tasks", "id='task-rebind-1'")
        assert stamped_a == PROJECT_ID_A

        # Second upsert (same id): RE-STAMPS to PROJECT_ID_B.
        # The task dict must carry an updated timestamp so the ON
        # CONFLICT clause's ``updated_at=excluded.updated_at`` is
        # observable, but the project_id re-stamp happens regardless.
        task_dict["updated_at"] = "2026-07-21T01:00:00Z"
        await db.upsert_coding_task(
            task_dict, principal_id="u1", project_id=PROJECT_ID_B,
        )
        stamped_b = await _fetch_project_id(db, "coding_tasks", "id='task-rebind-1'")
        assert stamped_b == PROJECT_ID_B, (
            "coding_tasks ON CONFLICT must re-stamp project_id "
            "(unlike sessions/messages/memories which are owner-preserving)"
        )
    finally:
        await db.close()


async def test_acceptance_17_coding_tasks_re_stamps_via_task_manager(tmp_path):
    """A5-1b #17: TaskManager re-persist re-stamps project_id (lifecycle).

    Integration-level check: when a task created under manager_a
    (``project_id=A``) is later persisted through manager_b
    (``project_id=B``), the DB row's ``project_id`` is re-stamped to
    B.  This mirrors the real-world scenario where a task is resumed
    under a different project context after a ``project_root`` move.

    The re-stamp happens because ``TaskManager._persist`` always passes
    ``self._project_id`` to ``upsert_coding_task``, and the DB method's
    ``ON CONFLICT`` clause updates ``project_id=excluded.project_id``.
    """
    db = await _make_db(tmp_path / "khaos.db")
    try:
        # manager_a creates the task → row stamped A.
        manager_a = TaskManager(db=db, principal_id="u1", project_id=PROJECT_ID_A)
        task = await manager_a.create("goal: lifecycle rebind")
        stamped_a = await _fetch_project_id(db, "coding_tasks", f"id='{task.id}'")
        assert stamped_a == PROJECT_ID_A

        # manager_b re-persists the SAME task object → row re-stamped B.
        manager_b = TaskManager(db=db, principal_id="u1", project_id=PROJECT_ID_B)
        # ``_persist`` is the internal write path used by ``create`` /
        # ``update_status`` / ``transition``.  Calling it directly
        # simulates a re-attach without going through the task cache.
        await manager_b._persist(task)
        stamped_b = await _fetch_project_id(db, "coding_tasks", f"id='{task.id}'")
        assert stamped_b == PROJECT_ID_B
    finally:
        await db.close()


# ───────────── scheduler_operation_journal stamping ────────────────────


async def test_acceptance_18_scheduler_journal_stamps_project_id(tmp_path):
    """A5-1b #18: ``insert_scheduler_journal_entry`` stamps project_id.

    B-5 added the ``scheduler_operation_journal`` table with
    ``principal_id`` and ``policy_digest`` columns but NOT
    ``project_id`` (oversight).  A-5-1a added the column; A-5-1b
    stamps it via ``CronEngine._project_id`` (which flows from
    ``AgentService._bound_project_id`` — RPC-verified).

    This test verifies the DB-layer stamping contract directly:
    ``insert_scheduler_journal_entry(..., project_id=X)`` produces a
    row with ``project_id=X``.
    """
    db = await _make_db(tmp_path / "khaos.db")
    try:
        # ``scheduler_operation_journal`` has no FK to ``scheduled_tasks``
        # (it's an append-only operation log), so we can insert a
        # journal entry directly without creating a scheduled task first.
        await db.insert_scheduler_journal_entry(
            operation_id="op-pause-1",
            task_id="cron-task-1",
            operation_type="pause",
            desired_status="paused",
            expected_version=1,
            target_version=2,
            principal_id="u1",
            policy_digest="digest-xyz",
            project_id=PROJECT_ID_A,
        )
        stamped = await _fetch_project_id(
            db, "scheduler_operation_journal", "operation_id='op-pause-1'",
        )
        assert stamped == PROJECT_ID_A
    finally:
        await db.close()


async def test_acceptance_19_scheduler_journal_default_empty_project_id(tmp_path):
    """A5-1b #19: ``insert_scheduler_journal_entry`` default project_id=''.

    Legacy callers that omit ``project_id`` produce ``project_id=''``
    rows — fail-closed default matching the schema column default.
    These rows are still visible (no filter is applied on this column
    yet) but distinguishable from rows stamped by a project-bound
    runtime.
    """
    db = await _make_db(tmp_path / "khaos.db")
    try:
        # Omit project_id — should default to ''.
        await db.insert_scheduler_journal_entry(
            operation_id="op-pause-2",
            task_id="cron-task-2",
            operation_type="pause",
            desired_status="paused",
            expected_version=1,
            target_version=2,
            principal_id="u1",
        )
        stamped = await _fetch_project_id(
            db, "scheduler_operation_journal", "operation_id='op-pause-2'",
        )
        assert stamped == ""
    finally:
        await db.close()


# ─────────────── session_bookmarks stamping + owner-preserving ─────────


async def test_acceptance_20_save_bookmark_stamps_project_id(tmp_path):
    """A5-1b #20: ``save_bookmark`` stamps project_id on insert.

    ``session_bookmarks`` is one of the 8 tables that received the
    ``project_id`` column in A-5-1a.  A-5-1b stamps the live
    ``project_id`` via the ``save_bookmark`` kwarg (plumbed from
    ``RuntimeConfig.project_id`` / ``agent._bound_project_id``).

    Verifies the DB-layer stamping contract: ``save_bookmark(...,
    project_id=X)`` produces a row with ``project_id=X``.
    """
    db = await _make_db(tmp_path / "khaos.db")
    try:
        await db.create_session("s1", "office", principal_id="u1", project_id=PROJECT_ID_A)
        await db.save_bookmark(
            session_id="s1",
            name="bm-1",
            description="checkpoint",
            mode="office",
            summary="reached step 3",
            principal_id="u1",
            project_id=PROJECT_ID_A,
        )
        stamped = await _fetch_project_id(
            db, "session_bookmarks", "name='bm-1'",
        )
        assert stamped == PROJECT_ID_A
    finally:
        await db.close()


async def test_acceptance_21_save_bookmark_rejects_cross_project_conflict(tmp_path):
    """A5-1b #21: re-save bookmark with different project_id fails closed.

    ``session_bookmarks`` UNIQUE key is ``(session_id, name)``; the
    ``ON CONFLICT DO UPDATE`` clause updates ``description`` / ``mode``
    / ``project_root`` / ``summary`` but NOT ``principal_id`` or
    ``project_id`` — once a bookmark is bound to a (principal, project),
    a later ``save_bookmark`` call from a different project context
    cannot re-stamp ownership.  This mirrors the owner-preserving
    policy on ``sessions`` / ``messages`` / ``memories``.
    """
    db = await _make_db(tmp_path / "khaos.db")
    try:
        await db.create_session("s1", "office", principal_id="u1", project_id=PROJECT_ID_A)
        # First save: stamps PROJECT_ID_A.
        await db.save_bookmark(
            session_id="s1", name="bm-shared", description="v1",
            summary="first", principal_id="u1", project_id=PROJECT_ID_A,
        )
        # A conflicting caller cannot use an owner-preserving UPSERT to
        # mutate another project's bookmark fields.
        with pytest.raises(sqlite3.IntegrityError, match="identity mismatch"):
            await db.save_bookmark(
                session_id="s1", name="bm-shared", description="v2",
                summary="second", principal_id="u1", project_id=PROJECT_ID_B,
            )
        stamped = await _fetch_project_id(
            db, "session_bookmarks", "name='bm-shared'",
        )
        assert stamped == PROJECT_ID_A, (
            "session_bookmarks ON CONFLICT must be owner-preserving "
            "(project_id not re-stamped)"
        )
        # The rejected write leaves both ownership and content unchanged.
        conn = await db._require_conn()
        cursor = await conn.execute(
            "SELECT description, summary FROM session_bookmarks "
            "WHERE name='bm-shared'"
        )
        row = await cursor.fetchone()
        await cursor.close()
        assert row[0] == "v1"
        assert row[1] == "first"
    finally:
        await db.close()


# ─────────────── scheduled_tasks stamping (DB layer) ──────────────────


async def test_acceptance_22_insert_scheduled_task_stamps_project_id(tmp_path):
    """A5-1b #22: ``insert_scheduled_task`` stamps project_id on the row.

    B-1 added ``project_id`` / ``policy_digest`` columns to
    ``scheduled_tasks`` for B-2 drift detection.  A-5-1b stamps the
    live ``project_id`` via the ``insert_scheduled_task`` kwarg, which
    flows from ``CronEngine._project_id`` (RPC-verified).

    Verifies the DB-layer stamping contract: ``insert_scheduled_task(
    ..., project_id=X)`` produces a row with ``project_id=X``.
    """
    db = await _make_db(tmp_path / "khaos.db")
    try:
        task_id = await db.insert_scheduled_task(
            name="cron-1", prompt="hello", status="pending",
            schedule=ScheduleConfig(cron="0 9"), deliver_to="local",
            meta={}, principal_id="u1",
            project_id=PROJECT_ID_A, policy_digest="sha256:policy-a",
        )
        stamped = await _fetch_project_id(
            db, "scheduled_tasks", f"id='{task_id}'",
        )
        assert stamped == PROJECT_ID_A
    finally:
        await db.close()


async def test_acceptance_23_insert_scheduled_task_default_empty_project_id(tmp_path):
    """A5-1b #23: ``insert_scheduled_task`` default project_id=''.

    Legacy callers that omit ``project_id`` produce ``project_id=''``
    rows — fail-closed default matching the schema column default.
    These rows are still visible (no filter is applied on this column
    at the DB layer) but B-2 drift detection will quarantine tasks
    with empty ``project_id`` if the live runtime is project-bound.
    """
    db = await _make_db(tmp_path / "khaos.db")
    try:
        task_id = await db.insert_scheduled_task(
            name="cron-legacy", prompt="hello", status="pending",
            schedule=ScheduleConfig(cron="0 9"), deliver_to="local",
            meta={}, principal_id="u1",
            # Omit project_id — should default to ''.
        )
        stamped = await _fetch_project_id(
            db, "scheduled_tasks", f"id='{task_id}'",
        )
        assert stamped == ""
    finally:
        await db.close()


# ─────────────── permissions stamping (DB layer) ──────────────────────


async def test_acceptance_24_insert_permission_rule_stamps_project_id(tmp_path):
    """A5-1b #24: ``insert_permission_rule`` stamps project_id on the row.

    ``permissions`` already had ``project_id`` since A-2 (CRITICAL #3),
    but A-5-1b re-confirms the stamping contract: rules are scoped by
    ``(principal_id, project_id, policy_digest)`` so a rule granted
    under project A does NOT match a runtime booted under project B.

    Verifies the DB-layer stamping contract: ``insert_permission_rule(
    ..., project_id=X)`` produces a row with ``project_id=X``, and
    ``list_permission_rules(project_id=X)`` filters by it.
    """
    db = await _make_db(tmp_path / "khaos.db")
    try:
        await db.insert_permission_rule(
            pattern="read_file:/tmp/**", permission_level="read",
            approval="auto", mode="office",
            principal_id="u1", project_id=PROJECT_ID_A,
            policy_digest="sha256:policy-a", generation=0,
        )
        # Row is stamped with PROJECT_ID_A.
        stamped = await _fetch_project_id(
            db, "permissions", "pattern='read_file:/tmp/**'",
        )
        assert stamped == PROJECT_ID_A

        # list_permission_rules(project_id=...) filters by it.
        rules_a = await db.list_permission_rules(
            principal_id="u1", project_id=PROJECT_ID_A,
        )
        assert any(r["pattern"] == "read_file:/tmp/**" for r in rules_a)
        # A different project sees no rules.
        rules_b = await db.list_permission_rules(
            principal_id="u1", project_id=PROJECT_ID_B,
        )
        assert not any(r["pattern"] == "read_file:/tmp/**" for r in rules_b)
    finally:
        await db.close()
