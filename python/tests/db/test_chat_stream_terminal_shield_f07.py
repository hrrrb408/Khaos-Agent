"""F-07 (third-round review) — Chat stream terminal shield + retention.

F-07 identified two gaps:

  1. **No terminal on failure**: when ``_build_runtime`` raises, the
     chat task is cancelled, or the model router fails, the durable
     ledger kept the ``started`` event without a matching terminal.
     Subscribers polled the 30 s idle deadline instead of seeing an
     explicit failure.

  2. **Unbounded growth**: ``chat_stream_events`` had no retention/GC
     path, so a long-lived service accumulated every event forever.

This file verifies:

  - F-07-A: ``_build_runtime`` failure appends a terminal ``error``
    event (every ``started`` → exactly one terminal).
  - F-07-B: ``CancelledError`` during the chat appends a terminal
    ``interrupted`` event.
  - F-07-C: normal ``done`` events are NOT double-terminated (the
    shield is a no-op when the loop already produced a terminal).
  - F-07-D: ``delete_chat_stream_events_for_session`` cascade-deletes.
  - F-07-E: ``prune_terminal_chat_streams`` drops aged terminal
    sessions but keeps fresh ones and non-terminal ones.
  - F-07-F: ``interrupted`` is recognised as terminal by the schema
    (is_terminal=1) so subscribers stop polling.
"""
from __future__ import annotations

import asyncio
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from khaos.db import Database
from khaos.grpc_server import AgentService
from khaos.runtime import RequestContext


PROJECT_ID = "a" * 32
PRINCIPAL = "alice"


# ───────────────────────────── helpers ────────────────────────────────


async def _make_db(path: Path) -> Database:
    db = Database(path)
    await db.connect()
    await db.run_migrations()
    return db


def _ctx(session_id: str = "s1") -> RequestContext:
    return RequestContext(
        principal_id=PRINCIPAL,
        project_id=PROJECT_ID,
        session_id=session_id,
        runtime_id="rt-1",
        source_transport="test",
        policy_digest="digest",
    )


class _FakeRequest:
    """Minimal stand-in for ChatRequest with the fields AgentService.chat reads."""
    def __init__(self, message: str = "hi", session_id: str = "", mode: str = "office"):
        self.message = message
        self.session_id = session_id
        self.mode = mode


async def _drain_chat(gen):
    """Consume an async generator to completion, capturing any raise."""
    events: list[dict] = []
    try:
        async for event in gen:
            events.append(event)
    except Exception as exc:
        return events, exc
    return events, None


# ───────────────────────── F-07-A: build failure → error terminal ─────


async def test_f07_a_build_runtime_failure_appends_error_terminal(tmp_path):
    """F-07-A: when ``_build_runtime`` raises, a shielded ``error``
    terminal event is appended so the ledger always has a terminal."""
    db = await _make_db(tmp_path / "f07.db")
    try:
        await db.create_session(
            "s1", "office", principal_id=PRINCIPAL, project_id=PROJECT_ID,
        )
        svc = AgentService(db=db, project_root=tmp_path)
        # Force _build_runtime to raise.
        svc._build_runtime = AsyncMock(side_effect=RuntimeError("router down"))

        events, exc = await _drain_chat(
            svc.chat(_ctx(), _FakeRequest(session_id="s1"))
        )
        assert exc is not None
        assert isinstance(exc, RuntimeError)
        assert "router down" in str(exc)

        # The first yielded event is ``started``.
        assert len(events) == 1
        assert events[0]["event"] == "started"

        # The ledger now has started + error (terminal).
        ledger = await db.list_chat_stream_events(
            session_id="s1", principal_id=PRINCIPAL, project_id=PROJECT_ID,
        )
        assert [e["event"] for e in ledger] == ["started", "error"]
        assert ledger[-1]["terminal"] is True
        assert ledger[-1]["data"]["reason"] == "RuntimeError"
        assert "router down" in ledger[-1]["data"]["message"]
    finally:
        await db.close()


# ───────────────────── F-07-B: cancellation → interrupted ─────────────


async def test_f07_b_cancellation_appends_interrupted_terminal(tmp_path):
    """F-07-B: ``CancelledError`` during the chat appends a terminal
    ``interrupted`` event (distinct from ``error``)."""
    db = await _make_db(tmp_path / "f07.db")
    try:
        await db.create_session(
            "s1", "office", principal_id=PRINCIPAL, project_id=PROJECT_ID,
        )
        svc = AgentService(db=db, project_root=tmp_path)

        async def slow_build(*args, **kwargs):
            await asyncio.sleep(10)  # never completes; we cancel first
            return MagicMock()

        svc._build_runtime = slow_build

        gen = svc.chat(_ctx(), _FakeRequest(session_id="s1"))
        # Pull the started event.
        started = await gen.__anext__()
        assert started["event"] == "started"

        # Cancel the generator.
        with pytest.raises(asyncio.CancelledError):
            task = asyncio.ensure_future(_drain_chat(gen))
            await asyncio.sleep(0.05)  # let it enter _build_runtime
            task.cancel()
            await task

        # Ledger has started + interrupted (terminal).
        ledger = await db.list_chat_stream_events(
            session_id="s1", principal_id=PRINCIPAL, project_id=PROJECT_ID,
        )
        assert [e["event"] for e in ledger] == ["started", "interrupted"]
        assert ledger[-1]["terminal"] is True
    finally:
        await db.close()


# ─────────── F-07-C: normal done is not double-terminated ─────────────


async def test_f07_c_normal_done_is_not_double_terminated(tmp_path):
    """F-07-C: when the loop already produced a ``done`` terminal, the
    except clause is a no-op (no second terminal appended)."""
    db = await _make_db(tmp_path / "f07.db")
    try:
        await db.create_session(
            "s1", "office", principal_id=PRINCIPAL, project_id=PROJECT_ID,
        )
        svc = AgentService(db=db, project_root=tmp_path)

        # Build a fake runtime whose loop.run yields a done event.
        # ``close_runtime_or_register`` is awaited in the finally block,
        # so ``aclose`` must be an AsyncMock to avoid TypeError.
        fake_runtime = MagicMock()
        fake_runtime.aclose = AsyncMock(return_value=None)

        class _FakeLoop:
            async def run(self, message, session_id):
                yield MagicMock(role="assistant", content="ok", token_count=1)
                yield MagicMock(role="assistant", content="done", token_count=0)

        fake_runtime.loop = _FakeLoop()
        svc._build_runtime = AsyncMock(return_value=fake_runtime)
        # Stub close_runtime_or_register so the finally block doesn't
        # try to actually close anything.
        import khaos.runtime as runtime_mod
        original_close = runtime_mod.close_runtime_or_register
        runtime_mod.close_runtime_or_register = AsyncMock(return_value=None)
        try:
            events, exc = await _drain_chat(
                svc.chat(_ctx(), _FakeRequest(session_id="s1"))
            )
        finally:
            runtime_mod.close_runtime_or_register = original_close

        assert exc is None  # no exception, no shield trigger

        ledger = await db.list_chat_stream_events(
            session_id="s1", principal_id=PRINCIPAL, project_id=PROJECT_ID,
        )
        # started + 2 messages — NO extra error/interrupted terminal.
        assert ledger[0]["event"] == "started"
        # No terminal ``error``/``interrupted`` appended by the shield.
        shield_terminals = [
            e for e in ledger
            if e["event"] in {"error", "interrupted"}
            and e["data"].get("reason") in {"RuntimeError", "CancelledError"}
        ]
        assert shield_terminals == []
    finally:
        await db.close()


# ─────────── F-07-D: session cascade delete ───────────────────────────


async def test_f07_d_delete_chat_stream_events_for_session(tmp_path):
    """F-07-D: ``delete_chat_stream_events_for_session`` removes all
    events for one session and leaves other sessions untouched."""
    db = await _make_db(tmp_path / "f07.db")
    try:
        await db.create_session("s1", principal_id=PRINCIPAL, project_id=PROJECT_ID)
        await db.create_session("s2", principal_id=PRINCIPAL, project_id=PROJECT_ID)
        await db.append_chat_stream_event(
            session_id="s1", principal_id=PRINCIPAL, project_id=PROJECT_ID,
            event_type="started", data={}, now=1.0,
        )
        await db.append_chat_stream_event(
            session_id="s1", principal_id=PRINCIPAL, project_id=PROJECT_ID,
            event_type="done", data={}, now=2.0,
        )
        await db.append_chat_stream_event(
            session_id="s2", principal_id=PRINCIPAL, project_id=PROJECT_ID,
            event_type="started", data={}, now=3.0,
        )

        deleted = await db.delete_chat_stream_events_for_session(
            session_id="s1", principal_id=PRINCIPAL, project_id=PROJECT_ID,
        )
        assert deleted == 2

        s1_events = await db.list_chat_stream_events(
            session_id="s1", principal_id=PRINCIPAL, project_id=PROJECT_ID,
        )
        s2_events = await db.list_chat_stream_events(
            session_id="s2", principal_id=PRINCIPAL, project_id=PROJECT_ID,
        )
        assert s1_events == []
        assert len(s2_events) == 1
        assert s2_events[0]["event"] == "started"
    finally:
        await db.close()


# ─────────── F-07-E: prune terminal aged sessions ─────────────────────


async def test_f07_e_prune_terminal_chat_streams(tmp_path):
    """F-07-E: ``prune_terminal_chat_streams`` drops aged terminal
    sessions but keeps fresh terminals and non-terminal sessions."""
    db = await _make_db(tmp_path / "f07.db")
    try:
        await db.create_session("aged", principal_id=PRINCIPAL, project_id=PROJECT_ID)
        await db.create_session("fresh", principal_id=PRINCIPAL, project_id=PROJECT_ID)
        await db.create_session("inflight", principal_id=PRINCIPAL, project_id=PROJECT_ID)

        now = time.time()
        # aged: terminal event 2 hours ago.
        await db.append_chat_stream_event(
            session_id="aged", principal_id=PRINCIPAL, project_id=PROJECT_ID,
            event_type="started", data={}, now=now - 7200,
        )
        await db.append_chat_stream_event(
            session_id="aged", principal_id=PRINCIPAL, project_id=PROJECT_ID,
            event_type="done", data={}, now=now - 7100,
        )
        # fresh: terminal event 10 seconds ago.
        await db.append_chat_stream_event(
            session_id="fresh", principal_id=PRINCIPAL, project_id=PROJECT_ID,
            event_type="started", data={}, now=now - 20,
        )
        await db.append_chat_stream_event(
            session_id="fresh", principal_id=PRINCIPAL, project_id=PROJECT_ID,
            event_type="done", data={}, now=now - 10,
        )
        # inflight: started but no terminal.
        await db.append_chat_stream_event(
            session_id="inflight", principal_id=PRINCIPAL, project_id=PROJECT_ID,
            event_type="started", data={}, now=now - 7200,
        )

        # Prune terminals older than 1 hour.
        pruned = await db.prune_terminal_chat_streams(
            older_than_seconds=3600, now=now,
        )
        assert pruned == 2  # aged started + aged done

        aged = await db.list_chat_stream_events(
            session_id="aged", principal_id=PRINCIPAL, project_id=PROJECT_ID,
        )
        fresh = await db.list_chat_stream_events(
            session_id="fresh", principal_id=PRINCIPAL, project_id=PROJECT_ID,
        )
        inflight = await db.list_chat_stream_events(
            session_id="inflight", principal_id=PRINCIPAL, project_id=PROJECT_ID,
        )
        assert aged == []           # pruned
        assert len(fresh) == 2       # kept (fresh terminal)
        assert len(inflight) == 1    # kept (non-terminal)
    finally:
        await db.close()


# ─────── F-07-F: interrupted is terminal in the schema ────────────────


async def test_f07_f_interrupted_is_terminal_in_schema(tmp_path):
    """F-07-F: ``interrupted`` events are stored with is_terminal=1 so
    subscribers stop polling immediately."""
    db = await _make_db(tmp_path / "f07.db")
    try:
        await db.create_session("s1", principal_id=PRINCIPAL, project_id=PROJECT_ID)
        await db.append_chat_stream_event(
            session_id="s1", principal_id=PRINCIPAL, project_id=PROJECT_ID,
            event_type="started", data={}, now=1.0,
        )
        await db.append_chat_stream_event(
            session_id="s1", principal_id=PRINCIPAL, project_id=PROJECT_ID,
            event_type="interrupted", data={"reason": "CancelledError"}, now=2.0,
        )
        events = await db.list_chat_stream_events(
            session_id="s1", principal_id=PRINCIPAL, project_id=PROJECT_ID,
        )
        assert events[0]["terminal"] is False  # started
        assert events[1]["terminal"] is True   # interrupted
    finally:
        await db.close()
