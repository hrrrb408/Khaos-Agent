"""M4 batch 3.1.16A-4-4-2 acceptance tests.

Verifies the closure of the History authority — the module-global
``_session_search`` holder and the ``set_session_search`` setter have
been removed and every handler receives ``principal_id`` + ``db`` via
broker injection (mirroring the cron_tools / orchestrator_tools /
permission_tools pattern).

Coverage:

1. **No module-global holder** — ``set_session_search`` and
   ``_session_search`` no longer exist on the module.
2. **Capability declaration** — all 3 history tools declare
   ``history.read`` in the registry.
3. **Broker injection** — :class:`ToolInvocationBroker.invoke` injects
   ``principal_id`` + ``db`` from ``tool_context`` when the capability
   matches.
4. **Fail-closed** — empty ``principal_id`` or missing ``db`` returns
   ``{"status": "unavailable", ...}`` instead of falling open to an
   unscoped query.
5. **Cross-principal isolation** — two principals sharing one DB each
   see only their own sessions / messages (the original CRITICAL bug:
   a single module-global ``SessionSearch`` could only ever serve one
   principal).
6. **Production wiring** — :func:`create_runtime_registry` binds the
   handlers and the handlers accept the new ``principal_id`` / ``db``
   kwargs without crashing (regression test for the broker contract).
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from khaos.db import Database
from khaos.tools import history_tools, registry


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_registry() -> registry.ToolRegistry:
    """Build a registry with concrete handlers bound (production wiring)."""
    return registry.create_runtime_registry()


async def _seeded_db(tmp_path: Path) -> Database:
    """Build a fresh DB with two principals' worth of session data so
    cross-principal scoping can be asserted."""
    db = Database(tmp_path / "h.db")
    await db.connect()
    await db.run_migrations()
    from khaos.agent.core import Message

    await db.create_session("s1", principal_id="api:alice")
    mid = await db.insert_message(
        "s1", Message(role="user", content="how to use pytest", token_count=4),
        principal_id="api:alice",
    )
    await db.insert_message_fts("s1", "user", "how to use pytest", 4, rowid=mid)
    mid = await db.insert_message(
        "s1", Message(role="assistant", content="run the pytest command", token_count=4),
        principal_id="api:alice",
    )
    await db.insert_message_fts("s1", "assistant", "run the pytest command", 4, rowid=mid)
    await db.create_session("s2", principal_id="api:bob")
    mid = await db.insert_message(
        "s2", Message(role="user", content="how to debug kubernetes pods", token_count=5),
        principal_id="api:bob",
    )
    await db.insert_message_fts("s2", "user", "how to debug kubernetes pods", 5, rowid=mid)
    return db


# ---------------------------------------------------------------------------
# 1. No module-global holder
# ---------------------------------------------------------------------------


def test_set_session_search_removed():
    """The setter function has been deleted — callers can no longer
    install a module-global SessionSearch (the source of the cross-
    principal leak)."""
    assert not hasattr(history_tools, "set_session_search")


def test_session_search_holder_removed():
    assert not hasattr(history_tools, "_session_search")


# ---------------------------------------------------------------------------
# 2. Capability declaration in the registry
# ---------------------------------------------------------------------------


def test_history_search_declares_history_read_cap():
    reg = _build_registry()
    tool = reg.get("history_search")
    cap_names = {c.name for c in tool.capabilities}
    assert "history.read" in cap_names


def test_history_browse_declares_history_read_cap():
    reg = _build_registry()
    tool = reg.get("history_browse")
    cap_names = {c.name for c in tool.capabilities}
    assert "history.read" in cap_names


def test_history_read_declares_history_read_cap():
    reg = _build_registry()
    tool = reg.get("history_read")
    cap_names = {c.name for c in tool.capabilities}
    assert "history.read" in cap_names


# ---------------------------------------------------------------------------
# 3. Broker injection from tool_context
# ---------------------------------------------------------------------------


def test_broker_injects_principal_and_db_for_history_search(tmp_path: Path) -> None:
    """``ToolInvocationBroker.invoke`` injects ``principal_id`` + ``db``
    from ``tool_context`` when the called tool declares ``history.read``.
    """
    async def run():
        db = await _seeded_db(tmp_path)
        try:
            reg = _build_registry()
            broker = registry.ToolInvocationBroker(reg)
            result = await broker.invoke(
                "history_search",
                mode="office",
                query="pytest",
                context={
                    "principal_id": "api:alice",
                    "db": db,
                },
            )
            assert result["query"] == "pytest"
            assert len(result["results"]) >= 1
        finally:
            await db.close()

    asyncio.run(run())


def test_broker_injects_principal_and_db_for_history_browse(tmp_path: Path) -> None:
    async def run():
        db = await _seeded_db(tmp_path)
        try:
            reg = _build_registry()
            broker = registry.ToolInvocationBroker(reg)
            result = await broker.invoke(
                "history_browse",
                mode="office",
                context={
                    "principal_id": "api:alice",
                    "db": db,
                },
            )
            assert len(result["sessions"]) == 1
            assert result["sessions"][0]["session_id"] == "s1"
        finally:
            await db.close()

    asyncio.run(run())


def test_broker_injects_principal_and_db_for_history_read(tmp_path: Path) -> None:
    async def run():
        db = await _seeded_db(tmp_path)
        try:
            reg = _build_registry()
            broker = registry.ToolInvocationBroker(reg)
            result = await broker.invoke(
                "history_read",
                mode="office",
                session_id="s1",
                context={
                    "principal_id": "api:alice",
                    "db": db,
                },
            )
            assert result["session_id"] == "s1"
            assert len(result["messages"]) == 2
        finally:
            await db.close()

    asyncio.run(run())


# ---------------------------------------------------------------------------
# 4. Fail-closed behavior via broker
# ---------------------------------------------------------------------------


def test_broker_fail_closes_when_principal_id_missing_in_context(tmp_path: Path) -> None:
    """If ``tool_context`` lacks ``principal_id`` (empty string default),
    the handler returns ``principal_id is required`` — fail-closed."""
    async def run():
        db = await _seeded_db(tmp_path)
        try:
            reg = _build_registry()
            broker = registry.ToolInvocationBroker(reg)
            result = await broker.invoke(
                "history_search",
                mode="office",
                query="pytest",
                context={
                    # principal_id intentionally missing → defaults to ""
                    "db": db,
                },
            )
            return result
        finally:
            await db.close()

    result = asyncio.run(run())
    assert result["status"] == "unavailable"
    assert "principal_id is required" in result["error"]


def test_broker_reports_unavailable_when_db_missing_in_context() -> None:
    """If ``tool_context`` lacks ``db``, the handler returns
    ``session search not configured`` — graceful unavailable."""
    reg = _build_registry()
    broker = registry.ToolInvocationBroker(reg)
    result = asyncio.run(broker.invoke(
        "history_search",
        mode="office",
        query="pytest",
        context={
            "principal_id": "api:alice",
            # db intentionally missing
        },
    ))
    assert result["status"] == "unavailable"
    assert "session search not configured" in result["error"]


# ---------------------------------------------------------------------------
# 5. Cross-principal isolation (the original CRITICAL bug regression)
# ---------------------------------------------------------------------------


def test_broker_does_not_leak_other_principals_history(tmp_path: Path) -> None:
    """Alice's broker call must not return Bob's sessions — the old
    module-global holder would have served the same ``SessionSearch``
    instance to every principal (whoever called ``set_session_search``
    last won)."""
    async def run():
        db = await _seeded_db(tmp_path)
        try:
            reg = _build_registry()
            broker = registry.ToolInvocationBroker(reg)
            # Alice searches "kubernetes" (only Bob has matches).
            alice_result = await broker.invoke(
                "history_search",
                mode="office",
                query="kubernetes",
                context={"principal_id": "api:alice", "db": db},
            )
            assert alice_result["results"] == [], (
                "Alice must not see Bob's kubernetes results"
            )
            # Bob searches "pytest" (only Alice has matches).
            bob_result = await broker.invoke(
                "history_search",
                mode="office",
                query="pytest",
                context={"principal_id": "api:bob", "db": db},
            )
            assert bob_result["results"] == [], (
                "Bob must not see Alice's pytest results"
            )
        finally:
            await db.close()

    asyncio.run(run())


def test_broker_read_returns_empty_for_foreign_session(tmp_path: Path) -> None:
    """Alice cannot read Bob's session via the broker —
    ``get_session_messages`` filters by ``principal_id``."""
    async def run():
        db = await _seeded_db(tmp_path)
        try:
            reg = _build_registry()
            broker = registry.ToolInvocationBroker(reg)
            result = await broker.invoke(
                "history_read",
                mode="office",
                session_id="s2",
                context={"principal_id": "api:alice", "db": db},
            )
            assert result["session_id"] == "s2"
            assert result["messages"] == [], (
                "Alice must not read Bob's session s2"
            )
        finally:
            await db.close()

    asyncio.run(run())


# ---------------------------------------------------------------------------
# 6. Production wiring regression
# ---------------------------------------------------------------------------


def test_runtime_registry_binds_history_handlers():
    """``create_runtime_registry`` must bind the handlers and they must
    accept the new ``principal_id`` / ``db`` kwargs without crashing
    (regression test for the broker contract)."""
    reg = _build_registry()
    assert reg.get("history_search").handler is history_tools.history_search
    assert reg.get("history_browse").handler is history_tools.history_browse
    assert reg.get("history_read").handler is history_tools.history_read


def test_handlers_accept_kwargs_without_crashing() -> None:
    """Direct call with the new kwargs must not raise TypeError —
    mirrors the broker's call signature."""
    async def run():
        # Fail-closed path: empty principal_id / None db — handlers
        # return unavailable dicts, do NOT raise.
        await history_tools.history_search("pytest", principal_id="", db=None)
        await history_tools.history_browse(principal_id="", db=None)
        await history_tools.history_read("s1", principal_id="", db=None)

    asyncio.run(run())
