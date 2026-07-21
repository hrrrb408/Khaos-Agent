"""M4 batch 3.1.16A-4-4-1 acceptance tests.

Verifies the closure of the Permission authority — the module-global
``_permission_engine`` / ``_audit_logger`` holders have been removed and
every handler receives ``principal_id`` + ``permission_engine`` +
``audit_logger`` via broker injection (mirroring the cron_tools /
orchestrator_tools pattern).

Coverage:

1. **No module-global holder** — the ``init_permission_tools`` function
   and the ``_permission_engine`` / ``_audit_logger`` attributes no
   longer exist on the module.
2. **Capability declaration** — all 5 permission tools declare
   ``permission.read`` or ``permission.manage`` in the registry.
3. **Broker injection** — :class:`ToolInvocationBroker.invoke` injects
   ``principal_id`` + ``permission_engine`` + ``audit_logger`` from
   ``tool_context`` when the capability matches.
4. **Fail-closed** — empty ``principal_id`` or missing engine/logger
   returns ``{"ok": False, ...}`` instead of silently no-op'ing.
5. **Audit logger principal override** — ``query_audit_logs`` and
   ``security_status`` pass ``principal_id`` explicitly to
   ``audit_logger.query`` so the server-lifecycle logger (bound to
   ``local-uid``) cannot leak another principal's audit trail.
6. **No cross-principal race** — two concurrent runtimes with different
   principals construct their own engine/logger; calling
   ``list_permission_rules`` with each set returns only that
   principal's rules (the old holder would have returned whatever the
   last ``init_permission_tools`` call installed — last-write-wins).
"""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

import pytest

from khaos.permissions.engine import ApprovalMode, PermissionRule
from khaos.tools import permission_tools, registry


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_engine(rules: list[PermissionRule] | None = None) -> MagicMock:
    """Build a fake PermissionEngine whose ``_rules`` is the given list."""
    engine = MagicMock()
    engine._rules = rules or []
    return engine


def _make_audit(entries: list) -> MagicMock:
    """Build a fake AuditLogger whose ``query`` returns the given entries."""
    audit = MagicMock()

    async def _query(*, action=None, result=None, limit=100, principal_id=None):
        return entries[:limit]

    audit.query = _query
    return audit


class _Entry:
    def __init__(self, result: str = "denied"):
        self.result = result

    def to_dict(self):
        return {"result": self.result}


# ---------------------------------------------------------------------------
# 1. No module-global holder
# ---------------------------------------------------------------------------


def test_init_permission_tools_removed():
    """The setter function has been deleted — callers can no longer
    install a module-global engine/logger (the source of the cross-
    principal race)."""
    assert not hasattr(permission_tools, "init_permission_tools")


def test_permission_engine_holder_removed():
    assert not hasattr(permission_tools, "_permission_engine")


def test_audit_logger_holder_removed():
    assert not hasattr(permission_tools, "_audit_logger")


# ---------------------------------------------------------------------------
# 2. Capability declaration in the registry
# ---------------------------------------------------------------------------


def _build_registry() -> registry.ToolRegistry:
    """Build a registry with concrete handlers bound (production wiring)."""
    return registry.create_runtime_registry()


def test_list_permission_rules_declares_permission_read_cap():
    reg = _build_registry()
    tool = reg.get("list_permission_rules")
    cap_names = {c.name for c in tool.capabilities}
    assert "permission.read" in cap_names


def test_query_audit_logs_declares_permission_read_cap():
    reg = _build_registry()
    tool = reg.get("query_audit_logs")
    cap_names = {c.name for c in tool.capabilities}
    assert "permission.read" in cap_names


def test_security_status_declares_permission_read_cap():
    reg = _build_registry()
    tool = reg.get("security_status")
    cap_names = {c.name for c in tool.capabilities}
    assert "permission.read" in cap_names


def test_grant_permission_declares_permission_manage_cap():
    reg = _build_registry()
    tool = reg.get("grant_permission")
    cap_names = {c.name for c in tool.capabilities}
    assert "permission.manage" in cap_names


def test_revoke_permission_declares_permission_manage_cap():
    reg = _build_registry()
    tool = reg.get("revoke_permission")
    cap_names = {c.name for c in tool.capabilities}
    assert "permission.manage" in cap_names


# ---------------------------------------------------------------------------
# 3. Broker injection from tool_context
# ---------------------------------------------------------------------------


async def test_broker_injects_principal_engine_and_logger_for_read_tools():
    """``ToolInvocationBroker.invoke`` injects ``principal_id`` +
    ``permission_engine`` + ``audit_logger`` from ``tool_context`` when
    the called tool declares ``permission.read``.
    """
    reg = _build_registry()
    broker = registry.ToolInvocationBroker(reg)
    engine = _make_engine(
        [PermissionRule(
            id=1, pattern="/**", permission_level="read",
            approval=ApprovalMode.AUTO_APPROVE, mode="all",
        )]
    )
    audit = _make_audit([_Entry()])

    result = await broker.invoke(
        "list_permission_rules",
        mode="office",
        context={
            "principal_id": "api:alice",
            "permission_engine": engine,
            "audit_logger": audit,
        },
    )

    assert result["ok"] is True
    assert result["total"] == 1


async def test_broker_injects_principal_engine_for_manage_tools():
    """Same injection for ``permission.manage`` tools (grant / revoke)."""
    reg = _build_registry()
    broker = registry.ToolInvocationBroker(reg)

    granted_rule = PermissionRule(
        id=42, pattern="/**", permission_level="write",
        approval=ApprovalMode.AUTO_APPROVE, mode="all",
    )
    engine = MagicMock()

    async def _grant(rule):
        return granted_rule

    engine.grant_rule = _grant

    result = await broker.invoke(
        "grant_permission",
        mode="office",
        pattern="/**",
        permission_level="write",
        context={
            "principal_id": "api:alice",
            "permission_engine": engine,
            "audit_logger": _make_audit([]),
        },
    )

    assert result["ok"] is True
    assert result["rule"]["id"] == 42


async def test_broker_returns_not_initialized_when_engine_missing_in_context():
    """If ``tool_context`` lacks ``permission_engine`` (e.g. a runtime
    that forgot to populate it), the handler returns ``not initialized``
    rather than silently succeeding."""
    reg = _build_registry()
    broker = registry.ToolInvocationBroker(reg)

    result = await broker.invoke(
        "list_permission_rules",
        mode="office",
        context={
            "principal_id": "api:alice",
            # permission_engine intentionally missing
            "audit_logger": _make_audit([]),
        },
    )

    assert result["ok"] is False
    assert "not initialized" in result["error"]


async def test_broker_fail_closes_when_principal_id_missing_in_context():
    """If ``tool_context`` lacks ``principal_id`` (empty string default),
    the handler returns ``principal_id is required`` — fail-closed."""
    reg = _build_registry()
    broker = registry.ToolInvocationBroker(reg)

    result = await broker.invoke(
        "list_permission_rules",
        mode="office",
        context={
            # principal_id intentionally missing → defaults to ""
            "permission_engine": _make_engine([]),
            "audit_logger": _make_audit([]),
        },
    )

    assert result["ok"] is False
    assert "principal_id is required" in result["error"]


# ---------------------------------------------------------------------------
# 4. Fail-closed behavior (direct handler calls, no broker)
# ---------------------------------------------------------------------------


async def test_handlers_reject_empty_principal_id():
    engine = _make_engine([])
    audit = _make_audit([])

    assert (
        await permission_tools.list_permission_rules(
            principal_id="", permission_engine=engine,
        )
    )["ok"] is False
    assert (
        await permission_tools.grant_permission(
            "*", "read", principal_id="", permission_engine=engine,
        )
    )["ok"] is False
    assert (
        await permission_tools.revoke_permission(
            1, principal_id="", permission_engine=engine,
        )
    )["ok"] is False
    assert (
        await permission_tools.query_audit_logs(
            principal_id="", audit_logger=audit,
        )
    )["ok"] is False
    assert (
        await permission_tools.security_status(
            principal_id="", permission_engine=engine, audit_logger=audit,
        )
    )["ok"] is False


async def test_handlers_reject_missing_engine_or_logger():
    assert (
        await permission_tools.list_permission_rules(
            principal_id="api:alice", permission_engine=None,
        )
    )["ok"] is False
    assert (
        await permission_tools.query_audit_logs(
            principal_id="api:alice", audit_logger=None,
        )
    )["ok"] is False


# ---------------------------------------------------------------------------
# 5. Audit logger principal override
# ---------------------------------------------------------------------------


async def test_query_audit_logs_passes_principal_id_explicitly():
    """``query_audit_logs`` must pass ``principal_id`` to
    ``audit_logger.query`` so the server-lifecycle logger (bound to
    ``local-uid``) returns the caller's entries, not the server-uid's.
    """
    captured: dict = {}

    async def _query(*, action=None, result=None, limit=100, principal_id=None):
        captured["principal_id"] = principal_id
        return []

    audit = MagicMock()
    audit.query = _query

    await permission_tools.query_audit_logs(
        principal_id="api:alice", audit_logger=audit,
    )

    assert captured["principal_id"] == "api:alice"


async def test_security_status_passes_principal_id_explicitly():
    captured: dict = {}

    async def _query(*, action=None, result=None, limit=100, principal_id=None):
        captured["principal_id"] = principal_id
        return []

    audit = MagicMock()
    audit.query = _query

    await permission_tools.security_status(
        principal_id="api:alice",
        permission_engine=_make_engine([]),
        audit_logger=audit,
    )

    assert captured["principal_id"] == "api:alice"


# ---------------------------------------------------------------------------
# 6. No cross-principal race (the original CRITICAL bug)
# ---------------------------------------------------------------------------


async def test_concurrent_principals_do_not_race_on_engine():
    """The original CRITICAL bug: ``init_permission_tools`` was called
    per-runtime, so two concurrent principals would overwrite each
    other's engine in the module-global holder.  With the holder gone,
    each call passes its own engine — no race.

    This test simulates two concurrent ``list_permission_rules`` calls
    with different engines and confirms each sees its own rules.
    """
    alice_engine = _make_engine([
        PermissionRule(
            id=1, pattern="/alice/**", permission_level="read",
            approval=ApprovalMode.AUTO_APPROVE, mode="all",
        )
    ])
    bob_engine = _make_engine([
        PermissionRule(
            id=2, pattern="/bob/**", permission_level="write",
            approval=ApprovalMode.ASK_EVERY, mode="all",
        )
    ])

    alice_result, bob_result = await asyncio.gather(
        permission_tools.list_permission_rules(
            principal_id="api:alice", permission_engine=alice_engine,
        ),
        permission_tools.list_permission_rules(
            principal_id="api:bob", permission_engine=bob_engine,
        ),
    )

    # Alice sees only /alice/**, Bob sees only /bob/**.
    assert alice_result["ok"] is True
    assert alice_result["total"] == 1
    assert alice_result["rules"][0]["pattern"] == "/alice/**"

    assert bob_result["ok"] is True
    assert bob_result["total"] == 1
    assert bob_result["rules"][0]["pattern"] == "/bob/**"
