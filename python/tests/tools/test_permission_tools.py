"""Tests for ``khaos.tools.permission_tools``.

M4 batch 3.1.16A-4-4-1 (CRITICAL): the module-global holders have been
removed.  Every handler now receives ``principal_id``,
``permission_engine`` and ``audit_logger`` as keyword arguments
(injected by the broker in production via the ``permission.read`` /
``permission.manage`` capabilities).  These tests pass them directly to
mimic the broker injection.
"""

from dataclasses import dataclass

from khaos.permissions.engine import ApprovalMode, PermissionRule
from khaos.tools import permission_tools


class FakePermissionEngine:
    def __init__(self):
        self._rules = [
            PermissionRule(
                id=1,
                pattern="/tmp/*",
                permission_level="read",
                approval=ApprovalMode.AUTO_APPROVE,
                mode="all",
            )
        ]
        self.revoked: int | None = None

    async def grant_rule(self, rule: PermissionRule) -> PermissionRule:
        persisted = PermissionRule(
            id=2,
            pattern=rule.pattern,
            permission_level=rule.permission_level,
            approval=rule.approval,
            mode=rule.mode,
        )
        self._rules.insert(0, persisted)
        return persisted

    async def revoke_rule(self, rule_id: int) -> None:
        self.revoked = rule_id


@dataclass
class FakeAuditEntry:
    action: str
    result: str

    def to_dict(self):
        return {"action": self.action, "result": self.result}


class FakeAuditLogger:
    def __init__(self):
        self.calls = []
        self.entries = [
            FakeAuditEntry("terminal", "denied"),
            FakeAuditEntry("read_file", "success"),
        ]

    async def query(self, action=None, result=None, limit=100, **kwargs):
        self.calls.append(
            {
                "action": action,
                "result": result,
                "limit": limit,
                "principal_id": kwargs.get("principal_id"),
            }
        )
        entries = self.entries
        if action is not None:
            entries = [entry for entry in entries if entry.action == action]
        if result is not None:
            entries = [entry for entry in entries if entry.result == result]
        return entries[:limit]


# ---------------------------------------------------------------------------
# Happy path — kwargs injected (mirrors broker injection in production)
# ---------------------------------------------------------------------------


async def test_list_permission_rules():
    engine = FakePermissionEngine()

    result = await permission_tools.list_permission_rules(
        principal_id="api:alice", permission_engine=engine,
    )

    assert result["ok"] is True
    assert result["total"] == 1
    assert result["rules"][0]["pattern"] == "/tmp/*"
    assert result["rules"][0]["approval"] == "auto-approve"


async def test_grant_permission():
    engine = FakePermissionEngine()

    result = await permission_tools.grant_permission(
        "/var/tmp/*", "write", "ask-every", "office",
        principal_id="api:alice", permission_engine=engine,
    )

    assert result["ok"] is True
    assert result["rule"]["id"] == 2
    assert result["rule"]["pattern"] == "/var/tmp/*"
    assert result["rule"]["level"] == "write"
    assert result["rule"]["approval"] == "ask-every"
    assert result["rule"]["mode"] == "office"


async def test_revoke_permission():
    engine = FakePermissionEngine()

    result = await permission_tools.revoke_permission(
        1, principal_id="api:alice", permission_engine=engine,
    )

    assert result == {"ok": True, "revoked": 1}
    assert engine.revoked == 1


async def test_query_audit_logs_passes_principal_id_to_logger():
    """M4 batch 3.1.16A-4-4-1 (CRITICAL): ``principal_id`` is passed
    explicitly to ``audit_logger.query`` so the server-lifecycle logger
    (bound to ``local-uid``) cannot leak another principal's audit trail.
    """
    audit = FakeAuditLogger()

    result = await permission_tools.query_audit_logs(
        action="terminal", result="denied", limit=5,
        principal_id="api:alice", audit_logger=audit,
    )

    assert result["ok"] is True
    assert result["total"] == 1
    assert result["logs"] == [{"action": "terminal", "result": "denied"}]
    assert audit.calls[-1] == {
        "action": "terminal",
        "result": "denied",
        "limit": 5,
        "principal_id": "api:alice",
    }


async def test_security_status_passes_principal_id_to_logger():
    audit = FakeAuditLogger()

    result = await permission_tools.security_status(
        principal_id="api:alice",
        permission_engine=FakePermissionEngine(),
        audit_logger=audit,
    )

    assert result["ok"] is True
    assert result["rules_count"] == 1
    assert result["audit_entries_sample"] == 2
    assert result["recent_denials"] == 1
    # The audit query was scoped to the caller's principal.
    assert audit.calls[-1]["principal_id"] == "api:alice"


# ---------------------------------------------------------------------------
# Fail-closed — missing principal_id / engine / logger
# ---------------------------------------------------------------------------


async def test_rejects_empty_principal_id():
    """Empty ``principal_id`` is rejected — fail-closed (no fallback to
    a shared pseudo-principal)."""
    engine = FakePermissionEngine()
    audit = FakeAuditLogger()

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
            principal_id="",
            permission_engine=engine,
            audit_logger=audit,
        )
    )["ok"] is False


async def test_rejects_missing_engine():
    """A missing ``permission_engine`` returns ``not initialized``."""
    assert (
        await permission_tools.list_permission_rules(
            principal_id="api:alice", permission_engine=None,
        )
    )["ok"] is False
    assert (
        await permission_tools.grant_permission(
            "*", "read",
            principal_id="api:alice", permission_engine=None,
        )
    )["ok"] is False
    assert (
        await permission_tools.revoke_permission(
            1, principal_id="api:alice", permission_engine=None,
        )
    )["ok"] is False


async def test_rejects_missing_audit_logger():
    """A missing ``audit_logger`` returns ``not initialized``."""
    assert (
        await permission_tools.query_audit_logs(
            principal_id="api:alice", audit_logger=None,
        )
    )["ok"] is False


async def test_security_status_requires_both_engine_and_logger():
    """``security_status`` needs both engine and logger — missing either
    returns ``not initialized``."""
    assert (
        await permission_tools.security_status(
            principal_id="api:alice",
            permission_engine=None,
            audit_logger=FakeAuditLogger(),
        )
    )["ok"] is False
    assert (
        await permission_tools.security_status(
            principal_id="api:alice",
            permission_engine=FakePermissionEngine(),
            audit_logger=None,
        )
    )["ok"] is False
