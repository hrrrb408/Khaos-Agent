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
        self.calls.append({"action": action, "result": result, "limit": limit})
        entries = self.entries
        if action is not None:
            entries = [entry for entry in entries if entry.action == action]
        if result is not None:
            entries = [entry for entry in entries if entry.result == result]
        return entries[:limit]


def setup_function():
    permission_tools.init_permission_tools(None, None)


async def test_list_permission_rules():
    engine = FakePermissionEngine()
    permission_tools.init_permission_tools(engine, FakeAuditLogger())

    result = await permission_tools.list_permission_rules()

    assert result["ok"] is True
    assert result["total"] == 1
    assert result["rules"][0]["pattern"] == "/tmp/*"
    assert result["rules"][0]["approval"] == "auto-approve"


async def test_grant_permission():
    engine = FakePermissionEngine()
    permission_tools.init_permission_tools(engine, FakeAuditLogger())

    result = await permission_tools.grant_permission("/var/tmp/*", "write", "ask-every", "office")

    assert result["ok"] is True
    assert result["rule"]["id"] == 2
    assert result["rule"]["pattern"] == "/var/tmp/*"
    assert result["rule"]["level"] == "write"
    assert result["rule"]["approval"] == "ask-every"
    assert result["rule"]["mode"] == "office"


async def test_revoke_permission():
    engine = FakePermissionEngine()
    permission_tools.init_permission_tools(engine, FakeAuditLogger())

    result = await permission_tools.revoke_permission(1)

    assert result == {"ok": True, "revoked": 1}
    assert engine.revoked == 1


async def test_query_audit_logs():
    audit = FakeAuditLogger()
    permission_tools.init_permission_tools(FakePermissionEngine(), audit)

    result = await permission_tools.query_audit_logs(action="terminal", result="denied", limit=5)

    assert result["ok"] is True
    assert result["total"] == 1
    assert result["logs"] == [{"action": "terminal", "result": "denied"}]
    assert audit.calls[-1] == {"action": "terminal", "result": "denied", "limit": 5}


async def test_security_status():
    permission_tools.init_permission_tools(FakePermissionEngine(), FakeAuditLogger())

    result = await permission_tools.security_status()

    assert result["ok"] is True
    assert result["rules_count"] == 1
    assert result["audit_entries_sample"] == 2
    assert result["recent_denials"] == 1


async def test_not_initialized():
    assert (await permission_tools.list_permission_rules())["ok"] is False
    assert (await permission_tools.grant_permission("*", "read"))["ok"] is False
    assert (await permission_tools.revoke_permission(1))["ok"] is False
    assert (await permission_tools.query_audit_logs())["ok"] is False
    assert (await permission_tools.security_status())["ok"] is False
