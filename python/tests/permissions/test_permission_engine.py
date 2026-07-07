from khaos.db import Database
from khaos.permissions import ApprovalMode, PermissionEngine, PermissionRule
from khaos.permissions.engine import normalize_command_target, split_command_segments


async def test_default_ask_every_requires_confirmation(tmp_path):
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    await db.create_session("s1")
    engine = PermissionEngine(db)

    decision = await engine.check("read_file", {"path": "a.txt"}, "read", "coding")

    assert decision.approved is ApprovalMode.ASK_EVERY
    assert decision.requires_user_confirm
    assert decision.target.endswith("a.txt")
    await db.close()


async def test_grant_rule_persists_and_matches(tmp_path):
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    await db.create_session("s1")
    engine = PermissionEngine(db)
    target = engine.normalize_target("read_file", {"path": tmp_path / "a.txt"})
    await engine.grant_rule(
        PermissionRule(
            id=None,
            pattern=target,
            permission_level="read",
            approval=ApprovalMode.AUTO_APPROVE,
            mode="coding",
        )
    )
    await engine.load_rules()

    decision = await engine.check("read_file", {"path": tmp_path / "a.txt"}, "read", "coding")

    assert decision.approved is ApprovalMode.AUTO_APPROVE
    assert not decision.requires_user_confirm
    await db.close()


async def test_rule_mode_is_isolated(tmp_path):
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    engine = PermissionEngine(db)
    target = engine.normalize_target("read_file", {"path": tmp_path / "a.txt"})
    await engine.grant_rule(
        PermissionRule(None, target, "read", ApprovalMode.AUTO_APPROVE, "coding")
    )

    decision = await engine.check("read_file", {"path": tmp_path / "a.txt"}, "read", "office")

    assert decision.approved is ApprovalMode.ASK_EVERY
    await db.close()


async def test_deny_default(tmp_path):
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    engine = PermissionEngine(db, default_mode=ApprovalMode.DENY)

    decision = await engine.check("terminal", {"command": "touch x"}, "execute", "coding")

    assert decision.approved is ApprovalMode.DENY
    assert not decision.requires_user_confirm
    await db.close()


async def test_revoke_rule(tmp_path):
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    engine = PermissionEngine(db)
    rule = await engine.grant_rule(
        PermissionRule(None, "*", "read", ApprovalMode.AUTO_APPROVE, "all")
    )

    await engine.revoke_rule(rule.id or 0)
    decision = await engine.check("read_file", {"path": "a.txt"}, "read", "coding")

    assert decision.approved is ApprovalMode.ASK_EVERY
    await db.close()


async def test_audit_log_is_written(tmp_path):
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    await db.create_session("s1")
    engine = PermissionEngine(db)

    await engine.audit("read_file", "/tmp/a.txt", "success", {"x": 1}, "s1")
    logs = await db.list_audit_logs()

    assert logs[0]["action"] == "read_file"
    assert logs[0]["target"] == "/tmp/a.txt"
    assert logs[0]["result"] == "success"
    await db.close()


def test_command_segments_split_control_operators():
    assert split_command_segments("echo a && pwd | wc -l") == ["echo a", "pwd", "wc -l"]


def test_command_target_uses_first_segment():
    assert normalize_command_target("echo a && rm x") == "echo a"
