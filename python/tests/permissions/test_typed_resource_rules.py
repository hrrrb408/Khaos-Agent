"""P1-4 typed persistent permission resource rules."""

import os

import pytest
from types import SimpleNamespace
from pathlib import Path

from khaos.db import Database
from khaos.permissions import (
    ApprovalMode,
    PermissionEngine,
    PermissionRule,
)
from khaos.permissions.resource import (
    resolve_authorization_resource,
    resolve_single_workspace_path,
)
from khaos.permissions.rules import (
    typed_rule_from_authorization_resource,
    validate_typed_rule,
)


async def _engine(tmp_path):
    db = Database(tmp_path / "typed-rules.db")
    await db.connect()
    await db.run_migrations()
    return db, PermissionEngine(db)


async def test_filesystem_root_rule_is_typed_and_scoped(tmp_path):
    db, engine = await _engine(tmp_path)
    rule = await engine.grant_rule(
        PermissionRule(
            id=None,
            pattern="",
            permission_level="read",
            approval=ApprovalMode.AUTO_APPROVE,
            mode="all",
            resource_type="filesystem",
            resource_spec={
                "operation": "read",
                "root": "/repo/src",
                "recursive": True,
            },
        )
    )

    assert rule.resource_type == "filesystem"
    assert rule.resource_spec == {
        "operation": "read",
        "recursive": True,
        "root": os.path.realpath("/repo/src"),
    }
    allowed = await engine.check(
        "read_file", {"path": "/repo/src/main.py"}, "read", "coding",
        source_transport="cli",
    )
    denied = await engine.check(
        "read_file", {"path": "/repo/tests/main.py"}, "read", "coding",
        source_transport="cli",
    )
    assert allowed.approved is ApprovalMode.AUTO_APPROVE
    assert denied.approved is ApprovalMode.ASK_EVERY
    await db.close()


async def test_remembered_rule_binds_the_authorization_resource(tmp_path: Path):
    db, _ = await _engine(tmp_path)
    engine = PermissionEngine(
        db,
        principal_id="principal-a",
        project_id="project-a",
        policy_digest="policy-a",
    )
    workspace = SimpleNamespace(
        id="workspace-a",
        task_id="task-a",
        worktree_path=tmp_path,
        generation=1,
        principal_id="principal-a",
        project_id="project-a",
        creator_runtime_id="runtime-a",
    )
    manager = SimpleNamespace(get=lambda workspace_id: workspace)
    resource = resolve_authorization_resource(
        "write_file",
        {"path": "src/main.py", "content": "x"},
        principal_id="principal-a",
        project_id="project-a",
        runtime_id="runtime-a",
        task_id="task-a",
        workspace_id="workspace-a",
        workspace_manager=manager,
        resource_resolver=resolve_single_workspace_path,
    )
    resource_type, resource_spec = typed_rule_from_authorization_resource(
        resource, "write"
    )
    rule = await engine.grant_rule(
        PermissionRule(
            id=None,
            pattern=resource.canonical_target,
            permission_level="write",
            approval=ApprovalMode.AUTO_APPROVE,
            mode="coding",
            resource_type=resource_type,
            resource_spec=resource_spec,
        )
    )
    decision = await engine.check(
        "write_file",
        {"path": "src/main.py", "content": "x"},
        "write",
        "coding",
        resource=resource,
        source_transport="cli",
    )
    assert rule.resource_type == "filesystem"
    assert decision.approved is ApprovalMode.AUTO_APPROVE
    await db.close()


async def test_exec_rule_matches_argv_prefix_not_shell_text(tmp_path):
    db, engine = await _engine(tmp_path)
    await engine.grant_rule(
        PermissionRule(
            id=None,
            pattern="",
            permission_level="execute",
            approval=ApprovalMode.AUTO_APPROVE,
            mode="coding",
            resource_type="exec",
            resource_spec={
                "executable": "git",
                "argv_prefix": ["status"],
                "allow_shell": False,
                "cwd_scope": "any",
            },
        )
    )
    status = await engine.check(
        "terminal", {"command": "git status --short"}, "execute", "coding",
        source_transport="cli",
    )
    push = await engine.check(
        "terminal", {"command": "git push origin main"}, "execute", "coding",
        source_transport="cli",
    )
    assert status.approved is ApprovalMode.AUTO_APPROVE
    assert push.approved is ApprovalMode.ASK_EVERY
    await db.close()


async def test_network_rule_binds_scheme_host_and_path(tmp_path):
    db, engine = await _engine(tmp_path)
    await engine.grant_rule(
        PermissionRule(
            id=None,
            pattern="",
            permission_level="network",
            approval=ApprovalMode.AUTO_APPROVE,
            mode="office",
            resource_type="network",
            resource_spec={
                "scheme": "https",
                "host": "API.GITHUB.COM",
                "path_prefix": "/repos",
            },
        )
    )
    allowed = await engine.check(
        "web_fetch", {"url": "https://api.github.com/repos/khaos"},
        "network", "office", source_transport="cli",
    )
    wrong_path = await engine.check(
        "web_fetch", {"url": "https://api.github.com/admin"},
        "network", "office", source_transport="cli",
    )
    wrong_host = await engine.check(
        "web_fetch", {"url": "https://evil.example/repos/khaos"},
        "network", "office", source_transport="cli",
    )
    assert allowed.approved is ApprovalMode.AUTO_APPROVE
    assert wrong_path.approved is ApprovalMode.ASK_EVERY
    assert wrong_host.approved is ApprovalMode.ASK_EVERY
    await db.close()


def test_relaxing_shell_rule_requires_script_digest():
    with pytest.raises(ValueError, match="script_digest"):
        validate_typed_rule(
            "exec",
            {
                "executable": "/bin/sh",
                "argv_prefix": [],
                "allow_shell": True,
            },
            ApprovalMode.AUTO_APPROVE,
        )


async def test_ambiguous_legacy_relaxing_rule_is_quarantined(tmp_path):
    db, engine = await _engine(tmp_path)
    await engine.load_rules()
    await db.insert_permission_rule(
        "rm?", "execute", "auto-approve", "coding",
        principal_id="legacy", project_id="", policy_digest="",
    )
    await engine.load_rules()
    assert engine._rules == []
    await db.close()
