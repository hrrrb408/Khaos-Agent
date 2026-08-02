"""Agent readiness checks cover real local dependencies."""

from __future__ import annotations

from khaos.db import Database
from khaos.grpc_server import AgentService


async def test_agent_service_health_checks_real_dependencies(tmp_path):
    (tmp_path / "prompts").mkdir()
    (tmp_path / "prompts" / "office.md").write_text("office", encoding="utf-8")
    (tmp_path / "prompts" / "coding.md").write_text("coding", encoding="utf-8")
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    service = AgentService(db, project_root=tmp_path)

    await service.start()
    health = await service.health()

    assert health["ready"] is True
    assert health["project_id"] == service._bound_project_id
    assert health["policy_digest"] == service._effective_policy.digest
    assert health["checks"]["agent_started"] is True
    assert health["checks"]["db"] == {
        "ok": True,
        "connected": True,
        "writable": True,
        "quick_check": "ok",
    }
    assert health["checks"]["audit_anchor"]["verified"] is True
    assert health["checks"]["browser_kernel_helper"]["required"] is False

    await service.shutdown()
    assert (await service.health())["ready"] is False
    await db.close()
