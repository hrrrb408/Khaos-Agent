import subprocess
import os
import uuid
from pathlib import Path

import pytest

from khaos.db import Database
from khaos.grpc_server import (
    AgentService,
    ChatRequest,
    ConfirmRequest,
    _parse_json_line,
    load_router_from_config,
    MemoryService,
    serve_json_lines,
    TaskService,
)
from khaos.memory import MemoryStore


async def test_agent_service_chat_streams_events(tmp_path):
    (tmp_path / "prompts").mkdir()
    (tmp_path / "prompts" / "office.md").write_text("office prompt", encoding="utf-8")
    (tmp_path / "prompts" / "coding.md").write_text("coding prompt", encoding="utf-8")
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    service = AgentService(db, project_root=tmp_path)

    events = [event async for event in service.chat(ChatRequest("s1", "hello", "office"))]

    assert events[0]["event"] == "message"
    assert events[-1]["event"] == "done"
    await db.close()


async def test_agent_service_switch_and_confirm(tmp_path):
    (tmp_path / "prompts").mkdir()
    (tmp_path / "prompts" / "office.md").write_text("office prompt", encoding="utf-8")
    (tmp_path / "prompts" / "coding.md").write_text("coding prompt", encoding="utf-8")
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    service = AgentService(db, project_root=tmp_path)

    mode = await service.switch_mode("s1", "coding")
    confirmation = await service.confirm_permission(ConfirmRequest("s1", "call_1", True, False))

    assert mode == {"current_mode": "coding"}
    assert confirmation["ok"] is False
    assert "principal/binding" in confirmation["error"]
    await db.close()


async def test_agent_service_starts_and_stops_cron_engine(tmp_path):
    (tmp_path / "prompts").mkdir()
    (tmp_path / "prompts" / "office.md").write_text("office", encoding="utf-8")
    (tmp_path / "prompts" / "coding.md").write_text("coding", encoding="utf-8")
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    service = AgentService(db, project_root=tmp_path)

    await service.start()
    assert service.cron_engine._running is True
    await service.shutdown()
    assert service.cron_engine._running is False
    await db.close()


async def test_task_service_only_approves_or_rejects_blocked_tasks():
    from khaos.coding.task_manager import TaskManager

    manager = TaskManager()
    service = TaskService(manager)
    task = await manager.create("approval")
    not_blocked = await service.approve(task.id)
    await manager.update_status(task.id, "blocked")
    approved = await service.approve(task.id)
    await manager.update_status(task.id, "blocked")
    rejected = await service.reject(task.id)
    assert not not_blocked["ok"]
    assert not approved["ok"]
    assert not rejected["ok"]


async def test_agent_service_permission_waits_for_confirm(tmp_path):
    project = tmp_path / "project"
    (project / "prompts").mkdir(parents=True)
    (project / "prompts" / "office.md").write_text("office prompt", encoding="utf-8")
    (project / "prompts" / "coding.md").write_text("coding prompt", encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=project, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=project, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=project, check=True)
    subprocess.run(["git", "add", "."], cwd=project, check=True)
    subprocess.run(["git", "commit", "-qm", "base"], cwd=project, check=True)
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    service = AgentService(db, project_root=project)
    target = "agent.txt"

    stream = service.chat(ChatRequest("s1", f"/tool write_file {target} hello", "coding"))
    first = await stream.__anext__()
    second = await stream.__anext__()
    assert first["event"] == "tool_call"
    assert second["event"] == "permission_request"

    confirmation = await service.confirm_permission(
        ConfirmRequest(
            "s1",
            second["data"]["id"],
            True,
            False,
            principal_id=f"local-uid:{os.getuid()}",
            binding_digest=second["data"]["binding_digest"],
        )
    )
    assert confirmation == {"ok": True}
    events = [event async for event in stream]

    assert any(event["event"] == "tool_result" and event["data"]["success"] for event in events)
    task = next(iter(service.task_manager._tasks.values()))
    target_path = task.metadata["worktree_path"]
    from pathlib import Path
    assert (Path(target_path) / target).read_text(encoding="utf-8") == "hello"
    assert not (project / target).exists()
    await db.close()


async def test_memory_service_crud_search(tmp_path):
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    service = MemoryService(MemoryStore(db))

    stored = await service.set_memory("global", "user", "Ruibang likes tests")
    memory = await service.get_memory("global", "user")
    results = await service.search_memory("tests")
    deleted = await service.delete_memory(stored["id"])

    assert stored["ok"]
    assert memory["value"] == "Ruibang likes tests"
    assert results[0]["key"] == "user"
    assert deleted == {"ok": True}
    await db.close()


async def test_json_line_server_chat(tmp_path):
    (tmp_path / "prompts").mkdir()
    (tmp_path / "prompts" / "office.md").write_text("office prompt", encoding="utf-8")
    (tmp_path / "prompts" / "coding.md").write_text("coding prompt", encoding="utf-8")
    import asyncio

    socket_path = Path("/tmp") / f"khaos-test-{uuid.uuid4().hex}.sock"
    task = asyncio.create_task(
        serve_json_lines(str(socket_path), str(tmp_path / "khaos.db"), project_root=tmp_path)
    )
    await asyncio.sleep(0.01)
    task.cancel()
    try:
        await task
    except PermissionError:
        pytest.skip("sandbox does not allow binding Unix sockets")
    except asyncio.CancelledError:
        pass


def test_parse_json_line_accepts_object_request():
    request = _parse_json_line(b'{"method":"AgentService.Chat","payload":{}}\n')

    assert request["method"] == "AgentService.Chat"
    assert request["payload"] == {}


def test_parse_json_line_rejects_malformed_payload():
    with pytest.raises(ValueError, match="JSON object line"):
        _parse_json_line(b"\n")


def test_parse_json_line_rejects_non_object_payload():
    with pytest.raises(ValueError, match="JSON object"):
        _parse_json_line(b"[]\n")


async def test_load_router_from_nvidia_config(tmp_path, monkeypatch):
    monkeypatch.setenv("NVIDIA_API_KEY", "secret")
    config = tmp_path / "config.yaml"
    config.write_text(
        """
models:
  providers:
    nvidia:
      type: openai_compatible
      base_url: "https://integrate.api.nvidia.com/v1"
      api_key: "${NVIDIA_API_KEY}"
      models:
        - name: "qwen/qwen3-8b"
          max_context_tokens: 32768
          supports_tools: true
          supports_vision: false
  default_model: "qwen/qwen3-8b"
  router:
    type: single
""",
        encoding="utf-8",
    )

    router = load_router_from_config(config)
    model = await router.resolve_model("agent_loop")
    provider = router.provider_manager.get_provider("nvidia")

    assert model.model == "qwen/qwen3-8b"
    assert provider.api_key == "secret"


async def test_load_router_from_project_config_merges_user_config(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    project_config = tmp_path / "config.yaml"
    project_config.write_text(
        """
models:
  providers:
    nvidia:
      type: openai_compatible
      base_url: "https://integrate.api.nvidia.com/v1"
      api_key: "${NVIDIA_API_KEY}"
      models:
        - name: "qwen/qwen3-8b"
          max_context_tokens: 32768
          supports_tools: true
          supports_vision: false
  default_model: "qwen/qwen3-8b"
  router:
    type: single
""",
        encoding="utf-8",
    )
    user_config = tmp_path / ".khaos" / "config.yaml"
    user_config.parent.mkdir()
    user_config.write_text(
        """
models:
  providers:
    nvidia:
      api_key: "user-config-key-123"
""",
        encoding="utf-8",
    )

    router = load_router_from_config(project_config, project_root=tmp_path)
    provider = router.provider_manager.get_provider("nvidia")

    assert provider.api_key == "user-config-key-123"


async def test_build_runtime_wires_token_engine_and_skills(tmp_path):
    """_build_runtime must assemble a working token engine and (if present)
    a skill_manager. The token engine is Rust when available, else the pure-
    Python fallback; either way it must count tokens."""
    (tmp_path / "prompts").mkdir()
    (tmp_path / "prompts" / "office.md").write_text("office", encoding="utf-8")
    (tmp_path / "prompts" / "coding.md").write_text("coding", encoding="utf-8")
    # Plant a skill on disk so the manager picks it up.
    skills_dir = tmp_path / "skills"
    skills_dir.mkdir()
    (skills_dir / "SKILL.md").write_text(
        "---\nname: py\ndescription: python.\ntriggers: [python]\n---\nuse type hints\n",
        encoding="utf-8",
    )
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    service = AgentService(db, project_root=tmp_path)

    _, loop = await service._build_runtime("s1", "office")

    # Token engine works for ASCII text either way.
    assert loop.token_engine.count_tokens("hello world") == 2
    # Skill was loaded and matched the planted trigger.
    assert loop.skill_manager is not None
    matched = loop.skill_manager.match("office", "help with python")
    assert any(s.name == "py" for s in matched)
    await db.close()


async def test_audit_service_query_roundtrip(tmp_path):
    """The JSON-line AuditService.Query returns persisted records."""
    from khaos.audit import AuditLogger
    from khaos.grpc_server import AuditService

    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    logger = AuditLogger(db)
    service = AuditService(logger)

    await logger.log("write_file", "/tmp/x", "success", {"size": 1})
    entries = await service.query(limit=10)

    assert len(entries) == 1
    assert entries[0]["action"] == "write_file"
    assert entries[0]["result"] == "success"
    await db.close()
