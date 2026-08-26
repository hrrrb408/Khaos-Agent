"""Machine contracts for the already-landed architecture junction splits."""

from __future__ import annotations

import ast
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[3]


def _source(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_machine_facts_bind_each_junction_to_one_owner() -> None:
    facts = yaml.safe_load((ROOT / "docs/security_facts.yaml").read_text(encoding="utf-8"))
    junctions = facts["architecture_junctions"]

    assert junctions["grpc"]["status"] == "ALREADY_SATISFIED"
    assert junctions["tool_scheduler"]["status"] == "ALREADY_SATISFIED"
    assert junctions["cron_scheduler"]["status"] == "ALREADY_SATISFIED"
    assert junctions["database"]["status"] == "COMPATIBILITY_MIGRATION_REMAINING"
    for path in (
        junctions["grpc"]["transport_owner"].split(":", 1)[0],
        junctions["grpc"]["composition_owner"],
        junctions["database"]["connection_owner"].split(":", 1)[0],
        junctions["database"]["repository_owner_root"],
        junctions["tool_scheduler"]["orchestration_owner"].split(":", 1)[0],
        junctions["cron_scheduler"]["execution_owner"].split(":", 1)[0],
    ):
        assert (ROOT / path).exists(), path


def test_rpc_transport_keeps_services_and_composition_out_of_the_transport_module() -> None:
    source = _source("python/khaos/grpc_server.py")
    tree = ast.parse(source)
    class_names = {
        node.name for node in ast.walk(tree) if isinstance(node, ast.ClassDef)
    }

    assert not {"AgentService", "TaskService", "ServiceComposition"} & class_names
    assert "from khaos.rpc.composition import" in source
    assert "GatewayRPCAuthenticator" in source
    assert "await agent.shutdown()" in source
    assert "await db.close()" in source


def test_database_scheduler_facades_delegate_without_a_second_sql_owner() -> None:
    source = _source("python/khaos/db/database.py")
    tree = ast.parse(source)
    methods = {
        node.name: node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    scheduler_methods = {
        "insert_scheduled_task",
        "update_scheduled_task_status",
        "update_scheduled_task",
        "list_scheduled_tasks",
        "get_scheduled_task",
        "claim_scheduled_task",
        "finalize_scheduled_task",
        "insert_scheduler_journal_entry",
    }
    for name in scheduler_methods:
        method = methods[name]
        body = ast.get_source_segment(source, method) or ""
        assert "_scheduler_repository" in body, name
        assert not any(token in body.upper() for token in ("SELECT ", "INSERT ", "UPDATE ", "DELETE "))
    assert "class DatabaseConnection" in _source("python/khaos/db/connection.py")


def test_tool_scheduler_consumes_named_security_owners() -> None:
    source = _source("python/khaos/tools/scheduler.py")

    for owner in (
        "ToolAdmission",
        "ToolAuthorization",
        "ToolExecutionCoordinator",
        "ToolResultFinalizer",
        "ToolPhaseCoordinator",
    ):
        assert owner in source
    assert "self._execution_coordinator.invoke(" in source
    assert "self._result_finalizer.terminalize" in source
