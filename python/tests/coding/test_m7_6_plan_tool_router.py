"""M7.6 published-plan routing and frontier regression tests."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field, replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from khaos.agent.control.state import AgentCognitiveState
from khaos.coding.planning.repository import PlanningTaskSnapshot
from khaos.coding.planning.revision import PlanOperation
from khaos.coding.planning.step_execution_repository import PlanStepExecutionRepository
from khaos.coding.planning.tool_router import PlanToolRouter
from khaos.coding.planning.tool_routing import (
    PlanRouteDisposition,
    PlanToolRouteBinding,
)
from khaos.db import Database
from khaos.permissions.resource import (
    AuthorizationResource,
    AuthorizationResourceKind,
    resolve_test_command,
)
from khaos.tools.admission import ToolAdmission
from khaos.tools.registry import ToolDefinition, ToolRegistry
from khaos.tools.scheduler import ToolScheduler

OWNER = "m7-6-owner"
PROJECT = "m7-6-project"
TASK = "m7-6-task"
WORKSPACE = "m7-6-workspace"
REPOSITORY = "m7-6-repository"


@dataclass
class FakeStep:
    step_id: str
    operation: PlanOperation
    target_files: tuple[str, ...] = ()
    dependencies: tuple[str, ...] = ()
    requires_approval: bool = False
    risk: object = field(
        default_factory=lambda: SimpleNamespace(requires_approval=False)
    )
    verification_requirements: tuple[object, ...] = ()

    def to_payload(self) -> dict[str, object]:
        return {"step_id": self.step_id, "operation": self.operation.value}


class FakePlanRepository:
    def __init__(self, *, published=None, recovery_id=None) -> None:
        self.published = published
        self.snapshot = PlanningTaskSnapshot(
            task_id=TASK,
            principal_id=OWNER,
            project_id=PROJECT,
            cognitive_state=AgentCognitiveState.IMPLEMENTING,
            control_state_version=2,
            task_status="running",
            workspace_id=WORKSPACE,
            base_revision="base-1",
            repository_id=REPOSITORY,
            last_applied_recovery_decision_id=recovery_id,
        )

    async def get_current_task_snapshot(self, task_id, *, principal_id, project_id):
        if (task_id, principal_id, project_id) != (TASK, OWNER, PROJECT):
            return None
        return self.snapshot

    async def get_published_for_task(self, task_id, *, principal_id, project_id):
        return self.published


class FakeRouteRepository:
    def __init__(self) -> None:
        self.routes = []
        self.states = {}

    async def append_route(self, binding):
        self.routes.append(binding)

    async def get_step_state(self, **kwargs):
        return self.states.get(kwargs["plan_step_id"])


def _resource(root: Path, *, tool: str, path: str) -> AuthorizationResource:
    return AuthorizationResource(
        kind=AuthorizationResourceKind.WORKSPACE_PATH,
        principal_id=OWNER,
        project_id=PROJECT,
        task_id=TASK,
        workspace_id=WORKSPACE,
        workspace_generation=1,
        canonical_target=f'{{"path":"{root / path}","tool":"{tool}"}}',
        root_device=1,
        root_inode=2,
        workspace_root=str(root),
    )


def _process_resource(
    root: Path, *, tool: str, argv: tuple[str, ...]
) -> AuthorizationResource:
    return AuthorizationResource(
        kind=AuthorizationResourceKind.PROCESS_ARGV,
        principal_id=OWNER,
        project_id=PROJECT,
        task_id=TASK,
        workspace_id=WORKSPACE,
        workspace_generation=1,
        canonical_target=(
            '{"argv":['
            + ",".join(f'"{item}"' for item in argv)
            + f'],"cwd":"{root}","tool":"{tool}"}}'
        ),
        root_device=1,
        root_inode=2,
        workspace_root=str(root),
    )


def _published(step, *, plan_id: str = "plan-1", workspace_id: str = WORKSPACE):
    revision = SimpleNamespace(
        task_id=TASK,
        goal_spec_id="goal-1",
        goal_spec_digest="g" * 64,
        workspace_id=workspace_id,
        repository_id=REPOSITORY,
        base_revision="base-1",
        steps=(step,) if not isinstance(step, tuple) else step,
        plan_semantic_digest="p" * 64,
    )
    return SimpleNamespace(plan_revision_id=plan_id, revision=revision)


def _context() -> dict[str, str | int]:
    return {
        "principal_id": OWNER,
        "project_id": PROJECT,
        "task_id": TASK,
        "workspace_id": WORKSPACE,
        "workspace_generation": 1,
    }


def _tool(name: str, role: str):
    return SimpleNamespace(name=name, plan_tool_role=role, security_digest="s" * 64)


@pytest.mark.asyncio
async def test_mutation_requires_exact_published_target_and_ignores_model_step_id(tmp_path):
    step = FakeStep("server-step", PlanOperation.MODIFY, ("src/a.py",))
    plans = FakePlanRepository(published=_published(step))
    routes = FakeRouteRepository()
    router = PlanToolRouter(plans, routes)

    allowed = await router.route(
        tool=_tool("write_file", "file_mutation"),
        arguments={"path": "src/a.py", "content": "x", "step_id": "attacker-choice"},
        resource=_resource(tmp_path, tool="write_file", path="src/a.py"),
        mode="coding",
        tool_context=_context(),
    )
    denied = await router.route(
        tool=_tool("write_file", "file_mutation"),
        arguments={"path": "src/b.py", "content": "x"},
        resource=_resource(tmp_path, tool="write_file", path="src/b.py"),
        mode="coding",
        tool_context=_context(),
    )

    assert allowed.disposition is PlanRouteDisposition.ALLOW
    assert allowed.binding.plan_step_id == "server-step"
    assert denied.disposition is PlanRouteDisposition.BLOCKED
    assert denied.reason_code == "no_matching_step"


@pytest.mark.asyncio
async def test_missing_published_plan_does_not_fallback_to_latest(tmp_path):
    plans = FakePlanRepository(published=None)
    router = PlanToolRouter(plans, FakeRouteRepository())
    decision = await router.route(
        tool=_tool("write_file", "file_mutation"),
        arguments={"path": "src/a.py", "content": "x"},
        resource=_resource(tmp_path, tool="write_file", path="src/a.py"),
        mode="coding",
        tool_context=_context(),
    )
    assert decision.disposition is PlanRouteDisposition.BLOCKED
    assert decision.reason_code == "no_published_plan"


@pytest.mark.asyncio
async def test_dependency_frontier_and_ambiguous_matches_fail_closed(tmp_path):
    parent = FakeStep("parent", PlanOperation.MODIFY, ("src/a.py",))
    child = FakeStep("child", PlanOperation.MODIFY, ("src/a.py",), ("parent",))
    plans = FakePlanRepository(published=_published((parent, child)))
    routes = FakeRouteRepository()
    router = PlanToolRouter(plans, routes)
    decision = await router.route(
        tool=_tool("write_file", "file_mutation"),
        arguments={"path": "src/a.py", "content": "x"},
        resource=_resource(tmp_path, tool="write_file", path="src/a.py"),
        mode="coding",
        tool_context=_context(),
    )
    assert decision.disposition is PlanRouteDisposition.AMBIGUOUS

    plans.published = _published(child)
    blocked = await router.route(
        tool=_tool("write_file", "file_mutation"),
        arguments={"path": "src/a.py", "content": "x"},
        resource=_resource(tmp_path, tool="write_file", path="src/a.py"),
        mode="coding",
        tool_context=_context(),
    )
    assert blocked.disposition is PlanRouteDisposition.BLOCKED
    assert blocked.reason_code == "dependency_not_satisfied"


@pytest.mark.asyncio
async def test_supporting_read_does_not_require_or_advance_a_plan_step(tmp_path):
    plans = FakePlanRepository(published=None)
    routes = FakeRouteRepository()
    router = PlanToolRouter(plans, routes)
    decision = await router.route(
        tool=_tool("read_file", "supporting_read"),
        arguments={"path": "src/a.py"},
        resource=_resource(tmp_path, tool="read_file", path="src/a.py"),
        mode="coding",
        tool_context=_context(),
    )
    assert decision.disposition is PlanRouteDisposition.SUPPORTING_READ
    assert decision.binding.plan_step_id is None
    assert routes.routes[-1].plan_step_id is None


@pytest.mark.asyncio
async def test_recovery_causal_identity_creates_a_new_execution_epoch(tmp_path):
    step = FakeStep("server-step", PlanOperation.MODIFY, ("src/a.py",))
    plans = FakePlanRepository(published=_published(step), recovery_id=None)
    router = PlanToolRouter(plans, FakeRouteRepository())
    first = await router.route(
        tool=_tool("write_file", "file_mutation"),
        arguments={"path": "src/a.py", "content": "x"},
        resource=_resource(tmp_path, tool="write_file", path="src/a.py"),
        mode="coding",
        tool_context=_context(),
    )
    plans.snapshot = replace(
        plans.snapshot, last_applied_recovery_decision_id="recovery-1"
    )
    second = await router.route(
        tool=_tool("write_file", "file_mutation"),
        arguments={"path": "src/a.py", "content": "x"},
        resource=_resource(tmp_path, tool="write_file", path="src/a.py"),
        mode="coding",
        tool_context=_context(),
    )
    assert first.binding.execution_epoch_digest != second.binding.execution_epoch_digest


@pytest.mark.asyncio
async def test_verification_command_requires_exact_planned_argv(tmp_path):
    intent = SimpleNamespace(command=("pytest", "-q", "tests/unit"))
    step = FakeStep(
        "verify",
        PlanOperation.TEST,
        verification_requirements=(intent,),
    )
    plans = FakePlanRepository(published=_published(step))
    router = PlanToolRouter(plans, FakeRouteRepository())
    exact = await router.route(
        tool=_tool("terminal_argv", "verification_command"),
        arguments={"argv": ["pytest", "-q", "tests/unit"]},
        resource=_process_resource(
            tmp_path,
            tool="terminal_argv",
            argv=("pytest", "-q", "tests/unit"),
        ),
        mode="coding",
        tool_context=_context(),
    )
    prefix_only = await router.route(
        tool=_tool("terminal_argv", "verification_command"),
        arguments={"argv": ["pytest"]},
        resource=_process_resource(tmp_path, tool="terminal_argv", argv=("pytest",)),
        mode="coding",
        tool_context=_context(),
    )
    assert exact.disposition is PlanRouteDisposition.ALLOW
    assert prefix_only.disposition is PlanRouteDisposition.BLOCKED


def test_test_run_resource_is_non_shell_and_matches_handler_argv(tmp_path):
    target = tmp_path / "tests"
    target.mkdir()
    canonical, kind = resolve_test_command(
        "test_run",
        {"command": "pytest -q tests/unit", "cwd": "."},
        tmp_path,
    )
    assert kind is AuthorizationResourceKind.PROCESS_ARGV
    assert '"argv":["pytest","-q","tests/unit"]' in canonical


@pytest.mark.asyncio
async def test_role_resource_mismatch_is_not_a_plan_route(tmp_path):
    step = FakeStep("verify", PlanOperation.TEST)
    router = PlanToolRouter(
        FakePlanRepository(published=_published(step)), FakeRouteRepository()
    )
    decision = await router.route(
        tool=_tool("terminal_argv", "verification_command"),
        arguments={"argv": ["pytest"]},
        resource=_resource(tmp_path, tool="terminal_argv", path="."),
        mode="coding",
        tool_context=_context(),
    )
    assert decision.disposition is PlanRouteDisposition.BLOCKED
    assert decision.reason_code == "no_matching_step"


@pytest.mark.asyncio
async def test_production_coding_scheduler_without_workspace_route_fails_closed(tmp_path):
    calls = 0

    async def handler() -> str:
        nonlocal calls
        calls += 1
        return "unexpected"

    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name="unplanned",
            description="unplanned",
            parameters={"type": "object", "properties": {}},
            modes=["coding"],
            permission_level="read",
            parallel=False,
            handler=handler,
        )
    )
    database = Database(tmp_path / "scheduler.db")
    await database.connect()
    await database.run_migrations()
    scheduler = ToolScheduler(registry, object())
    result = await scheduler.execute_batch(
        [{"id": "unplanned-1", "name": "unplanned", "arguments": {}}],
        mode="coding",
        tool_context={"production_runtime": True},
    )
    assert not result[0].success
    assert "resource boundary" in result[0].error
    assert calls == 0
    await database.close()


def test_admission_discards_model_plan_and_approval_metadata():
    admitted = ToolAdmission.normalize_call(
        {
            "id": "call-1",
            "name": "write_file",
            "arguments": {"path": "src/a.py", "content": "x"},
            "step_id": "attacker-step",
            "plan_step_id": "attacker-step",
            "plan_id": "attacker-plan",
            "plan_revision_id": "attacker-revision",
            "route_id": "attacker-route",
            "execution_epoch": "attacker-epoch",
            "approved": True,
            "requires_approval": False,
            "target_files": ["outside.py"],
            "risk": "low",
        }
    )
    assert admitted == {
        "id": "call-1",
        "name": "write_file",
        "arguments": {"path": "src/a.py", "content": "x"},
    }


def _bound_route() -> PlanToolRouteBinding:
    binding = PlanToolRouteBinding(
        route_id="route-effects",
        route_digest="",
        principal_id=OWNER,
        project_id=PROJECT,
        task_id=TASK,
        workspace_id=WORKSPACE,
        workspace_generation=1,
        plan_revision_id="plan-1",
        plan_revision_digest="p" * 64,
        plan_step_id="step-1",
        plan_step_digest="s" * 64,
        execution_epoch_digest="e" * 64,
        tool_name="write_file",
        tool_security_digest="t" * 64,
        arguments_digest="a" * 64,
        authorization_resource_digest="r" * 64,
        disposition=PlanRouteDisposition.ALLOW,
        reason_code="matched",
    )
    object.__setattr__(binding, "route_digest", binding.recompute_digest())
    return binding


@pytest.mark.asyncio
async def test_effect_statuses_are_conservative_and_route_ledger_is_append_only(tmp_path):
    database = Database(tmp_path / "m7-6.db")
    await database.connect()
    await database.run_migrations()
    route_repository = database.plan_tool_route_repository
    binding = _bound_route()
    stored = await route_repository.append_route(binding)
    assert stored.route_sequence == 1
    assert (
        await route_repository.get_route(
            binding.route_id,
            principal_id=OWNER,
            project_id=PROJECT,
            task_id=TASK,
        )
    ) is not None

    with pytest.raises(sqlite3.IntegrityError):
        async with database.transaction() as conn:
            await conn.execute(
                "UPDATE agent_plan_tool_routes SET reason_code = 'tampered' WHERE route_id = ?",
                (binding.route_id,),
            )

    step_repository = PlanStepExecutionRepository(database)
    pending = await step_repository.record_effect(
        binding, effect_status="not_applied", effect_id="effect-1"
    )
    uncertain = await step_repository.record_effect(
        binding, effect_status="partial", effect_id="effect-2"
    )
    assert pending is not None and pending.state == "PENDING"
    assert uncertain is not None and uncertain.state == "UNCERTAIN"
    async with database.transaction() as conn:
        fence_values = (
            "fence-1", "route-effects", binding.route_digest, OWNER, PROJECT,
            TASK, binding.execution_epoch_digest, "plan-1", "step-1", WORKSPACE,
            1, "ACTIVE", "now", None, None, None,
        )
        await conn.execute(
            "INSERT INTO agent_plan_dispatch_fences "
            "(fence_id, route_id, route_digest, principal_id, project_id, task_id, "
            "execution_epoch_digest, plan_revision_id, plan_step_id, workspace_id, "
            "workspace_generation, status, created_at, finished_at, effect_status, effect_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            fence_values,
        )
        with pytest.raises(sqlite3.IntegrityError):
            await conn.execute(
                "INSERT INTO agent_plan_dispatch_fences "
                "(fence_id, route_id, route_digest, principal_id, project_id, task_id, "
                "execution_epoch_digest, plan_revision_id, plan_step_id, workspace_id, "
                "workspace_generation, status, created_at, finished_at, effect_status, effect_id) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                ("fence-2", "route-effects-2", binding.route_digest, OWNER, PROJECT,
                 TASK, binding.execution_epoch_digest, "plan-1", "step-1", WORKSPACE,
                 1, "ACTIVE", "now", None, None, None),
            )
    await database.close()
