"""M7.6 published-plan routing and frontier regression tests."""

from __future__ import annotations

import asyncio
import json
import sqlite3
from dataclasses import dataclass, field, replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from khaos.agent.control.state import AgentCognitiveState
from khaos.coding.intelligence.context import ContextFreshness
from khaos.coding.planning.repository import PlanningTaskSnapshot
from khaos.coding.planning.revision import (
    PLANNER_ALGORITHM_VERSION,
    PLANNING_SCHEMA_VERSION,
    PlanDisposition,
    PlanningRisk,
    PlanningRiskLevel,
    PlanningStep,
    PlanOperation,
    PlanRevision,
)
from khaos.coding.planning.step_execution_repository import PlanStepExecutionRepository
from khaos.coding.planning.tool_router import PlanToolRouter
from khaos.coding.planning.tool_routing import (
    PlanExecutionEpochBinding,
    PlanRouteDisposition,
    PlanToolRouteBinding,
)
from khaos.coding.task_manager import TaskManager, TaskStatus
from khaos.db import Database
from khaos.permissions.resource import (
    AuthorizationResource,
    AuthorizationResourceKind,
    resolve_test_command,
)
from khaos.security.protocol_boundary import canonical_digest
from khaos.subagents.assignment import (
    ASSIGNMENT_SCHEMA_VERSION,
    SubAgentAssignment,
    SubAgentPolicy,
)
from khaos.time_utils import utc_now_naive
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
        canonical_target=json.dumps(
            {"path": str(root / path), "tool": tool},
            separators=(",", ":"),
        ),
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
        canonical_target=json.dumps(
            {"argv": list(argv), "cwd": str(root), "tool": tool},
            separators=(",", ":"),
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


async def _dispatch_case(path: Path):
    """Create a published real plan for repository-level dispatch tests."""
    database = Database(path)
    await database.connect()
    await database.run_migrations()
    manager = TaskManager(db=database, principal_id=OWNER, project_id=PROJECT)
    task = await manager.create("修复 src/a.py")
    await manager.update_status(task.id, TaskStatus.RUNNING)
    initialized = await manager.initialize_cognitive_state(task.id)
    assert initialized.updated
    await manager.update_status(
        task.id,
        TaskStatus.RUNNING,
        workspace_id=WORKSPACE,
        base_sha="base-a",
        repository_id=REPOSITORY,
    )

    snapshot = await database.plan_revision_repository.get_current_task_snapshot(
        task.id, principal_id=OWNER, project_id=PROJECT
    )
    assert snapshot is not None
    transition = await database.agent_control_state_repository.compare_and_transition(
        task.id,
        principal_id=OWNER,
        project_id=PROJECT,
        expected_state=snapshot.cognitive_state,
        expected_version=snapshot.control_state_version,
        target_state=AgentCognitiveState.PLANNING,
        expected_task_status=snapshot.task_status,
    )
    assert transition.updated
    planning = await database.plan_revision_repository.get_current_task_snapshot(
        task.id, principal_id=OWNER, project_id=PROJECT
    )
    assert planning is not None
    goal_spec = await manager.goal_spec_repository.get_for_task(
        task.id, principal_id=OWNER, project_id=PROJECT
    )
    assert goal_spec is not None
    step = PlanningStep(
        step_id="step-a",
        title="修复目标文件",
        description="Apply the planned change to the target file.",
        operation=PlanOperation.MODIFY,
        target_files=("src/a.py",),
        target_symbols=(),
        dependencies=(),
        expected_outcome="The target file contains the planned change.",
        verification_requirements=(),
        risk=PlanningRisk(
            level=PlanningRiskLevel.LOW,
            category="test",
            description="A bounded test mutation.",
            affected_scope=("src/a.py",),
            mitigation="Verify the exact target after dispatch.",
            requires_approval=False,
        ),
        requires_approval=False,
        evidence=(),
    )
    revision = PlanRevision(
        schema_version=PLANNING_SCHEMA_VERSION,
        plan_revision_id="",
        task_id=task.id,
        principal_id=OWNER,
        project_id=PROJECT,
        revision_sequence=0,
        parent_revision_id=None,
        goal_spec_id=goal_spec.goal_spec_id,
        goal_spec_digest=goal_spec.semantic_digest,
        workspace_id=WORKSPACE,
        repository_id=REPOSITORY,
        base_revision="base-a",
        context_bundle_id="dispatch-bundle",
        context_bundle_digest="b" * 64,
        context_request_digest="c" * 64,
        repository_generation="repository-generation-1",
        index_generation="index-generation-1",
        context_freshness=ContextFreshness.FRESH,
        cognitive_state=planning.cognitive_state,
        control_state_version=planning.control_state_version,
        task_status=planning.task_status,
        planner_schema_version=PLANNING_SCHEMA_VERSION,
        planner_algorithm_version=PLANNER_ALGORITHM_VERSION,
        planning_input_digest="d" * 64,
        disposition=PlanDisposition.READY,
        summary="A single bounded dispatch step.",
        steps=(step,),
    )
    stored = await database.plan_revision_repository.append(
        revision, principal_id=OWNER, project_id=PROJECT
    )
    publication = await database.plan_revision_repository.publish_ready_revision(
        stored.plan_revision_id, principal_id=OWNER, project_id=PROJECT
    )
    assert publication.status.value == "published"
    current = await database.plan_revision_repository.get_current_task_snapshot(
        task.id, principal_id=OWNER, project_id=PROJECT
    )
    assert current is not None
    epoch = PlanExecutionEpochBinding(
        principal_id=OWNER,
        project_id=PROJECT,
        task_id=task.id,
        goal_spec_id=goal_spec.goal_spec_id,
        goal_spec_digest=goal_spec.semantic_digest,
        workspace_id=WORKSPACE,
        repository_id=REPOSITORY,
        base_revision="base-a",
        workspace_generation=1,
        plan_revision_id=stored.plan_revision_id,
        plan_revision_digest=stored.revision.plan_semantic_digest,
        recovery_decision_id=current.last_applied_recovery_decision_id,
    )
    binding = PlanToolRouteBinding(
        route_id="route-a",
        route_digest="",
        principal_id=OWNER,
        project_id=PROJECT,
        task_id=task.id,
        workspace_id=WORKSPACE,
        workspace_generation=1,
        plan_revision_id=stored.plan_revision_id,
        plan_revision_digest=stored.revision.plan_semantic_digest,
        plan_step_id=step.step_id,
        plan_step_digest=canonical_digest(step.to_payload()),
        execution_epoch_digest=epoch.digest(),
        tool_name="write_file",
        tool_security_digest="t" * 64,
        arguments_digest="a" * 64,
        authorization_resource_digest="r" * 64,
        disposition=PlanRouteDisposition.ALLOW,
        reason_code="matched",
    )
    object.__setattr__(binding, "route_digest", binding.recompute_digest())
    return database, binding, step


def _route_variant(binding: PlanToolRouteBinding, route_id: str) -> PlanToolRouteBinding:
    variant = replace(binding, route_id=route_id, route_digest="")
    object.__setattr__(variant, "route_digest", variant.recompute_digest())
    return variant


async def _state_for(database: Database, binding: PlanToolRouteBinding):
    return await database.plan_step_execution_repository.get_step_state(
        principal_id=OWNER,
        project_id=PROJECT,
        task_id=binding.task_id,
        execution_epoch_digest=binding.execution_epoch_digest,
        plan_step_id=binding.plan_step_id,
    )


@pytest.mark.asyncio
async def test_begin_dispatch_rejects_stale_allow_after_executed(tmp_path: Path):
    database, route_a, step = await _dispatch_case(tmp_path / "executed.db")
    try:
        repository = PlanStepExecutionRepository(database)
        pending = await repository.record_effect(
            route_a, effect_status="not_applied", effect_id="seed-pending"
        )
        assert pending is not None and pending.state == "PENDING"
        route_b = _route_variant(route_a, "route-b")

        fence_a = await repository.begin_dispatch(route_a)
        await repository.finish_dispatch(
            fence_a,
            effect_status="applied",
            effect_id="effect-a",
            affected_targets=step.target_files,
        )
        executed = await _state_for(database, route_a)
        assert executed is not None and executed.state == "EXECUTED"

        with pytest.raises(PermissionError, match="durably PENDING"):
            await repository.begin_dispatch(route_b)
        unchanged = await _state_for(database, route_a)
        assert unchanged is not None and unchanged.state == "EXECUTED"
        async with database.read_connection() as conn:
            cursor = await conn.execute(
                "SELECT COUNT(*) AS count FROM agent_plan_dispatch_fences "
                "WHERE task_id = ? AND execution_epoch_digest = ? AND status = 'ACTIVE'",
                (route_a.task_id, route_a.execution_epoch_digest),
            )
            row = await cursor.fetchone()
        assert row["count"] == 0
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_begin_dispatch_rejects_stale_allow_after_uncertain(tmp_path: Path):
    database, route_a, _step = await _dispatch_case(tmp_path / "uncertain.db")
    try:
        repository = PlanStepExecutionRepository(database)
        pending = await repository.record_effect(
            route_a, effect_status="not_applied", effect_id="seed-pending"
        )
        assert pending is not None and pending.state == "PENDING"
        route_b = _route_variant(route_a, "route-b")

        fence_a = await repository.begin_dispatch(route_a)
        await repository.finish_dispatch(
            fence_a, effect_status="partial", effect_id="effect-partial"
        )
        uncertain = await _state_for(database, route_a)
        assert uncertain is not None and uncertain.state == "UNCERTAIN"

        with pytest.raises(PermissionError, match="durably PENDING"):
            await repository.begin_dispatch(route_b)
        unchanged = await _state_for(database, route_a)
        assert unchanged is not None and unchanged.state == "UNCERTAIN"
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_concurrent_dispatches_have_one_pending_to_active_winner(tmp_path: Path):
    database, route_a, step = await _dispatch_case(tmp_path / "concurrent.db")
    try:
        repository = PlanStepExecutionRepository(database)
        assert await _state_for(database, route_a) is None
        route_b = _route_variant(route_a, "route-b")
        results = await asyncio.gather(
            repository.begin_dispatch(route_a),
            repository.begin_dispatch(route_b),
            return_exceptions=True,
        )
        winners = [item for item in results if not isinstance(item, BaseException)]
        rejected = [item for item in results if isinstance(item, PermissionError)]
        assert len(winners) == 1
        assert len(rejected) == 1
        winner = winners[0]
        assert winner.status == "ACTIVE"
        await repository.finish_dispatch(
            winner,
            effect_status="applied",
            effect_id="effect-winner",
            affected_targets=step.target_files,
        )
        state = await _state_for(database, route_a)
        assert state is not None and state.state == "EXECUTED"
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_parent_and_delegated_child_share_monotonic_step_state(tmp_path: Path):
    database, parent_route, step = await _dispatch_case(tmp_path / "parent-child.db")
    try:
        repository = PlanStepExecutionRepository(database)
        pending = await repository.record_effect(
            parent_route, effect_status="not_applied", effect_id="seed-pending"
        )
        assert pending is not None and pending.state == "PENDING"
        child_principal = f"subagent:{OWNER}:child-1"
        snapshot = await database.plan_revision_repository.get_current_task_snapshot(
            parent_route.task_id, principal_id=OWNER, project_id=PROJECT
        )
        assert snapshot is not None
        published = await database.plan_revision_repository.get_published_for_task(
            parent_route.task_id, principal_id=OWNER, project_id=PROJECT
        )
        assert published is not None
        assignment = SubAgentAssignment(
            schema_version=ASSIGNMENT_SCHEMA_VERSION,
            assignment_id="assignment-monotonic",
            assignment_sequence=1,
            task_owner_principal_id=OWNER,
            project_id=PROJECT,
            parent_task_id=parent_route.task_id,
            goal_spec_id=published.revision.goal_spec_id,
            goal_spec_digest=published.revision.goal_spec_digest,
            parent_task_status=snapshot.task_status,
            parent_cognitive_state=snapshot.cognitive_state.value,
            parent_control_state_version=snapshot.control_state_version,
            workspace_id=parent_route.workspace_id,
            repository_id=REPOSITORY,
            base_revision="base-a",
            workspace_generation=1,
            published_plan_revision_id=parent_route.plan_revision_id,
            published_plan_revision_digest=parent_route.plan_revision_digest,
            execution_epoch_digest=parent_route.execution_epoch_digest,
            plan_step_id=step.step_id,
            plan_step_digest=parent_route.plan_step_digest,
            plan_operation=PlanOperation.MODIFY.value,
            allowed_tools=("write_file",),
            child_execution_principal_id=child_principal,
            child_session_id="session-child-1",
            child_runtime_id="runtime-child-1",
            depth=1,
            policy_digest=SubAgentPolicy().policy_digest,
            created_at=utc_now_naive().isoformat(),
        )
        stored_assignment = await database.subagent_assignment_repository.append(
            assignment
        )
        assert await database.subagent_assignment_repository.activate(
            stored_assignment.assignment_id
        )
        child_route = replace(
            parent_route,
            route_id="route-child",
            route_digest="",
            execution_principal_id=child_principal,
            subagent_assignment_id=stored_assignment.assignment_id,
            subagent_assignment_digest=stored_assignment.assignment_digest,
        )
        object.__setattr__(child_route, "route_digest", child_route.recompute_digest())

        results = await asyncio.gather(
            repository.begin_dispatch(parent_route),
            repository.begin_dispatch(child_route),
            return_exceptions=True,
        )
        winners = [item for item in results if not isinstance(item, BaseException)]
        rejected = [item for item in results if isinstance(item, PermissionError)]
        assert len(winners) == 1
        assert len(rejected) == 1
        await repository.finish_dispatch(
            winners[0],
            effect_status="applied",
            effect_id="parent-child-winner",
            affected_targets=step.target_files,
        )
        state = await _state_for(database, parent_route)
        assert state is not None and state.state == "EXECUTED"
        stale = child_route if winners[0].route_id == parent_route.route_id else parent_route
        with pytest.raises(PermissionError, match="durably PENDING"):
            await repository.begin_dispatch(stale)
        final = await _state_for(database, parent_route)
        assert final is not None and final.state == "EXECUTED"
    finally:
        await database.close()


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
