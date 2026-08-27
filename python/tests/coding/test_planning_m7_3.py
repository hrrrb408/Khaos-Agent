"""M7.3 context-bound deterministic planning control-plane tests."""

from __future__ import annotations

import asyncio
import hashlib
import sqlite3
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from khaos.agent.control.goal import GoalSpec
from khaos.agent.control.state import AgentCognitiveState
from khaos.coding.intelligence.context import (
    ContextBundle,
    ContextDocument,
    ContextFreshness,
    ContextRequest,
    ContextSourceKind,
)
from khaos.coding.planning.coordinator import (
    PlanningControlCoordinator,
    PlanningControlStatus,
)
from khaos.coding.planning.repository import (
    PlanRevisionConflictError,
    PlanRevisionIntegrityError,
)
from khaos.coding.planning.revision import (
    PLANNER_ALGORITHM_VERSION,
    PLANNING_SCHEMA_VERSION,
    PlanDisposition,
    PlanningContractError,
    PlanningInput,
    plan_revision_from_canonical_json,
)
from khaos.coding.planning.service import DeterministicPlanningService
from khaos.coding.task_manager import TaskManager, TaskStatus
from khaos.db import Database

OWNER = "m7-owner"
PROJECT = "m7-project"
WORKSPACE = "workspace-a"
REPOSITORY = "repository-a"
BASE_REVISION = "base-a"


def _content_digest(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _request(
    goal_spec: GoalSpec,
    *,
    task_id: str = "task-a",
    target_files: tuple[str, ...] = (),
    target_symbols: tuple[str, ...] = (),
) -> ContextRequest:
    return ContextRequest(
        task_id=task_id,
        principal_id=OWNER,
        project_id=PROJECT,
        goal_spec_id=goal_spec.goal_spec_id,
        goal_spec_digest=goal_spec.semantic_digest,
        workspace_id=WORKSPACE,
        repository_id=REPOSITORY,
        query=goal_spec.normalized_goal,
        base_revision=BASE_REVISION,
        target_files=target_files,
        target_symbols=target_symbols,
    )


def _document(path: str, content: str, *, relevance_score: int = 1) -> ContextDocument:
    digest = _content_digest(content)
    return ContextDocument(
        relative_path=path,
        language="python",
        content=content,
        content_digest=digest,
        file_size=len(content.encode("utf-8")),
        source_kind=ContextSourceKind.WORKSPACE_SNAPSHOT,
        workspace_id=WORKSPACE,
        repository_id=REPOSITORY,
        base_revision=BASE_REVISION,
        repository_generation="repository-generation-1",
        index_generation="index-generation-1",
        excerpt_end=len(content.encode("utf-8")),
        relevance_score=relevance_score,
    )


def _bundle(
    request: ContextRequest,
    goal_spec: GoalSpec,
    *,
    documents: tuple[ContextDocument, ...] = (),
    freshness: ContextFreshness = ContextFreshness.FRESH,
    truncated: bool = False,
    truncation_reasons: tuple[str, ...] = (),
) -> ContextBundle:
    return ContextBundle(
        bundle_id=f"bundle-{request.task_id}",
        task_id=request.task_id,
        principal_id=request.principal_id,
        project_id=request.project_id,
        goal_spec_id=goal_spec.goal_spec_id,
        goal_spec_digest=goal_spec.semantic_digest,
        workspace_id=request.workspace_id,
        repository_id=request.repository_id,
        base_revision=request.base_revision,
        request_digest=request.request_digest,
        repository_generation="repository-generation-1",
        index_generation="index-generation-1",
        freshness=freshness,
        documents=documents,
        truncated=truncated,
        truncation_reasons=truncation_reasons,
    )


def _planning_input(
    goal_spec: GoalSpec,
    request: ContextRequest,
    bundle: ContextBundle,
    *,
    cognitive_state: AgentCognitiveState = AgentCognitiveState.UNDERSTANDING,
    control_state_version: int = 0,
    task_status: str = "running",
) -> PlanningInput:
    return PlanningInput(
        schema_version=PLANNING_SCHEMA_VERSION,
        task_id=request.task_id,
        principal_id=request.principal_id,
        project_id=request.project_id,
        goal_spec_id=goal_spec.goal_spec_id,
        goal_spec_digest=goal_spec.semantic_digest,
        workspace_id=bundle.workspace_id,
        repository_id=bundle.repository_id,
        base_revision=bundle.base_revision,
        context_bundle_id=bundle.bundle_id,
        context_bundle_digest=bundle.bundle_digest,
        context_request_digest=bundle.request_digest,
        repository_generation=bundle.repository_generation,
        index_generation=bundle.index_generation,
        context_freshness=bundle.freshness,
        cognitive_state=cognitive_state,
        control_state_version=control_state_version,
        task_status=task_status,
        planner_schema_version=PLANNING_SCHEMA_VERSION,
        planner_algorithm_version=PLANNER_ALGORITHM_VERSION,
        target_files=request.target_files,
        target_symbols=request.target_symbols,
        context_truncated=bundle.truncated,
        truncation_reasons=bundle.truncation_reasons,
    )


def _build_revision(
    *,
    goal_spec: GoalSpec,
    task_id: str = "task-a",
    documents: tuple[ContextDocument, ...] = (),
    target_files: tuple[str, ...] = (),
    freshness: ContextFreshness = ContextFreshness.FRESH,
    truncated: bool = False,
    truncation_reasons: tuple[str, ...] = (),
    cognitive_state: AgentCognitiveState = AgentCognitiveState.UNDERSTANDING,
    control_state_version: int = 0,
    task_status: str = "running",
):
    request = _request(
        goal_spec,
        task_id=task_id,
        target_files=target_files,
    )
    bundle = _bundle(
        request,
        goal_spec,
        documents=documents,
        freshness=freshness,
        truncated=truncated,
        truncation_reasons=truncation_reasons,
    )
    planning_input = _planning_input(
        goal_spec,
        request,
        bundle,
        cognitive_state=cognitive_state,
        control_state_version=control_state_version,
        task_status=task_status,
    )
    service = DeterministicPlanningService(None, repositories={})
    return service.plan_from_context(
        goal_spec=goal_spec,
        planning_input=planning_input,
        context_bundle=bundle,
    )


def test_context_bound_plan_is_immutable_and_digest_deterministic() -> None:
    goal_spec = GoalSpec.from_user_goal("修复 foo.py")
    first_document = _document("foo.py", "def repair_target():\n    return 1\n")
    second_document = _document("bar.py", "def related_target():\n    return 2\n")
    first = _build_revision(
        goal_spec=goal_spec,
        documents=(second_document, first_document),
        target_files=("foo.py",),
    )
    reversed_revision = _build_revision(
        goal_spec=goal_spec,
        documents=(first_document, second_document),
        target_files=("foo.py",),
    )

    assert first.disposition is PlanDisposition.READY
    assert first.plan_semantic_digest == reversed_revision.plan_semantic_digest
    decoded = plan_revision_from_canonical_json(
        first.canonical_json(),
        expected_digest=first.plan_semantic_digest,
    )
    assert decoded.plan_semantic_digest == first.plan_semantic_digest
    identity_only_change = replace(
        first,
        plan_revision_id="server-assigned-id",
        revision_sequence=1,
        created_at="2026-08-27T00:00:00+00:00",
    )
    assert identity_only_change.plan_semantic_digest == first.plan_semantic_digest

    changed_summary = replace(
        first,
        summary="a different deterministic summary",
        plan_semantic_digest="",
    )
    assert changed_summary.plan_semantic_digest != first.plan_semantic_digest
    with pytest.raises((AttributeError, TypeError)):
        first.steps[0].title = "mutated"  # type: ignore[misc]


def test_stale_or_global_incomplete_context_never_becomes_ready() -> None:
    goal_spec = GoalSpec.from_user_goal("修复 foo.py")
    document = _document("foo.py", "def repair_target():\n    return 1\n")
    stale = _build_revision(
        goal_spec=goal_spec,
        documents=(document,),
        freshness=ContextFreshness.STALE,
    )
    assert stale.disposition is PlanDisposition.STALE

    global_goal = GoalSpec.from_user_goal("对整个项目进行 repository-wide 修改")
    complete_context = _build_revision(
        goal_spec=global_goal,
        documents=(document,),
    )
    assert complete_context.disposition is PlanDisposition.BLOCKED
    assert any(
        item.code == "global-target-unbound" for item in complete_context.diagnostics
    )

    truncated_local = _build_revision(
        goal_spec=goal_spec,
        documents=(document,),
        target_files=("foo.py",),
        truncated=True,
        truncation_reasons=("file_excerpt_bound",),
    )
    assert truncated_local.disposition is PlanDisposition.READY
    assert any(
        item.code == "context-truncated" for item in truncated_local.diagnostics
    )

    for goal in (
        "rename foo.py",
        "update dependency lock for foo.py",
        "update security configuration in foo.py",
    ):
        high_risk = _build_revision(
            goal_spec=GoalSpec.from_user_goal(goal),
            documents=(document,),
            target_files=("foo.py",),
            truncated=True,
            truncation_reasons=("repository_bound",),
        )
        assert high_risk.disposition is not PlanDisposition.READY
        assert any(
            item.code == "high-risk-context-incomplete"
            for item in high_risk.diagnostics
        )

    missing_target = _build_revision(
        goal_spec=goal_spec,
        documents=(document,),
    )
    assert missing_target.disposition is PlanDisposition.BLOCKED
    assert any(
        item.code == "missing-explicit-target"
        for item in missing_target.diagnostics
    )


def test_plan_revision_contract_rejects_missing_dependency_and_cycle() -> None:
    goal_spec = GoalSpec.from_user_goal("修复 foo.py")
    revision = _build_revision(
        goal_spec=goal_spec,
        documents=(_document("foo.py", "def target():\n    return 1\n"),),
        target_files=("foo.py",),
    )
    missing_dependency = replace(
        revision.steps[0],
        dependencies=("missing-step",),
    )
    with pytest.raises(PlanningContractError, match="dependency is missing"):
        replace(
            revision,
            steps=(missing_dependency, *revision.steps[1:]),
            plan_semantic_digest="",
        )

    inspect, modify, verify = revision.steps
    cycle_inspect = replace(inspect, dependencies=(verify.step_id,))
    cycle_verify = replace(verify, dependencies=(modify.step_id,))
    cycle_modify = replace(modify, dependencies=(cycle_inspect.step_id,))
    with pytest.raises(PlanningContractError, match="dependency cycle"):
        replace(
            revision,
            steps=(cycle_inspect, cycle_modify, cycle_verify),
            plan_semantic_digest="",
        )


async def _make_task_database(
    path: Path,
    *,
    goal: str = "修复 foo.py",
) -> tuple[Database, TaskManager, object]:
    database = Database(path)
    await database.connect()
    await database.run_migrations()
    manager = TaskManager(
        db=database,
        principal_id=OWNER,
        project_id=PROJECT,
    )
    task = await manager.create(goal)
    await manager.update_status(task.id, TaskStatus.RUNNING)
    initialized = await manager.initialize_cognitive_state(task.id)
    assert initialized.updated
    await manager.update_status(
        task.id,
        TaskStatus.RUNNING,
        workspace_id=WORKSPACE,
        base_sha=BASE_REVISION,
        repository_id=REPOSITORY,
    )
    return database, manager, task


async def _task_revision(
    task: object,
    manager: TaskManager,
    *,
    target_files: tuple[str, ...] = ("foo.py",),
    documents: tuple[ContextDocument, ...] = (),
):
    task_id = task.id  # type: ignore[attr-defined]
    goal_spec = await manager.goal_spec_repository.get_for_task(
        task_id,
        principal_id=OWNER,
        project_id=PROJECT,
    )
    assert goal_spec is not None
    return _build_revision(
        goal_spec=goal_spec,
        task_id=task_id,
        documents=documents or (_document("foo.py", "def target():\n    return 1\n"),),
        target_files=target_files,
        cognitive_state=task.cognitive_state,  # type: ignore[attr-defined]
        control_state_version=task.control_state_version,  # type: ignore[attr-defined]
        task_status=task.status.value,  # type: ignore[attr-defined]
    )


@pytest.mark.asyncio
async def test_plan_revision_repository_binds_owner_sequences_and_is_append_only(
    tmp_path: Path,
) -> None:
    database, manager, task = await _make_task_database(tmp_path / "plans.db")
    try:
        revision = await _task_revision(task, manager)
        stored = await database.plan_revision_repository.append(
            revision,
            principal_id=OWNER,
            project_id=PROJECT,
        )
        assert stored.revision_sequence == 1
        assert stored.revision.parent_revision_id is None
        assert (
            await database.plan_revision_repository.get_latest_for_task(
                task.id,
                principal_id=OWNER,
                project_id=PROJECT,
            )
        ).plan_revision_id == stored.plan_revision_id

        second = replace(revision, parent_revision_id=stored.plan_revision_id)
        second_stored = await database.plan_revision_repository.append(
            second,
            principal_id=OWNER,
            project_id=PROJECT,
        )
        assert second_stored.revision_sequence == 2
        assert second_stored.revision.parent_revision_id == stored.plan_revision_id
        assert (
            await database.plan_revision_repository.get_latest_for_task(
                task.id,
                principal_id="foreign-owner",
                project_id=PROJECT,
            )
            is None
        )

        with pytest.raises(sqlite3.IntegrityError):
            async with database.transaction() as conn:
                await conn.execute(
                    "UPDATE agent_plan_revisions SET plan_semantic_digest = ? "
                    "WHERE plan_revision_id = ?",
                    ("0" * 64, stored.plan_revision_id),
                )
        with pytest.raises(sqlite3.IntegrityError):
            async with database.transaction() as conn:
                await conn.execute(
                    "DELETE FROM agent_plan_revisions WHERE plan_revision_id = ?",
                    (stored.plan_revision_id,),
                )
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_plan_revision_repository_rejects_malformed_latest_without_fallback(
    tmp_path: Path,
) -> None:
    database, manager, task = await _make_task_database(tmp_path / "malformed.db")
    try:
        revision = await _task_revision(task, manager)
        stored = await database.plan_revision_repository.append(
            revision,
            principal_id=OWNER,
            project_id=PROJECT,
        )
        columns = (
            "plan_revision_id", "task_id", "principal_id", "project_id",
            "revision_sequence", "parent_revision_id", "schema_version",
            "planner_schema_version", "planner_algorithm_version", "goal_spec_id",
            "goal_spec_digest", "workspace_id", "repository_id", "base_revision",
            "context_bundle_id", "context_bundle_digest", "context_request_digest",
            "repository_generation", "index_generation", "context_freshness",
            "cognitive_state", "control_state_version", "task_status", "disposition",
            "planning_input_digest", "plan_semantic_digest", "canonical_json",
            "created_at",
        )
        placeholders = ", ".join("?" for _ in columns)
        async with database.transaction() as conn:
            row = await (
                await conn.execute(
                    "SELECT * FROM agent_plan_revisions WHERE plan_revision_id = ?",
                    (stored.plan_revision_id,),
                )
            ).fetchone()
            values = [row[column] for column in columns]
            values[0] = "malformed-latest"
            values[4] = 99
            values[26] = "{"  # canonical_json
            await conn.execute(
                "INSERT INTO agent_plan_revisions ("
                + ", ".join(columns)
                + ") VALUES ("
                + placeholders
                + ")",
                values,
            )
        with pytest.raises(PlanRevisionIntegrityError, match="plan revision"):
            await database.plan_revision_repository.get_latest_for_task(
                task.id,
                principal_id=OWNER,
                project_id=PROJECT,
            )
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_plan_revision_append_uses_parent_as_concurrent_history_fence(
    tmp_path: Path,
) -> None:
    database, manager, task = await _make_task_database(tmp_path / "race.db")
    try:
        revision = await _task_revision(task, manager)
        results = await asyncio.gather(
            database.plan_revision_repository.append(
                revision,
                principal_id=OWNER,
                project_id=PROJECT,
            ),
            database.plan_revision_repository.append(
                revision,
                principal_id=OWNER,
                project_id=PROJECT,
            ),
            return_exceptions=True,
        )
        assert sum(not isinstance(result, Exception) for result in results) == 1
        assert sum(isinstance(result, PlanRevisionConflictError) for result in results) == 1
        latest = await database.plan_revision_repository.get_latest_for_task(
            task.id,
            principal_id=OWNER,
            project_id=PROJECT,
        )
        assert latest is not None
        assert latest.revision_sequence == 1
        assert latest.revision.parent_revision_id is None
    finally:
        await database.close()


class _FakeContextIntelligence:
    def __init__(self, paths: tuple[str, ...]) -> None:
        self._paths = paths

    def repository_id_for_workspace(self, workspace: object) -> str:
        del workspace
        return REPOSITORY

    async def retrieve(
        self,
        request: ContextRequest,
        goal_spec: GoalSpec,
    ) -> ContextBundle:
        documents = tuple(
            _document(path, f"def {Path(path).stem}_target():\n    return 1\n")
            for path in self._paths
        )
        return _bundle(request, goal_spec, documents=documents)


class _EventSink:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, object]]] = []

    async def emit(self, event_type: str, payload: dict[str, object]) -> None:
        self.events.append((event_type, payload))


class _StatusChangingPlanRepository:
    """Test-only wrapper that races TaskStatus after revision append."""

    def __init__(self, delegate: object, manager: TaskManager, task_id: str) -> None:
        self._delegate = delegate
        self._manager = manager
        self._task_id = task_id

    async def get_current_task_snapshot(self, *args: object, **kwargs: object):
        return await self._delegate.get_current_task_snapshot(*args, **kwargs)

    async def get_latest_for_task(self, *args: object, **kwargs: object):
        return await self._delegate.get_latest_for_task(*args, **kwargs)

    async def append(self, *args: object, **kwargs: object):
        stored = await self._delegate.append(*args, **kwargs)
        await self._manager.update_status(self._task_id, TaskStatus.BLOCKED)
        return stored


class _WorkspaceChangingPlanRepository:
    """Test-only wrapper that races the workspace binding after append."""

    def __init__(self, delegate: object, manager: TaskManager, task_id: str) -> None:
        self._delegate = delegate
        self._manager = manager
        self._task_id = task_id

    async def get_current_task_snapshot(self, *args: object, **kwargs: object):
        return await self._delegate.get_current_task_snapshot(*args, **kwargs)

    async def get_latest_for_task(self, *args: object, **kwargs: object):
        return await self._delegate.get_latest_for_task(*args, **kwargs)

    async def append(self, *args: object, **kwargs: object):
        stored = await self._delegate.append(*args, **kwargs)
        await self._manager.update_status(
            self._task_id,
            TaskStatus.RUNNING,
            workspace_id="workspace-b",
            base_sha=BASE_REVISION,
            repository_id=REPOSITORY,
        )
        return stored


@pytest.mark.asyncio
async def test_planning_coordinator_publishes_ready_without_task_lifecycle_authority(
    tmp_path: Path,
) -> None:
    database, _manager, task = await _make_task_database(tmp_path / "coordinator.db")
    try:
        coordinator = PlanningControlCoordinator(
            planning_service=DeterministicPlanningService(None, repositories={}),
            context_intelligence=_FakeContextIntelligence(("foo.py",)),
            goal_spec_repository=database.goal_spec_repository,
            plan_revision_repository=database.plan_revision_repository,
            control_state_repository=database.agent_control_state_repository,
            principal_id=OWNER,
            project_id=PROJECT,
        )
        sink = _EventSink()
        result = await coordinator.plan(
            task.id,
            workspace=SimpleNamespace(id=WORKSPACE),
            query="修复 foo.py",
            target_files=("foo.py",),
            event_sink=sink,
        )
        assert result.status is PlanningControlStatus.IMPLEMENTING
        assert result.disposition is PlanDisposition.READY
        assert [event[0] for event in sink.events] == [
            "planning.started",
            "planning.revision.created",
        ]
        physical = await database.agent_control_state_repository.get_snapshot(
            task.id,
            principal_id=OWNER,
            project_id=PROJECT,
        )
        assert physical is not None
        assert physical.cognitive_state is AgentCognitiveState.IMPLEMENTING
        assert physical.control_state_version == 3
        assert physical.task_status == TaskStatus.RUNNING.value
        current = await database.list_coding_tasks(
            principal_id=OWNER,
            project_id=PROJECT,
        )
        assert current[0]["status"] == TaskStatus.RUNNING.value
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_planning_publication_status_fence_rejects_post_append_race(
    tmp_path: Path,
) -> None:
    database, manager, task = await _make_task_database(tmp_path / "status-race.db")
    try:
        repository = _StatusChangingPlanRepository(
            database.plan_revision_repository,
            manager,
            task.id,
        )
        coordinator = PlanningControlCoordinator(
            planning_service=DeterministicPlanningService(None, repositories={}),
            context_intelligence=_FakeContextIntelligence(("foo.py",)),
            goal_spec_repository=database.goal_spec_repository,
            plan_revision_repository=repository,  # type: ignore[arg-type]
            control_state_repository=database.agent_control_state_repository,
            principal_id=OWNER,
            project_id=PROJECT,
        )
        result = await coordinator.plan(
            task.id,
            workspace=SimpleNamespace(id=WORKSPACE),
            target_files=("foo.py",),
        )
        assert result.status is PlanningControlStatus.STALE
        physical = await database.agent_control_state_repository.get_snapshot(
            task.id,
            principal_id=OWNER,
            project_id=PROJECT,
        )
        assert physical is not None
        assert physical.cognitive_state is AgentCognitiveState.PLANNING
        assert physical.task_status == TaskStatus.BLOCKED.value
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_planning_publication_workspace_fence_rejects_post_append_race(
    tmp_path: Path,
) -> None:
    database, manager, task = await _make_task_database(tmp_path / "workspace-race.db")
    try:
        repository = _WorkspaceChangingPlanRepository(
            database.plan_revision_repository,
            manager,
            task.id,
        )
        coordinator = PlanningControlCoordinator(
            planning_service=DeterministicPlanningService(None, repositories={}),
            context_intelligence=_FakeContextIntelligence(("foo.py",)),
            goal_spec_repository=database.goal_spec_repository,
            plan_revision_repository=repository,  # type: ignore[arg-type]
            control_state_repository=database.agent_control_state_repository,
            principal_id=OWNER,
            project_id=PROJECT,
        )
        result = await coordinator.plan(
            task.id,
            workspace=SimpleNamespace(id=WORKSPACE),
            target_files=("foo.py",),
        )
        assert result.status is PlanningControlStatus.STALE
        physical = await database.agent_control_state_repository.get_snapshot(
            task.id,
            principal_id=OWNER,
            project_id=PROJECT,
        )
        assert physical is not None
        assert physical.cognitive_state is AgentCognitiveState.PLANNING
        assert physical.task_status == TaskStatus.RUNNING.value
        current = await database.plan_revision_repository.get_current_task_snapshot(
            task.id,
            principal_id=OWNER,
            project_id=PROJECT,
        )
        assert current is not None
        assert current.workspace_id == "workspace-b"
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_ambiguous_context_records_blocked_plan_without_implementing(
    tmp_path: Path,
) -> None:
    database, _manager, task = await _make_task_database(
        tmp_path / "blocked.db",
        goal="修复相关代码",
    )
    try:
        coordinator = PlanningControlCoordinator(
            planning_service=DeterministicPlanningService(None, repositories={}),
            context_intelligence=_FakeContextIntelligence(("foo.py", "bar.py")),
            goal_spec_repository=database.goal_spec_repository,
            plan_revision_repository=database.plan_revision_repository,
            control_state_repository=database.agent_control_state_repository,
            principal_id=OWNER,
            project_id=PROJECT,
        )
        result = await coordinator.plan(
            task.id,
            workspace=SimpleNamespace(id=WORKSPACE),
            query="修复相关代码",
        )
        assert result.status is PlanningControlStatus.BLOCKED
        assert result.disposition is PlanDisposition.BLOCKED
        snapshot = await database.agent_control_state_repository.get_snapshot(
            task.id,
            principal_id=OWNER,
            project_id=PROJECT,
        )
        assert snapshot is not None
        assert snapshot.cognitive_state is AgentCognitiveState.PLANNING
        assert snapshot.task_status == TaskStatus.RUNNING.value
    finally:
        await database.close()
