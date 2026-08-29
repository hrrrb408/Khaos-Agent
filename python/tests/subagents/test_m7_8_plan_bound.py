"""M7.8 contracts: immutable assignments and fail-closed delegation edges."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest
from khaos.db import Database
from khaos.subagents.assignment import (
    AssignmentRunState,
    SubAgentAssignment,
    SubAgentPolicy,
)
from khaos.subagents.planner import TaskPlanner


def _assignment() -> SubAgentAssignment:
    return SubAgentAssignment(
        schema_version=1,
        assignment_id="assignment-1",
        assignment_sequence=1,
        task_owner_principal_id="user:alice",
        project_id="project-1",
        parent_task_id="task-1",
        goal_spec_id="goal-1",
        goal_spec_digest="goal-digest",
        parent_task_status="running",
        parent_cognitive_state="implementing",
        parent_control_state_version=3,
        workspace_id="workspace-1",
        repository_id="repo-1",
        base_revision="base-1",
        workspace_generation=1,
        published_plan_revision_id="plan-1",
        published_plan_revision_digest="plan-digest",
        execution_epoch_digest="epoch-digest",
        plan_step_id="step-1",
        plan_step_digest="step-digest",
        plan_operation="modify",
        allowed_tools=("patch",),
        child_execution_principal_id="subagent:user:alice:assignment-1",
        child_session_id="subagent:user:alice:assignment-1/session",
        child_runtime_id="runtime-1",
        depth=1,
        policy_digest=SubAgentPolicy().policy_digest,
        created_at="2026-08-29T00:00:00",
    )


def test_assignment_is_immutable_and_owner_bound() -> None:
    assignment = _assignment()

    with pytest.raises(FrozenInstanceError):
        assignment.plan_step_id = "other-step"  # type: ignore[misc]
    with pytest.raises(ValueError, match="depth 1"):
        SubAgentAssignment(**{**assignment.to_payload(), "depth": 2})


@pytest.mark.asyncio
async def test_assignment_run_is_append_only_and_cas(tmp_path) -> None:
    database = Database(tmp_path / "m7-8.db")
    await database.connect()
    await database.run_migrations()
    repository = database.subagent_assignment_repository
    assignment = _assignment()

    await repository.append(assignment)
    assert await repository.get(
        assignment.assignment_id,
        task_owner_principal_id="user:alice",
        project_id="project-1",
    ) == assignment
    assert await repository.active_count(
        task_owner_principal_id="user:alice",
        project_id="project-1",
        parent_task_id="task-1",
    ) == 1
    assert await repository.activate(assignment.assignment_id)
    assert not await repository.activate(assignment.assignment_id)
    assert await repository.validate_active_for_route(
        assignment_id=assignment.assignment_id,
        assignment_digest=assignment.assignment_digest,
        child_execution_principal_id=assignment.child_execution_principal_id,
        task_owner_principal_id=assignment.task_owner_principal_id,
        project_id=assignment.project_id,
        parent_task_id=assignment.parent_task_id,
        workspace_id=assignment.workspace_id,
        published_plan_revision_id=assignment.published_plan_revision_id,
        plan_step_id=assignment.plan_step_id,
        execution_epoch_digest=assignment.execution_epoch_digest,
    )
    assert await repository.transition(
        assignment.assignment_id,
        expected_version=1,
        state=AssignmentRunState.COMPLETED,
    )
    assert await repository.active_count(
        task_owner_principal_id="user:alice",
        project_id="project-1",
        parent_task_id="task-1",
    ) == 0
    await database.close()


def test_legacy_invalid_dependency_plan_has_no_executable_layers() -> None:
    plan = TaskPlanner.from_json(
        '{"tasks":[{"id":"a","goal":"a"}],'
        '"dependencies":{"a":["missing"]}}'
    )
    assert plan is not None
    assert plan.invalid_reasons
    assert TaskPlanner._topological_layers(plan) == []
