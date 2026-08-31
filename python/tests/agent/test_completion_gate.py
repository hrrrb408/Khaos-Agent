"""M7.1.7 Completion Gate and atomic task projection tests."""

from __future__ import annotations

import asyncio
import json
import uuid
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest
from khaos.agent import AgentConfig, AgentLoop, Message
from khaos.agent.control.completion import (
    AssessmentStatus,
    CompletionDecision,
    RequirementAssessment,
)
from khaos.agent.control.completion_evaluator import (
    CompletionConstraint,
    CompletionConstraintCode,
    CompletionEvaluationSnapshot,
    CompletionEvaluator,
)
from khaos.agent.control.completion_flow import CompletionFactBundle
from khaos.agent.control.completion_gate import (
    CompletionAuthorityResult,
    CompletionAuthorityStatus,
    CompletionGate,
    CompletionGateResult,
    CompletionGateStatus,
)
from khaos.agent.control.completion_gate_repository import CompletionGateRepository
from khaos.agent.control.state import AgentCognitiveState
from khaos.coding.task_manager import CodingTask, TaskManager, TaskStatus
from khaos.db import Database
from khaos.modes import Mode, ModeManager


class _AllowCompletionAuthority:
    """Test-only authority policy bound to the exact loaded decision."""

    def __init__(self, before_return=None) -> None:
        self._before_return = before_return

    async def authorize(
        self,
        *,
        goal_spec,
        decision,
        principal_id,
        project_id,
    ) -> CompletionAuthorityResult:
        if self._before_return is not None:
            await self._before_return(decision)
        return CompletionAuthorityResult(
            task_id=decision.task_id,
            goal_spec_id=goal_spec.goal_spec_id,
            goal_spec_digest=goal_spec.semantic_digest,
            decision_id=decision.decision_id,
            decision_digest=decision.decision_digest,
            status=CompletionAuthorityStatus.AUTHORIZED,
        )


class _SatisfyingFactProvider:
    async def collect(self, *, proposal, goal_spec, snapshot):
        del proposal, snapshot
        return CompletionFactBundle(
            requirement_assessments=tuple(
                RequirementAssessment(
                    requirement_id=requirement.requirement_id,
                    status=AssessmentStatus.SATISFIED,
                )
                for requirement in goal_spec.requirements
                if requirement.required
            )
        )


class _EndTurnRouter:
    def __init__(self, content: str) -> None:
        self._content = content

    async def call(self, function, messages, **kwargs):
        del function, messages, kwargs
        yield Message(role="assistant", content=self._content)
        yield Message(role="assistant", content="", stop_reason="end_turn")


async def _make_db(path: Path) -> Database:
    db = Database(path)
    await db.connect()
    await db.run_migrations()
    return db


async def _create_running_task(
    db: Database,
    *,
    workspace_id: str | None = None,
    principal_id: str = "alice",
    project_id: str = "project-a",
) -> tuple[TaskManager, CodingTask]:
    manager = TaskManager(
        db=db,
        principal_id=principal_id,
        project_id=project_id,
    )
    task = await manager.create("修复目标并保留验证证据")
    assert (await manager.update_status(task.id, TaskStatus.RUNNING)).value == "updated"
    initialized = await manager.initialize_cognitive_state(task.id)
    assert initialized.updated
    if workspace_id is not None:
        await manager.update_status(
            task.id,
            TaskStatus.RUNNING,
            workspace_id=workspace_id,
        )
    return manager, task


async def _record_decision(
    db: Database,
    task: CodingTask,
    *,
    principal_id: str = "alice",
    project_id: str = "project-a",
    outcome_constraint: CompletionConstraint | None = None,
) -> CompletionDecision:
    goal_spec = await db.goal_spec_repository.get_for_task(
        task.id,
        principal_id=principal_id,
        project_id=project_id,
    )
    assert goal_spec is not None
    snapshot = await db.completion_decision_repository.read_current_task_snapshot(
        task.id,
        principal_id=principal_id,
        project_id=project_id,
        goal_spec=goal_spec,
    )
    assert snapshot is not None
    decision = CompletionEvaluator.evaluate(
        decision_id=f"decision-{uuid.uuid4().hex}",
        goal_spec=goal_spec,
        snapshot=snapshot,
        requirement_assessments=tuple(
            RequirementAssessment(
                requirement_id=requirement.requirement_id,
                status=AssessmentStatus.SATISFIED,
            )
            for requirement in goal_spec.requirements
            if requirement.required
        ),
        constraints=(
            (outcome_constraint,)
            if outcome_constraint is not None
            else ()
        ),
    )
    await db.completion_decision_repository.append(
        decision,
        principal_id=principal_id,
        project_id=project_id,
    )
    return decision


def _gate(
    db: Database,
    *,
    manager: TaskManager | None = None,
    authority=None,
    principal_id: str = "alice",
    project_id: str = "project-a",
) -> CompletionGate:
    return CompletionGate(
        decision_repository=db.completion_decision_repository,
        goal_spec_repository=db.goal_spec_repository,
        principal_id=principal_id,
        project_id=project_id,
        authority_policy=authority,
        task_projection=manager,
    )


@pytest.mark.asyncio
async def test_authorized_fresh_complete_projects_atomically(tmp_path: Path) -> None:
    db = await _make_db(tmp_path / "fresh.db")
    try:
        manager, task = await _create_running_task(db)
        decision = await _record_decision(db, task)

        result = await _gate(
            db,
            manager=manager,
            authority=_AllowCompletionAuthority(),
        ).evaluate(decision.decision_id)

        assert result.status is CompletionGateStatus.COMPLETED
        assert result.task_status == TaskStatus.COMPLETED.value
        assert (await manager.get(task.id)).status is TaskStatus.COMPLETED
        rows = await db.list_coding_tasks(
            principal_id="alice",
            project_id="project-a",
        )
        assert rows[0]["status"] == TaskStatus.COMPLETED.value
        async with db.read_connection() as conn:
            cursor = await conn.execute(
                "SELECT state_json FROM coding_tasks WHERE id = ?",
                (task.id,),
            )
            state_row = await cursor.fetchone()
        assert state_row is not None
        assert json.loads(state_row["state_json"])["status"] == "completed"
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_default_authority_is_fail_closed(tmp_path: Path) -> None:
    db = await _make_db(tmp_path / "default-deny.db")
    try:
        _, task = await _create_running_task(db)
        decision = await _record_decision(db, task)

        result = await _gate(db).evaluate(decision.decision_id)

        assert result.status is CompletionGateStatus.AUTHORITY_INSUFFICIENT
        assert (
            await db.list_coding_tasks(
                principal_id="alice",
                project_id="project-a",
            )
        )[0]["status"] == TaskStatus.RUNNING.value
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_non_complete_outcomes_never_project(tmp_path: Path) -> None:
    db = await _make_db(tmp_path / "passive-outcomes.db")
    try:
        constraints = (
            CompletionConstraintCode.PLAN_INCOMPLETE,
            CompletionConstraintCode.EXTERNAL_BLOCKER,
            CompletionConstraintCode.UNRECOVERABLE_FAILURE,
        )
        expected = (
            CompletionGateStatus.NOT_COMPLETE,
            CompletionGateStatus.NOT_COMPLETE,
            CompletionGateStatus.NOT_COMPLETE,
        )
        for code, expected_status in zip(constraints, expected, strict=True):
            manager, task = await _create_running_task(db)
            decision = await _record_decision(
                db,
                task,
                outcome_constraint=CompletionConstraint(code),
            )
            result = await _gate(
                db,
                manager=manager,
                authority=_AllowCompletionAuthority(),
            ).evaluate(decision.decision_id)
            assert result.status is expected_status
            assert (await manager.get(task.id)).status is not TaskStatus.COMPLETED
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_stale_cognitive_snapshot_is_rejected(tmp_path: Path) -> None:
    db = await _make_db(tmp_path / "stale-cognitive.db")
    try:
        manager, task = await _create_running_task(db)
        decision = await _record_decision(db, task)
        changed = await manager.transition_cognitive_state(
            task.id,
            target=AgentCognitiveState.EXPLORING,
            expected_state=AgentCognitiveState.UNDERSTANDING,
            expected_version=1,
        )
        assert changed.updated

        result = await _gate(
            db,
            authority=_AllowCompletionAuthority(),
        ).evaluate(decision.decision_id)

        assert result.status is CompletionGateStatus.STALE
        assert (await manager.get(task.id)).status is not TaskStatus.COMPLETED
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_stale_task_status_is_rejected(tmp_path: Path) -> None:
    db = await _make_db(tmp_path / "stale-status.db")
    try:
        manager, task = await _create_running_task(db)
        decision = await _record_decision(db, task)
        assert (
            await manager.update_status(task.id, TaskStatus.BLOCKED)
        ).value == "updated"

        result = await _gate(
            db,
            authority=_AllowCompletionAuthority(),
        ).evaluate(decision.decision_id)

        assert result.status is CompletionGateStatus.STALE
        assert (await manager.get(task.id)).status is TaskStatus.BLOCKED
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_stale_workspace_snapshot_is_rejected(tmp_path: Path) -> None:
    db = await _make_db(tmp_path / "stale-workspace.db")
    try:
        manager, task = await _create_running_task(db, workspace_id="workspace-1")
        decision = await _record_decision(db, task)
        await manager.update_status(
            task.id,
            TaskStatus.RUNNING,
            workspace_id="workspace-2",
        )

        result = await _gate(
            db,
            authority=_AllowCompletionAuthority(),
        ).evaluate(decision.decision_id)

        assert result.status is CompletionGateStatus.STALE
        assert (await manager.get(task.id)).status is not TaskStatus.COMPLETED
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_malformed_workspace_projection_fails_closed(tmp_path: Path) -> None:
    db = await _make_db(tmp_path / "malformed-workspace.db")
    try:
        _manager, task = await _create_running_task(db)
        decision = await _record_decision(db, task)
        async with db.transaction() as conn:
            await conn.execute(
                "UPDATE coding_tasks SET state_json = ? WHERE id = ?",
                (json.dumps({"metadata": {"workspace_id": 123}}), task.id),
            )

        result = await _gate(
            db,
            authority=_AllowCompletionAuthority(),
        ).evaluate(decision.decision_id)

        assert result.status is CompletionGateStatus.ERROR
        assert (
            await db.list_coding_tasks(
                principal_id="alice",
                project_id="project-a",
            )
        )[0]["status"] == TaskStatus.RUNNING.value
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_goal_spec_binding_mismatch_is_rejected(tmp_path: Path) -> None:
    db = await _make_db(tmp_path / "goal-spec-mismatch.db")
    try:
        _, task_a = await _create_running_task(db)
        _, task_b = await _create_running_task(db)
        spec_a = await db.goal_spec_repository.get_for_task(
            task_a.id,
            principal_id="alice",
            project_id="project-a",
        )
        spec_b = await db.goal_spec_repository.get_for_task(
            task_b.id,
            principal_id="alice",
            project_id="project-a",
        )
        snapshot_a = await db.completion_decision_repository.read_current_task_snapshot(
            task_a.id,
            principal_id="alice",
            project_id="project-a",
            goal_spec=spec_a,
        )
        assert spec_a is not None
        assert spec_b is not None
        assert snapshot_a is not None
        mismatched_snapshot = CompletionEvaluationSnapshot(
            task_id=task_a.id,
            goal_spec_id=spec_b.goal_spec_id,
            goal_spec_digest=spec_b.semantic_digest,
            cognitive_state=snapshot_a.cognitive_state,
            control_state_version=snapshot_a.control_state_version,
            task_status=snapshot_a.task_status,
            workspace_id=snapshot_a.workspace_id,
        )
        mismatched = CompletionEvaluator.evaluate(
            decision_id=f"mismatched-{uuid.uuid4().hex}",
            goal_spec=spec_b,
            snapshot=mismatched_snapshot,
            requirement_assessments=tuple(
                RequirementAssessment(
                    requirement_id=requirement.requirement_id,
                    status=AssessmentStatus.SATISFIED,
                )
                for requirement in spec_b.requirements
                if requirement.required
            ),
        )
        async with db.transaction() as conn:
            await conn.execute(
                """
                INSERT INTO agent_completion_decisions (
                    decision_id, task_id, principal_id, project_id,
                    decision_sequence, schema_version, decision_digest,
                    canonical_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    mismatched.decision_id,
                    task_a.id,
                    "alice",
                    "project-a",
                    1,
                    mismatched.schema_version,
                    mismatched.decision_digest,
                    mismatched.canonical_json(),
                    "2026-08-27T00:00:00",
                ),
            )

        result = await _gate(
            db,
            authority=_AllowCompletionAuthority(),
        ).evaluate(mismatched.decision_id)

        assert result.status in {
            CompletionGateStatus.REJECTED,
            CompletionGateStatus.STALE,
        }
        assert (
            await db.list_coding_tasks(
                principal_id="alice",
                project_id="project-a",
            )
        )[0]["status"] == TaskStatus.RUNNING.value
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_foreign_project_cannot_gate_decision(tmp_path: Path) -> None:
    db = await _make_db(tmp_path / "project-isolation.db")
    try:
        _, task = await _create_running_task(db)
        decision = await _record_decision(db, task)

        result = await _gate(
            db,
            authority=_AllowCompletionAuthority(),
            principal_id="alice",
            project_id="project-b",
        ).evaluate(decision.decision_id)

        assert result.status is CompletionGateStatus.REJECTED
        assert (
            await db.list_coding_tasks(
                principal_id="alice",
                project_id="project-a",
            )
        )[0]["status"] == TaskStatus.RUNNING.value
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_authority_insufficient_result_cannot_project(tmp_path: Path) -> None:
    db = await _make_db(tmp_path / "authority-binding.db")
    try:
        _, task = await _create_running_task(db)
        decision = await _record_decision(db, task)

        class _WrongBindingAuthority:
            async def authorize(self, *, goal_spec, decision, principal_id, project_id):
                del goal_spec, principal_id, project_id
                return CompletionAuthorityResult(
                    task_id="other-task",
                    goal_spec_id=decision.goal_spec_id,
                    goal_spec_digest=decision.goal_spec_digest,
                    decision_id=decision.decision_id,
                    decision_digest=decision.decision_digest,
                    status=CompletionAuthorityStatus.AUTHORIZED,
                )

        result = await _gate(
            db,
            authority=_WrongBindingAuthority(),
        ).evaluate(decision.decision_id)

        assert result.status is CompletionGateStatus.REJECTED
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_explicit_authority_rejection_is_not_projectable(tmp_path: Path) -> None:
    db = await _make_db(tmp_path / "authority-rejected.db")
    try:
        _, task = await _create_running_task(db)
        decision = await _record_decision(db, task)

        class _RejectedAuthority:
            async def authorize(self, *, goal_spec, decision, principal_id, project_id):
                del goal_spec, principal_id, project_id
                return CompletionAuthorityResult(
                    task_id=decision.task_id,
                    goal_spec_id=decision.goal_spec_id,
                    goal_spec_digest=decision.goal_spec_digest,
                    decision_id=decision.decision_id,
                    decision_digest=decision.decision_digest,
                    status=CompletionAuthorityStatus.REJECTED,
                    reason="policy rejected completion",
                )

        result = await _gate(
            db,
            authority=_RejectedAuthority(),
        ).evaluate(decision.decision_id)

        assert result.status is CompletionGateStatus.REJECTED
        assert (
            await db.list_coding_tasks(
                principal_id="alice",
                project_id="project-a",
            )
        )[0]["status"] == TaskStatus.RUNNING.value
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_projection_repository_cannot_be_used_as_free_authority(
    tmp_path: Path,
) -> None:
    db = await _make_db(tmp_path / "repository-owner.db")
    try:
        _, task = await _create_running_task(db)
        decision = await _record_decision(db, task)
        authority = CompletionAuthorityResult(
            task_id=decision.task_id,
            goal_spec_id=decision.goal_spec_id,
            goal_spec_digest=decision.goal_spec_digest,
            decision_id=decision.decision_id,
            decision_digest=decision.decision_digest,
            status=CompletionAuthorityStatus.AUTHORIZED,
        )

        with pytest.raises(PermissionError):
            await CompletionGateRepository(db).project_completion(
                decision.decision_id,
                principal_id="alice",
                project_id="project-a",
                authority=authority,
                gate_token=object(),
            )

        assert (
            await db.list_coding_tasks(
                principal_id="alice",
                project_id="project-a",
            )
        )[0]["status"] == TaskStatus.RUNNING.value
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_task_cache_reflection_requires_gate_token(tmp_path: Path) -> None:
    db = await _make_db(tmp_path / "cache-reflection-owner.db")
    try:
        manager, task = await _create_running_task(db)

        with pytest.raises(TypeError):
            await manager.reflect_gate_completion(task.id)  # type: ignore[call-arg]
        with pytest.raises(PermissionError):
            await manager.reflect_gate_completion(task.id, gate_token=object())

        assert (
            await db.list_coding_tasks(
                principal_id="alice",
                project_id="project-a",
            )
        )[0]["status"] == TaskStatus.RUNNING.value
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_malformed_decision_row_fails_closed(tmp_path: Path) -> None:
    db = await _make_db(tmp_path / "malformed-decision.db")
    try:
        _, task = await _create_running_task(db)
        decision_id = f"malformed-{uuid.uuid4().hex}"
        async with db.transaction() as conn:
            await conn.execute(
                """
                INSERT INTO agent_completion_decisions (
                    decision_id, task_id, principal_id, project_id,
                    decision_sequence, schema_version, decision_digest,
                    canonical_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    decision_id,
                    task.id,
                    "alice",
                    "project-a",
                    99,
                    1,
                    "bad-digest",
                    "not-json",
                    "2026-08-27T00:00:00",
                ),
            )

        result = await _gate(db).evaluate(decision_id)

        assert result.status is CompletionGateStatus.ERROR
        assert (
            await db.list_coding_tasks(
                principal_id="alice",
                project_id="project-a",
            )
        )[0]["status"] == TaskStatus.RUNNING.value
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_foreign_owner_cannot_gate_decision(tmp_path: Path) -> None:
    db = await _make_db(tmp_path / "owner-isolation.db")
    try:
        _, task = await _create_running_task(db)
        decision = await _record_decision(db, task)

        result = await _gate(
            db,
            authority=_AllowCompletionAuthority(),
            principal_id="bob",
            project_id="project-a",
        ).evaluate(decision.decision_id)

        assert result.status is CompletionGateStatus.REJECTED
        assert (
            await db.list_coding_tasks(
                principal_id="alice",
                project_id="project-a",
            )
        )[0]["status"] == TaskStatus.RUNNING.value
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_two_gate_calls_have_one_successful_projection(tmp_path: Path) -> None:
    db = await _make_db(tmp_path / "gate-race.db")
    try:
        _, task = await _create_running_task(db)
        decision = await _record_decision(db, task)
        gates = [
            _gate(db, authority=_AllowCompletionAuthority()),
            _gate(db, authority=_AllowCompletionAuthority()),
        ]

        results = await asyncio.gather(
            *(gate.evaluate(decision.decision_id) for gate in gates)
        )

        statuses = {result.status for result in results}
        assert CompletionGateStatus.COMPLETED in statuses
        assert statuses <= {
            CompletionGateStatus.COMPLETED,
            CompletionGateStatus.ALREADY_TERMINAL,
        }
        assert sum(
            result.status is CompletionGateStatus.COMPLETED for result in results
        ) == 1
        assert (
            await db.list_coding_tasks(
                principal_id="alice",
                project_id="project-a",
            )
        )[0]["status"] == TaskStatus.COMPLETED.value
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_state_change_between_reload_and_projection_is_stale(
    tmp_path: Path,
) -> None:
    db = await _make_db(tmp_path / "gate-state-race.db")
    try:
        manager, task = await _create_running_task(db)
        decision = await _record_decision(db, task)

        async def mutate_before_authorize(_decision) -> None:
            changed = await manager.transition_cognitive_state(
                task.id,
                target=AgentCognitiveState.EXPLORING,
                expected_state=AgentCognitiveState.UNDERSTANDING,
                expected_version=1,
            )
            assert changed.updated

        result = await _gate(
            db,
            authority=_AllowCompletionAuthority(mutate_before_authorize),
        ).evaluate(decision.decision_id)

        assert result.status is CompletionGateStatus.STALE
        assert (
            await db.list_coding_tasks(
                principal_id="alice",
                project_id="project-a",
            )
        )[0]["status"] == TaskStatus.RUNNING.value
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_restart_blocks_task_and_prevents_blind_gate_projection(
    tmp_path: Path,
) -> None:
    db = await _make_db(tmp_path / "restart-before-gate.db")
    try:
        _, task = await _create_running_task(db)
        decision = await _record_decision(db, task)
        restarted = TaskManager(
            db=db,
            principal_id="alice",
            project_id="project-a",
        )
        await restarted.load()
        loaded = await restarted.get(task.id)
        assert loaded is not None
        assert loaded.status is TaskStatus.BLOCKED
        assert loaded.cognitive_state is AgentCognitiveState.UNDERSTANDING
        assert loaded.control_state_version == 1

        result = await _gate(
            db,
            manager=restarted,
            authority=_AllowCompletionAuthority(),
        ).evaluate(decision.decision_id)

        assert result.status is CompletionGateStatus.STALE
        assert loaded.status is TaskStatus.BLOCKED
    finally:
        await db.close()


def test_gate_contracts_are_immutable() -> None:
    result = CompletionGateResult(
        status=CompletionGateStatus.AUTHORITY_INSUFFICIENT,
        decision_id="decision-1",
        decision_digest="d" * 64,
        task_status="running",
    )
    with pytest.raises(FrozenInstanceError):
        result.status = CompletionGateStatus.COMPLETED  # type: ignore[misc]


def test_agent_loop_has_no_legacy_successful_completion_write() -> None:
    source = Path("python/khaos/agent/core.py").read_text(encoding="utf-8")
    assert "update_status(task_id, TaskStatus.COMPLETED)" not in source


@pytest.mark.asyncio
async def test_agent_loop_end_turn_uses_gate_and_preserves_event_order(
    tmp_path: Path,
) -> None:
    prompts = tmp_path / "prompts"
    prompts.mkdir()
    (prompts / "office.md").write_text("office", encoding="utf-8")
    (prompts / "coding.md").write_text("coding", encoding="utf-8")
    db = await _make_db(tmp_path / "agent-gate.db")
    try:
        await db.create_session(
            "s1",
            mode="coding",
            principal_id="alice",
            project_id="project-a",
        )
        mode_manager = ModeManager(
            db,
            project_root=tmp_path,
            principal_id="alice",
            session_id="s1",
            project_id="project-a",
        )
        await mode_manager.switch(Mode.CODING)
        task_manager = TaskManager(
            db=db,
            principal_id="alice",
            project_id="project-a",
        )
        gate = _gate(
            db,
            manager=task_manager,
            authority=_AllowCompletionAuthority(),
        )
        loop = AgentLoop(
            AgentConfig(),
            mode_manager,
            _EndTurnRouter("Done. Everything is complete."),
            db,
            project_root=tmp_path,
            task_manager=task_manager,
            principal_id="alice",
            project_id="project-a",
            completion_fact_provider=_SatisfyingFactProvider(),
            completion_gate=gate,
        )

        output = [message async for message in loop.run("完成目标", "s1")]
        gated = next(message for message in output if message.event == "completion_gated")
        assert gated.metadata["status"] == CompletionGateStatus.COMPLETED.value
        task_rows = await db.list_coding_tasks(
            principal_id="alice",
            project_id="project-a",
        )
        assert task_rows[0]["status"] == TaskStatus.COMPLETED.value
        assert (await task_manager.get(task_rows[0]["id"])).status is TaskStatus.COMPLETED
        assert task_rows[0]["cognitive_state"] == AgentCognitiveState.UNDERSTANDING.value
        assert task_rows[0]["control_state_version"] == 1

        done = next(message for message in output if message.event == "done")
        events = await db.list_agent_turn_events(done.metadata["turn_id"])
        assert [event["event_type"] for event in events] == [
            "turn.started",
            "completion.proposed",
            "completion.evaluated",
            "completion.gated",
            "turn.completed",
        ]
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_assistant_prose_and_complete_decision_do_not_bypass_default_authority(
    tmp_path: Path,
) -> None:
    prompts = tmp_path / "prompts"
    prompts.mkdir()
    (prompts / "office.md").write_text("office", encoding="utf-8")
    (prompts / "coding.md").write_text("coding", encoding="utf-8")
    db = await _make_db(tmp_path / "prose-no-authority.db")
    try:
        await db.create_session(
            "s1",
            mode="coding",
            principal_id="alice",
            project_id="project-a",
        )
        mode_manager = ModeManager(
            db,
            project_root=tmp_path,
            principal_id="alice",
            session_id="s1",
            project_id="project-a",
        )
        await mode_manager.switch(Mode.CODING)
        manager = TaskManager(
            db=db,
            principal_id="alice",
            project_id="project-a",
        )
        loop = AgentLoop(
            AgentConfig(),
            mode_manager,
            _EndTurnRouter("Done. Everything is complete."),
            db,
            project_root=tmp_path,
            task_manager=manager,
            principal_id="alice",
            project_id="project-a",
        )

        output = [message async for message in loop.run("完成目标", "s1")]

        gated = next(message for message in output if message.event == "completion_gated")
        assert gated.metadata["status"] == CompletionGateStatus.NOT_COMPLETE.value
        row = (
            await db.list_coding_tasks(
                principal_id="alice",
                project_id="project-a",
            )
        )[0]
        assert row["status"] == TaskStatus.RUNNING.value
    finally:
        await db.close()
