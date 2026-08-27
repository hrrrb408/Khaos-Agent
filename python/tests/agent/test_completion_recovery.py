"""M7.1.8/M7.1.9 durable completion recovery and closure tests."""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest
from khaos.agent import AgentConfig, AgentLoop
from khaos.agent.control.completion import (
    AssessmentStatus,
    CompletionDecision,
    CompletionOutcome,
    RequirementAssessment,
)
from khaos.agent.control.completion_evaluator import (
    CompletionConstraint,
    CompletionConstraintCode,
    CompletionEvaluator,
)
from khaos.agent.control.completion_gate import (
    CompletionAuthorityResult,
    CompletionAuthorityStatus,
    CompletionGate,
    CompletionGateStatus,
)
from khaos.agent.control.completion_recovery import (
    MAX_COMPLETION_GATE_HISTORY_RECORDS,
    MAX_COMPLETION_GATE_PAYLOAD_BYTES,
    CompletionContinuationState,
    CompletionRecoveryService,
    DatabaseCompletionGateHistoryReader,
)
from khaos.agent.control.goal_repository import GoalSpecIntegrityError
from khaos.coding.task_manager import CodingTask, TaskManager, TaskStatus
from khaos.db import Database


class _AllowCompletionAuthority:
    """Test-only authority used to exercise the already-closed Gate."""

    async def authorize(
        self,
        *,
        goal_spec,
        decision,
        principal_id,
        project_id,
    ) -> CompletionAuthorityResult:
        del principal_id, project_id
        return CompletionAuthorityResult(
            task_id=decision.task_id,
            goal_spec_id=goal_spec.goal_spec_id,
            goal_spec_digest=goal_spec.semantic_digest,
            decision_id=decision.decision_id,
            decision_digest=decision.decision_digest,
            status=CompletionAuthorityStatus.AUTHORIZED,
        )


async def _make_db(path: Path) -> Database:
    db = Database(path)
    await db.connect()
    await db.run_migrations()
    return db


async def _create_running_task(
    db: Database,
    *,
    principal_id: str = "alice",
    project_id: str = "project-a",
) -> tuple[TaskManager, CodingTask]:
    manager = TaskManager(
        db=db,
        principal_id=principal_id,
        project_id=project_id,
    )
    task = await manager.create("完成中文目标并保留 durable continuation")
    assert (await manager.update_status(task.id, TaskStatus.RUNNING)).value == "updated"
    initialized = await manager.initialize_cognitive_state(task.id)
    assert initialized.updated
    return manager, task


async def _record_decision(
    db: Database,
    task: CodingTask,
    *,
    outcome: CompletionOutcome = CompletionOutcome.COMPLETE,
    principal_id: str = "alice",
    project_id: str = "project-a",
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
    constraint_by_outcome = {
        CompletionOutcome.REPLAN: CompletionConstraintCode.PLAN_INCOMPLETE,
        CompletionOutcome.BLOCKED: CompletionConstraintCode.EXTERNAL_BLOCKER,
        CompletionOutcome.FAILED: CompletionConstraintCode.UNRECOVERABLE_FAILURE,
    }
    assessments = tuple(
        RequirementAssessment(
            requirement_id=requirement.requirement_id,
            status=AssessmentStatus.SATISFIED,
        )
        for requirement in goal_spec.requirements
        if requirement.required
    )
    constraints = (
        (CompletionConstraint(constraint_by_outcome[outcome]),)
        if outcome is not CompletionOutcome.COMPLETE
        else ()
    )
    decision = CompletionEvaluator.evaluate(
        decision_id=f"decision-{uuid.uuid4().hex}",
        goal_spec=goal_spec,
        snapshot=snapshot,
        requirement_assessments=assessments,
        constraints=constraints,
    )
    assert decision.outcome is outcome
    await db.completion_decision_repository.append(
        decision,
        principal_id=principal_id,
        project_id=project_id,
    )
    return decision


async def _record_gate_event(
    db: Database,
    task: CodingTask,
    *,
    decision_id: str,
    decision_digest: str | None,
    gate_status: CompletionGateStatus,
    principal_id: str = "alice",
    project_id: str = "project-a",
    resulting_task_status: str | None = None,
    payload_override: dict[str, object] | None = None,
    now: float | None = None,
) -> None:
    """Append a bounded gate event through the existing turn ledger."""
    turn_id = f"turn-{uuid.uuid4().hex}"
    session_id = f"session-{uuid.uuid4().hex}"
    event_now = 1000.0 + len(turn_id) if now is None else now
    await db.create_session(
        session_id,
        mode="coding",
        principal_id=principal_id,
        project_id=project_id,
    )
    await db.start_agent_turn(
        turn_id=turn_id,
        attempt_id=f"attempt-{uuid.uuid4().hex}",
        session_id=session_id,
        task_id=task.id,
        payload={"task_id": task.id},
        now=event_now,
        principal_id=principal_id,
        project_id=project_id,
    )
    payload = payload_override or {
        "task_id": task.id,
        "decision_id": decision_id,
        "decision_digest": decision_digest,
        "gate_status": gate_status.value,
        "resulting_task_status": resulting_task_status,
    }
    await db.append_agent_turn_event(
        turn_id=turn_id,
        expected_sequence=1,
        event_type="completion.gated",
        payload=payload,
        now=event_now + 1,
    )
    await db.append_agent_turn_event(
        turn_id=turn_id,
        expected_sequence=2,
        event_type="turn.completed",
        payload={},
        now=event_now + 2,
        terminal_status="completed",
    )


def _recovery_service(db: Database, *, principal_id: str = "alice", project_id: str = "project-a") -> CompletionRecoveryService:
    return CompletionRecoveryService(
        decision_repository=db.completion_decision_repository,
        goal_spec_repository=db.goal_spec_repository,
        gate_history_reader=DatabaseCompletionGateHistoryReader(db),
        principal_id=principal_id,
        project_id=project_id,
    )


@pytest.mark.asyncio
async def test_replan_decision_survives_restart_as_continuation_requirement(
    tmp_path: Path,
) -> None:
    db = await _make_db(tmp_path / "replan.db")
    try:
        _manager, task = await _create_running_task(db)
        decision = await _record_decision(
            db,
            task,
            outcome=CompletionOutcome.REPLAN,
        )

        restarted = TaskManager(db=db, principal_id="alice", project_id="project-a")
        await restarted.load()
        recovered = await _recovery_service(db).recover(task.id)

        assert recovered is not None
        assert recovered.continuation_state is CompletionContinuationState.REPLAN_REQUIRED
        assert recovered.latest_decision_id == decision.decision_id
        assert recovered.latest_decision_sequence == 1
        assert (await restarted.get(task.id)).status is TaskStatus.BLOCKED
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_old_complete_decision_after_restart_requires_reevaluation(
    tmp_path: Path,
) -> None:
    db = await _make_db(tmp_path / "restart-complete.db")
    try:
        _manager, task = await _create_running_task(db)
        decision = await _record_decision(db, task)
        restarted = TaskManager(db=db, principal_id="alice", project_id="project-a")
        await restarted.load()

        recovered = await _recovery_service(db).recover(task.id)

        assert recovered is not None
        assert recovered.continuation_state is CompletionContinuationState.REEVALUATION_REQUIRED
        assert recovered.latest_decision_id == decision.decision_id
        assert recovered.task_status == TaskStatus.BLOCKED.value
        assert not (await db.completion_decision_repository.list_for_task(
            task.id,
            principal_id="alice",
            project_id="project-a",
        ))[0].decision.continuation_possible
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_complete_with_authority_insufficient_recovers_without_replay(
    tmp_path: Path,
) -> None:
    db = await _make_db(tmp_path / "authority-required.db")
    try:
        _manager, task = await _create_running_task(db)
        decision = await _record_decision(db, task)
        gate = CompletionGate(
            decision_repository=db.completion_decision_repository,
            goal_spec_repository=db.goal_spec_repository,
            principal_id="alice",
            project_id="project-a",
        )
        result = await gate.evaluate(decision.decision_id)
        assert result.status is CompletionGateStatus.AUTHORITY_INSUFFICIENT
        await _record_gate_event(
            db,
            task,
            decision_id=decision.decision_id,
            decision_digest=decision.decision_digest,
            gate_status=result.status,
            resulting_task_status=result.task_status,
        )

        recovered = await _recovery_service(db).recover(task.id)

        assert recovered is not None
        assert recovered.continuation_state is CompletionContinuationState.AUTHORITY_REQUIRED
        assert recovered.gate_status is CompletionGateStatus.AUTHORITY_INSUFFICIENT
        assert (await db.list_coding_tasks(
            principal_id="alice",
            project_id="project-a",
        ))[0]["status"] == TaskStatus.RUNNING.value
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_successful_gate_restart_recovers_terminal_completed(
    tmp_path: Path,
) -> None:
    db = await _make_db(tmp_path / "terminal-completed.db")
    try:
        manager, task = await _create_running_task(db)
        decision = await _record_decision(db, task)
        gate = CompletionGate(
            decision_repository=db.completion_decision_repository,
            goal_spec_repository=db.goal_spec_repository,
            principal_id="alice",
            project_id="project-a",
            authority_policy=_AllowCompletionAuthority(),
            task_projection=manager,
        )
        result = await gate.evaluate(decision.decision_id)
        assert result.status is CompletionGateStatus.COMPLETED
        await _record_gate_event(
            db,
            task,
            decision_id=decision.decision_id,
            decision_digest=decision.decision_digest,
            gate_status=result.status,
            resulting_task_status=TaskStatus.COMPLETED.value,
        )
        restarted = TaskManager(db=db, principal_id="alice", project_id="project-a")
        await restarted.load()

        recovered = await _recovery_service(db).recover(task.id)

        assert recovered is not None
        assert recovered.continuation_state is CompletionContinuationState.TERMINAL_COMPLETED
        assert (await restarted.get(task.id)).status is TaskStatus.COMPLETED
    finally:
        await db.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (TaskStatus.FAILED, CompletionContinuationState.TERMINAL_FAILED),
        (TaskStatus.CANCELLED, CompletionContinuationState.TERMINAL_CANCELLED),
    ],
)
async def test_terminal_task_status_has_precedence(
    tmp_path: Path,
    status: TaskStatus,
    expected: CompletionContinuationState,
) -> None:
    db = await _make_db(tmp_path / f"terminal-{status.value}.db")
    try:
        manager, task = await _create_running_task(db)
        await _record_decision(db, task, outcome=CompletionOutcome.REPLAN)
        assert (await manager.update_status(task.id, status)).value == "updated"

        recovered = await _recovery_service(db).recover(task.id)

        assert recovered is not None
        assert recovered.continuation_state is expected
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_no_decision_after_restart_is_conservative_and_deterministic(
    tmp_path: Path,
) -> None:
    db = await _make_db(tmp_path / "no-decision.db")
    try:
        _manager, task = await _create_running_task(db)
        first = await _recovery_service(db).recover(task.id)
        restarted = TaskManager(db=db, principal_id="alice", project_id="project-a")
        await restarted.load()
        second = await _recovery_service(db).recover(task.id)

        assert first is not None and second is not None
        assert first.continuation_state is CompletionContinuationState.NO_DECISION
        assert second.continuation_state is CompletionContinuationState.NO_DECISION
        assert second.task_status == TaskStatus.BLOCKED.value
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_latest_decision_sequence_wins_without_falling_back(
    tmp_path: Path,
) -> None:
    db = await _make_db(tmp_path / "latest-sequence.db")
    try:
        _manager, task = await _create_running_task(db)
        first = await _record_decision(db, task, outcome=CompletionOutcome.COMPLETE)
        second = await _record_decision(db, task, outcome=CompletionOutcome.REPLAN)

        recovered = await _recovery_service(db).recover(task.id)

        assert recovered is not None
        assert recovered.latest_decision_id == second.decision_id
        assert recovered.latest_decision_id != first.decision_id
        assert recovered.latest_decision_sequence == 2
        assert recovered.continuation_state is CompletionContinuationState.REPLAN_REQUIRED
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_malformed_latest_decision_fails_closed_without_old_fallback(
    tmp_path: Path,
) -> None:
    db = await _make_db(tmp_path / "malformed-latest.db")
    try:
        _manager, task = await _create_running_task(db)
        await _record_decision(db, task, outcome=CompletionOutcome.COMPLETE)
        async with db.transaction() as conn:
            await conn.execute(
                """
                INSERT INTO agent_completion_decisions(
                    decision_id, task_id, principal_id, project_id,
                    decision_sequence, schema_version, decision_digest,
                    canonical_json, created_at
                ) VALUES (?, ?, ?, ?, 2, 1, ?, ?, ?)
                """,
                (
                    "malformed-latest",
                    task.id,
                    "alice",
                    "project-a",
                    "f" * 64,
                    json.dumps({"malformed": True}),
                    "2026-08-27T00:00:00",
                ),
            )

        recovered = await _recovery_service(db).recover(task.id)

        assert recovered is not None
        assert recovered.continuation_state is CompletionContinuationState.INTEGRITY_ERROR
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_gate_history_binding_mismatch_cannot_influence_latest_decision(
    tmp_path: Path,
) -> None:
    db = await _make_db(tmp_path / "gate-binding.db")
    try:
        _manager, task = await _create_running_task(db)
        decision = await _record_decision(db, task)
        await _record_gate_event(
            db,
            task,
            decision_id="foreign-decision",
            decision_digest="f" * 64,
            gate_status=CompletionGateStatus.AUTHORITY_INSUFFICIENT,
        )

        recovered = await _recovery_service(db).recover(task.id)

        assert recovered is not None
        assert recovered.latest_decision_id == decision.decision_id
        assert recovered.gate_status is None
        assert recovered.continuation_state is CompletionContinuationState.REEVALUATION_REQUIRED
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_malformed_gate_history_is_ignored_as_authority(
    tmp_path: Path,
) -> None:
    db = await _make_db(tmp_path / "malformed-gate-history.db")
    try:
        _manager, task = await _create_running_task(db)
        decision = await _record_decision(db, task)
        await _record_gate_event(
            db,
            task,
            decision_id=decision.decision_id,
            decision_digest=decision.decision_digest,
            gate_status=CompletionGateStatus.AUTHORITY_INSUFFICIENT,
            payload_override={
                "task_id": task.id,
                "decision_id": decision.decision_id,
                "decision_digest": decision.decision_digest,
                "gate_status": "not-a-gate-status",
                "resulting_task_status": None,
            },
        )

        recovered = await _recovery_service(db).recover(task.id)

        assert recovered is not None
        assert recovered.continuation_state is CompletionContinuationState.REEVALUATION_REQUIRED
        assert recovered.gate_status is None
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_newer_malformed_gate_history_cannot_fall_back_to_older_valid_result(
    tmp_path: Path,
) -> None:
    db = await _make_db(tmp_path / "malformed-newer-gate-history.db")
    try:
        _manager, task = await _create_running_task(db)
        decision = await _record_decision(db, task)
        await _record_gate_event(
            db,
            task,
            decision_id=decision.decision_id,
            decision_digest=decision.decision_digest,
            gate_status=CompletionGateStatus.AUTHORITY_INSUFFICIENT,
            now=1000.0,
        )
        await _record_gate_event(
            db,
            task,
            decision_id=decision.decision_id,
            decision_digest=decision.decision_digest,
            gate_status=CompletionGateStatus.AUTHORITY_INSUFFICIENT,
            payload_override={
                "task_id": task.id,
                "decision_id": decision.decision_id,
                "decision_digest": decision.decision_digest,
                "gate_status": "malformed-status",
                "resulting_task_status": None,
            },
            now=2000.0,
        )

        recovered = await _recovery_service(db).recover(task.id)

        assert recovered is not None
        assert recovered.continuation_state is CompletionContinuationState.REEVALUATION_REQUIRED
        assert recovered.gate_status is None
        assert "no current gate result" in recovered.reason
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_oversized_gate_history_is_ignored_as_authority(
    tmp_path: Path,
) -> None:
    db = await _make_db(tmp_path / "oversized-gate-history.db")
    try:
        _manager, task = await _create_running_task(db)
        decision = await _record_decision(db, task)
        await _record_gate_event(
            db,
            task,
            decision_id=decision.decision_id,
            decision_digest=decision.decision_digest,
            gate_status=CompletionGateStatus.AUTHORITY_INSUFFICIENT,
            payload_override={
                "task_id": task.id,
                "decision_id": decision.decision_id,
                "decision_digest": decision.decision_digest,
                "gate_status": CompletionGateStatus.AUTHORITY_INSUFFICIENT.value,
                "resulting_task_status": None,
                "reason": "x"
                * (MAX_COMPLETION_GATE_PAYLOAD_BYTES + 1),
            },
        )

        recovered = await _recovery_service(db).recover(task.id)

        assert recovered is not None
        assert recovered.continuation_state is CompletionContinuationState.REEVALUATION_REQUIRED
        assert recovered.gate_status is None
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_gate_history_reads_only_a_bounded_newest_tail(tmp_path: Path) -> None:
    db = await _make_db(tmp_path / "bounded-gate-history.db")
    try:
        _manager, task = await _create_running_task(db)
        session_id = "bounded-history-session"
        await db.create_session(
            session_id,
            mode="coding",
            principal_id="alice",
            project_id="project-a",
        )
        total = MAX_COMPLETION_GATE_HISTORY_RECORDS + 17
        payload = json.dumps(
            {
                "task_id": task.id,
                "decision_id": "history-decision",
                "decision_digest": "d" * 64,
                "gate_status": CompletionGateStatus.NOT_COMPLETE.value,
                "resulting_task_status": TaskStatus.RUNNING.value,
            },
            sort_keys=True,
        )
        async with db.transaction() as conn:
            for index in range(total):
                turn_id = f"bounded-history-turn-{index}"
                await conn.execute(
                    """
                    INSERT INTO agent_turns(
                        turn_id, attempt_id, session_id, task_id, status,
                        last_sequence, started_at, principal_id, project_id
                    ) VALUES (?, ?, ?, ?, 'completed', 2, ?, ?, ?)
                    """,
                    (
                        turn_id,
                        f"bounded-history-attempt-{index}",
                        session_id,
                        task.id,
                        float(index),
                        "alice",
                        "project-a",
                    ),
                )
                await conn.execute(
                    "INSERT INTO agent_turn_events VALUES (?, 2, 'completion.gated', ?, ?)",
                    (turn_id, payload, float(index)),
                )

        records = await db.list_completion_gate_history(
            task.id,
            principal_id="alice",
            project_id="project-a",
        )

        assert len(records) == MAX_COMPLETION_GATE_HISTORY_RECORDS
        assert records[0].created_at == float(total - MAX_COMPLETION_GATE_HISTORY_RECORDS)
        assert records[-1].created_at == float(total - 1)
        assert all(record.payload_bytes == len(payload.encode("utf-8")) for record in records)
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_recovery_is_idempotent_and_does_not_append_or_gate(
    tmp_path: Path,
) -> None:
    db = await _make_db(tmp_path / "idempotent.db")
    try:
        _manager, task = await _create_running_task(db)
        _decision = await _record_decision(db, task, outcome=CompletionOutcome.REPLAN)
        before = len(await db.completion_decision_repository.list_for_task(
            task.id,
            principal_id="alice",
            project_id="project-a",
        ))
        gate_events_before = await db.list_completion_gate_history(
            task.id,
            principal_id="alice",
            project_id="project-a",
        )

        service = _recovery_service(db)
        first = await service.recover(task.id)
        second = await service.recover(task.id)
        after = len(await db.completion_decision_repository.list_for_task(
            task.id,
            principal_id="alice",
            project_id="project-a",
        ))
        gate_events_after = await db.list_completion_gate_history(
            task.id,
            principal_id="alice",
            project_id="project-a",
        )

        assert first == second
        assert before == after == 1
        assert gate_events_before == gate_events_after == ()
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_refresh_projection_reconciles_stale_cache_without_restart_transition(
    tmp_path: Path,
) -> None:
    db = await _make_db(tmp_path / "refresh.db")
    try:
        manager, task = await _create_running_task(db)
        decision = await _record_decision(db, task)
        gate = CompletionGate(
            decision_repository=db.completion_decision_repository,
            goal_spec_repository=db.goal_spec_repository,
            principal_id="alice",
            project_id="project-a",
            authority_policy=_AllowCompletionAuthority(),
        )
        assert (await gate.evaluate(decision.decision_id)).status is CompletionGateStatus.COMPLETED
        assert task.status is TaskStatus.RUNNING

        refreshed = await manager.refresh_projection(task.id)

        assert refreshed is not None
        assert refreshed.status is TaskStatus.COMPLETED
        assert (await db.list_coding_tasks(
            principal_id="alice",
            project_id="project-a",
        ))[0]["status"] == TaskStatus.COMPLETED.value
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_refresh_projection_does_not_apply_load_blocking_rule(
    tmp_path: Path,
) -> None:
    db = await _make_db(tmp_path / "refresh-active.db")
    try:
        _manager, task = await _create_running_task(db)
        observer = TaskManager(db=db, principal_id="alice", project_id="project-a")

        refreshed = await observer.refresh_projection(task.id)

        assert refreshed is not None
        assert refreshed.status is TaskStatus.RUNNING
        assert (await db.list_coding_tasks(
            principal_id="alice",
            project_id="project-a",
        ))[0]["status"] == TaskStatus.RUNNING.value
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_refresh_projection_fails_closed_on_malformed_workspace(
    tmp_path: Path,
) -> None:
    db = await _make_db(tmp_path / "refresh-malformed-workspace.db")
    try:
        manager, task = await _create_running_task(db)
        async with db.transaction() as conn:
            row = await (
                await conn.execute(
                    "SELECT state_json FROM coding_tasks WHERE id = ?",
                    (task.id,),
                )
            ).fetchone()
            state = json.loads(row["state_json"])
            state["metadata"]["workspace_id"] = 42
            await conn.execute(
                "UPDATE coding_tasks SET state_json = ? WHERE id = ?",
                (json.dumps(state), task.id),
            )

        with pytest.raises(GoalSpecIntegrityError):
            await manager.refresh_projection(task.id)
        assert (await manager.get(task.id)).status is TaskStatus.RUNNING
        assert (await db.list_coding_tasks(
            principal_id="alice",
            project_id="project-a",
        ))[0]["status"] == TaskStatus.RUNNING.value
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_recovery_is_owner_and_project_scoped(tmp_path: Path) -> None:
    db = await _make_db(tmp_path / "owner-scope.db")
    try:
        _manager, task = await _create_running_task(db)
        assert await _recovery_service(db, principal_id="bob").recover(task.id) is None
        assert await _recovery_service(db, project_id="project-b").recover(task.id) is None
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_agent_loop_exposes_bounded_recovery_fact_without_execution(
    tmp_path: Path,
) -> None:
    db = await _make_db(tmp_path / "durable-fact.db")
    try:
        manager, task = await _create_running_task(db)
        decision = await _record_decision(db, task, outcome=CompletionOutcome.REPLAN)
        loop = AgentLoop(
            AgentConfig(),
            mode_manager=object(),
            router=object(),
            db=db,
            task_manager=manager,
            principal_id="alice",
            project_id="project-a",
        )

        facts = await loop._build_durable_task_facts(task.id)
        assert len(facts) == 1
        payload = json.loads(facts[0].content.removeprefix("# Durable Task Facts\n"))
        recovery = payload["completion_recovery"]
        assert recovery["task_id"] == task.id
        assert recovery["latest_decision_id"] == decision.decision_id
        assert recovery["continuation_state"] == CompletionContinuationState.REPLAN_REQUIRED.value
        assert "evidence" not in recovery
        assert "reasoning" not in recovery
    finally:
        await db.close()
