"""M7.1.6/7 coding proposal and Completion Gate flow tests."""

from __future__ import annotations

import json
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest
from khaos.agent import AgentConfig, AgentLoop, Message
from khaos.agent.control.completion import (
    AssessmentStatus,
    CompletionOutcome,
    RequirementAssessment,
)
from khaos.agent.control.completion_evaluator import (
    CompletionConstraint,
    CompletionConstraintCode,
)
from khaos.agent.control.completion_flow import (
    CompletionFactBundle,
    CompletionProposal,
    CompletionProposalController,
    CompletionProposalStatus,
    CompletionProposalTrigger,
)
from khaos.agent.control.completion_gate import CompletionGateStatus
from khaos.agent.control.state import AgentCognitiveState
from khaos.coding.task_manager import CodingTask, TaskManager, TaskStatus
from khaos.db import Database
from khaos.modes import Mode, ModeManager


class _SatisfyingFactProvider:
    async def collect(self, *, proposal, goal_spec, snapshot):
        del proposal, snapshot
        return CompletionFactBundle(
            requirement_assessments=tuple(
                RequirementAssessment(
                    requirement.requirement_id,
                    AssessmentStatus.SATISFIED,
                )
                for requirement in goal_spec.requirements
                if requirement.required
            )
        )


class _FailingVerificationFactProvider(_SatisfyingFactProvider):
    async def collect(self, *, proposal, goal_spec, snapshot):
        bundle = await super().collect(
            proposal=proposal,
            goal_spec=goal_spec,
            snapshot=snapshot,
        )
        return CompletionFactBundle(
            requirement_assessments=bundle.requirement_assessments,
            constraints=(
                CompletionConstraint(CompletionConstraintCode.VERIFICATION_FAILED),
            ),
        )


class _StaleSnapshotFactProvider(_SatisfyingFactProvider):
    def __init__(self, manager: TaskManager) -> None:
        self._manager = manager

    async def collect(self, *, proposal, goal_spec, snapshot):
        result = await self._manager.transition_cognitive_state(
            proposal.task_id,
            target=AgentCognitiveState.EXPLORING,
            expected_state=snapshot.cognitive_state,
            expected_version=snapshot.control_state_version,
        )
        assert result.updated
        return await super().collect(
            proposal=proposal,
            goal_spec=goal_spec,
            snapshot=snapshot,
        )


class _EndTurnRouter:
    def __init__(self, response: str) -> None:
        self._response = response

    async def call(self, function, messages, **kwargs):
        del function, messages, kwargs
        yield Message(role="assistant", content=self._response)
        yield Message(role="assistant", content="", stop_reason="end_turn")


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
    goal: str = "修复中文目标并保留回归证据",
) -> tuple[TaskManager, CodingTask]:
    manager = TaskManager(
        db=db,
        principal_id=principal_id,
        project_id=project_id,
    )
    task = await manager.create(goal)
    assert (await manager.update_status(task.id, TaskStatus.RUNNING)).value == "updated"
    cognitive_result = await manager.initialize_cognitive_state(task.id)
    assert cognitive_result.updated
    return manager, task


def _proposal(task_id: str) -> CompletionProposal:
    return CompletionProposal(
        task_id=task_id,
        turn_id="turn-1",
        attempt_id="attempt-1",
        trigger=CompletionProposalTrigger.MODEL_END_TURN,
    )


def test_completion_flow_contracts_are_typed_and_immutable() -> None:
    proposal = _proposal("task-1")
    with pytest.raises(FrozenInstanceError):
        proposal.task_id = "tampered"  # type: ignore[misc]
    with pytest.raises(ValueError, match="must be a tuple"):
        CompletionFactBundle(requirement_assessments=[])


@pytest.mark.asyncio
async def test_controller_records_complete_without_projecting_task_status(
    tmp_path: Path,
) -> None:
    db = await _make_db(tmp_path / "complete.db")
    try:
        _, task = await _create_running_task(db)
        controller = CompletionProposalController(
            goal_spec_repository=db.goal_spec_repository,
            decision_repository=db.completion_decision_repository,
            principal_id="alice",
            project_id="project-a",
            fact_provider=_SatisfyingFactProvider(),
        )

        result = await controller.propose(_proposal(task.id))

        assert result.status is CompletionProposalStatus.RECORDED
        assert result.decision is not None
        assert result.decision.outcome is CompletionOutcome.COMPLETE
        assert result.decision_sequence == 1
        assert result.decision.decision_id != "decision-1"
        current = await db.completion_decision_repository.get_latest_for_task(
            task.id,
            principal_id="alice",
            project_id="project-a",
        )
        assert current is not None
        assert current.decision == result.decision
        task_row = (await db.list_coding_tasks(
            principal_id="alice",
            project_id="project-a",
        ))[0]
        assert task_row["status"] == TaskStatus.RUNNING.value
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_default_provider_is_conservative_and_records_replan(
    tmp_path: Path,
) -> None:
    db = await _make_db(tmp_path / "default-facts.db")
    try:
        _, task = await _create_running_task(db)
        controller = CompletionProposalController(
            goal_spec_repository=db.goal_spec_repository,
            decision_repository=db.completion_decision_repository,
            principal_id="alice",
            project_id="project-a",
        )

        result = await controller.propose(_proposal(task.id))

        assert result.status is CompletionProposalStatus.RECORDED
        assert result.decision is not None
        assert result.decision.outcome is CompletionOutcome.REPLAN
        assert result.decision.requirement_assessments[0].status is AssessmentStatus.UNKNOWN
        assert task.status is TaskStatus.RUNNING
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_negative_verification_fact_only_narrows_completion(
    tmp_path: Path,
) -> None:
    db = await _make_db(tmp_path / "verification-failure.db")
    try:
        _, task = await _create_running_task(db)
        controller = CompletionProposalController(
            goal_spec_repository=db.goal_spec_repository,
            decision_repository=db.completion_decision_repository,
            principal_id="alice",
            project_id="project-a",
            fact_provider=_FailingVerificationFactProvider(),
        )

        result = await controller.propose(_proposal(task.id))

        assert result.status is CompletionProposalStatus.RECORDED
        assert result.decision is not None
        assert result.decision.outcome is CompletionOutcome.REPLAN
        assert result.decision.issues[0].code.value == "verification_failed"
        assert task.status is TaskStatus.RUNNING
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_stale_snapshot_is_rejected_without_reusing_old_facts(
    tmp_path: Path,
) -> None:
    db = await _make_db(tmp_path / "stale.db")
    try:
        manager, task = await _create_running_task(db)
        controller = CompletionProposalController(
            goal_spec_repository=db.goal_spec_repository,
            decision_repository=db.completion_decision_repository,
            principal_id="alice",
            project_id="project-a",
            fact_provider=_StaleSnapshotFactProvider(manager),
        )

        result = await controller.propose(_proposal(task.id))

        assert result.status is CompletionProposalStatus.STALE
        assert result.decision is None
        assert await db.completion_decision_repository.list_for_task(
            task.id,
            principal_id="alice",
            project_id="project-a",
        ) == []
        assert task.status is TaskStatus.RUNNING
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_foreign_owner_cannot_load_goal_or_append_decision(
    tmp_path: Path,
) -> None:
    db = await _make_db(tmp_path / "owner-isolation.db")
    try:
        _, task = await _create_running_task(db)
        controller = CompletionProposalController(
            goal_spec_repository=db.goal_spec_repository,
            decision_repository=db.completion_decision_repository,
            principal_id="bob",
            project_id="project-a",
            fact_provider=_SatisfyingFactProvider(),
        )

        result = await controller.propose(_proposal(task.id))

        assert result.status is CompletionProposalStatus.REJECTED
        assert result.decision is None
        assert await db.completion_decision_repository.list_for_task(
            task.id,
            principal_id="alice",
            project_id="project-a",
        ) == []
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_end_turn_interception_records_events_and_keeps_task_running(
    tmp_path: Path,
) -> None:
    prompts = tmp_path / "prompts"
    prompts.mkdir()
    (prompts / "office.md").write_text("office", encoding="utf-8")
    (prompts / "coding.md").write_text("coding", encoding="utf-8")
    db = await _make_db(tmp_path / "agent-loop.db")
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
        loop = AgentLoop(
            AgentConfig(),
            mode_manager,
            _EndTurnRouter("Done. Everything is complete."),
            db,
            project_root=tmp_path,
            task_manager=task_manager,
            principal_id="alice",
            project_id="project-a",
        )

        output = [message async for message in loop.run("修复中文目标", "s1")]

        completion = next(
            message for message in output if message.event == "completion_evaluated"
        )
        assert completion.metadata["status"] == CompletionProposalStatus.RECORDED.value
        assert completion.metadata["outcome"] == CompletionOutcome.REPLAN.value
        done = next(message for message in output if message.event == "done")
        assert done.metadata["turn_id"] == completion.metadata["turn_id"]
        turn_events = await db.list_agent_turn_events(done.metadata["turn_id"])
        assert [event["event_type"] for event in turn_events] == [
            "turn.started",
            "completion.proposed",
            "completion.evaluated",
            "completion.gated",
            "turn.completed",
        ]
        proposed_payload = json.loads(turn_events[1]["payload_json"])
        evaluated_payload = json.loads(turn_events[2]["payload_json"])
        gated_payload = json.loads(turn_events[3]["payload_json"])
        assert proposed_payload["trigger"] == "model_end_turn"
        assert evaluated_payload["outcome"] == CompletionOutcome.REPLAN.value
        assert gated_payload["gate_status"] == "not_complete"
        assert gated_payload["resulting_task_status"] == TaskStatus.RUNNING.value
        task_rows = await db.list_coding_tasks(
            principal_id="alice",
            project_id="project-a",
        )
        assert len(task_rows) == 1
        assert task_rows[0]["status"] == TaskStatus.RUNNING.value
        assert task_rows[0]["cognitive_state"] == AgentCognitiveState.UNDERSTANDING.value
        assert task_rows[0]["control_state_version"] == 1
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_explicit_satisfied_provider_complete_is_still_passive(
    tmp_path: Path,
) -> None:
    prompts = tmp_path / "prompts"
    prompts.mkdir()
    (prompts / "office.md").write_text("office", encoding="utf-8")
    (prompts / "coding.md").write_text("coding", encoding="utf-8")
    db = await _make_db(tmp_path / "passive-complete.db")
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
        loop = AgentLoop(
            AgentConfig(),
            mode_manager,
            _EndTurnRouter("done"),
            db,
            project_root=tmp_path,
            task_manager=task_manager,
            principal_id="alice",
            project_id="project-a",
            completion_fact_provider=_SatisfyingFactProvider(),
        )

        output = [message async for message in loop.run("完成目标", "s1")]

        completion = next(
            message for message in output if message.event == "completion_evaluated"
        )
        assert completion.metadata["outcome"] == CompletionOutcome.COMPLETE.value
        gated = next(
            message for message in output if message.event == "completion_gated"
        )
        assert gated.metadata["status"] == (
            CompletionGateStatus.AUTHORITY_INSUFFICIENT.value
        )
        task_rows = await db.list_coding_tasks(
            principal_id="alice",
            project_id="project-a",
        )
        assert task_rows[0]["status"] != TaskStatus.COMPLETED.value
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_completion_decision_survives_restart_without_resuming_task(
    tmp_path: Path,
) -> None:
    db = await _make_db(tmp_path / "restart.db")
    try:
        _, task = await _create_running_task(db)
        controller = CompletionProposalController(
            goal_spec_repository=db.goal_spec_repository,
            decision_repository=db.completion_decision_repository,
            principal_id="alice",
            project_id="project-a",
            fact_provider=_SatisfyingFactProvider(),
        )
        result = await controller.propose(_proposal(task.id))
        assert result.decision is not None
        goal_spec_id = result.decision.goal_spec_id
        goal_spec_digest = result.decision.goal_spec_digest

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
        assert loaded.goal_spec_id == goal_spec_id
        assert loaded.goal_spec_digest == goal_spec_digest
        latest = await db.completion_decision_repository.get_latest_for_task(
            task.id,
            principal_id="alice",
            project_id="project-a",
        )
        assert latest is not None
        assert latest.decision.outcome is CompletionOutcome.COMPLETE
        assert (
            await db.list_coding_tasks(
                principal_id="alice",
                project_id="project-a",
            )
        )[0]["status"] == TaskStatus.BLOCKED.value
    finally:
        await db.close()
