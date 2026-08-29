"""M7.9 contract, adversarial, determinism, and ledger tests."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from khaos.agent.control.completion import CompletionDecision, CompletionOutcome
from khaos.agent.control.goal import GoalSpec
from khaos.agent.control.state import AgentCognitiveState
from khaos.db import Database
from khaos.evaluation import (
    CapabilityEvaluationIntegrityError,
    CapabilityEvaluationPolicy,
    CapabilityEvaluationReport,
    CapabilityEvaluationRepository,
    CapabilityEvaluator,
    CapabilityEvidenceSnapshot,
    EvaluationDisposition,
    EvidenceRecord,
    SecurityIntegrity,
    SourceAvailability,
    SourceHighWaterMark,
    TaskEvidence,
    build_capability_evaluation_service,
    default_capability_benchmark_manifest,
    judge_benchmark,
)
from khaos.security.protocol_boundary import canonical_digest

SOURCES = (
    "task",
    "goal_spec",
    "completion_decisions",
    "plan_revisions",
    "verification_assessments",
    "recovery_decisions",
    "routes",
    "step_states",
    "dispatch_fences",
    "subagent_assignments",
    "subagent_runs",
    "turns",
    "audit_log",
    "memory",
)


def _record(source: str, record_id: str, sequence: int, fields: dict[str, object]) -> EvidenceRecord:
    digest = canonical_digest({"source": source, "record_id": record_id, "sequence": sequence, "fields": fields})
    return EvidenceRecord(source, record_id, digest, sequence, fields)


def _snapshot(*, status: str = "running", records: dict[str, tuple[EvidenceRecord, ...]] | None = None, goal_id: str = "goal-1", goal_available: bool = True) -> CapabilityEvidenceSnapshot:
    policy = CapabilityEvaluationPolicy.production()
    task_digest = canonical_digest({"task": status})
    task = TaskEvidence("task-1", "principal-1", "project-1", status, "verifying", 3, "ws-1", "repo-1", "base-1", "plan-2", task_digest)
    marks = tuple(
        SourceHighWaterMark(source, None, "head-" + source, canonical_digest({"source": source}))
        for source in SOURCES
    )
    availability = tuple(SourceAvailability(source, goal_available if source == "goal_spec" else True) for source in SOURCES)
    values = records or {}
    return CapabilityEvidenceSnapshot(
        principal_id="principal-1",
        project_id="project-1",
        task_id="task-1",
        goal_spec_id=goal_id,
        goal_spec_digest=canonical_digest({"goal": "goal-1"}),
        task=task,
        workspace_id="ws-1",
        repository_id="repo-1",
        base_revision="base-1",
        published_plan_revision_id="plan-2",
        source_high_water_marks=marks,
        source_availability=availability,
        captured_at="2026-08-29T00:00:00",
        policy_digest=policy.policy_digest,
        **values,
    )


def test_same_snapshot_is_byte_identical_and_sort_order_independent() -> None:
    policy = CapabilityEvaluationPolicy.production()
    first = _record("completion_decisions", "d-1", 1, {"outcome": "replan"})
    second = _record("completion_decisions", "d-2", 2, {"outcome": "complete"})
    a = _snapshot(records={"completion_decisions": (second, first)})
    b = _snapshot(records={"completion_decisions": (first, second)})
    evaluator = CapabilityEvaluator()
    left = evaluator.evaluate(a, policy)
    right = evaluator.evaluate(b, policy)
    assert a.snapshot_digest == b.snapshot_digest
    assert left.canonical_json() == right.canonical_json()
    assert left.evaluation_digest == right.evaluation_digest


def test_self_report_is_not_an_outcome_and_false_completion_is_typed() -> None:
    evaluation = CapabilityEvaluator().evaluate(
        _snapshot(
            records={
                "completion_decisions": (_record("completion_decisions", "d-1", 1, {"outcome": "replan"}),),
                "turns": (_record("turns", "turn-1", 1, {"status": "completed", "assistant_self_report": "done"}),),
            }
        ),
        CapabilityEvaluationPolicy.production(),
    )
    assert evaluation.disposition is EvaluationDisposition.EVALUATED
    assert evaluation.outcome_metrics.completion_acceptances == 0
    assert evaluation.outcome_metrics.false_completion_attempts == 1


def test_completed_task_without_completion_decision_is_integrity_failure() -> None:
    evaluation = CapabilityEvaluator().evaluate(_snapshot(status="completed"), CapabilityEvaluationPolicy.production())
    assert evaluation.outcome_metrics.terminal_without_completion_gate == 1
    assert evaluation.security_integrity is SecurityIntegrity.FAIL


def test_security_bypass_is_hard_fail_even_with_functional_success() -> None:
    evaluation = CapabilityEvaluator().evaluate(
        _snapshot(
            status="completed",
            records={
                "completion_decisions": (_record("completion_decisions", "d-1", 1, {"outcome": "complete"}),),
                "audit_events": (_record("audit_log", "a-1", 1, {"action": "security:authority_bypass", "result": "success"}),),
            },
        ),
        CapabilityEvaluationPolicy.production(),
    )
    assert evaluation.outcome_metrics.completion_acceptances == 1
    assert evaluation.security_integrity is SecurityIntegrity.FAIL


def test_legacy_missing_goal_is_first_class_insufficient_evidence() -> None:
    evaluation = CapabilityEvaluator().evaluate(
        _snapshot(goal_id="missing-goal-spec:task-1", goal_available=False),
        CapabilityEvaluationPolicy.production(),
    )
    assert evaluation.disposition is EvaluationDisposition.INSUFFICIENT_EVIDENCE


@pytest.mark.asyncio
async def test_evaluation_ledger_is_owner_scoped_append_only(tmp_path: Path) -> None:
    db = Database(tmp_path / "evaluation.db")
    await db.connect()
    await db.run_migrations()
    repository = CapabilityEvaluationRepository(db)
    evaluation = CapabilityEvaluator().evaluate(_snapshot(), CapabilityEvaluationPolicy.production())
    saved = await repository.append(evaluation)
    assert saved.evaluation_sequence == 1
    assert await repository.latest_for_task(
        principal_id="principal-1", project_id="project-1", task_id="task-1"
    ) == saved
    assert await repository.latest_for_task(
        principal_id="other", project_id="project-1", task_id="task-1"
    ) is None
    with pytest.raises(sqlite3.IntegrityError):
        async with db.transaction() as conn:
            await conn.execute(
                "UPDATE agent_capability_evaluations SET disposition = 'INVALID' WHERE evaluation_id = ?",
                (saved.evaluation_id,),
            )
    await db.close()


@pytest.mark.asyncio
async def test_evidence_service_uses_durable_completion_and_goal_identity(tmp_path: Path) -> None:
    db = Database(tmp_path / "capture.db")
    await db.connect()
    await db.run_migrations()
    async with db.transaction() as conn:
        await conn.execute(
            """INSERT INTO coding_tasks (
                id, goal, status, state_json, created_at, updated_at,
                principal_id, project_id, cognitive_state, control_state_version
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            ("task-1", "goal", "running", "{}", "now", "now", "principal-1", "project-1", "verifying", 3),
        )
    goal = GoalSpec.from_parts(goal_spec_id="goal-1", raw_goal="goal")
    await db.goal_spec_repository.insert(goal, task_id="task-1", principal_id="principal-1", project_id="project-1")
    decision = CompletionDecision.from_parts(
        decision_id="decision-1",
        task_id="task-1",
        goal_spec_id="goal-1",
        goal_spec_digest=goal.semantic_digest,
        cognitive_state=AgentCognitiveState.VERIFYING,
        control_state_version=3,
        task_status_at_evaluation="running",
        outcome=CompletionOutcome.REPLAN,
    )
    await db.completion_decision_repository.append(decision, principal_id="principal-1", project_id="project-1")
    service = build_capability_evaluation_service(db)
    result = await service.evaluate_task(
        principal_id="principal-1", project_id="project-1", task_id="task-1"
    )
    assert result.disposition is EvaluationDisposition.EVALUATED
    assert result.outcome_metrics.completion_proposals == 1
    assert result.outcome_metrics.false_completion_attempts == 1
    assert await service.latest_current_for_task(
        principal_id="principal-1", project_id="project-1", task_id="task-1"
    ) == result
    repeated = await service.evaluate_task(
        principal_id="principal-1", project_id="project-1", task_id="task-1"
    )
    assert repeated.evaluation_sequence == 2
    assert repeated.evaluation_digest == result.evaluation_digest
    assert repeated.evaluation_id != result.evaluation_id
    async with db.transaction() as conn:
        await conn.execute(
            "UPDATE coding_tasks SET status = 'completed' WHERE id = ? AND principal_id = ? AND project_id = ?",
            ("task-1", "principal-1", "project-1"),
        )
    assert await service.latest_current_for_task(
        principal_id="principal-1", project_id="project-1", task_id="task-1"
    ) is None
    await db.close()


def test_trusted_benchmark_manifest_hard_fails_security_bypass() -> None:
    evaluation = CapabilityEvaluator().evaluate(
        _snapshot(
            status="completed",
            records={
                "completion_decisions": (_record("completion_decisions", "d-1", 1, {"outcome": "complete"}),),
                "audit_events": (_record("audit_log", "a-1", 1, {"action": "security:authority_bypass", "result": "success"}),),
            },
        ),
        CapabilityEvaluationPolicy.production(),
    )
    manifest = default_capability_benchmark_manifest()
    scenario = manifest.scenarios[0]
    result = judge_benchmark(manifest, scenario, evaluation)
    assert result.verdict.value == "FAIL"
    assert result.reason_code == "security_integrity_failure"
    report = CapabilityEvaluationReport(evaluation, source_sha="source-sha")
    assert "security_integrity" in report.canonical_json()


@pytest.mark.asyncio
async def test_malformed_newest_evaluation_fails_closed(tmp_path: Path) -> None:
    db = Database(tmp_path / "malformed.db")
    await db.connect()
    await db.run_migrations()
    async with db.transaction() as conn:
        await conn.execute(
            """INSERT INTO agent_capability_evaluations (
                evaluation_id, principal_id, project_id, task_id,
                evaluation_sequence, goal_spec_id, goal_spec_digest,
                snapshot_digest, policy_digest, evaluator_schema_version,
                evaluator_algorithm_version, disposition, evaluation_json,
                evaluation_digest, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                "bad-evaluation", "principal-1", "project-1", "task-1", 1,
                "goal-1", "0" * 64, "1" * 64, "2" * 64, 1, "m7.9-1",
                "EVALUATED", "{}", "3" * 64, "2026-08-29T00:00:00",
            ),
        )
    with pytest.raises(CapabilityEvaluationIntegrityError):
        await db.capability_evaluation_repository.latest_for_task(
            principal_id="principal-1", project_id="project-1", task_id="task-1"
        )
    await db.close()


@pytest.mark.asyncio
async def test_coherent_reader_transaction_cannot_mix_before_and_after_state(tmp_path: Path) -> None:
    db = Database(tmp_path / "coherent.db")
    await db.connect()
    await db.run_migrations()
    async with db.transaction() as conn:
        await conn.execute(
            "INSERT INTO coding_tasks (id, goal, status, state_json, created_at, updated_at, principal_id, project_id) "
            "VALUES ('task-1', 'goal', 'running', '{}', 'now', 'now', 'principal-1', 'project-1')"
        )
    async with db.read_transaction() as reader:
        before = await (await reader.execute("SELECT status FROM coding_tasks WHERE id = 'task-1'")).fetchone()
        async with db.transaction() as writer:
            await writer.execute("UPDATE coding_tasks SET status = 'completed' WHERE id = 'task-1'")
        after = await (await reader.execute("SELECT status FROM coding_tasks WHERE id = 'task-1'")).fetchone()
    assert before["status"] == "running"
    assert after["status"] == "running"
    async with db.read_connection() as reader:
        current = await (await reader.execute("SELECT status FROM coding_tasks WHERE id = 'task-1'")).fetchone()
    assert current["status"] == "completed"
    await db.close()
