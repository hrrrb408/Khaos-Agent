"""AgentLoop reachability tests for the durable GoalSpec creation path."""

from __future__ import annotations

import json

from khaos.agent import AgentConfig, AgentLoop
from khaos.agent.control.completion import CompletionOutcome
from khaos.agent.control.state import AgentCognitiveState
from khaos.coding.task_manager import TaskManager, TaskStatus
from khaos.db import Database
from khaos.modes import Mode, ModeManager
from khaos.routing.router import create_default_router


async def test_coding_agent_loop_auto_created_task_has_goal_spec(tmp_path) -> None:
    prompts = tmp_path / "prompts"
    prompts.mkdir()
    (prompts / "office.md").write_text("office", encoding="utf-8")
    (prompts / "coding.md").write_text("coding", encoding="utf-8")

    db = Database(tmp_path / "agent.db")
    await db.connect()
    await db.run_migrations()
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
        create_default_router(),
        db,
        project_root=tmp_path,
        task_manager=task_manager,
        principal_id="alice",
        project_id="project-a",
    )

    try:
        events = [message async for message in loop.run("修复中文目标", "s1")]
        tasks = await db.list_coding_tasks(
            principal_id="alice", project_id="project-a"
        )
        assert len(tasks) == 1
        task_id = tasks[0]["id"]
        spec = await db.goal_spec_repository.get_for_task(
            task_id, principal_id="alice", project_id="project-a"
        )
        assert spec is not None
        assert spec.raw_goal == "修复中文目标"
        assert tasks[0]["goal"] == spec.raw_goal
        assert tasks[0]["goal_spec_id"] == spec.goal_spec_id
        assert tasks[0]["goal_spec_digest"] == spec.semantic_digest
        assert tasks[0]["cognitive_state"] == AgentCognitiveState.UNDERSTANDING.value
        assert tasks[0]["control_state_version"] == 1
        facts = await loop._build_durable_task_facts(task_id)
        fact_payload = json.loads(facts[0].content.removeprefix("# Durable Task Facts\n"))
        assert fact_payload["cognitive_state"] == AgentCognitiveState.UNDERSTANDING.value
        assert fact_payload["control_state_version"] == 1
        assert any(message.event == "done" for message in events)
        decisions = await db.completion_decision_repository.list_for_task(
            task_id,
            principal_id="alice",
            project_id="project-a",
        )
        assert len(decisions) == 1
        assert decisions[0].outcome is CompletionOutcome.REPLAN
        # END_TURN is a completion proposal only.  The M7.1.7 gate owns any
        # future TaskStatus projection, so this task remains non-terminal.
        assert tasks[0]["status"] == TaskStatus.RUNNING.value
    finally:
        await db.close()
