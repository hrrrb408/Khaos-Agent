from khaos.agent.core import AgentLoop, StopReason
from khaos.coding.task_manager import TaskManager, TaskStatus
from khaos.coding.verify_fix import VerifyFixLoop


async def test_terminal_state_cannot_return_to_active():
    manager = TaskManager()
    task = await manager.create("work")
    await manager.update_status(task.id, TaskStatus.FAILED)
    await manager.update_status(task.id, TaskStatus.RUNNING)
    assert (await manager.get(task.id)).status == TaskStatus.FAILED


async def test_finalize_marks_max_turns_failed():
    manager = TaskManager()
    task = await manager.create("work")
    loop = AgentLoop.__new__(AgentLoop)
    loop.task_manager = manager
    loop.verify_fix_loop = None
    loop.skill_generator = None
    await loop._finalize_task(task.id, StopReason.MAX_TURNS.value)
    assert (await manager.get(task.id)).status == TaskStatus.FAILED


async def test_latest_failing_verification_cannot_complete_on_end_turn():
    manager = TaskManager()
    task = await manager.create("work")
    verify_fix = VerifyFixLoop(max_fix_attempts=3)
    observation = verify_fix.observe_test_result(
        {
            "name": "test_run",
            "output": {"passed": 0, "failed": 1, "errors": 0},
        }
    )
    assert observation is not None
    assert observation.state.value == "failing"

    loop = AgentLoop.__new__(AgentLoop)
    loop.task_manager = manager
    loop.verify_fix_loop = verify_fix
    loop.skill_generator = None
    await loop._finalize_task(task.id, StopReason.END_TURN.value)

    assert (await manager.get(task.id)).status == TaskStatus.FAILED


async def test_latest_pass_after_repair_budget_stays_gate_owned():
    manager = TaskManager()
    task = await manager.create("work")
    verify_fix = VerifyFixLoop(max_fix_attempts=3)
    failed = {"name": "test_run", "output": {"passed": 0, "failed": 1, "errors": 0}}
    for _ in range(3):
        observation = verify_fix.observe_test_result(failed)
        assert observation is not None
        assert verify_fix.should_enter_loop(failed, observation=observation)
        assert verify_fix.build_failure_context(failed, observation=observation)

    passed = verify_fix.observe_test_result(
        {"name": "test_run", "output": {"passed": 1, "failed": 0, "errors": 0}}
    )
    assert passed is not None
    assert passed.state.value == "passed"
    assert verify_fix.is_loop_exhausted() is False

    loop = AgentLoop.__new__(AgentLoop)
    loop.task_manager = manager
    loop.verify_fix_loop = verify_fix
    loop.skill_generator = None
    await loop._finalize_task(task.id, StopReason.END_TURN.value)

    # M7.1.7 removes the legacy successful finalizer write.  A passing latest
    # observation is preserved by VerifyFixLoop, but only CompletionGate may
    # project a COMPLETE decision onto TaskStatus.COMPLETED.
    assert (await manager.get(task.id)).status is not TaskStatus.COMPLETED


def test_verify_fix_instances_do_not_share_state():
    first = VerifyFixLoop()
    failed = {"name": "test_run", "output": {"passed": 0, "failed": 1, "errors": 0}}
    for _ in range(3):
        observation = first.observe_test_result(failed)
        assert observation is not None
        if first.should_enter_loop(failed, observation=observation):
            first.build_failure_context(failed, observation=observation)
    terminal = first.observe_test_result(failed)
    assert terminal is not None
    second = VerifyFixLoop()
    assert first.is_loop_exhausted()
    assert second.attempt_count == 0
