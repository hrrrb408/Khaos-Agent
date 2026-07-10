from khaos.agent.core import AgentLoop, StopReason
from khaos.coding.task_manager import TaskManager, TaskStatus
from khaos.coding.verify_fix import VerifyFixLoop


async def test_terminal_state_cannot_return_to_active():
    manager = TaskManager()
    task = await manager.create("work")
    await manager.update_status(task.id, TaskStatus.COMPLETED)
    await manager.update_status(task.id, TaskStatus.RUNNING)
    assert (await manager.get(task.id)).status == TaskStatus.COMPLETED


async def test_finalize_marks_max_turns_failed():
    manager = TaskManager()
    task = await manager.create("work")
    loop = AgentLoop.__new__(AgentLoop)
    loop.task_manager = manager
    loop.verify_fix_loop = None
    loop.skill_generator = None
    await loop._finalize_task(task.id, StopReason.MAX_TURNS.value)
    assert (await manager.get(task.id)).status == TaskStatus.FAILED


def test_verify_fix_instances_do_not_share_state():
    first = VerifyFixLoop()
    first._attempt_count = 3
    second = VerifyFixLoop()
    assert first.is_loop_exhausted()
    assert second.attempt_count == 0
