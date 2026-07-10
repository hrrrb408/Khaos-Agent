from khaos.coding.task_manager import TaskManager, TaskStatus, TransitionResult


async def test_terminal_states_are_strictly_immutable():
    manager = TaskManager()
    task = await manager.create("terminal")
    assert await manager.update_status(task.id, TaskStatus.COMPLETED) == TransitionResult.UPDATED
    assert await manager.update_status(task.id, TaskStatus.FAILED) == TransitionResult.INVALID_TRANSITION
    assert await manager.cancel(task.id) == TransitionResult.INVALID_TRANSITION


async def test_event_sequence_increments_independently_of_trace():
    manager = TaskManager()
    task = await manager.create("events")
    initial = task.event_sequence
    assert await manager.update_status(task.id, TaskStatus.RUNNING) == TransitionResult.UPDATED
    assert (await manager.get(task.id)).event_sequence == initial + 1
    assert await manager.update_status(task.id, TaskStatus.BLOCKED) == TransitionResult.UPDATED
    current = await manager.get(task.id)
    assert current.event_sequence == initial + 2
    assert current.trace == []
