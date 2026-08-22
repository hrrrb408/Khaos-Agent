"""Structural ownership tests for the scheduler engine split.

The lifecycle facade must compose explicit execution and recovery owners.
These tests keep the refactor honest: adding a wrapper back to ``engine.py``
would move the behavior boundary without changing the public API and should
fail loudly here.
"""

from khaos.scheduler import engine as engine_module
from khaos.scheduler.engine import CronEngine
from khaos.scheduler.execution import SchedulerExecution
from khaos.scheduler.recovery import PendingPersistence, SchedulerRecovery


def test_lifecycle_facade_and_owner_modules_are_explicit() -> None:
    """Lifecycle orchestration stays in engine; execution/recovery do not."""
    assert CronEngine.start.__module__ == engine_module.__name__
    assert CronEngine.stop.__module__ == engine_module.__name__
    assert CronEngine.create.__module__ == engine_module.__name__
    assert CronEngine.pause.__module__ == engine_module.__name__
    assert CronEngine.resume.__module__ == engine_module.__name__
    assert CronEngine.remove.__module__ == engine_module.__name__

    for method_name in (
        "_wrap_executor",
        "_cancel_in_flight_execution",
        "_tick_loop",
        "_execute_task",
        "_persist_task_state",
    ):
        assert getattr(CronEngine, method_name).__module__ == SchedulerExecution.__module__

    for method_name in (
        "_reconcile_pending_persistence",
        "_replay_pending_journal_entries",
        "_check_snapshot_drift",
        "_quarantine_drifted_task",
        "_load_tasks",
        "_revoke_and_recover_lease",
    ):
        assert getattr(CronEngine, method_name).__module__ == SchedulerRecovery.__module__


def test_recovery_types_are_not_reexported_by_transport_facade() -> None:
    """The old engine module no longer owns recovery implementation types."""
    assert PendingPersistence.__module__ == "khaos.scheduler.recovery"
    assert not hasattr(engine_module, "PendingPersistence")
    assert not hasattr(engine_module, "_task_from_row")
    assert not hasattr(engine_module, "_CANCEL_IN_FLIGHT_TIMEOUT")
