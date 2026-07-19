"""Tools for scheduled task management.

The handlers delegate to a process-wide :class:`CronEngine` instance injected
via :func:`set_cron_engine` (called once at startup, mirroring how
``terminal_tools`` holds a module-level guard). Until an engine is injected the
handlers report "not available" rather than pretending success — a tool that
claims to create a task but creates nothing is worse than an honest failure.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# Module-level holder for the live CronEngine. Injected at startup by the
# server bootstrap (grpc_server / CLI). Same pattern as terminal_tools.
_cron_engine: Any = None


def set_cron_engine(engine: Any) -> None:
    """Inject the process-wide CronEngine instance (called at startup)."""
    global _cron_engine
    _cron_engine = engine
    logger.info("cron engine injected into cron_tools")


async def cron_create(name: str, prompt: str, schedule: str, **kwargs: Any) -> dict:
    """Create a new scheduled task.

    Args:
        name: Task name
        prompt: Prompt to execute when triggered
        schedule: Schedule expression (cron "0 9" / interval "30m" / ISO time)
        repeat: Optional max repeat count
        deliver_to: Where to send results (local / session:<id> / all)
    """
    config = _parse_schedule(schedule)
    if kwargs.get("repeat"):
        config.repeat = int(kwargs["repeat"])
    deliver = kwargs.get("deliver_to") or "local"

    if _cron_engine is None:
        return {
            "status": "unavailable",
            "error": "cron engine not configured",
            "name": name,
        }
    task = await _cron_engine.create(name, prompt, config, deliver_to=deliver)
    return {
        "status": "created",
        "task_id": task.id,
        "name": name,
        "schedule": schedule,
        "deliver_to": deliver,
        "next_run": task.next_run.isoformat() if task.next_run else None,
    }


async def cron_list(**kwargs: Any) -> dict:
    """List all scheduled tasks."""
    if _cron_engine is None:
        return {"status": "unavailable", "error": "cron engine not configured", "tasks": []}
    tasks = await _cron_engine.list_tasks()
    return {
        "tasks": [
            {
                "id": t.id,
                "name": t.name,
                "status": t.status.value,
                "next_run": t.next_run.isoformat() if t.next_run else None,
                "run_count": t.run_count,
            }
            for t in tasks
        ]
    }


async def cron_remove(task_id: str, **kwargs: Any) -> dict:
    """Remove a scheduled task.

    Returns ``removed`` on success, ``not_found`` if the task does not
    exist, or ``cancellation_pending`` if the in-flight executor did
    not terminate within the cancel budget — in the last case the
    task's desired state is ``cancelled`` but the old executor may
    still be producing side effects; the caller should retry.
    """
    if _cron_engine is None:
        return {"status": "unavailable", "error": "cron engine not configured"}
    result = await _cron_engine.remove(task_id)
    if result == "ok":
        return {"status": "removed", "task_id": task_id}
    if result == "not_found":
        return {"status": "not_found", "task_id": task_id}
    # cancellation_pending — executor did not terminate; task is still
    # in _tasks with CANCELLED status, caller can retry.
    return {
        "status": "cancellation_pending",
        "task_id": task_id,
        "error": "executor did not terminate within cancel budget; "
                 "task is marked cancelled but the old executor may "
                 "still be running — retry remove() to confirm",
    }


async def cron_pause(task_id: str, **kwargs: Any) -> dict:
    """Pause a scheduled task.

    Returns ``paused`` on success, ``not_found`` if the task does not
    exist, or ``cancellation_pending`` if the in-flight executor did
    not terminate within the cancel budget — in the last case the
    task's desired state is ``paused`` but the old executor may still
    be producing side effects; the caller should retry.
    """
    if _cron_engine is None:
        return {"status": "unavailable", "error": "cron engine not configured"}
    result = await _cron_engine.pause(task_id)
    if result == "ok":
        return {"status": "paused", "task_id": task_id}
    if result == "not_found":
        return {"status": "not_found", "task_id": task_id}
    # cancellation_pending — executor did not terminate; task is
    # paused in memory + DB but old executor may still be running.
    return {
        "status": "cancellation_pending",
        "task_id": task_id,
        "error": "executor did not terminate within cancel budget; "
                 "task is marked paused but the old executor may "
                 "still be running — retry pause() to confirm",
    }


async def cron_resume(task_id: str, **kwargs: Any) -> dict:
    """Resume a paused scheduled task."""
    if _cron_engine is None:
        return {"status": "unavailable", "error": "cron engine not configured"}
    ok = await _cron_engine.resume(task_id)
    return {"status": "resumed" if ok else "not_found", "task_id": task_id}


def _parse_schedule(schedule: str) -> "ScheduleConfig":
    """Parse schedule expression into ScheduleConfig."""
    from khaos.scheduler.models import ScheduleConfig

    config = ScheduleConfig()

    # ISO timestamp
    if "T" in schedule and len(schedule) > 10:
        config.iso_time = schedule
        return config

    # Interval: "<n>m" / "<n>h" / "<n>s". Guard against non-numeric prefixes
    # (e.g. "bogus" ends with "s" but isn't a valid interval).
    if len(schedule) >= 2 and schedule[-1] in "mhs":
        prefix = schedule[:-1]
        try:
            n = int(prefix)
        except ValueError:
            n = None
        if n is not None:
            if schedule[-1] == "m":
                config.interval_seconds = n * 60
            elif schedule[-1] == "h":
                config.interval_seconds = n * 3600
            else:
                config.interval_seconds = n
            return config

    # Cron expression (分 时 日 月 星期)
    parts = schedule.split()
    if len(parts) >= 2:
        config.cron = schedule
        return config

    return config


# Tool definitions for registry
CRON_TOOLS = [
    {
        "name": "cron_create",
        "description": "Create a new scheduled task. Schedule formats: cron '0 9' (daily 9am), interval '30m'/'2h', ISO timestamp (one-shot).",
        "parameters": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Task name"},
                "prompt": {"type": "string", "description": "Prompt to execute when triggered"},
                "schedule": {"type": "string", "description": "Schedule expression"},
                "repeat": {"type": "integer", "description": "Max repeat count (optional)"},
                "deliver_to": {"type": "string", "description": "Where to send results"},
            },
            "required": ["name", "prompt", "schedule"],
        },
    },
    {
        "name": "cron_list",
        "description": "List all scheduled tasks.",
        "parameters": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "cron_remove",
        "description": "Remove a scheduled task.",
        "parameters": {
            "type": "object",
            "properties": {
                "task_id": {"type": "string", "description": "Task ID to remove"},
            },
            "required": ["task_id"],
        },
    },
    {
        "name": "cron_pause",
        "description": "Pause a scheduled task.",
        "parameters": {
            "type": "object",
            "properties": {
                "task_id": {"type": "string", "description": "Task ID"},
            },
            "required": ["task_id"],
        },
    },
    {
        "name": "cron_resume",
        "description": "Resume a paused scheduled task.",
        "parameters": {
            "type": "object",
            "properties": {
                "task_id": {"type": "string", "description": "Task ID"},
            },
            "required": ["task_id"],
        },
    },
]
