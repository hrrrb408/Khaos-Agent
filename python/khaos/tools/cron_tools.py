"""Tools for scheduled task management.

The handlers delegate to a process-wide :class:`CronEngine` instance injected
via :func:`set_cron_engine` (called once at startup, mirroring how
``terminal_tools`` holds a module-level guard). Until an engine is injected the
handlers report "not available" rather than pretending success — a tool that
claims to create a task but creates nothing is worse than an honest failure.

M4 batch 3.1.10 (CRITICAL): all handlers now accept a ``principal_id``
keyword parameter (injected by the ``ToolInvocationBroker`` via the
``cron.manage`` capability declared in ``registry.py``).  ``cron_create``
stamps the principal on the task; ``cron_list`` / ``cron_pause`` /
``cron_resume`` / ``cron_remove`` filter / verify ownership.  Empty
principal is rejected — fail-closed (no fallback to a shared pseudo-
principal).
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


def _require_principal(principal_id: str) -> dict[str, Any] | None:
    """M4 batch 3.1.10 (CRITICAL): return an ``ok=false`` error dict if
    ``principal_id`` is empty, else ``None``.

    The cron tools must not fail open to a shared pseudo-principal when
    the caller's principal is missing — that would let a misconfigured
    tool context silently operate on any principal's tasks.  Empty
    principal is rejected.
    """
    if not principal_id:
        return {"status": "error", "error": "principal_id is required"}
    return None


async def cron_create(name: str, prompt: str, schedule: str, *, principal_id: str = "", **kwargs: Any) -> dict:
    """Create a new scheduled task.

    Args:
        name: Task name
        prompt: Prompt to execute when triggered
        schedule: Schedule expression (cron "0 9" / interval "30m" / ISO time)
        repeat: Optional max repeat count
        deliver_to: Where to send results (local / session:<id> / all)
        principal_id: Caller's principal ID (injected by broker via
            ``cron.manage`` capability).  Required — the task is bound
            to this principal.
    """
    principal_error = _require_principal(principal_id)
    if principal_error is not None:
        return principal_error

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
    try:
        task = await _cron_engine.create(
            name, prompt, config, deliver_to=deliver,
            principal_id=principal_id,
        )
    except ValueError as exc:
        # principal_id validation failure
        return {"status": "error", "error": str(exc), "name": name}
    return {
        "status": "created",
        "task_id": task.id,
        "name": name,
        "schedule": schedule,
        "deliver_to": deliver,
        "next_run": task.next_run.isoformat() if task.next_run else None,
    }


async def cron_list(*, principal_id: str = "", **kwargs: Any) -> dict:
    """List scheduled tasks for the caller's principal.

    M4 batch 3.1.10 (CRITICAL): only tasks belonging to
    ``principal_id`` are returned.

    M4 batch 3.1.16B-3 (CRITICAL): exposes ``error`` (so quarantined
    tasks surface their drift reason) and a truncated
    ``policy_digest_prefix`` (8 chars — enough for debugging which
    policy snapshot the task was created under, without exposing the
    full digest fingerprint).  ``project_id_prefix`` is similarly
    truncated.  This lets users see at a glance whether a ``failed``
    task is a natural failure or a security-context drift quarantine.
    """
    principal_error = _require_principal(principal_id)
    if principal_error is not None:
        return principal_error

    if _cron_engine is None:
        return {"status": "unavailable", "error": "cron engine not configured", "tasks": []}
    tasks = await _cron_engine.list_tasks(principal_id=principal_id)
    return {
        "tasks": [
            {
                "id": t.id,
                "name": t.name,
                "status": t.status.value,
                "next_run": t.next_run.isoformat() if t.next_run else None,
                "run_count": t.run_count,
                # M4 batch 3.1.16B-3: surface the error message so
                # quarantined tasks (status=failed + error starts with
                # "quarantined:") are distinguishable from natural
                # failures.  None for tasks without an error.
                "error": t.error,
                # M4 batch 3.1.16B-3: truncated policy/project
                # fingerprints for debugging.  Empty string for
                # legacy/test tasks (no snapshot).  Only the first 8
                # chars are exposed — enough to compare two snapshots
                # for equality, not enough to reconstruct the full
                # digest (which is a security fingerprint).
                "policy_digest_prefix": t.policy_digest[:8] if t.policy_digest else "",
                "project_id_prefix": t.project_id[:8] if t.project_id else "",
            }
            for t in tasks
        ]
    }


async def cron_remove(task_id: str, *, principal_id: str = "", **kwargs: Any) -> dict:
    """Remove a scheduled task.

    M4 batch 3.1.10 (CRITICAL): ``principal_id`` is required.  Returns
    ``not_found`` if the task belongs to a different principal (fail-
    closed — does not reveal existence).
    """
    principal_error = _require_principal(principal_id)
    if principal_error is not None:
        return principal_error

    if _cron_engine is None:
        return {"status": "unavailable", "error": "cron engine not configured"}
    result = await _cron_engine.remove(task_id, principal_id=principal_id)
    if result == "ok":
        return {"status": "removed", "task_id": task_id}
    if result == "not_found":
        return {"status": "not_found", "task_id": task_id}
    if result == "invalid_state":
        return {
            "status": "invalid_state",
            "task_id": task_id,
            "error": "task is in a terminal execution state "
                     "(COMPLETED / FAILED) — cannot be re-cancelled. "
                     "Note: drift-quarantined tasks (FAILED with "
                     "error starting 'quarantined:') CAN be removed; "
                     "use cron_list to check the error field.",
        }
    if result == "persistence_pending":
        return {
            "status": "persistence_pending",
            "task_id": task_id,
            "error": "executor terminated but the DB write failed; "
                     "stop() will retry — the cancelled state may not "
                     "survive a restart",
        }
    # cancellation_pending — executor did not terminate
    return {
        "status": "cancellation_pending",
        "task_id": task_id,
        "error": "executor did not terminate within cancel budget; "
                 "task is marked cancelled but the old executor may "
                 "still be running — retry remove() to confirm",
    }


async def cron_pause(task_id: str, *, principal_id: str = "", **kwargs: Any) -> dict:
    """Pause a scheduled task.

    M4 batch 3.1.10 (CRITICAL): ``principal_id`` is required.  Returns
    ``not_found`` if the task belongs to a different principal.
    """
    principal_error = _require_principal(principal_id)
    if principal_error is not None:
        return principal_error

    if _cron_engine is None:
        return {"status": "unavailable", "error": "cron engine not configured"}
    result = await _cron_engine.pause(task_id, principal_id=principal_id)
    if result == "ok":
        return {"status": "paused", "task_id": task_id}
    if result == "not_found":
        return {"status": "not_found", "task_id": task_id}
    if result == "invalid_state":
        return {
            "status": "invalid_state",
            "task_id": task_id,
            "error": "task is in a state that cannot be paused "
                     "(CANCELLED tombstone or terminal COMPLETED / "
                     "FAILED) — state is unchanged",
        }
    if result == "persistence_pending":
        return {
            "status": "persistence_pending",
            "task_id": task_id,
            "error": "executor terminated but the DB write failed; "
                     "stop() will retry — the paused state may not "
                     "survive a restart",
        }
    # cancellation_pending
    return {
        "status": "cancellation_pending",
        "task_id": task_id,
        "error": "executor did not terminate within cancel budget; "
                 "task is marked paused but the old executor may "
                 "still be running — retry pause() to confirm",
    }


async def cron_resume(task_id: str, *, principal_id: str = "", **kwargs: Any) -> dict:
    """Resume a paused scheduled task.

    M4 batch 3.1.10 (CRITICAL): ``principal_id`` is required.  Returns
    ``not_found`` if the task belongs to a different principal.

    M4 batch 3.1.10 (MEDIUM): the engine's ``resume()`` may return
    ``persistence_pending`` when the DB write fails.  Previously the
    tool layer only handled ``ok`` / ``not_found`` / ``invalid_state``
    and lumped everything else (including ``persistence_pending``)
    into ``execution_pending`` — giving the user the misleading error
    "old executor is still alive" when the real cause was a DB write
    failure.  Now ``persistence_pending`` has its own branch.
    """
    principal_error = _require_principal(principal_id)
    if principal_error is not None:
        return principal_error

    if _cron_engine is None:
        return {"status": "unavailable", "error": "cron engine not configured"}
    result = await _cron_engine.resume(task_id, principal_id=principal_id)
    if result == "ok":
        return {"status": "resumed", "task_id": task_id}
    if result == "not_found":
        return {"status": "not_found", "task_id": task_id}
    if result == "invalid_state":
        return {
            "status": "invalid_state",
            "task_id": task_id,
            "error": "task is not in the PAUSED state — only PAUSED "
                     "tasks can be resumed (state is unchanged)",
        }
    if result == "persistence_pending":
        # M4 batch 3.1.10 (MEDIUM): dedicated branch — the DB write
        # failed, NOT the executor being alive.  The task stays PAUSED
        # in memory and tick does not fire it.  The caller should
        # retry resume() to confirm.
        return {
            "status": "persistence_pending",
            "task_id": task_id,
            "error": "DB write failed; task remains paused in memory "
                     "and will NOT be fired by tick — retry resume() "
                     "to confirm the state is durable",
        }
    # result == "execution_pending" — PAUSED but old executor alive
    return {
        "status": "execution_pending",
        "task_id": task_id,
        "error": "task is PAUSED but the old executor is still "
                 "alive — resuming would cause double side effects; "
                 "wait for the executor to terminate or call "
                 "remove() to force-cancel",
    }


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
