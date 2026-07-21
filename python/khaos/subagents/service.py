"""SubAgent JSON-line RPC service called by the Go gateway."""

from __future__ import annotations

import logging
from typing import Any

from khaos.runtime import RequestContext
from khaos.subagents.runner import SubAgentRunner
from khaos.subagents.spawner import SubAgentSpawner, SubAgentTask

logger = logging.getLogger(__name__)


class SubAgentService:
    """Handle SubAgent RPC requests from the Go gateway.

    B1: every method scopes results to ``ctx.principal_id``.  A different
    principal cannot observe another's goal / result / error / status —
    closing the cross-tenant data leakage.

    M2: every handler rejects an empty ``principal_id`` BEFORE calling
    the spawner.  Previously, a missing ``principal_id`` resolved to the
    empty string and the spawner treated empty principal as "return ALL
    tasks" (legacy behavior) — a fail-open security boundary.  Now the
    service rejects empty principal up-front, and the spawner's empty-
    principal path returns NOTHING (defense in depth).

    M4 batch 3.1.16A-4-2: ``principal_id`` is now read from the
    immutable :class:`RequestContext` (transport-authenticated) instead
    of the RPC payload (which could be forged by a compromised
    Gateway).  The ``_handle_optional_subagent`` dispatcher no longer
    needs to stamp ``principal_id`` onto the payload.
    """

    def __init__(self, spawner: SubAgentSpawner, runner: SubAgentRunner | None):
        self.spawner = spawner
        self.runner = runner

    async def shutdown(self, *, timeout: float = 30.0) -> None:
        """H1: production shutdown authority for the SubAgentService.

        Delegates to ``SubAgentSpawner.shutdown`` so the JSON-line server
        can tear down every detached background subagent task BEFORE the
        shared Office / Browser / Audit / DB authorities are dismantled.
        The ``SubAgentRunner`` already borrows those shared authorities, so
        letting them be torn down while a detached task is still in-flight
        is the gap this closes.
        """
        await self.spawner.shutdown(timeout=timeout)

    async def handle_spawn(
        self, ctx: RequestContext, payload: dict,
    ) -> dict[str, Any]:
        """Handle a Spawn request.

        ``ctx.principal_id`` is the transport-authenticated principal —
        stamped onto the task so ``collect`` / ``status`` can filter by
        it.  Empty principal is rejected up-front (the RPC authenticator
        always provides one; a missing one is a bug or an attack).
        """
        principal_id = ctx.principal_id
        if not principal_id:
            return {"ok": False, "error": "principal_id is required"}
        task = SubAgentTask(
            id="",
            goal=payload.get("goal", ""),
            context=payload.get("context", ""),
            tools=payload.get("tools", []),
            timeout=payload.get("timeout", 300),
            # B1: derive a per-principal parent session so tasks from
            # different principals don't share a session namespace.
            parent_session_id=f"subagent:{principal_id}",
            depth=1,
            principal_id=principal_id,
        )
        try:
            result = await self.spawner.spawn(task)
            # M3 (round-5): return the actual task status, not a hardcoded
            # "running".  If shutdown began during spawn's DB work, the
            # spawner aborts and returns a task with status="failed" /
            # error="cancelled".  Previously the service reported
            # ok=true, status=running regardless — so a caller could
            # believe a task was running when it had already been
            # cancelled and would never produce a result.
            if result.status == "failed":
                return {
                    "ok": False,
                    "task_id": result.id,
                    "status": "failed",
                    "error": result.error or "aborted",
                }
            return {"ok": True, "task_id": result.id, "status": result.status}
        except Exception as exc:
            logger.warning("subagent spawn failed: %s", exc)
            return {"ok": False, "error": str(exc)}

    async def handle_collect(
        self, ctx: RequestContext, payload: dict,
    ) -> dict[str, Any]:
        """Handle a Collect request.

        Only returns tasks owned by ``ctx.principal_id``.
        """
        principal_id = ctx.principal_id
        if not principal_id:
            return {"ok": False, "error": "principal_id is required"}
        _ = payload  # No payload fields are read.
        try:
            tasks = await self.spawner.wait_all(timeout=600, principal_id=principal_id)
            results = []
            completed = 0
            failed = 0
            for task in tasks:
                results.append(
                    {
                        "task_id": task.id,
                        "goal": task.goal,
                        "status": task.status,
                        "result": task.result,
                        "error": task.error,
                    }
                )
                if task.status == "completed":
                    completed += 1
                elif task.status == "failed":
                    failed += 1
            return {
                "ok": True,
                "results": results,
                "total": len(tasks),
                "completed": completed,
                "failed": failed,
            }
        except Exception as exc:
            logger.warning("subagent collect failed: %s", exc)
            return {"ok": False, "error": str(exc)}

    async def handle_status(
        self, ctx: RequestContext, payload: dict,
    ) -> dict[str, Any]:
        """Handle a Status request.

        Only counts tasks owned by ``ctx.principal_id``.
        """
        principal_id = ctx.principal_id
        if not principal_id:
            return {"ok": False, "error": "principal_id is required"}
        _ = payload  # No payload fields are read.
        return {"ok": True, "stats": self.spawner.stats(principal_id=principal_id)}
