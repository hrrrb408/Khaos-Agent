"""SubAgent JSON-line RPC service called by the Go gateway."""

from __future__ import annotations

import logging
from typing import Any

from khaos.subagents.runner import SubAgentRunner
from khaos.subagents.spawner import SubAgentSpawner, SubAgentTask

logger = logging.getLogger(__name__)


class SubAgentService:
    """Handle SubAgent RPC requests from the Go gateway.

    B1: every method reads ``principal_id`` from the authenticated RPC
    payload and scopes results to that principal.  A different principal
    cannot observe another's goal / result / error / status — closing
    the cross-tenant data leakage.

    M2: every handler rejects an empty ``principal_id`` BEFORE calling
    the spawner.  Previously, a missing ``principal_id`` resolved to the
    empty string and the spawner treated empty principal as "return ALL
    tasks" (legacy behavior) — a fail-open security boundary.  Now the
    service rejects empty principal up-front, and the spawner's empty-
    principal path returns NOTHING (defense in depth).
    """

    def __init__(self, spawner: SubAgentSpawner, runner: SubAgentRunner | None):
        self.spawner = spawner
        self.runner = runner

    async def handle_spawn(self, payload: dict) -> dict[str, Any]:
        """Handle a Spawn request.

        B1: ``principal_id`` is read from the authenticated payload and
        stamped onto the task so ``collect`` / ``status`` can filter by
        it.  M2: empty ``principal_id`` is rejected up-front — the Go
        gateway always forwards the authenticated principal, so a missing
        one is a bug or an attack.
        """
        principal_id = str(payload.get("principal_id") or "")
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
            return {"ok": True, "task_id": result.id, "status": "running"}
        except Exception as exc:
            logger.warning("subagent spawn failed: %s", exc)
            return {"ok": False, "error": str(exc)}

    async def handle_collect(self, payload: dict) -> dict[str, Any]:
        """Handle a Collect request.

        B1: only returns tasks owned by the authenticated principal.
        M2: empty ``principal_id`` is rejected up-front.
        """
        principal_id = str(payload.get("principal_id") or "")
        if not principal_id:
            return {"ok": False, "error": "principal_id is required"}
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

    async def handle_status(self, payload: dict) -> dict[str, Any]:
        """Handle a Status request.

        B1: only counts tasks owned by the authenticated principal.
        M2: empty ``principal_id`` is rejected up-front.
        """
        principal_id = str(payload.get("principal_id") or "")
        if not principal_id:
            return {"ok": False, "error": "principal_id is required"}
        return {"ok": True, "stats": self.spawner.stats(principal_id=principal_id)}
