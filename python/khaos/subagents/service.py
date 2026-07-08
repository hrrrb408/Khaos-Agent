"""SubAgent JSON-line RPC service called by the Go gateway."""

from __future__ import annotations

import logging
from typing import Any

from khaos.subagents.runner import SubAgentRunner
from khaos.subagents.spawner import SubAgentSpawner, SubAgentTask

logger = logging.getLogger(__name__)


class SubAgentService:
    """Handle SubAgent RPC requests from the Go gateway."""

    def __init__(self, spawner: SubAgentSpawner, runner: SubAgentRunner | None):
        self.spawner = spawner
        self.runner = runner

    async def handle_spawn(self, payload: dict) -> dict[str, Any]:
        """Handle a Spawn request."""
        task = SubAgentTask(
            id="",
            goal=payload.get("goal", ""),
            context=payload.get("context", ""),
            tools=payload.get("tools", []),
            timeout=payload.get("timeout", 300),
            parent_session_id="gateway",
            depth=1,
        )
        try:
            result = await self.spawner.spawn(task)
            return {"ok": True, "task_id": result.id, "status": "running"}
        except Exception as exc:
            logger.warning("subagent spawn failed: %s", exc)
            return {"ok": False, "error": str(exc)}

    async def handle_collect(self, payload: dict) -> dict[str, Any]:
        """Handle a Collect request."""
        del payload
        try:
            tasks = await self.spawner.wait_all(timeout=600)
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
        """Handle a Status request."""
        del payload
        return {"ok": True, "stats": self.spawner.stats()}
