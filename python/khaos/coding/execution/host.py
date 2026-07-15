"""Host execution backend with process-group and path safeguards."""

from __future__ import annotations

import os
from pathlib import Path

from khaos.coding.execution.models import ExecutionRequest, ExecutionResult, NetworkPolicy
from khaos.coding.execution.supervisor import ProcessSupervisor


class ExecutionDenied(PermissionError):
    """Raised when an execution request violates the workspace boundary."""


class HostExecutionBackend:
    name = "host"

    def __init__(self, supervisor: ProcessSupervisor | None = None) -> None:
        self.supervisor = supervisor or ProcessSupervisor()

    def _get_supervisor(self) -> ProcessSupervisor:
        """Return the supervisor, including for legacy subclasses skipping init."""
        supervisor = getattr(self, "supervisor", None)
        if supervisor is None:
            supervisor = ProcessSupervisor()
            self.supervisor = supervisor
        return supervisor

    async def probe(self) -> dict[str, object]:
        return {
            "available": True,
            "network_enforcement": "best-effort",
            "network_policy": NetworkPolicy.NONE.value,
        }

    async def execute(self, request: ExecutionRequest) -> ExecutionResult:
        if not request.argv or any(not isinstance(arg, str) for arg in request.argv):
            raise ValueError("argv must contain at least one string")
        cwd = request.cwd.expanduser().resolve()
        if not cwd.is_dir():
            raise ExecutionDenied(f"cwd is not a directory: {cwd}")
        profile = request.permission_profile
        if profile is None:
            raise ExecutionDenied("execution request has no permission profile")
        roots = profile.workspace_roots
        if roots and not _under(cwd, roots):
            raise ExecutionDenied("cwd is outside permission profile workspace roots")
        if profile.network is not NetworkPolicy.NONE:
            raise ExecutionDenied("host backend only permits network_policy=none")
        env = {
            key: value
            for key, value in os.environ.items()
            if key in profile.environment_keys
        }
        env.update(
            {
                key: value
                for key, value in request.environment.items()
                if key in profile.environment_keys
            }
        )
        return await self._get_supervisor().run(request, cwd=cwd, env=env)

    async def terminate(self, execution_id: str) -> None:
        await self._get_supervisor().terminate(execution_id)


def _under(path: Path, roots: tuple[Path, ...]) -> bool:
    return any(path == root or root in path.parents for root in roots)
