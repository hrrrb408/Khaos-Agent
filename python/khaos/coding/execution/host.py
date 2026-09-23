"""Host execution backend with process-group and path safeguards."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from khaos.coding.execution.environment import build_task_environment
from khaos.coding.execution.models import (
    ExecutionRequest,
    ExecutionResult,
    NetworkPolicy,
)
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
        # The service has already canonicalized and bound production cwd
        # identity.  Keep this backend path lexical; the supervisor opens the
        # validated directory by FD immediately before spawn.
        cwd = request.cwd.expanduser().absolute()
        if not cwd.is_dir():
            raise ExecutionDenied(f"cwd is not a directory: {cwd}")
        profile = request.permission_profile
        if profile is None:
            raise ExecutionDenied("execution request has no permission profile")
        roots = profile.workspace_roots
        if roots and not _under(cwd, roots):
            raise ExecutionDenied("cwd is outside permission profile workspace roots")
        if profile.network is not NetworkPolicy.NONE:
            raise ExecutionDenied(
                "host backend only permits network policy none; it cannot prove "
                "network isolation; use an OS sandbox"
            )
        requested_environment = {
            key: value
            for key, value in os.environ.items()
            if key in profile.environment_keys
        }
        requested_environment.update(
            {
                key: value
                for key, value in request.environment.items()
                if key in profile.environment_keys
            }
        )
        workspace_root = (
            profile.workspace_roots[0]
            if profile.filesystem.value == "workspace-write"
            else None
        )
        # The host backend is retained for trusted local/test adapters, but
        # even that path must not hand the caller's HOME to a model-reachable
        # child.  Keep the synthetic home alive for the complete supervisor
        # ownership interval; TemporaryDirectory cleanup happens only after
        # the child has reached a terminal state.
        with tempfile.TemporaryDirectory(prefix="khaos-task-home-") as home:
            temporary_home = Path(home)
            temporary_tmp = temporary_home / "tmp"
            temporary_tmp.mkdir(mode=0o700)
            environment = build_task_environment(
                home=str(temporary_home),
                tmpdir=str(temporary_tmp),
                base_environment=requested_environment,
                allowed_keys=profile.environment_keys,
            )
            return await self._get_supervisor().run(
                request,
                cwd=cwd,
                execution_root=roots[0] if roots else None,
                env=environment,
                workspace_root=workspace_root,
                workspace_baseline=request.workspace_baseline,
            )

    async def terminate(self, execution_id: str) -> None:
        await self._get_supervisor().terminate(execution_id)


def _under(path: Path, roots: tuple[Path, ...]) -> bool:
    return any(path == root or root in path.parents for root in roots)
