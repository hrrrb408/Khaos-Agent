"""OS-sandboxed execution composition for trusted Coding oracles.

The evaluator has no private subprocess fallback.  A command oracle is usable
only when the existing platform selector proves an OS-enforced backend for the
current host; otherwise the caller receives an infrastructure error.
"""

from __future__ import annotations

from khaos.coding.execution import (
    BackendSelector,
    ExecutionService,
    ProcessSupervisor,
    UnsupportedBackend,
)
from khaos.runtime import RuntimeProfile


class CodingSandboxUnavailableError(RuntimeError):
    """No kernel-enforced execution backend was available for the oracle."""


async def build_oracle_execution_service(
    *,
    principal_id: str,
    project_id: str,
    runtime_id: str = "m8-oracle-runtime",
) -> ExecutionService:
    """Build a read-only oracle service with no host-backend fallback."""

    supervisor = ProcessSupervisor(runtime_profile=RuntimeProfile.TESTING)
    selector = BackendSelector(
        supervisor=supervisor,
        runtime_profile=RuntimeProfile.TESTING,
    )
    backend = await selector.select_async(writable=False)
    if isinstance(backend, UnsupportedBackend):
        await supervisor.close()
        raise CodingSandboxUnavailableError(
            backend.reason or "no kernel-enforced oracle backend is available"
        )
    return ExecutionService(
        backend=backend,
        process_supervisor=supervisor,
        principal_id=principal_id,
        project_id=project_id,
        runtime_id=runtime_id,
        runtime_profile=RuntimeProfile.TESTING,
    )


__all__ = ["CodingSandboxUnavailableError", "build_oracle_execution_service"]
