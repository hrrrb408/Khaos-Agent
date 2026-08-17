"""Execution backends for Coding Tasks.

Keep this package initializer lightweight.  The native launcher runtime imports
receipt-binding helpers after environment scrubbing and must not eagerly load
the full agent, model, or HTTP stack merely to verify a launch digest.
"""

from importlib import import_module

_LAZY_EXPORTS = {
    "BackendSelector": ("khaos.coding.execution.platform", "BackendSelector"),
    "DockerBackend": ("khaos.coding.execution.docker", "DockerBackend"),
    "DockerSandboxDecision": ("khaos.coding.execution.capability", "DockerSandboxDecision"),
    "ExecutionAuthority": ("khaos.coding.execution.authority", "ExecutionAuthority"),
    "ExecutionRequest": ("khaos.coding.execution.models", "ExecutionRequest"),
    "ExecutionResult": ("khaos.coding.execution.models", "ExecutionResult"),
    "ExecutionService": ("khaos.coding.execution.service", "ExecutionService"),
    "FileSystemAccess": ("khaos.coding.execution.models", "FileSystemAccess"),
    "HostExecutionBackend": ("khaos.coding.execution.host", "HostExecutionBackend"),
    "LinuxBubblewrapBackend": ("khaos.coding.execution.platform", "LinuxBubblewrapBackend"),
    "MacOSSandboxBackend": ("khaos.coding.execution.platform", "MacOSSandboxBackend"),
    "ManagedProcessHandle": ("khaos.coding.execution.managed", "ManagedProcessHandle"),
    "NetworkPolicy": ("khaos.coding.execution.models", "NetworkPolicy"),
    "PermissionProfile": ("khaos.coding.execution.models", "PermissionProfile"),
    "ProcessSupervisor": ("khaos.coding.execution.supervisor", "ProcessSupervisor"),
    "ResolvedExecutionContext": ("khaos.coding.execution.models", "ResolvedExecutionContext"),
    "ResolvedSpawnPlan": ("khaos.coding.execution.models", "ResolvedSpawnPlan"),
    "ResourceBudget": ("khaos.coding.execution.models", "ResourceBudget"),
    "ResourceOwner": ("khaos.coding.execution.resource_owner", "ResourceOwner"),
    "ResourceOwnerInvariantError": ("khaos.coding.execution.resource_owner", "ResourceOwnerInvariantError"),
    "ResourceOwnerSnapshot": ("khaos.coding.execution.resource_owner", "ResourceOwnerSnapshot"),
    "SandboxDecision": ("khaos.coding.execution.capability", "SandboxDecision"),
    "SupervisorClosedError": ("khaos.coding.execution.supervisor", "SupervisorClosedError"),
    "UnsupportedBackend": ("khaos.coding.execution.platform", "UnsupportedBackend"),
    "WindowsSandboxBackend": ("khaos.coding.execution.platform", "WindowsSandboxBackend"),
    "inspect_resource_owner": ("khaos.coding.execution.resource_owner", "inspect_resource_owner"),
    "require_terminal_resource_owner": ("khaos.coding.execution.resource_owner", "require_terminal_resource_owner"),
}


def __getattr__(name: str):
    """Load one public execution helper on first access."""
    target = _LAZY_EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module = import_module(target[0])
    value = getattr(module, target[1])
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    """Expose lazy public names to introspection and IDEs."""
    return sorted(set(globals()) | set(__all__))

__all__ = [
    "BackendSelector",
    "DockerBackend",
    "DockerSandboxDecision",
    "ExecutionAuthority",
    "ExecutionRequest",
    "ExecutionResult",
    "ExecutionService",
    "FileSystemAccess",
    "HostExecutionBackend",
    "LinuxBubblewrapBackend",
    "MacOSSandboxBackend",
    "ManagedProcessHandle",
    "NetworkPolicy",
    "PermissionProfile",
    "ProcessSupervisor",
    "ResolvedExecutionContext",
    "ResolvedSpawnPlan",
    "ResourceBudget",
    "ResourceOwner",
    "ResourceOwnerInvariantError",
    "ResourceOwnerSnapshot",
    "SandboxDecision",
    "SupervisorClosedError",
    "UnsupportedBackend",
    "WindowsSandboxBackend",
    "inspect_resource_owner",
    "require_terminal_resource_owner",
]
