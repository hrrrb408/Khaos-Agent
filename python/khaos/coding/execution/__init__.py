"""Execution backends for Coding Tasks."""

from khaos.coding.execution.authority import ExecutionAuthority
from khaos.coding.execution.capability import DockerSandboxDecision, SandboxDecision
from khaos.coding.execution.docker import DockerBackend
from khaos.coding.execution.host import HostExecutionBackend
from khaos.coding.execution.managed import ManagedProcessHandle
from khaos.coding.execution.models import (
    ExecutionRequest,
    ExecutionResult,
    FileSystemAccess,
    NetworkPolicy,
    PermissionProfile,
    ResolvedExecutionContext,
    ResolvedSpawnPlan,
    ResourceBudget,
)
from khaos.coding.execution.platform import (
    BackendSelector,
    LinuxBubblewrapBackend,
    MacOSSandboxBackend,
    UnsupportedBackend,
    WindowsSandboxBackend,
)
from khaos.coding.execution.resource_owner import (
    ResourceOwner,
    ResourceOwnerInvariantError,
    ResourceOwnerSnapshot,
    inspect_resource_owner,
    require_terminal_resource_owner,
)
from khaos.coding.execution.service import ExecutionService
from khaos.coding.execution.supervisor import ProcessSupervisor, SupervisorClosedError

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
