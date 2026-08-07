"""Execution backends for Coding Tasks."""

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
    ResourceBudget,
)
from khaos.coding.execution.platform import (
    BackendSelector,
    LinuxBubblewrapBackend,
    MacOSSandboxBackend,
    UnsupportedBackend,
)
from khaos.coding.execution.service import ExecutionService
from khaos.coding.execution.supervisor import ProcessSupervisor, SupervisorClosedError

__all__ = ["BackendSelector", "DockerBackend", "ExecutionRequest", "ExecutionResult", "ExecutionService", "FileSystemAccess", "HostExecutionBackend", "LinuxBubblewrapBackend", "MacOSSandboxBackend", "ManagedProcessHandle", "NetworkPolicy", "PermissionProfile", "ProcessSupervisor", "ResolvedExecutionContext", "ResourceBudget", "SupervisorClosedError", "UnsupportedBackend"]
