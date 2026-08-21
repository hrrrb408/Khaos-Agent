"""Tool registry skeleton."""

from khaos.tools.approval_callback import ApprovalCallbackRunner
from khaos.tools.authorization import (
    RememberRuleProjection,
    ToolAuthorization,
    build_approval_binding,
    build_permission_request,
    tool_has_capability,
)
from khaos.tools.execution_coordinator import ToolExecutionCoordinator
from khaos.tools.operation_store import OperationClaim, ToolOperationStore
from khaos.tools.registry import (
    ToolCapability,
    ToolDefinition,
    ToolInvocationBroker,
    ToolRegistry,
    create_builtin_registry,
    create_runtime_registry,
)
from khaos.tools.result_codec import ToolResultCodec
from khaos.tools.result_store import ToolResultStore

__all__ = [
    "ApprovalCallbackRunner",
    "OperationClaim",
    "RememberRuleProjection",
    "ToolAuthorization",
    "ToolCapability",
    "ToolDefinition",
    "ToolExecutionCoordinator",
    "ToolInvocationBroker",
    "ToolOperationStore",
    "ToolRegistry",
    "ToolResultCodec",
    "ToolResultStore",
    "build_approval_binding",
    "build_permission_request",
    "create_builtin_registry",
    "create_runtime_registry",
    "tool_has_capability",
]
