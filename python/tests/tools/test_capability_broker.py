import pytest

from khaos.tools.registry import ToolDefinition, ToolInvocationBroker, ToolRegistry


@pytest.mark.asyncio
async def test_process_tool_fails_closed_without_execution_service():
    registry = ToolRegistry(enforce_capabilities=True)
    registry.register(ToolDefinition("terminal", "", {"type": "object"}, ["coding"], "write", False, handler=lambda: None))
    with pytest.raises(PermissionError, match="ExecutionService"):
        await ToolInvocationBroker(registry).invoke("terminal", mode="coding", context={})


@pytest.mark.asyncio
async def test_filesystem_write_requires_task_workspace():
    registry = ToolRegistry(enforce_capabilities=True)
    registry.register(ToolDefinition("write_file", "", {"type": "object"}, ["coding"], "write", False, handler=lambda: None))
    with pytest.raises(PermissionError, match="TaskWorkspace"):
        await ToolInvocationBroker(registry).invoke("write_file", mode="coding", context={})
