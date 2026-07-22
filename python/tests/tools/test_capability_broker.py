import os

import pytest

from khaos.tools.registry import (
    ToolCapability,
    ToolDefinition,
    ToolInvocationBroker,
    ToolRegistry,
)


PROCESS_CAP = ToolCapability(
    "process.execute", frozenset({"coding"}), frozenset({"task-workspace"})
)
WRITE_CAP = ToolCapability(
    "filesystem.write", frozenset({"coding"}), frozenset({"task-workspace"})
)


@pytest.mark.asyncio
async def test_process_tool_fails_closed_without_execution_service():
    registry = ToolRegistry(enforce_capabilities=True)
    registry.register(ToolDefinition("terminal", "", {"type": "object"}, ["coding"], "write", False, handler=lambda: None, capabilities=(PROCESS_CAP,)))
    with pytest.raises(PermissionError, match="ExecutionService"):
        await ToolInvocationBroker(registry).invoke("terminal", mode="coding", context={})


@pytest.mark.asyncio
async def test_filesystem_write_requires_task_workspace():
    registry = ToolRegistry(enforce_capabilities=True)
    registry.register(ToolDefinition("write_file", "", {"type": "object"}, ["coding"], "write", False, handler=lambda: None, capabilities=(WRITE_CAP,)))
    with pytest.raises(PermissionError, match="TaskWorkspace"):
        await ToolInvocationBroker(registry).invoke("write_file", mode="coding", context={})


@pytest.mark.asyncio
async def test_workspace_ids_cannot_replace_workspace_authority():
    registry = ToolRegistry(enforce_capabilities=True)
    registry.register(ToolDefinition("write_file", "", {"type": "object"}, ["coding"], "write", False, handler=lambda: None, capabilities=(WRITE_CAP,)))

    with pytest.raises(PermissionError, match="TaskWorkspace"):
        await ToolInvocationBroker(registry).invoke(
            "write_file",
            mode="coding",
            context={"task_id": "forged", "workspace_id": "forged"},
        )


def test_registry_rejects_missing_capability_in_enforced_mode():
    registry = ToolRegistry(enforce_capabilities=True)
    with pytest.raises(ValueError, match="must declare explicit capabilities"):
        registry.register(
            ToolDefinition("new_tool", "", {"type": "object"}, ["office"], "read", True)
        )


@pytest.mark.asyncio
async def test_host_notes_reject_remote_and_background_principals():
    notes_cap = ToolCapability(
        "host.notes.read",
        frozenset({"office"}),
        frozenset({"local-interactive-user"}),
    )

    async def handler():
        return {"ok": True}

    registry = ToolRegistry(enforce_capabilities=True)
    registry.register(
        ToolDefinition(
            "list_notes", "", {"type": "object"}, ["office"], "read", True,
            handler=handler, capabilities=(notes_cap,),
        )
    )
    broker = ToolInvocationBroker(registry)

    with pytest.raises(PermissionError, match="local interactive"):
        await broker.invoke(
            "list_notes",
            mode="office",
            context={
                "principal_id": "webhook:slack:attacker",
                "source_transport": "webhook",
                "foreground_session": False,
            },
        )
    with pytest.raises(PermissionError, match="foreground"):
        await broker.invoke(
            "list_notes",
            mode="office",
            context={
                "principal_id": f"local-uid:{os.getuid()}",
                "source_transport": "cron",
                "foreground_session": False,
            },
        )


@pytest.mark.asyncio
async def test_host_notes_allow_local_foreground_cli():
    notes_cap = ToolCapability(
        "host.notes.read",
        frozenset({"office"}),
        frozenset({"local-interactive-user"}),
    )

    async def handler():
        return {"ok": True}

    registry = ToolRegistry(enforce_capabilities=True)
    registry.register(
        ToolDefinition(
            "list_notes", "", {"type": "object"}, ["office"], "read", True,
            handler=handler, capabilities=(notes_cap,),
        )
    )

    result = await ToolInvocationBroker(registry).invoke(
        "list_notes",
        mode="office",
        context={
            "principal_id": f"local-uid:{os.getuid()}",
            "source_transport": "cli",
            "foreground_session": True,
        },
    )
    assert result == {"ok": True}
