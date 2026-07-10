"""Tools for channel registration status management."""

from __future__ import annotations

from typing import Any

_registry: Any = None


def set_channel_registry(registry: Any) -> None:
    global _registry
    _registry = registry


async def channel_list(**kwargs: Any) -> dict[str, Any]:
    if _registry is None:
        return {"status": "unavailable", "error": "channel registry not configured"}
    return {"channels": [{"id": item.id, "type": item.channel_type.value, "enabled": item.is_enabled, "healthy": item.is_healthy, "status": item.health.status.value} for item in _registry.list_all()]}


async def channel_health(**kwargs: Any) -> dict[str, Any]:
    if _registry is None:
        return {"status": "unavailable"}
    return {"report": _registry.get_health_report()}


async def channel_enable(channel_id: str, **kwargs: Any) -> dict[str, str]:
    if _registry is None:
        return {"status": "unavailable", "channel_id": channel_id}
    return {"status": "enabled" if _registry.enable(channel_id) else "not_found", "channel_id": channel_id}


async def channel_disable(channel_id: str, **kwargs: Any) -> dict[str, str]:
    if _registry is None:
        return {"status": "unavailable", "channel_id": channel_id}
    return {"status": "disabled" if _registry.disable(channel_id) else "not_found", "channel_id": channel_id}


CHANNEL_TOOLS = [
    {"name": "channel_list", "description": "List registered communication channels.", "parameters": {"type": "object", "properties": {}}},
    {"name": "channel_health", "description": "Get channel health reports.", "parameters": {"type": "object", "properties": {}}},
    {"name": "channel_enable", "description": "Enable a registered channel.", "parameters": {"type": "object", "properties": {"channel_id": {"type": "string"}}, "required": ["channel_id"]}},
    {"name": "channel_disable", "description": "Disable a registered channel.", "parameters": {"type": "object", "properties": {"channel_id": {"type": "string"}}, "required": ["channel_id"]}},
]
