"""Regression tests proving blocking approval work stays off asyncio."""

from __future__ import annotations

import asyncio
import time

from khaos.tools.registry import ToolRegistry
from khaos.tools.scheduler import PermissionRequest, ToolScheduler


async def test_synchronous_approval_callback_does_not_starve_event_loop():
    scheduler = ToolScheduler(ToolRegistry(), permission_engine=None)
    callback_started = False

    def blocking_callback(_payload):
        nonlocal callback_started
        callback_started = True
        time.sleep(0.15)
        return {"approved": True}

    request = PermissionRequest(
        tool_call_id="call-1",
        name="terminal_shell",
        arguments={},
        level="dangerous",
        target="workspace:task",
        reason="test",
        expires_at=time.time() + 1,
    )
    confirmation = asyncio.create_task(
        scheduler._confirm(request, blocking_callback)
    )
    heartbeats = 0
    deadline = asyncio.get_running_loop().time() + 0.1
    while asyncio.get_running_loop().time() < deadline:
        await asyncio.sleep(0.005)
        heartbeats += 1
    result = await confirmation

    assert callback_started
    assert heartbeats >= 5
    assert result["approved"] is True


async def test_synchronous_approval_callback_obeys_deadline():
    scheduler = ToolScheduler(ToolRegistry(), permission_engine=None)

    def blocking_callback(_payload):
        time.sleep(0.2)
        return {"approved": True}

    request = PermissionRequest(
        tool_call_id="call-timeout",
        name="terminal_shell",
        arguments={},
        level="dangerous",
        target="workspace:task",
        reason="test",
        expires_at=time.time() + 0.03,
    )
    started = time.monotonic()
    result = await scheduler._confirm(request, blocking_callback)
    elapsed = time.monotonic() - started

    assert result == {
        "approved": False,
        "reason": "approval_callback_timeout",
    }
    assert elapsed < 0.15
