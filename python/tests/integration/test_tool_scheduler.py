"""ToolScheduler + SecurityMiddleware 集成测试。"""

from __future__ import annotations

from khaos.db import Database
from khaos.permissions import ApprovalMode, PermissionEngine
from khaos.tools.registry import ToolDefinition, ToolRegistry
from khaos.tools.scheduler import ToolScheduler


class RecordingTerminal:
    """Callable terminal stub used to prove dispatch happened."""

    def __init__(self):
        self.calls: list[str] = []

    async def __call__(self, command: str, cwd: str = "", background: bool = False, timeout: int = 30):
        del cwd, background, timeout
        self.calls.append(command)
        return {"stdout": "scheduled\n", "stderr": "", "returncode": 0}


class RecordingWriteFile:
    """Callable write_file stub used to prove blocked calls do not execute."""

    def __init__(self):
        self.calls: list[tuple[str, str]] = []

    async def __call__(self, path: str, content: str):
        self.calls.append((path, content))
        return {"path": path, "bytes": len(content)}


def scheduler_registry(terminal: RecordingTerminal, write_file: RecordingWriteFile) -> ToolRegistry:
    """Create a small registry with the real tool names used by SecurityMiddleware."""
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name="terminal",
            description="terminal",
            parameters={
                "type": "object",
                "properties": {"command": {"type": "string"}},
                "required": ["command"],
            },
            modes=["coding"],
            permission_level="execute",
            parallel=False,
            handler=terminal,
        )
    )
    registry.register(
        ToolDefinition(
            name="write_file",
            description="write_file",
            parameters={
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "content": {"type": "string"},
                },
                "required": ["path", "content"],
            },
            modes=["coding"],
            permission_level="write",
            parallel=False,
            handler=write_file,
        )
    )
    return registry


async def create_scheduler(tmp_path, default_mode: ApprovalMode = ApprovalMode.AUTO_APPROVE):
    """Create a scheduler with recording handlers."""
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    terminal = RecordingTerminal()
    write_file = RecordingWriteFile()
    scheduler = ToolScheduler(
        scheduler_registry(terminal, write_file),
        PermissionEngine(db, default_mode=default_mode),
    )
    return db, scheduler, terminal, write_file


class TestSchedulerSafeCommand:
    async def test_safe_terminal_command_is_dispatched(self, tmp_path):
        db, scheduler, terminal, _ = await create_scheduler(tmp_path)

        results = await scheduler.execute_batch(
            [{"id": "1", "name": "terminal", "arguments": {"command": "ls -la"}}],
            mode="coding",
        )

        assert results[0].success
        assert terminal.calls == ["ls -la"]
        await db.close()


class TestSchedulerBlockedCommand:
    async def test_blocked_terminal_command_is_not_executed(self, tmp_path):
        db, scheduler, terminal, _ = await create_scheduler(tmp_path)

        results = await scheduler.execute_batch(
            [{"id": "1", "name": "terminal", "arguments": {"command": "sudo rm -rf /"}}],
            mode="coding",
        )

        assert not results[0].success
        assert "Security check blocked" in results[0].error
        assert terminal.calls == []
        await db.close()


class TestSchedulerWriteProtectedPath:
    async def test_write_file_to_etc_is_blocked_by_path_guard(self, tmp_path):
        db, scheduler, _, write_file = await create_scheduler(tmp_path)

        results = await scheduler.execute_batch(
            [
                {
                    "id": "1",
                    "name": "write_file",
                    "arguments": {"path": "/etc/passwd", "content": "hacked"},
                }
            ],
            mode="coding",
        )

        assert not results[0].success
        assert "Security check blocked" in results[0].error
        assert write_file.calls == []
        await db.close()


class TestSchedulerPermissionCheck:
    async def test_permission_engine_allows_and_tool_executes(self, tmp_path):
        db, scheduler, terminal, _ = await create_scheduler(
            tmp_path,
            default_mode=ApprovalMode.AUTO_APPROVE,
        )

        results = await scheduler.execute_batch(
            [{"id": "1", "name": "terminal", "arguments": {"command": "ls"}}],
            mode="coding",
        )

        assert results[0].success
        assert terminal.calls == ["ls"]
        await db.close()
