"""Declarative tool registry and JSON Schema validation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Awaitable, Callable

from khaos.exceptions import ToolNotFoundError


@dataclass
class ToolDefinition:
    """Declarative tool definition."""

    name: str
    description: str
    parameters: dict
    modes: list[str]
    permission_level: str
    parallel: bool
    timeout: int = 60
    handler: Callable[..., Awaitable[Any]] | None = None


class ToolRegistry:
    """Runtime registry for declared tools."""

    def __init__(self):
        self._tools: dict[str, ToolDefinition] = {}

    def register(self, definition: ToolDefinition) -> None:
        """Register a tool definition."""
        if definition.name in self._tools:
            raise ValueError(f"tool already registered: {definition.name}")
        self._tools[definition.name] = definition

    def get(self, name: str) -> ToolDefinition:
        """Return a registered tool or raise ToolNotFoundError."""
        try:
            return self._tools[name]
        except KeyError as exc:
            raise ToolNotFoundError(name) from exc

    def list_by_mode(self, mode: str) -> list[ToolDefinition]:
        """List tools available to a mode."""
        return [
            tool
            for tool in self._tools.values()
            if "all" in tool.modes or mode in tool.modes
        ]

    def get_parallel_tools(self, tool_calls: list[dict]) -> tuple[list[dict], list[dict]]:
        """Split tool calls into parallel-safe and serial groups."""
        parallel_calls: list[dict] = []
        serial_calls: list[dict] = []
        for call in tool_calls:
            tool = self.get(str(call["name"]))
            if tool.parallel and tool.permission_level == "read":
                parallel_calls.append(call)
            else:
                serial_calls.append(call)
        return parallel_calls, serial_calls

    def validate_call(self, name: str, params: dict) -> bool:
        """Validate a small useful subset of JSON Schema."""
        schema = self.get(name).parameters
        if schema.get("type") == "object" and not isinstance(params, dict):
            return False
        for required in schema.get("required", []):
            if required not in params:
                return False
        properties = schema.get("properties", {})
        for key, value in params.items():
            if key not in properties:
                continue
            expected = properties[key].get("type")
            if expected == "string" and not isinstance(value, str):
                return False
            if expected == "integer" and not isinstance(value, int):
                return False
            if expected == "boolean" and not isinstance(value, bool):
                return False
            if expected == "object" and not isinstance(value, dict):
                return False
        return True


def register_builtin_tools(registry: ToolRegistry) -> None:
    """Register the Phase 1 built-in tool declarations."""
    registry.register(
        ToolDefinition(
            name="read_file",
            description="Read file content with pagination and line numbers.",
            parameters={
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "offset": {"type": "integer"},
                    "limit": {"type": "integer"},
                },
                "required": ["path"],
            },
            modes=["all"],
            permission_level="read",
            parallel=True,
        )
    )
    registry.register(
        ToolDefinition(
            name="write_file",
            description="Overwrite a file and create parent directories.",
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
        )
    )
    registry.register(
        ToolDefinition(
            name="patch",
            description="Apply an atomic find-and-replace patch to a file.",
            parameters={
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "old": {"type": "string"},
                    "new": {"type": "string"},
                    "fuzzy": {"type": "boolean"},
                },
                "required": ["path", "old", "new"],
            },
            modes=["coding"],
            permission_level="write",
            parallel=False,
        )
    )
    registry.register(
        ToolDefinition(
            name="search_files",
            description="Search filenames by glob or file contents by text.",
            parameters={
                "type": "object",
                "properties": {
                    "root": {"type": "string"},
                    "query": {"type": "string"},
                    "glob": {"type": "string"},
                    "content": {"type": "boolean"},
                    "limit": {"type": "integer"},
                },
            },
            modes=["all"],
            permission_level="read",
            parallel=True,
        )
    )
    registry.register(
        ToolDefinition(
            name="terminal",
            description="Run a foreground or background terminal command.",
            parameters={
                "type": "object",
                "properties": {
                    "command": {"type": "string"},
                    "cwd": {"type": "string"},
                    "background": {"type": "boolean"},
                    "timeout": {"type": "integer"},
                },
                "required": ["command"],
            },
            modes=["coding"],
            permission_level="execute",
            parallel=False,
        )
    )
    registry.register(
        ToolDefinition(
            name="process",
            description="Poll, wait, kill, or read logs for a background process.",
            parameters={
                "type": "object",
                "properties": {
                    "action": {"type": "string"},
                    "id": {"type": "string"},
                    "timeout": {"type": "integer"},
                },
                "required": ["action", "id"],
            },
            modes=["coding"],
            permission_level="execute",
            parallel=False,
        )
    )
    registry.register(
        ToolDefinition(
            name="sandbox_exec",
            description="Run a command inside an isolated Docker sandbox.",
            parameters={
                "type": "object",
                "properties": {
                    "command": {"type": "string"},
                    "image": {"type": "string"},
                    "project_dir": {"type": "string"},
                    "network": {"type": "boolean"},
                    "timeout": {"type": "integer"},
                },
                "required": ["command"],
            },
            modes=["coding"],
            permission_level="execute",
            parallel=False,
        )
    )
    registry.register(
        ToolDefinition(
            name="sandbox_build",
            description="Build a Docker image for sandbox execution.",
            parameters={
                "type": "object",
                "properties": {
                    "dockerfile": {"type": "string"},
                    "context": {"type": "string"},
                    "tag": {"type": "string"},
                    "timeout": {"type": "integer"},
                },
                "required": ["dockerfile"],
            },
            modes=["coding"],
            permission_level="execute",
            parallel=False,
        )
    )
    registry.register(
        ToolDefinition(
            name="git_diff",
            description="Show git diff.",
            parameters={
                "type": "object",
                "properties": {"repo": {"type": "string"}, "staged": {"type": "boolean"}},
            },
            modes=["coding"],
            permission_level="read",
            parallel=True,
        )
    )
    registry.register(
        ToolDefinition(
            name="git_commit",
            description="Create a git commit.",
            parameters={
                "type": "object",
                "properties": {"repo": {"type": "string"}, "message": {"type": "string"}},
                "required": ["message"],
            },
            modes=["coding"],
            permission_level="write",
            parallel=False,
        )
    )
    registry.register(
        ToolDefinition(
            name="git_branch",
            description="List or create git branches.",
            parameters={
                "type": "object",
                "properties": {
                    "repo": {"type": "string"},
                    "name": {"type": "string"},
                    "checkout": {"type": "boolean"},
                },
            },
            modes=["coding"],
            permission_level="write",
            parallel=False,
        )
    )
    registry.register(
        ToolDefinition(
            name="git_log",
            description="Show git log.",
            parameters={
                "type": "object",
                "properties": {"repo": {"type": "string"}, "limit": {"type": "integer"}},
            },
            modes=["coding"],
            permission_level="read",
            parallel=True,
        )
    )
    for name, description, parameters in [
        (
            "browser_navigate",
            "Navigate browser to URL.",
            {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]},
        ),
        (
            "browser_click",
            "Click an element.",
            {"type": "object", "properties": {"selector": {"type": "string"}}, "required": ["selector"]},
        ),
        (
            "browser_type",
            "Type text into an element.",
            {
                "type": "object",
                "properties": {"selector": {"type": "string"}, "text": {"type": "string"}},
                "required": ["selector", "text"],
            },
        ),
        ("browser_snapshot", "Read browser snapshot.", {"type": "object", "properties": {}}),
        ("browser_vision", "Read visual browser summary.", {"type": "object", "properties": {}}),
    ]:
        registry.register(
            ToolDefinition(
                name=name,
                description=description,
                parameters=parameters,
                modes=["office"],
                permission_level="read" if name in {"browser_snapshot", "browser_vision"} else "network",
                parallel=False,
            )
        )
    registry.register(
        ToolDefinition(
            name="code_search",
            description="Search code files for text.",
            parameters={
                "type": "object",
                "properties": {
                    "root": {"type": "string"},
                    "query": {"type": "string"},
                    "glob": {"type": "string"},
                    "limit": {"type": "integer"},
                },
                "required": ["query"],
            },
            modes=["coding"],
            permission_level="read",
            parallel=True,
        )
    )
    registry.register(
        ToolDefinition(
            name="code_symbols",
            description="Extract symbols from a Python source file.",
            parameters={
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
            modes=["coding"],
            permission_level="read",
            parallel=True,
        )
    )


def create_builtin_registry() -> ToolRegistry:
    """Create a registry with the Phase 1 built-in declarations."""
    registry = ToolRegistry()
    register_builtin_tools(registry)
    return registry


def create_runtime_registry() -> ToolRegistry:
    """Create a built-in registry with concrete P0-B tool handlers."""
    from khaos.tools import (
        browser_tools,
        code_search_tools,
        file_tools,
        git_tools,
        sandbox_tools,
        terminal_tools,
    )

    registry = create_builtin_registry()
    registry.get("read_file").handler = file_tools.read_file
    registry.get("write_file").handler = file_tools.write_file
    registry.get("patch").handler = file_tools.patch
    registry.get("search_files").handler = file_tools.search_files
    registry.get("terminal").handler = terminal_tools.terminal
    registry.get("process").handler = terminal_tools.process
    registry.get("sandbox_exec").handler = sandbox_tools.sandbox_exec
    registry.get("sandbox_build").handler = sandbox_tools.sandbox_build
    registry.get("git_diff").handler = git_tools.git_diff
    registry.get("git_commit").handler = git_tools.git_commit
    registry.get("git_branch").handler = git_tools.git_branch
    registry.get("git_log").handler = git_tools.git_log
    registry.get("browser_navigate").handler = browser_tools.browser_navigate
    registry.get("browser_click").handler = browser_tools.browser_click
    registry.get("browser_type").handler = browser_tools.browser_type
    registry.get("browser_snapshot").handler = browser_tools.browser_snapshot
    registry.get("browser_vision").handler = browser_tools.browser_vision
    registry.get("code_search").handler = code_search_tools.code_search
    registry.get("code_symbols").handler = code_search_tools.code_symbols
    return registry
