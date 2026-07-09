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
        return self._validate_schema_value(schema, params)

    def _validate_schema_value(self, schema: dict, value: Any) -> bool:
        expected = schema.get("type")
        if "enum" in schema and value not in schema["enum"]:
            return False
        if expected == "string":
            return isinstance(value, str)
        if expected == "integer":
            return isinstance(value, int)
        if expected == "boolean":
            return isinstance(value, bool)
        if expected == "object":
            if not isinstance(value, dict):
                return False
            for required in schema.get("required", []):
                if required not in value:
                    return False
            properties = schema.get("properties", {})
            return all(
                key not in properties or self._validate_schema_value(properties[key], item)
                for key, item in value.items()
            )
        if expected == "array":
            if not isinstance(value, list):
                return False
            item_schema = schema.get("items")
            if item_schema is None:
                return True
            return all(self._validate_schema_value(item_schema, item) for item in value)
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
            name="multi_edit",
            description=(
                "Apply multiple search-and-replace edits to a single file in one call. "
                "If any edit fails to match, no changes are written."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File path"},
                    "edits": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "old_text": {"type": "string"},
                                "new_text": {"type": "string"},
                            },
                            "required": ["old_text", "new_text"],
                        },
                        "description": "List of edits to apply",
                    },
                },
                "required": ["path", "edits"],
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
            name="list_directory",
            description="List directory contents with structured info (dirs, files, sizes).",
            parameters={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Directory path (default: current directory)",
                        "default": ".",
                    }
                },
                "required": [],
            },
            modes=["office", "coding"],
            permission_level="read",
            parallel=True,
        )
    )
    registry.register(
        ToolDefinition(
            name="file_info",
            description=(
                "Get detailed file/directory metadata "
                "(size, type, modified date, mime type)."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File or directory path"}
                },
                "required": ["path"],
            },
            modes=["office", "coding"],
            permission_level="read",
            parallel=True,
        )
    )
    registry.register(
        ToolDefinition(
            name="tree_view",
            description="Generate a tree view of a directory structure.",
            parameters={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "default": "."},
                    "max_depth": {
                        "type": "integer",
                        "description": "Max recursion depth (default 3)",
                        "default": 3,
                    },
                },
                "required": [],
            },
            modes=["office", "coding"],
            permission_level="read",
            parallel=True,
        )
    )
    registry.register(
        ToolDefinition(
            name="copy_file",
            description="Copy a file or directory.",
            parameters={
                "type": "object",
                "properties": {
                    "src": {"type": "string"},
                    "dst": {"type": "string"},
                },
                "required": ["src", "dst"],
            },
            modes=["office", "coding"],
            permission_level="write",
            parallel=False,
        )
    )
    registry.register(
        ToolDefinition(
            name="move_file",
            description="Move or rename a file or directory.",
            parameters={
                "type": "object",
                "properties": {
                    "src": {"type": "string"},
                    "dst": {"type": "string"},
                },
                "required": ["src", "dst"],
            },
            modes=["office", "coding"],
            permission_level="write",
            parallel=False,
        )
    )
    registry.register(
        ToolDefinition(
            name="file_search_content",
            description=(
                "Search file contents for a pattern (substring or regex). "
                "Returns matching lines with file paths and line numbers."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Directory to search in",
                        "default": ".",
                    },
                    "pattern": {"type": "string"},
                    "max_results": {"type": "integer", "default": 50},
                },
                "required": ["pattern"],
            },
            modes=["office", "coding"],
            permission_level="read",
            parallel=True,
        )
    )
    registry.register(
        ToolDefinition(
            name="quick_note",
            description="Quick capture a note with optional title and tags. Saved to ~/.khaos/notes/.",
            parameters={
                "type": "object",
                "properties": {
                    "content": {"type": "string"},
                    "title": {"type": "string", "default": ""},
                    "tags": {
                        "type": "array",
                        "items": {"type": "string"},
                        "default": [],
                    },
                },
                "required": ["content"],
            },
            modes=["office"],
            permission_level="write",
            parallel=False,
        )
    )
    registry.register(
        ToolDefinition(
            name="search_notes",
            description="Search notes by query string (matches title, tags, and content).",
            parameters={
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "max_results": {"type": "integer", "default": 10},
                },
                "required": ["query"],
            },
            modes=["office"],
            permission_level="read",
            parallel=True,
        )
    )
    registry.register(
        ToolDefinition(
            name="list_notes",
            description="List recent notes, optionally filtered by tag.",
            parameters={
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "default": 20},
                    "tag": {"type": "string", "default": ""},
                },
            },
            modes=["office"],
            permission_level="read",
            parallel=True,
        )
    )
    registry.register(
        ToolDefinition(
            name="delete_note",
            description="Delete a note file. Only files under ~/.khaos/notes/ can be deleted.",
            parameters={
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
            modes=["office"],
            permission_level="write",
            parallel=False,
        )
    )
    registry.register(
        ToolDefinition(
            name="markdown_to_text",
            description="Convert Markdown to plain text, stripping all formatting.",
            parameters={
                "type": "object",
                "properties": {"markdown": {"type": "string"}},
                "required": ["markdown"],
            },
            modes=["office"],
            permission_level="read",
            parallel=True,
        )
    )
    registry.register(
        ToolDefinition(
            name="extract_headings",
            description="Extract heading structure (TOC) from Markdown text.",
            parameters={
                "type": "object",
                "properties": {"markdown": {"type": "string"}},
                "required": ["markdown"],
            },
            modes=["office"],
            permission_level="read",
            parallel=True,
        )
    )
    registry.register(
        ToolDefinition(
            name="count_words",
            description=(
                "Count words, characters, lines, paragraphs, "
                "and estimate reading time."
            ),
            parameters={
                "type": "object",
                "properties": {"text": {"type": "string"}},
                "required": ["text"],
            },
            modes=["office"],
            permission_level="read",
            parallel=True,
        )
    )
    registry.register(
        ToolDefinition(
            name="format_markdown_table",
            description="Format structured data as a Markdown table.",
            parameters={
                "type": "object",
                "properties": {
                    "headers": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                    "rows": {
                        "type": "array",
                        "items": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                    },
                },
                "required": ["headers", "rows"],
            },
            modes=["office"],
            permission_level="read",
            parallel=True,
        )
    )
    registry.register(
        ToolDefinition(
            name="clipboard_read",
            description="Read the system clipboard content.",
            parameters={"type": "object", "properties": {}},
            modes=["office"],
            permission_level="read",
            parallel=False,
        )
    )
    registry.register(
        ToolDefinition(
            name="clipboard_write",
            description="Write text to the system clipboard.",
            parameters={
                "type": "object",
                "properties": {"text": {"type": "string"}},
                "required": ["text"],
            },
            modes=["office"],
            permission_level="write",
            parallel=False,
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
    registry.register(
        ToolDefinition(
            name="test_run",
            description=(
                "Run test commands and parse results. Returns structured "
                "output with pass/fail counts and failed test details."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "Test command to run",
                    },
                    "cwd": {
                        "type": "string",
                        "description": "Working directory",
                    },
                },
                "required": ["command", "cwd"],
            },
            modes=["coding"],
            permission_level="write",
            parallel=False,
        )
    )
    registry.register(
        ToolDefinition(
            name="git_status",
            description="Get current git status (branch, modified/added/deleted/untracked files).",
            parameters={
                "type": "object",
                "properties": {
                    "cwd": {
                        "type": "string",
                        "description": "Working directory",
                    },
                },
                "required": ["cwd"],
            },
            modes=["coding", "office"],
            permission_level="read",
            parallel=True,
        )
    )
    registry.register(
        ToolDefinition(
            name="git_smart_commit",
            description=(
                "Stage all changes and commit with an auto-generated or custom "
                "conventional commit message."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "cwd": {
                        "type": "string",
                        "description": "Working directory",
                    },
                    "message": {
                        "type": "string",
                        "description": "Optional commit message. Auto-generated if empty.",
                    },
                },
                "required": ["cwd"],
            },
            modes=["coding"],
            permission_level="write",
            parallel=False,
        )
    )
    registry.register(
        ToolDefinition(
            name="git_undo",
            description="Undo the last commit, keeping file changes staged (soft reset).",
            parameters={
                "type": "object",
                "properties": {
                    "cwd": {
                        "type": "string",
                        "description": "Working directory",
                    },
                },
                "required": ["cwd"],
            },
            modes=["coding"],
            permission_level="write",
            parallel=False,
        )
    )
    registry.register(
        ToolDefinition(
            name="git_create_branch",
            description="Create and switch to a new branch off a base branch (default: main).",
            parameters={
                "type": "object",
                "properties": {
                    "cwd": {
                        "type": "string",
                        "description": "Working directory",
                    },
                    "branch_name": {
                        "type": "string",
                        "description": "Branch name (e.g. fix/login-bug, feat/add-auth)",
                    },
                    "from_base": {
                        "type": "string",
                        "description": "Base branch to branch off (default: main)",
                        "default": "main",
                    },
                },
                "required": ["cwd", "branch_name"],
            },
            modes=["coding"],
            permission_level="write",
            parallel=False,
        )
    )
    registry.register(
        ToolDefinition(
            name="git_push",
            description="Push the current (or named) branch to a remote, setting up tracking.",
            parameters={
                "type": "object",
                "properties": {
                    "cwd": {
                        "type": "string",
                        "description": "Working directory",
                    },
                    "remote": {
                        "type": "string",
                        "description": "Remote name (default: origin)",
                        "default": "origin",
                    },
                    "branch": {
                        "type": "string",
                        "description": "Branch to push (empty = current branch)",
                    },
                },
                "required": ["cwd"],
            },
            modes=["coding"],
            permission_level="write",
            parallel=False,
        )
    )
    registry.register(
        ToolDefinition(
            name="git_pr_body",
            description=(
                "Generate a PR description draft (title, body, changed files) "
                "from the current branch's commits relative to main."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "cwd": {
                        "type": "string",
                        "description": "Working directory",
                    },
                },
                "required": ["cwd"],
            },
            modes=["coding"],
            permission_level="read",
            parallel=True,
        )
    )
    registry.register(
        ToolDefinition(
            name="todo_write",
            description="Write or append to a todo list. Use this to track your plan and progress.",
            parameters={
                "type": "object",
                "properties": {
                    "append": {
                        "type": "boolean",
                        "description": (
                            "If true, append to existing todos; if false, replace entire list"
                        ),
                    },
                    "todos": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "content": {"type": "string"},
                                "id": {"type": "string"},
                                "status": {"type": "string"},
                            },
                            "required": ["content"],
                        },
                    },
                },
                "required": ["append", "todos"],
            },
            modes=["coding"],
            permission_level="read",
            parallel=False,
        )
    )
    registry.register(
        ToolDefinition(
            name="todo_read",
            description="Read the current todo list.",
            parameters={"type": "object", "properties": {}},
            modes=["coding"],
            permission_level="read",
            parallel=True,
        )
    )
    registry.register(
        ToolDefinition(
            name="todo_update",
            description="Update a todo item's status (pending/in_progress/completed).",
            parameters={
                "type": "object",
                "properties": {
                    "todo_id": {"type": "string"},
                    "status": {
                        "type": "string",
                        "enum": ["pending", "in_progress", "completed"],
                    },
                },
                "required": ["todo_id", "status"],
            },
            modes=["coding"],
            permission_level="read",
            parallel=False,
        )
    )
    # ── Phase 6 browser tools (Playwright-backed, mock fallback) ──
    # read-permission tools
    for name, description, parameters in [
        (
            "browser_launch",
            "Launch a browser instance (Chromium/Firefox/WebKit). Must be called before other browser tools.",
            {
                "type": "object",
                "properties": {
                    "headless": {
                        "type": "boolean",
                        "description": "Run in headless mode (default true)",
                        "default": True,
                    },
                    "browser_type": {
                        "type": "string",
                        "enum": ["chromium", "firefox", "webkit"],
                        "description": "Browser engine to use",
                        "default": "chromium",
                    },
                },
            },
        ),
        (
            "browser_close",
            "Close the browser instance and release resources.",
            {"type": "object", "properties": {}},
        ),
        (
            "browser_navigate",
            "Navigate to a URL and wait for the page to load.",
            {
                "type": "object",
                "properties": {"url": {"type": "string", "description": "URL to navigate to"}},
                "required": ["url"],
            },
        ),
        (
            "browser_click",
            "Click an element by CSS selector, text=, or XPath.",
            {
                "type": "object",
                "properties": {
                    "selector": {
                        "type": "string",
                        "description": "CSS selector, text=Label, or xpath=//expression",
                    }
                },
                "required": ["selector"],
            },
        ),
        (
            "browser_snapshot",
            "Get the current page DOM content (HTML).",
            {"type": "object", "properties": {}},
        ),
        (
            "browser_screenshot",
            "Take a screenshot of the current page.",
            {
                "type": "object",
                "properties": {
                    "save_path": {
                        "type": "string",
                        "description": "File path to save screenshot (optional, returns base64 if empty)",
                    }
                },
            },
        ),
        (
            "browser_scroll",
            "Scroll the page up or down.",
            {
                "type": "object",
                "properties": {
                    "direction": {"type": "string", "enum": ["up", "down"]},
                    "amount": {
                        "type": "integer",
                        "description": "Scroll amount multiplier (default 3)",
                        "default": 3,
                    },
                },
                "required": ["direction"],
            },
        ),
        (
            "browser_vision",
            "Get a text description of the current page state (URL, title).",
            {"type": "object", "properties": {}},
        ),
    ]:
        registry.register(
            ToolDefinition(
                name=name,
                description=description,
                parameters=parameters,
                modes=["office", "coding"],
                permission_level="read",
                parallel=False,
            )
        )
    # write-permission browser tools
    for name, description, parameters in [
        (
            "browser_type",
            "Type text into an input field (clears existing text first).",
            {
                "type": "object",
                "properties": {
                    "selector": {"type": "string"},
                    "text": {"type": "string"},
                    "press_enter": {
                        "type": "boolean",
                        "description": "Press Enter after typing",
                        "default": False,
                    },
                },
                "required": ["selector", "text"],
            },
        ),
        (
            "browser_evaluate",
            "Execute JavaScript in the browser page context.",
            {
                "type": "object",
                "properties": {
                    "expression": {
                        "type": "string",
                        "description": "JavaScript expression to evaluate",
                    }
                },
                "required": ["expression"],
            },
        ),
        (
            "browser_file_upload",
            "Upload a file to a file input element.",
            {
                "type": "object",
                "properties": {
                    "selector": {"type": "string"},
                    "file_path": {
                        "type": "string",
                        "description": "Absolute path to file",
                    },
                },
                "required": ["selector", "file_path"],
            },
        ),
    ]:
        registry.register(
            ToolDefinition(
                name=name,
                description=description,
                parameters=parameters,
                modes=["office", "coding"],
                permission_level="write",
                parallel=False,
            )
        )
    # ── Phase 6 web content tools (HTML→Markdown, tables, metadata) ──
    for name, description, parameters in [
        (
            "web_fetch",
            "Fetch a webpage and extract its content as clean Markdown. Strips ads, navigation, scripts, and formatting noise.",
            {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "URL to fetch"},
                    "timeout": {
                        "type": "integer",
                        "description": "Request timeout in seconds (default 30)",
                        "default": 30,
                    },
                },
                "required": ["url"],
            },
        ),
        (
            "web_extract_tables",
            "Extract structured table data from a webpage.",
            {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "URL containing tables"}
                },
                "required": ["url"],
            },
        ),
        (
            "web_metadata",
            "Get webpage metadata (title, description, author) without downloading full content.",
            {
                "type": "object",
                "properties": {"url": {"type": "string", "description": "URL to inspect"}},
                "required": ["url"],
            },
        ),
    ]:
        registry.register(
            ToolDefinition(
                name=name,
                description=description,
                parameters=parameters,
                modes=["office", "coding"],
                permission_level="read",
                parallel=True,
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
    # ── Phase 8.3 orchestrator tools (subagent spawn / collect / plan) ──
    registry.register(
        ToolDefinition(
            name="spawn_subagent",
            description=(
                "Spawn a subagent to execute a task in parallel. "
                "The subagent runs independently with its own context and tool set."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "goal": {
                        "type": "string",
                        "description": "Task description for the subagent",
                    },
                    "context": {
                        "type": "string",
                        "description": "Additional context for the subagent",
                        "default": "",
                    },
                    "tools": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Tools available to the subagent (empty = all tools)",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Timeout in seconds (default 300)",
                        "default": 300,
                    },
                },
                "required": ["goal"],
            },
            modes=["office", "coding"],
            permission_level="write",
            parallel=False,
        )
    )
    registry.register(
        ToolDefinition(
            name="collect_results",
            description="Wait for all running subagents to complete and collect their results.",
            parameters={"type": "object", "properties": {}},
            modes=["office", "coding"],
            permission_level="read",
            parallel=False,
        )
    )
    registry.register(
        ToolDefinition(
            name="execute_plan",
            description=(
                "Execute a task plan (JSON) with dependencies. Tasks without "
                "dependencies run in parallel; dependent tasks wait for their "
                "upstream to complete."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "plan_json": {
                        "type": "string",
                        "description": "JSON task plan with tasks, dependencies, and context",
                    },
                },
                "required": ["plan_json"],
            },
            modes=["office", "coding"],
            permission_level="write",
            parallel=False,
        )
    )
    registry.register(
        ToolDefinition(
            name="subagent_status",
            description="Check the status of all subagents without waiting.",
            parameters={"type": "object", "properties": {}},
            modes=["office", "coding"],
            permission_level="read",
            parallel=True,
        )
    )
    registry.register(
        ToolDefinition(
            name="list_permission_rules",
            description="List all permission rules (patterns, approval modes, scopes).",
            parameters={"type": "object", "properties": {}},
            modes=["office"],
            permission_level="read",
            parallel=True,
        )
    )
    registry.register(
        ToolDefinition(
            name="grant_permission",
            description="Grant a permission rule to auto-approve or deny a tool pattern.",
            parameters={
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "Glob pattern (e.g. /home/user/**)",
                    },
                    "permission_level": {
                        "type": "string",
                        "enum": ["read", "write"],
                        "description": "Permission level",
                    },
                    "approval": {
                        "type": "string",
                        "enum": ["auto-approve", "ask-every", "deny"],
                        "default": "auto-approve",
                    },
                    "mode": {
                        "type": "string",
                        "enum": ["office", "coding", "all"],
                        "default": "all",
                    },
                },
                "required": ["pattern", "permission_level"],
            },
            modes=["office"],
            permission_level="write",
            parallel=False,
        )
    )
    registry.register(
        ToolDefinition(
            name="revoke_permission",
            description="Revoke a permission rule by its ID.",
            parameters={
                "type": "object",
                "properties": {"rule_id": {"type": "integer"}},
                "required": ["rule_id"],
            },
            modes=["office"],
            permission_level="write",
            parallel=False,
        )
    )
    registry.register(
        ToolDefinition(
            name="query_audit_logs",
            description="Query audit logs (permission decisions, tool executions).",
            parameters={
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "description": "Filter by tool/action name",
                    },
                    "result": {
                        "type": "string",
                        "enum": ["approved", "denied", "error", "success"],
                        "description": "Filter by result type",
                    },
                    "limit": {"type": "integer", "default": 50},
                },
            },
            modes=["office"],
            permission_level="read",
            parallel=True,
        )
    )
    registry.register(
        ToolDefinition(
            name="security_status",
            description="Get security status overview (rule count, recent denials).",
            parameters={"type": "object", "properties": {}},
            modes=["office"],
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
        clipboard_tools,
        code_search_tools,
        file_tools,
        git_tools,
        markdown_tools,
        note_tools,
        permission_tools,
        sandbox_tools,
        terminal_tools,
        test_tools,
        todo_tools,
        web_tools,
    )

    registry = create_builtin_registry()
    registry.get("read_file").handler = file_tools.read_file
    registry.get("write_file").handler = file_tools.write_file
    registry.get("patch").handler = file_tools.patch
    registry.get("multi_edit").handler = file_tools.multi_edit
    registry.get("search_files").handler = file_tools.search_files
    registry.get("list_directory").handler = file_tools.list_directory
    registry.get("file_info").handler = file_tools.file_info
    registry.get("tree_view").handler = file_tools.tree_view
    registry.get("copy_file").handler = file_tools.copy_file
    registry.get("move_file").handler = file_tools.move_file
    registry.get("file_search_content").handler = file_tools.file_search_content
    registry.get("quick_note").handler = note_tools.quick_note
    registry.get("search_notes").handler = note_tools.search_notes
    registry.get("list_notes").handler = note_tools.list_notes
    registry.get("delete_note").handler = note_tools.delete_note
    registry.get("markdown_to_text").handler = markdown_tools.markdown_to_text
    registry.get("extract_headings").handler = markdown_tools.extract_headings
    registry.get("count_words").handler = markdown_tools.count_words
    registry.get("format_markdown_table").handler = markdown_tools.format_markdown_table
    registry.get("clipboard_read").handler = clipboard_tools.clipboard_read
    registry.get("clipboard_write").handler = clipboard_tools.clipboard_write
    registry.get("terminal").handler = terminal_tools.terminal
    registry.get("process").handler = terminal_tools.process
    registry.get("sandbox_exec").handler = sandbox_tools.sandbox_exec
    registry.get("sandbox_build").handler = sandbox_tools.sandbox_build
    registry.get("git_diff").handler = git_tools.git_diff
    registry.get("git_commit").handler = git_tools.git_commit
    registry.get("git_branch").handler = git_tools.git_branch
    registry.get("git_log").handler = git_tools.git_log
    registry.get("git_status").handler = git_tools.git_status
    registry.get("git_smart_commit").handler = git_tools.git_smart_commit
    registry.get("git_undo").handler = git_tools.git_undo
    registry.get("git_create_branch").handler = git_tools.git_create_branch
    registry.get("git_push").handler = git_tools.git_push
    registry.get("git_pr_body").handler = git_tools.git_pr_body
    registry.get("test_run").handler = test_tools.test_run
    # Phase 6 browser tools — all backed by browser_tools (Playwright or mock)
    registry.get("browser_launch").handler = browser_tools.browser_launch
    registry.get("browser_close").handler = browser_tools.browser_close
    registry.get("browser_navigate").handler = browser_tools.browser_navigate
    registry.get("browser_click").handler = browser_tools.browser_click
    registry.get("browser_type").handler = browser_tools.browser_type
    registry.get("browser_snapshot").handler = browser_tools.browser_snapshot
    registry.get("browser_screenshot").handler = browser_tools.browser_screenshot
    registry.get("browser_scroll").handler = browser_tools.browser_scroll
    registry.get("browser_vision").handler = browser_tools.browser_vision
    registry.get("browser_evaluate").handler = browser_tools.browser_evaluate
    registry.get("browser_file_upload").handler = browser_tools.browser_file_upload
    # Phase 6 web content tools
    registry.get("web_fetch").handler = web_tools.web_fetch
    registry.get("web_extract_tables").handler = web_tools.web_extract_tables
    registry.get("web_metadata").handler = web_tools.web_metadata
    registry.get("code_search").handler = code_search_tools.code_search
    registry.get("code_symbols").handler = code_search_tools.code_symbols
    registry.get("todo_write").handler = todo_tools.todo_write
    registry.get("todo_read").handler = todo_tools.todo_read
    registry.get("todo_update").handler = todo_tools.todo_update
    # Phase 8.3 orchestrator tools
    from khaos.tools import orchestrator_tools

    registry.get("spawn_subagent").handler = orchestrator_tools.spawn_subagent
    registry.get("collect_results").handler = orchestrator_tools.collect_results
    registry.get("execute_plan").handler = orchestrator_tools.execute_plan
    registry.get("subagent_status").handler = orchestrator_tools.subagent_status
    registry.get("list_permission_rules").handler = permission_tools.list_permission_rules
    registry.get("grant_permission").handler = permission_tools.grant_permission
    registry.get("revoke_permission").handler = permission_tools.revoke_permission
    registry.get("query_audit_logs").handler = permission_tools.query_audit_logs
    registry.get("security_status").handler = permission_tools.security_status
    return registry
