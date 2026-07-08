"""Todo tools for coding mode planning state."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any
from uuid import uuid4

TODO_FILE = Path.home() / ".khaos" / "todo.json"
VALID_STATUSES = {"pending", "in_progress", "completed"}
STATUS_ORDER = {"in_progress": 0, "pending": 1, "completed": 2}


def _load_todos() -> list[dict]:
    """Load the todo list, returning an empty list when no file exists."""
    if not TODO_FILE.exists():
        return []
    try:
        data = json.loads(TODO_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(data, list):
        return []
    return [todo for todo in data if isinstance(todo, dict)]


def _save_todos(todos: list[dict]) -> None:
    """Persist the todo list, creating the parent directory if needed."""
    TODO_FILE.parent.mkdir(parents=True, exist_ok=True)
    TODO_FILE.write_text(
        json.dumps(todos, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


async def todo_write(append: bool, todos: list[dict]) -> str:
    """Write or append todo items and return the full current list as JSON."""
    return await asyncio.to_thread(_todo_write_sync, append, todos)


async def todo_read() -> str:
    """Read the current todo list as sorted JSON."""
    return await asyncio.to_thread(_todo_read_sync)


async def todo_update(todo_id: str, status: str) -> str:
    """Update a todo item's status and return the updated item as JSON."""
    return await asyncio.to_thread(_todo_update_sync, todo_id, status)


def _todo_write_sync(append: bool, todos: list[dict]) -> str:
    if not isinstance(append, bool):
        raise ValueError("append must be a boolean")
    normalized = [_normalize_todo(todo) for todo in todos]
    current = _load_todos() if append else []
    updated = [*current, *normalized]
    _save_todos(updated)
    return json.dumps({"todos": _sort_todos(updated)}, ensure_ascii=False)


def _todo_read_sync() -> str:
    todos = _sort_todos(_load_todos())
    if not todos:
        return json.dumps({"todos": [], "message": "No todos."}, ensure_ascii=False)
    return json.dumps({"todos": todos}, ensure_ascii=False)


def _todo_update_sync(todo_id: str, status: str) -> str:
    if status not in VALID_STATUSES:
        return json.dumps(
            {"error": f"invalid status: {status}", "todo_id": todo_id},
            ensure_ascii=False,
        )

    todos = _load_todos()
    for todo in todos:
        if todo.get("id") == todo_id:
            todo["status"] = status
            _save_todos(todos)
            return json.dumps({"todo": todo}, ensure_ascii=False)

    return json.dumps(
        {"error": "todo_id not found", "todo_id": todo_id},
        ensure_ascii=False,
    )


def _normalize_todo(todo: dict) -> dict[str, Any]:
    if not isinstance(todo, dict):
        raise ValueError("todo must be an object")
    content = todo.get("content")
    if not isinstance(content, str) or not content.strip():
        raise ValueError("todo content is required")
    status = todo.get("status", "pending")
    if status not in VALID_STATUSES:
        raise ValueError(f"invalid status: {status}")
    todo_id = todo.get("id") or str(uuid4())
    if not isinstance(todo_id, str):
        raise ValueError("todo id must be a string")
    return {"id": todo_id, "content": content, "status": status}


def _sort_todos(todos: list[dict]) -> list[dict]:
    return sorted(
        todos,
        key=lambda todo: (STATUS_ORDER.get(str(todo.get("status")), 99), str(todo.get("id", ""))),
    )
