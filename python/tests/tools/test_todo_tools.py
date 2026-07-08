import json

from khaos.tools import todo_tools


async def test_todo_read_empty_returns_message(tmp_path, monkeypatch):
    monkeypatch.setattr(todo_tools, "TODO_FILE", tmp_path / "todo.json")

    result = json.loads(await todo_tools.todo_read())

    assert result == {"todos": [], "message": "No todos."}


async def test_todo_write_replaces_and_defaults_fields(tmp_path, monkeypatch):
    monkeypatch.setattr(todo_tools, "TODO_FILE", tmp_path / "todo.json")

    result = json.loads(
        await todo_tools.todo_write(False, [{"content": "write tests"}])
    )

    assert len(result["todos"]) == 1
    todo = result["todos"][0]
    assert todo["content"] == "write tests"
    assert todo["status"] == "pending"
    assert isinstance(todo["id"], str)


async def test_todo_write_appends_and_sorts_by_status(tmp_path, monkeypatch):
    monkeypatch.setattr(todo_tools, "TODO_FILE", tmp_path / "todo.json")
    await todo_tools.todo_write(
        False,
        [{"id": "done", "content": "done item", "status": "completed"}],
    )

    result = json.loads(
        await todo_tools.todo_write(
            True,
            [
                {"id": "active", "content": "active item", "status": "in_progress"},
                {"id": "pending", "content": "pending item"},
            ],
        )
    )

    assert [todo["id"] for todo in result["todos"]] == ["active", "pending", "done"]


async def test_todo_update_changes_status(tmp_path, monkeypatch):
    monkeypatch.setattr(todo_tools, "TODO_FILE", tmp_path / "todo.json")
    await todo_tools.todo_write(False, [{"id": "task-1", "content": "ship"}])

    result = json.loads(await todo_tools.todo_update("task-1", "completed"))

    assert result == {
        "todo": {"id": "task-1", "content": "ship", "status": "completed"}
    }
    todos = json.loads(await todo_tools.todo_read())["todos"]
    assert todos[0]["status"] == "completed"


async def test_todo_update_returns_error_for_missing_id(tmp_path, monkeypatch):
    monkeypatch.setattr(todo_tools, "TODO_FILE", tmp_path / "todo.json")

    result = json.loads(await todo_tools.todo_update("missing", "completed"))

    assert result == {"error": "todo_id not found", "todo_id": "missing"}
