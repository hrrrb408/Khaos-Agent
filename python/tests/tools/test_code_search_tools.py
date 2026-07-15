from types import SimpleNamespace

import pytest

from khaos.coding.workspace.boundary import WorkspaceBoundaryError
from khaos.tools.code_search_tools import code_search, code_symbols
from khaos.tools.registry import create_runtime_registry


async def test_code_search_finds_query(tmp_path):
    file_path = tmp_path / "app.py"
    file_path.write_text("def hello():\n    return 'khaos'\n", encoding="utf-8")

    result = await code_search(str(tmp_path), "khaos")

    assert result["count"] == 1
    assert result["matches"][0]["line"] == 2


async def test_code_symbols_extracts_python_symbols(tmp_path):
    file_path = tmp_path / "app.py"
    file_path.write_text("class App:\n    async def run(self):\n        pass\n", encoding="utf-8")

    result = await code_symbols(str(file_path))

    assert [symbol["name"] for symbol in result["symbols"]] == ["App", "run"]


def test_runtime_registry_binds_code_search_tools():
    registry = create_runtime_registry()

    assert registry.get("code_search").handler is not None
    assert registry.get("code_symbols").permission_level == "read"


async def test_coding_code_search_rejects_symlink_escape(tmp_path):
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()
    (outside / "secret.py").write_text("SECRET = True\n", encoding="utf-8")
    (tmp_path / "leak.py").symlink_to(outside / "secret.py")
    (tmp_path / "safe.py").write_text("def visible(): pass\n", encoding="utf-8")
    workspace = SimpleNamespace(task_id="task", worktree_path=tmp_path)
    manager = SimpleNamespace(get=lambda _workspace_id: workspace)
    context = {"workspace_manager": manager, "task_id": "task", "workspace_id": "ws"}

    result = await code_search(".", "SECRET", **context)
    assert result["matches"] == []
    with pytest.raises(WorkspaceBoundaryError):
        await code_symbols("leak.py", **context)
