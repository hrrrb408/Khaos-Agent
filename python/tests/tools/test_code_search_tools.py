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

