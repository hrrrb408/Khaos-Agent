from pathlib import Path

from khaos.coding import CodeParser


def test_parse_symbols_extracts_python_symbols(tmp_path: Path) -> None:
    source = tmp_path / "sample.py"
    source.write_text(
        "\n".join(
            [
                "import os",
                "from pathlib import Path",
                "",
                "class Worker:",
                "    async def run(self, value: str) -> None:",
                "        return None",
                "",
                "def build(name: str) -> Worker:",
                "    return Worker()",
            ]
        ),
        encoding="utf-8",
    )

    symbols = CodeParser().parse_symbols(source)

    assert symbols == [
        {"name": "Worker", "kind": "class", "line": 4, "signature": "class Worker"},
        {
            "name": "Worker.run",
            "kind": "async_method",
            "line": 5,
            "signature": "async def run(self, value)",
        },
        {"name": "build", "kind": "function", "line": 8, "signature": "def build(name)"},
    ]


def test_parse_imports_extracts_python_imports(tmp_path: Path) -> None:
    source = tmp_path / "sample.py"
    source.write_text(
        "import os\nimport sys as system\nfrom khaos.agent import core\nfrom .local import item\n",
        encoding="utf-8",
    )

    imports = CodeParser().parse_imports(source)

    assert imports == [".local", "khaos.agent", "os", "sys"]


def test_build_symbol_table_uses_relative_paths(tmp_path: Path) -> None:
    source = tmp_path / "pkg" / "sample.py"
    source.parent.mkdir()
    source.write_text("def build():\n    return None\n", encoding="utf-8")

    table = CodeParser().build_symbol_table(tmp_path, [source])

    assert list(table) == ["pkg/sample.py"]
    assert table["pkg/sample.py"][0]["name"] == "build"
