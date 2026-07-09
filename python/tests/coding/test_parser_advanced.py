"""Tests for call-graph and dependency-graph builders."""

from __future__ import annotations

from pathlib import Path

from khaos.coding import CodingContextBuilder, CodeParser, build_call_graph, build_dependency_graph


# ---------------------------------------------------------------------------
# Call graph
# ---------------------------------------------------------------------------


def test_call_graph_basic(tmp_path: Path) -> None:
    source = tmp_path / "mod.py"
    source.write_text(
        "\n".join(
            [
                "def alpha():",
                "    beta()",
                "",
                "def beta():",
                "    gamma()",
                "",
                "def gamma():",
                "    return 1",
            ]
        ),
        encoding="utf-8",
    )

    graph = build_call_graph(tmp_path, [source])

    assert graph["alpha"] == {"beta"}
    assert graph["beta"] == {"gamma"}
    assert graph["gamma"] == set()


def test_call_graph_nested(tmp_path: Path) -> None:
    source = tmp_path / "nested.py"
    source.write_text(
        "\n".join(
            [
                "def outer():",
                "    def inner():",
                "        deep()",
                "    inner()",
                "",
                "def deep():",
                "    return 0",
            ]
        ),
        encoding="utf-8",
    )

    graph = build_call_graph(tmp_path, [source])

    # outer calls inner; the nested inner() calls deep.
    assert "inner" in graph["outer"]
    assert "deep" in graph["inner"]


def test_call_graph_methods_use_qualified_names(tmp_path: Path) -> None:
    source = tmp_path / "cls.py"
    source.write_text(
        "\n".join(
            [
                "class Worker:",
                "    def run(self):",
                "        self.helper()",
                "",
                "    def helper(self):",
                "        return 1",
            ]
        ),
        encoding="utf-8",
    )

    graph = build_call_graph(tmp_path, [source])

    assert "Worker.run" in graph
    # self.helper() is recorded as self.helper.
    assert "self.helper" in graph["Worker.run"]


def test_call_graph_empty_for_go(tmp_path: Path) -> None:
    go_file = tmp_path / "main.go"
    go_file.write_text("package main\n", encoding="utf-8")

    graph = build_call_graph(tmp_path, [go_file])

    assert graph == {}


# ---------------------------------------------------------------------------
# Dependency graph
# ---------------------------------------------------------------------------


def test_dependency_graph_imports(tmp_path: Path) -> None:
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "a.py").write_text("import pkg.b\n", encoding="utf-8")
    (pkg / "b.py").write_text("x = 1\n", encoding="utf-8")

    a = (pkg / "a.py").resolve()
    b = (pkg / "b.py").resolve()
    graph = build_dependency_graph(tmp_path, [a, b])

    assert b in graph[a]


def test_dependency_graph_from_import(tmp_path: Path) -> None:
    # ``from pkg import thing`` where thing is a submodule.
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "main.py").write_text("from pkg import thing\n", encoding="utf-8")
    (pkg / "thing.py").write_text("y = 2\n", encoding="utf-8")

    main = (pkg / "main.py").resolve()
    thing = (pkg / "thing.py").resolve()
    graph = build_dependency_graph(tmp_path, [main, thing])

    assert thing in graph[main]


def test_dependency_graph_from_import_attribute(tmp_path: Path) -> None:
    # ``from pkg.module import name`` where name is just an attribute of module.
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "module.py").write_text("name = 5\n", encoding="utf-8")
    (pkg / "user.py").write_text("from pkg.module import name\n", encoding="utf-8")

    user = (pkg / "user.py").resolve()
    module = (pkg / "module.py").resolve()
    graph = build_dependency_graph(tmp_path, [user, module])

    # module.py exists as a real file → resolved as the attribute's home.
    assert module in graph[user]


def test_dependency_graph_empty_for_go(tmp_path: Path) -> None:
    go_file = tmp_path / "main.go"
    go_file.write_text("package main\n", encoding="utf-8")

    graph = build_dependency_graph(tmp_path, [go_file])

    # Go file is present as a node but has no resolved Python imports.
    assert graph == {go_file.resolve(): set()}


def test_dependency_graph_skips_self_edges(tmp_path: Path) -> None:
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "rec.py").write_text("import pkg.rec\n", encoding="utf-8")

    rec = (pkg / "rec.py").resolve()
    graph = build_dependency_graph(tmp_path, [rec])

    # rec.py must not depend on itself; only legitimate package edges survive.
    assert rec not in graph[rec]
    # ``import pkg.rec`` legitimately resolves the package __init__.py too.
    init = (pkg / "__init__.py").resolve()
    assert graph[rec] == {init}


# ---------------------------------------------------------------------------
# Context builder integration: dependency scoring
# ---------------------------------------------------------------------------


def test_context_builder_uses_dependency_scoring(tmp_path: Path) -> None:
    """A file that imports a target is surfaced via the dependency boost."""
    target = tmp_path / "python" / "khaos" / "core.py"
    caller = tmp_path / "python" / "khaos" / "caller.py"
    target.parent.mkdir(parents=True)
    # Use a dotted path that matches the filesystem under tmp_path.
    target.write_text("class Core:\n    pass\n", encoding="utf-8")
    caller.write_text("from python.khaos.core import Core\n", encoding="utf-8")

    builder = CodingContextBuilder()
    context = builder.build(
        "refactor the Core class",
        tmp_path,
        [Path("python/khaos/core.py")],
    )

    paths = [item["path"] for item in context]
    # The caller imports the target → should be pulled in by dependency scoring.
    assert caller in paths
    # And its relevance reason should mention the dependency relationship.
    caller_entry = next(item for item in context if item["path"] == caller)
    assert "import" in caller_entry["relevance"]
