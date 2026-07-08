from pathlib import Path

from khaos.coding import CodingContextBuilder


def test_build_prioritizes_target_files(tmp_path: Path) -> None:
    target = tmp_path / "python" / "khaos" / "agent" / "core.py"
    related = tmp_path / "python" / "khaos" / "agent" / "helper.py"
    config = tmp_path / "pyproject.toml"
    target.parent.mkdir(parents=True)
    target.write_text("class AgentLoop:\n    pass\n", encoding="utf-8")
    related.write_text("from python.khaos.agent.core import AgentLoop\n", encoding="utf-8")
    config.write_text("[project]\nname = 'demo'\n", encoding="utf-8")

    context = CodingContextBuilder().build(
        "change AgentLoop behavior",
        tmp_path,
        [Path("python/khaos/agent/core.py")],
    )

    assert context[0]["path"] == target
    assert context[0]["relevance"] == "target_file"
    assert any(item["path"] == related for item in context)


def test_build_matches_path_keywords(tmp_path: Path) -> None:
    memory_file = tmp_path / "python" / "khaos" / "memory" / "store.py"
    unrelated = tmp_path / "python" / "khaos" / "tools" / "registry.py"
    memory_file.parent.mkdir(parents=True)
    unrelated.parent.mkdir(parents=True)
    memory_file.write_text("class MemoryStore:\n    pass\n", encoding="utf-8")
    unrelated.write_text("class ToolRegistry:\n    pass\n", encoding="utf-8")

    context = CodingContextBuilder().build("fix memory store lookup", tmp_path, None)

    paths = [item["path"] for item in context]
    assert memory_file in paths
    assert unrelated not in paths
