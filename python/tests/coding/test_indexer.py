from pathlib import Path

from khaos.coding import RepoIndexer


def test_scan_identifies_repository_structure(tmp_path: Path) -> None:
    (tmp_path / "python" / "app").mkdir(parents=True)
    (tmp_path / "python" / "tests").mkdir(parents=True)
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "python" / "app" / "main.py").write_text("print('hello')\n", encoding="utf-8")
    (tmp_path / "python" / "tests" / "test_main.py").write_text("", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'demo'\n", encoding="utf-8")
    (tmp_path / "node_modules" / "ignored.js").write_text("", encoding="utf-8")

    result = RepoIndexer().scan(tmp_path)

    files = {path.relative_to(tmp_path) for path in result["files"]}
    assert Path("python/app/main.py") in files
    assert Path("python/tests/test_main.py") in files
    assert Path("node_modules/ignored.js") not in files
    assert tmp_path / "python" / "app" / "main.py" in result["entry_files"]
    assert tmp_path / "pyproject.toml" in result["config_files"]
    assert tmp_path / "python" / "tests" in result["test_dirs"]
    assert result["total_files"] == 3
    assert "main.py" in result["tree"]


def test_scan_treats_go_test_files_as_test_dirs(tmp_path: Path) -> None:
    (tmp_path / "go" / "internal").mkdir(parents=True)
    test_file = tmp_path / "go" / "internal" / "handler_test.go"
    test_file.write_text("package internal\n", encoding="utf-8")

    result = RepoIndexer().scan(tmp_path)

    assert test_file.parent in result["test_dirs"]
