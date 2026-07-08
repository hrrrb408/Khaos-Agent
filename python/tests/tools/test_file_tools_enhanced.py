from khaos.tools.file_tools import (
    copy_file,
    file_info,
    file_search_content,
    list_directory,
    move_file,
    tree_view,
)


class TestListDirectory:
    async def test_lists_regular_directory_with_files_and_dirs(self, tmp_path):
        (tmp_path / "docs").mkdir()
        (tmp_path / "note.txt").write_text("hello", encoding="utf-8")

        result = await list_directory(str(tmp_path))

        assert result["ok"] is True
        assert result["path"] == str(tmp_path)
        assert result["dirs"] == [{"name": "docs", "item_count": 0}]
        assert result["files"] == [
            {"name": "note.txt", "size_bytes": 5, "extension": ".txt"}
        ]
        assert result["total_items"] == 2

    async def test_lists_empty_directory(self, tmp_path):
        result = await list_directory(str(tmp_path))

        assert result["ok"] is True
        assert result["dirs"] == []
        assert result["files"] == []
        assert result["total_items"] == 0

    async def test_missing_path_returns_error(self, tmp_path):
        result = await list_directory(str(tmp_path / "missing"))

        assert result["ok"] is False
        assert "does not exist" in result["error"]

    async def test_sorts_dirs_before_files_by_name(self, tmp_path):
        (tmp_path / "zeta.txt").write_text("z", encoding="utf-8")
        (tmp_path / "alpha.txt").write_text("a", encoding="utf-8")
        (tmp_path / "z_dir").mkdir()
        (tmp_path / "a_dir").mkdir()

        result = await list_directory(str(tmp_path))

        assert [item["name"] for item in result["dirs"]] == ["a_dir", "z_dir"]
        assert [item["name"] for item in result["files"]] == ["alpha.txt", "zeta.txt"]


class TestFileInfo:
    async def test_regular_file(self, tmp_path):
        file_path = tmp_path / "note.txt"
        file_path.write_text("hello", encoding="utf-8")

        result = await file_info(str(file_path))

        assert result["ok"] is True
        assert result["path"] == str(file_path)
        assert result["type"] == "file"
        assert result["size_bytes"] == 5
        assert result["extension"] == ".txt"
        assert result["is_hidden"] is False
        assert result["is_symlink"] is False
        assert result["mime_type"] == "text/plain"

    async def test_directory(self, tmp_path):
        dir_path = tmp_path / "docs"
        dir_path.mkdir()

        result = await file_info(str(dir_path))

        assert result["ok"] is True
        assert result["type"] == "directory"
        assert result["extension"] == ""

    async def test_missing_returns_error(self, tmp_path):
        result = await file_info(str(tmp_path / "missing.txt"))

        assert result["ok"] is False
        assert "does not exist" in result["error"]


class TestTreeView:
    async def test_shallow_directory(self, tmp_path):
        (tmp_path / "docs").mkdir()
        (tmp_path / "docs" / "a.txt").write_text("a", encoding="utf-8")
        (tmp_path / "b.txt").write_text("b", encoding="utf-8")

        result = await tree_view(str(tmp_path), max_depth=2)

        assert result["ok"] is True
        assert "├── docs/" in result["tree"]
        assert "│   └── a.txt" in result["tree"]
        assert "└── b.txt" in result["tree"]
        assert result["total_dirs"] == 1
        assert result["total_files"] == 2

    async def test_max_depth_one_limits_children(self, tmp_path):
        (tmp_path / "docs").mkdir()
        (tmp_path / "docs" / "a.txt").write_text("a", encoding="utf-8")

        result = await tree_view(str(tmp_path), max_depth=1)

        assert result["tree"] == "└── docs/"
        assert "a.txt" not in result["tree"]
        assert result["total_dirs"] == 1
        assert result["total_files"] == 0

    async def test_excludes_generated_directories(self, tmp_path):
        (tmp_path / ".git").mkdir()
        (tmp_path / ".git" / "config").write_text("config", encoding="utf-8")
        (tmp_path / "__pycache__").mkdir()
        (tmp_path / "__pycache__" / "module.pyc").write_text("cache", encoding="utf-8")
        (tmp_path / "src").mkdir()

        result = await tree_view(str(tmp_path), max_depth=2)

        assert ".git" not in result["tree"]
        assert "__pycache__" not in result["tree"]
        assert result["tree"] == "└── src/"

    async def test_empty_directory(self, tmp_path):
        result = await tree_view(str(tmp_path))

        assert result["ok"] is True
        assert result["tree"] == ""
        assert result["total_files"] == 0
        assert result["total_dirs"] == 0


class TestCopyFile:
    async def test_copy_file_success(self, tmp_path):
        src = tmp_path / "source.txt"
        dst = tmp_path / "target.txt"
        src.write_text("hello", encoding="utf-8")

        result = await copy_file(str(src), str(dst))

        assert result["ok"] is True
        assert dst.read_text(encoding="utf-8") == "hello"
        assert result["size_bytes"] == 5

    async def test_missing_source_returns_error(self, tmp_path):
        result = await copy_file(str(tmp_path / "missing.txt"), str(tmp_path / "target.txt"))

        assert result["ok"] is False
        assert "source does not exist" in result["error"]


class TestMoveFile:
    async def test_move_file_success(self, tmp_path):
        src = tmp_path / "source.txt"
        dst = tmp_path / "renamed.txt"
        src.write_text("hello", encoding="utf-8")

        result = await move_file(str(src), str(dst))

        assert result["ok"] is True
        assert not src.exists()
        assert dst.read_text(encoding="utf-8") == "hello"

    async def test_missing_source_returns_error(self, tmp_path):
        result = await move_file(str(tmp_path / "missing.txt"), str(tmp_path / "target.txt"))

        assert result["ok"] is False
        assert "source does not exist" in result["error"]


class TestFileSearchContent:
    async def test_finds_matching_results(self, tmp_path):
        file_path = tmp_path / "a.txt"
        file_path.write_text("alpha\nneedle here\nomega\n", encoding="utf-8")
        (tmp_path / "b.txt").write_text("nothing\n", encoding="utf-8")

        result = await file_search_content(str(tmp_path), "needle")

        assert result["ok"] is True
        assert result["matches"] == [
            {
                "file": str(file_path),
                "line_number": 2,
                "line": "needle here",
            }
        ]
        assert result["match_count"] == 1
        assert result["files_searched"] == 2

    async def test_no_match_returns_empty_list(self, tmp_path):
        (tmp_path / "a.txt").write_text("alpha\n", encoding="utf-8")

        result = await file_search_content(str(tmp_path), "missing")

        assert result["ok"] is True
        assert result["matches"] == []
        assert result["match_count"] == 0

    async def test_max_results_limit(self, tmp_path):
        (tmp_path / "a.txt").write_text("needle 1\nneedle 2\nneedle 3\n", encoding="utf-8")

        result = await file_search_content(str(tmp_path), "needle", max_results=2)

        assert result["match_count"] == 2
        assert [item["line_number"] for item in result["matches"]] == [1, 2]
