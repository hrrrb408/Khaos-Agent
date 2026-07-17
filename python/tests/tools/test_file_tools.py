from khaos.tools.file_tools import patch, read_file, search_files, write_file


async def test_read_file_paginates_with_line_numbers(tmp_path):
    file_path = tmp_path / "note.txt"
    file_path.write_text("a\nb\nc\n", encoding="utf-8")

    result = await read_file(
        str(file_path), offset=2, limit=2, workspace_root=tmp_path
    )

    assert result["total_lines"] == 3
    assert result["content"] == "2: b\n3: c"


async def test_write_file_creates_parent_and_overwrites(tmp_path):
    file_path = tmp_path / "nested" / "note.txt"

    result = await write_file(str(file_path), "hello", workspace_root=tmp_path)

    assert file_path.read_text(encoding="utf-8") == "hello"
    assert result["bytes"] == 5


async def test_patch_exact_replace(tmp_path):
    file_path = tmp_path / "note.txt"
    file_path.write_text("alpha\nbeta\n", encoding="utf-8")

    result = await patch(
        str(file_path), "beta", "gamma", workspace_root=tmp_path
    )

    assert result["replaced"] == 1
    assert result["fuzzy"] is False
    assert file_path.read_text(encoding="utf-8") == "alpha\ngamma\n"


async def test_patch_fuzzy_replace(tmp_path):
    file_path = tmp_path / "note.txt"
    file_path.write_text("alpha\ncolour blue\nomega\n", encoding="utf-8")

    result = await patch(
        str(file_path), "color blue", "color green", fuzzy=True,
        workspace_root=tmp_path,
    )

    assert result["fuzzy"] is True
    assert "color green" in file_path.read_text(encoding="utf-8")


async def test_patch_raises_when_missing(tmp_path):
    file_path = tmp_path / "note.txt"
    file_path.write_text("alpha\n", encoding="utf-8")

    try:
        await patch(
            str(file_path), "missing", "new", fuzzy=False,
            workspace_root=tmp_path,
        )
    except ValueError as exc:
        assert "not found" in str(exc)
    else:
        raise AssertionError("expected ValueError")


async def test_search_files_by_glob_and_query(tmp_path):
    (tmp_path / "a.py").write_text("print('a')", encoding="utf-8")
    (tmp_path / "b.txt").write_text("b", encoding="utf-8")

    result = await search_files(
        ".", query="a", glob="*.py", content=False,
        workspace_root=tmp_path,
    )

    assert result["count"] == 1
    assert result["matches"][0]["path"].endswith("a.py")


async def test_search_files_by_content(tmp_path):
    (tmp_path / "a.py").write_text("needle\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("hay\n", encoding="utf-8")

    result = await search_files(
        ".", query="needle", glob="*.py", content=True,
        workspace_root=tmp_path,
    )

    assert result["matches"] == [
        {"path": str(tmp_path / "a.py"), "line": 1, "text": "needle"}
    ]
