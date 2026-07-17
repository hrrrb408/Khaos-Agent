import json

from khaos.tools.file_tools import multi_edit


async def test_multi_edit_applies_multiple_exact_edits_atomically(tmp_path):
    file_path = tmp_path / "note.txt"
    file_path.write_text("alpha beta\ngamma delta\n", encoding="utf-8")

    result = json.loads(
        await multi_edit(
            str(file_path),
            [
                {"old_text": "gamma delta", "new_text": "gamma epsilon"},
                {"old_text": "alpha", "new_text": "omega"},
            ],
            workspace_root=tmp_path,
        )
    )

    assert result["applied"] == 2
    assert result["failed"] == []
    assert file_path.read_text(encoding="utf-8") == "omega beta\ngamma epsilon\n"


async def test_multi_edit_does_not_write_when_any_edit_is_missing(tmp_path):
    file_path = tmp_path / "note.txt"
    original = "alpha beta\ngamma delta\n"
    file_path.write_text(original, encoding="utf-8")

    result = json.loads(
        await multi_edit(
            str(file_path),
            [
                {"old_text": "alpha", "new_text": "omega"},
                {"old_text": "missing", "new_text": "new"},
            ],
            workspace_root=tmp_path,
        )
    )

    assert result["applied"] == 0
    assert result["failed"] == [
        {
            "index": 1,
            "old_text": "missing",
            "matches": 0,
            "error": "old_text not found",
        }
    ]
    assert file_path.read_text(encoding="utf-8") == original


async def test_multi_edit_requires_unique_match(tmp_path):
    file_path = tmp_path / "note.txt"
    original = "alpha alpha\n"
    file_path.write_text(original, encoding="utf-8")

    result = json.loads(
        await multi_edit(
            str(file_path),
            [{"old_text": "alpha", "new_text": "omega"}],
            workspace_root=tmp_path,
        )
    )

    assert result["applied"] == 0
    assert result["failed"][0]["matches"] == 2
    assert result["failed"][0]["error"] == "old_text is not unique"
    assert file_path.read_text(encoding="utf-8") == original


async def test_multi_edit_replaces_longer_text_first(tmp_path):
    file_path = tmp_path / "note.txt"
    file_path.write_text("prefix-middle suffix\n", encoding="utf-8")

    result = json.loads(
        await multi_edit(
            str(file_path),
            [
                {"old_text": "suffix", "new_text": "tail"},
                {"old_text": "prefix-middle", "new_text": "head"},
            ],
            workspace_root=tmp_path,
        )
    )

    assert result["applied"] == 2
    assert file_path.read_text(encoding="utf-8") == "head tail\n"
