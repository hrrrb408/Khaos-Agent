import json
from pathlib import Path

from khaos.tools import note_tools
from khaos.tools.note_tools import delete_note, list_notes, quick_note, search_notes


def _write_note(path: Path, title: str, tags: list[str], created: str, body: str) -> None:
    path.write_text(
        "---\n"
        f'title: "{title}"\n'
        f"tags: {json.dumps(tags)}\n"
        f"created: {created}\n"
        "---\n\n"
        f"{body}\n",
        encoding="utf-8",
    )


async def test_quick_note(tmp_path, monkeypatch):
    monkeypatch.setattr(note_tools, "DEFAULT_NOTES_DIR", tmp_path)

    result = await quick_note("Remember the meeting notes", title="Meeting")

    assert result["ok"] is True
    assert result["title"] == "Meeting"
    assert result["tags"] == []
    note_path = Path(result["path"])
    assert note_path.exists()
    assert "Remember the meeting notes" in note_path.read_text(encoding="utf-8")


async def test_quick_note_with_tags(tmp_path, monkeypatch):
    monkeypatch.setattr(note_tools, "DEFAULT_NOTES_DIR", tmp_path)

    result = await quick_note("Capture this", tags=["work", "idea"], title="Inbox")

    assert result["ok"] is True
    assert result["tags"] == ["work", "idea"]
    text = Path(result["path"]).read_text(encoding="utf-8")
    assert 'tags: ["work", "idea"]' in text


async def test_search_notes(tmp_path, monkeypatch):
    monkeypatch.setattr(note_tools, "DEFAULT_NOTES_DIR", tmp_path)
    _write_note(
        tmp_path / "2026-07-08_100000_a.md",
        "Project Alpha",
        ["work"],
        "2026-07-08T10:00:00",
        "Quarterly planning",
    )
    _write_note(
        tmp_path / "2026-07-08_110000_b.md",
        "Inbox",
        ["personal"],
        "2026-07-08T11:00:00",
        "Buy milk",
    )

    result = await search_notes("alpha")

    assert result["ok"] is True
    assert result["total"] == 1
    assert result["results"][0]["title"] == "Project Alpha"


async def test_search_notes_no_match(tmp_path, monkeypatch):
    monkeypatch.setattr(note_tools, "DEFAULT_NOTES_DIR", tmp_path)
    _write_note(
        tmp_path / "2026-07-08_100000_a.md",
        "Project Alpha",
        ["work"],
        "2026-07-08T10:00:00",
        "Quarterly planning",
    )

    result = await search_notes("missing")

    assert result == {"ok": True, "results": [], "total": 0}


async def test_list_notes(tmp_path, monkeypatch):
    monkeypatch.setattr(note_tools, "DEFAULT_NOTES_DIR", tmp_path)
    _write_note(
        tmp_path / "2026-07-08_100000_a.md",
        "Older",
        ["work"],
        "2026-07-08T10:00:00",
        "Old body",
    )
    _write_note(
        tmp_path / "2026-07-08_120000_b.md",
        "Newer",
        ["work"],
        "2026-07-08T12:00:00",
        "New body",
    )

    result = await list_notes()

    assert result["ok"] is True
    assert [note["title"] for note in result["notes"]] == ["Newer", "Older"]
    assert result["total"] == 2


async def test_list_notes_by_tag(tmp_path, monkeypatch):
    monkeypatch.setattr(note_tools, "DEFAULT_NOTES_DIR", tmp_path)
    _write_note(
        tmp_path / "2026-07-08_100000_a.md",
        "Work",
        ["work"],
        "2026-07-08T10:00:00",
        "Work body",
    )
    _write_note(
        tmp_path / "2026-07-08_120000_b.md",
        "Home",
        ["personal"],
        "2026-07-08T12:00:00",
        "Home body",
    )

    result = await list_notes(tag="work")

    assert result["ok"] is True
    assert [note["title"] for note in result["notes"]] == ["Work"]
    assert result["total"] == 1


async def test_delete_note(tmp_path, monkeypatch):
    monkeypatch.setattr(note_tools, "DEFAULT_NOTES_DIR", tmp_path)
    note_path = tmp_path / "2026-07-08_100000_a.md"
    _write_note(note_path, "Delete Me", [], "2026-07-08T10:00:00", "Body")

    result = await delete_note(str(note_path))

    assert result == {"ok": True, "path": str(note_path.resolve())}
    assert not note_path.exists()


async def test_delete_note_outside_dir(tmp_path, monkeypatch):
    notes_dir = tmp_path / "notes"
    notes_dir.mkdir()
    outside = tmp_path / "outside.md"
    outside.write_text("outside", encoding="utf-8")
    monkeypatch.setattr(note_tools, "DEFAULT_NOTES_DIR", notes_dir)

    result = await delete_note(str(outside))

    assert result["ok"] is False
    assert "outside notes dir" in result["error"]
    assert outside.exists()
