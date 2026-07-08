"""Note-taking and quick capture tools for office mode."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_NOTES_DIR = Path.home() / ".khaos" / "notes"


async def quick_note(
    content: str,
    tags: list[str] | None = None,
    title: str = "",
) -> dict[str, Any]:
    """Quickly capture a Markdown note with frontmatter."""
    return await asyncio.to_thread(_quick_note_sync, content, tags, title)


def _quick_note_sync(
    content: str,
    tags: list[str] | None,
    title: str,
) -> dict[str, Any]:
    normalized_tags = tags or []
    DEFAULT_NOTES_DIR.mkdir(parents=True, exist_ok=True)

    created = datetime.now().isoformat(timespec="seconds")
    now = datetime.now()
    digest = hashlib.sha1(f"{created}\n{title}\n{content}".encode("utf-8")).hexdigest()[:6]
    file_name = f"{now.strftime('%Y-%m-%d_%H%M%S')}_{digest}.md"
    note_path = DEFAULT_NOTES_DIR / file_name

    note_content = (
        "---\n"
        f"title: {json.dumps(title, ensure_ascii=False)}\n"
        f"tags: {json.dumps(normalized_tags, ensure_ascii=False)}\n"
        f"created: {created}\n"
        "---\n\n"
        f"{content}\n"
    )
    note_path.write_text(note_content, encoding="utf-8")
    return {
        "ok": True,
        "path": str(note_path),
        "title": title,
        "tags": normalized_tags,
    }


async def search_notes(query: str, max_results: int = 10) -> dict[str, Any]:
    """Search notes by title, tags, and body preview."""
    return await asyncio.to_thread(_search_notes_sync, query, max_results)


def _search_notes_sync(query: str, max_results: int) -> dict[str, Any]:
    if max_results < 1:
        return {"ok": False, "error": "max_results must be >= 1"}
    if not DEFAULT_NOTES_DIR.exists():
        return {"ok": True, "results": [], "total": 0}

    needle = query.casefold()
    scored_results: list[tuple[int, dict[str, Any]]] = []
    for note_path in sorted(DEFAULT_NOTES_DIR.glob("*.md"), reverse=True):
        note = _read_note_summary(note_path)
        title = str(note["title"]).casefold()
        tags = [str(tag).casefold() for tag in note["tags"]]
        preview = str(note["preview"]).casefold()

        score = 0
        if needle in title:
            score = 3
        elif any(needle in tag for tag in tags):
            score = 2
        elif needle in preview:
            score = 1

        if score > 0:
            scored_results.append((score, note))

    scored_results.sort(
        key=lambda item: (item[0], str(item[1]["created"]), str(item[1]["path"])),
        reverse=True,
    )
    results = [note for _, note in scored_results[:max_results]]
    return {"ok": True, "results": results, "total": len(scored_results)}


async def list_notes(limit: int = 20, tag: str = "") -> dict[str, Any]:
    """List recent notes, optionally filtered by tag."""
    return await asyncio.to_thread(_list_notes_sync, limit, tag)


def _list_notes_sync(limit: int, tag: str) -> dict[str, Any]:
    if limit < 1:
        return {"ok": False, "error": "limit must be >= 1"}
    if not DEFAULT_NOTES_DIR.exists():
        return {"ok": True, "notes": [], "total": 0}

    normalized_tag = tag.casefold()
    notes: list[dict[str, Any]] = []
    for note_path in sorted(DEFAULT_NOTES_DIR.glob("*.md"), reverse=True):
        note = _read_note_summary(note_path)
        if normalized_tag and normalized_tag not in [
            str(item).casefold() for item in note["tags"]
        ]:
            continue
        notes.append(
            {
                "path": note["path"],
                "title": note["title"],
                "tags": note["tags"],
                "created": note["created"],
            }
        )

    return {"ok": True, "notes": notes[:limit], "total": len(notes)}


async def delete_note(path: str) -> dict[str, Any]:
    """Delete a note only when it is inside DEFAULT_NOTES_DIR."""
    return await asyncio.to_thread(_delete_note_sync, path)


def _delete_note_sync(path: str) -> dict[str, Any]:
    notes_dir = DEFAULT_NOTES_DIR.expanduser().resolve()
    note_path = Path(path).expanduser().resolve()
    try:
        note_path.relative_to(notes_dir)
    except ValueError:
        return {"ok": False, "path": str(note_path), "error": "path is outside notes dir"}

    if not note_path.exists():
        return {"ok": False, "path": str(note_path), "error": "note does not exist"}
    if not note_path.is_file():
        return {"ok": False, "path": str(note_path), "error": "path is not a file"}

    try:
        os.unlink(note_path)
    except OSError as exc:
        logger.warning("Failed to delete note %s: %s", note_path, exc)
        return {"ok": False, "path": str(note_path), "error": str(exc)}
    return {"ok": True, "path": str(note_path)}


def _read_note_summary(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        text = path.read_text(encoding="utf-8", errors="replace")

    metadata, body = _parse_frontmatter(text)
    preview = body.strip().replace("\n", " ")[:200]
    return {
        "path": str(path),
        "title": str(metadata.get("title", "")),
        "tags": _normalize_tags(metadata.get("tags", [])),
        "preview": preview,
        "created": str(metadata.get("created", "")),
    }


def _parse_frontmatter(text: str) -> tuple[dict[str, Any], str]:
    if not text.startswith("---\n"):
        return {}, text

    try:
        _, frontmatter, body = text.split("---\n", 2)
    except ValueError:
        return {}, text

    metadata: dict[str, Any] = {}
    for line in frontmatter.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        metadata[key.strip()] = _parse_frontmatter_value(value.strip())
    return metadata, body


def _parse_frontmatter_value(value: str) -> Any:
    if not value:
        return ""
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value.strip('"')


def _normalize_tags(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            try:
                loaded = json.loads(stripped)
            except json.JSONDecodeError:
                loaded = []
            if isinstance(loaded, list):
                return [str(item) for item in loaded]
        return [stripped] if stripped else []
    return []
