"""File operation tools."""

from __future__ import annotations

import asyncio
import fnmatch
import json
import os
import tempfile
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any


async def read_file(path: str, offset: int = 1, limit: int = 500) -> dict[str, Any]:
    """Read a file page with one-based line numbers."""
    return await asyncio.to_thread(_read_file_sync, path, offset, limit)


def _read_file_sync(path: str, offset: int, limit: int) -> dict[str, Any]:
    file_path = Path(path).expanduser().resolve()
    if offset < 1:
        raise ValueError("offset must be >= 1")
    if limit < 1:
        raise ValueError("limit must be >= 1")
    lines = file_path.read_text(encoding="utf-8").splitlines()
    start = offset - 1
    selected = lines[start : start + limit]
    numbered = [f"{start + index + 1}: {line}" for index, line in enumerate(selected)]
    return {
        "path": str(file_path),
        "offset": offset,
        "limit": limit,
        "total_lines": len(lines),
        "content": "\n".join(numbered),
    }


async def write_file(path: str, content: str) -> dict[str, Any]:
    """Overwrite a file, creating parent directories as needed."""
    return await asyncio.to_thread(_write_file_sync, path, content)


def _write_file_sync(path: str, content: str) -> dict[str, Any]:
    file_path = Path(path).expanduser().resolve()
    file_path.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write(file_path, content)
    return {"path": str(file_path), "bytes": len(content.encode("utf-8"))}


async def patch(path: str, old: str, new: str, fuzzy: bool = True) -> dict[str, Any]:
    """Atomically replace text in a file, with optional fuzzy block matching."""
    return await asyncio.to_thread(_patch_sync, path, old, new, fuzzy)


def _patch_sync(path: str, old: str, new: str, fuzzy: bool) -> dict[str, Any]:
    file_path = Path(path).expanduser().resolve()
    original = file_path.read_text(encoding="utf-8")
    if old in original:
        updated = original.replace(old, new, 1)
        _atomic_write(file_path, updated)
        return {"path": str(file_path), "replaced": 1, "fuzzy": False}
    if not fuzzy:
        raise ValueError("old text not found")

    match = _find_fuzzy_block(original, old)
    if match is None:
        raise ValueError("old text not found")
    start, end, score = match
    updated = original[:start] + new + original[end:]
    _atomic_write(file_path, updated)
    return {"path": str(file_path), "replaced": 1, "fuzzy": True, "score": score}


async def multi_edit(path: str, edits: list[dict]) -> str:
    """Apply multiple exact search-and-replace edits to one file atomically."""
    return await asyncio.to_thread(_multi_edit_sync, path, edits)


def _multi_edit_sync(path: str, edits: list[dict]) -> str:
    file_path = Path(path).expanduser().resolve()
    original = file_path.read_text(encoding="utf-8")
    normalized_edits = _normalize_multi_edits(edits)
    sorted_edits = sorted(
        enumerate(normalized_edits),
        key=lambda item: len(item[1]["old_text"]),
        reverse=True,
    )

    failures: list[dict[str, Any]] = []
    for original_index, edit in sorted_edits:
        count = original.count(edit["old_text"])
        if count != 1:
            failures.append(
                {
                    "index": original_index,
                    "old_text": edit["old_text"],
                    "matches": count,
                    "error": "old_text not found" if count == 0 else "old_text is not unique",
                }
            )

    if failures:
        return json.dumps(
            {
                "path": str(file_path),
                "applied": 0,
                "failed": sorted(failures, key=lambda item: int(item["index"])),
            },
            ensure_ascii=False,
        )

    updated = original
    applied: list[dict[str, Any]] = []
    for original_index, edit in sorted_edits:
        updated = updated.replace(edit["old_text"], edit["new_text"], 1)
        applied.append({"index": original_index, "old_text": edit["old_text"]})

    _atomic_write(file_path, updated)
    return json.dumps(
        {
            "path": str(file_path),
            "applied": len(applied),
            "failed": [],
            "message": "All edits applied.",
        },
        ensure_ascii=False,
    )


def _normalize_multi_edits(edits: list[dict]) -> list[dict[str, str]]:
    if not isinstance(edits, list):
        raise ValueError("edits must be a list")
    normalized: list[dict[str, str]] = []
    for index, edit in enumerate(edits):
        if not isinstance(edit, dict):
            raise ValueError(f"edit at index {index} must be an object")
        old_text = edit.get("old_text")
        new_text = edit.get("new_text")
        if not isinstance(old_text, str) or not isinstance(new_text, str):
            raise ValueError(f"edit at index {index} must include string old_text and new_text")
        if old_text == "":
            raise ValueError(f"edit at index {index} old_text must not be empty")
        normalized.append({"old_text": old_text, "new_text": new_text})
    return normalized


async def search_files(
    root: str = ".",
    query: str = "",
    glob: str = "*",
    content: bool = False,
    limit: int = 100,
) -> dict[str, Any]:
    """Search file paths by glob or file contents by text."""
    return await asyncio.to_thread(_search_files_sync, root, query, glob, content, limit)


def _search_files_sync(
    root: str,
    query: str,
    glob: str,
    content: bool,
    limit: int,
) -> dict[str, Any]:
    root_path = Path(root).expanduser().resolve()
    if limit < 1:
        raise ValueError("limit must be >= 1")
    matches: list[dict[str, Any]] = []
    for file_path in sorted(path for path in root_path.rglob("*") if path.is_file()):
        relative = str(file_path.relative_to(root_path))
        if not fnmatch.fnmatch(relative, glob):
            continue
        if not content:
            if not query or query in relative:
                matches.append({"path": str(file_path)})
        else:
            try:
                lines = file_path.read_text(encoding="utf-8").splitlines()
            except UnicodeDecodeError:
                continue
            for line_number, line in enumerate(lines, start=1):
                if query in line:
                    matches.append(
                        {
                            "path": str(file_path),
                            "line": line_number,
                            "text": line,
                        }
                    )
                    break
        if len(matches) >= limit:
            break
    return {"root": str(root_path), "matches": matches, "count": len(matches)}


def _atomic_write(path: Path, content: str) -> None:
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
        os.replace(temp_name, path)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def _find_fuzzy_block(content: str, old: str) -> tuple[int, int, float] | None:
    old_lines = old.splitlines()
    if not old_lines:
        return None
    content_lines = content.splitlines(keepends=True)
    plain_lines = [line.rstrip("\n") for line in content_lines]
    window_size = len(old_lines)
    best: tuple[int, int, float] | None = None
    cursor_offsets: list[int] = []
    cursor = 0
    for line in content_lines:
        cursor_offsets.append(cursor)
        cursor += len(line)
    for index in range(0, max(len(plain_lines) - window_size + 1, 0)):
        candidate = "\n".join(plain_lines[index : index + window_size])
        score = SequenceMatcher(None, old, candidate).ratio()
        if best is None or score > best[2]:
            start = cursor_offsets[index]
            end_index = index + window_size
            end = cursor_offsets[end_index] if end_index < len(cursor_offsets) else len(content)
            best = (start, end, score)
    if best is None or best[2] < 0.72:
        return None
    return best
