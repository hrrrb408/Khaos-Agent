"""File operation tools."""

from __future__ import annotations

import asyncio
import fnmatch
import json
import mimetypes
import os
import re
import shutil
import tempfile
from difflib import SequenceMatcher
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


TREE_EXCLUDE_DIRS = {
    ".git",
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    ".next",
    "target",
    "dist",
    "build",
}


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


async def list_directory(path: str = ".", include_hidden: bool = True) -> dict[str, Any]:
    """List directory contents with structured metadata."""
    return await asyncio.to_thread(_list_directory_sync, path, include_hidden)


def _list_directory_sync(path: str, include_hidden: bool) -> dict[str, Any]:
    dir_path = Path(path).expanduser().resolve()
    if not dir_path.exists():
        return {"ok": False, "path": str(dir_path), "error": "path does not exist"}
    if not dir_path.is_dir():
        return {"ok": False, "path": str(dir_path), "error": "path is not a directory"}

    dirs: list[dict[str, Any]] = []
    files: list[dict[str, Any]] = []
    try:
        entries = list(dir_path.iterdir())
    except OSError as exc:
        return {"ok": False, "path": str(dir_path), "error": str(exc)}

    for entry in entries:
        if not include_hidden and entry.name.startswith("."):
            continue
        if entry.name == ".git":
            continue
        try:
            if entry.is_dir():
                dirs.append({"name": entry.name, "item_count": _count_directory_items(entry)})
            elif entry.is_file():
                files.append(
                    {
                        "name": entry.name,
                        "size_bytes": entry.stat().st_size,
                        "extension": entry.suffix,
                    }
                )
        except OSError:
            continue

    dirs.sort(key=lambda item: str(item["name"]).lower())
    files.sort(key=lambda item: str(item["name"]).lower())
    return {
        "ok": True,
        "path": str(dir_path),
        "dirs": dirs,
        "files": files,
        "total_items": len(dirs) + len(files),
    }


async def file_info(path: str) -> dict[str, Any]:
    """Get detailed file or directory metadata."""
    return await asyncio.to_thread(_file_info_sync, path)


def _file_info_sync(path: str) -> dict[str, Any]:
    item_path = Path(path).expanduser().resolve()
    if not item_path.exists():
        return {"ok": False, "path": str(item_path), "error": "path does not exist"}

    try:
        stat_result = item_path.stat()
    except OSError as exc:
        return {"ok": False, "path": str(item_path), "error": str(exc)}

    item_type = "directory" if item_path.is_dir() else "file"
    modified = datetime.fromtimestamp(stat_result.st_mtime, tz=timezone.utc).isoformat()
    mime_type, _ = mimetypes.guess_type(str(item_path))
    return {
        "ok": True,
        "path": str(item_path),
        "type": item_type,
        "size_bytes": stat_result.st_size,
        "extension": item_path.suffix if item_path.is_file() else "",
        "modified": modified,
        "is_hidden": item_path.name.startswith("."),
        "is_symlink": item_path.is_symlink(),
        "mime_type": mime_type,
    }


async def tree_view(path: str = ".", max_depth: int = 3) -> dict[str, Any]:
    """Generate a formatted directory tree view."""
    return await asyncio.to_thread(_tree_view_sync, path, max_depth)


def _tree_view_sync(path: str, max_depth: int) -> dict[str, Any]:
    root_path = Path(path).expanduser().resolve()
    if max_depth < 0:
        return {"ok": False, "path": str(root_path), "error": "max_depth must be >= 0"}
    if not root_path.exists():
        return {"ok": False, "path": str(root_path), "error": "path does not exist"}
    if not root_path.is_dir():
        return {"ok": False, "path": str(root_path), "error": "path is not a directory"}

    lines: list[str] = []
    counts = {"files": 0, "dirs": 0}
    _build_tree_lines(root_path, max_depth, "", lines, counts)
    return {
        "ok": True,
        "path": str(root_path),
        "tree": "\n".join(lines),
        "total_files": counts["files"],
        "total_dirs": counts["dirs"],
    }


async def copy_file(src: str, dst: str) -> dict[str, Any]:
    """Copy a file or directory."""
    return await asyncio.to_thread(_copy_file_sync, src, dst)


def _copy_file_sync(src: str, dst: str) -> dict[str, Any]:
    src_path = Path(src).expanduser().resolve()
    dst_path = Path(dst).expanduser().resolve()
    if not src_path.exists():
        return {
            "ok": False,
            "src": str(src_path),
            "dst": str(dst_path),
            "error": "source does not exist",
        }
    if not dst_path.parent.exists():
        return {
            "ok": False,
            "src": str(src_path),
            "dst": str(dst_path),
            "error": "destination parent does not exist",
        }

    try:
        if src_path.is_dir():
            shutil.copytree(src_path, dst_path)
            size_bytes = _directory_size(dst_path)
        else:
            shutil.copy2(src_path, dst_path)
            size_bytes = dst_path.stat().st_size
    except OSError as exc:
        return {"ok": False, "src": str(src_path), "dst": str(dst_path), "error": str(exc)}

    return {"ok": True, "src": str(src_path), "dst": str(dst_path), "size_bytes": size_bytes}


async def move_file(src: str, dst: str) -> dict[str, Any]:
    """Move or rename a file or directory."""
    return await asyncio.to_thread(_move_file_sync, src, dst)


def _move_file_sync(src: str, dst: str) -> dict[str, Any]:
    src_path = Path(src).expanduser().resolve()
    dst_path = Path(dst).expanduser().resolve()
    if not src_path.exists():
        return {
            "ok": False,
            "src": str(src_path),
            "dst": str(dst_path),
            "error": "source does not exist",
        }
    if not dst_path.parent.exists():
        return {
            "ok": False,
            "src": str(src_path),
            "dst": str(dst_path),
            "error": "destination parent does not exist",
        }

    try:
        shutil.move(str(src_path), str(dst_path))
    except OSError as exc:
        return {"ok": False, "src": str(src_path), "dst": str(dst_path), "error": str(exc)}
    return {"ok": True, "src": str(src_path), "dst": str(dst_path)}


async def file_search_content(
    path: str,
    pattern: str,
    max_results: int = 50,
) -> dict[str, Any]:
    """Search text file contents for a substring or basic regular expression."""
    return await asyncio.to_thread(_file_search_content_sync, path, pattern, max_results)


def _file_search_content_sync(path: str, pattern: str, max_results: int) -> dict[str, Any]:
    root_path = Path(path).expanduser().resolve()
    if max_results < 1:
        return {
            "ok": False,
            "path": str(root_path),
            "pattern": pattern,
            "error": "max_results must be >= 1",
        }
    if not root_path.exists():
        return {
            "ok": False,
            "path": str(root_path),
            "pattern": pattern,
            "error": "path does not exist",
        }

    try:
        regex = re.compile(pattern)
    except re.error:
        regex = None

    matches: list[dict[str, Any]] = []
    files_searched = 0
    file_paths = [root_path] if root_path.is_file() else _iter_searchable_files(root_path)
    for file_path in file_paths:
        try:
            lines = file_path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError):
            continue

        files_searched += 1
        for line_number, line in enumerate(lines, start=1):
            matched = regex.search(line) is not None if regex is not None else pattern in line
            if not matched:
                continue
            matches.append(
                {
                    "file": str(file_path),
                    "line_number": line_number,
                    "line": line,
                }
            )
            if len(matches) >= max_results:
                return {
                    "ok": True,
                    "pattern": pattern,
                    "matches": matches,
                    "match_count": len(matches),
                    "files_searched": files_searched,
                }

    return {
        "ok": True,
        "pattern": pattern,
        "matches": matches,
        "match_count": len(matches),
        "files_searched": files_searched,
    }


def _count_directory_items(path: Path) -> int:
    try:
        return sum(1 for item in path.iterdir() if item.name != ".git")
    except OSError:
        return 0


def _directory_size(path: Path) -> int:
    if path.is_file():
        return path.stat().st_size
    total = 0
    for file_path in path.rglob("*"):
        if file_path.is_file():
            try:
                total += file_path.stat().st_size
            except OSError:
                continue
    return total


def _build_tree_lines(
    path: Path,
    max_depth: int,
    prefix: str,
    lines: list[str],
    counts: dict[str, int],
    depth: int = 1,
) -> None:
    if depth > max_depth:
        return

    entries = _sorted_tree_entries(path)
    for index, entry in enumerate(entries):
        connector = "└── " if index == len(entries) - 1 else "├── "
        is_dir = entry.is_dir()
        lines.append(f"{prefix}{connector}{entry.name}{'/' if is_dir else ''}")
        if is_dir:
            counts["dirs"] += 1
            extension = "    " if index == len(entries) - 1 else "│   "
            _build_tree_lines(entry, max_depth, prefix + extension, lines, counts, depth + 1)
        else:
            counts["files"] += 1


def _sorted_tree_entries(path: Path) -> list[Path]:
    try:
        entries = [
            item
            for item in path.iterdir()
            if not (item.is_dir() and item.name in TREE_EXCLUDE_DIRS)
        ]
    except OSError:
        return []
    return sorted(entries, key=lambda item: (not item.is_dir(), item.name.lower()))


def _iter_searchable_files(root_path: Path) -> list[Path]:
    files: list[Path] = []
    for dir_path, dir_names, file_names in os.walk(root_path):
        dir_names[:] = sorted(
            [name for name in dir_names if name not in TREE_EXCLUDE_DIRS],
            key=str.lower,
        )
        for file_name in sorted(file_names, key=str.lower):
            files.append(Path(dir_path) / file_name)
    return files


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
