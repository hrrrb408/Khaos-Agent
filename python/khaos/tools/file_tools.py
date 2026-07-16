"""File operation tools."""

from __future__ import annotations

import asyncio
import fnmatch
import json
import mimetypes
import os
import re
import shutil
import stat
import tempfile
from difflib import SequenceMatcher
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from khaos.security.path_guard import PathGuard


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

_SECURITY_ENABLED = True
_PATH_GUARD = PathGuard()


def enable_security(enabled: bool = True) -> None:
    """启用/禁用安全检查（测试用）。"""
    global _SECURITY_ENABLED
    _SECURITY_ENABLED = enabled


async def read_file(path: str, offset: int = 1, limit: int = 500, workspace_manager=None, task_id: str | None = None, workspace_id: str | None = None) -> dict[str, Any]:
    """Read a file page with one-based line numbers."""
    if workspace_manager is not None:
        workspace = workspace_manager.get(workspace_id or "")
        if workspace is None or workspace.task_id != task_id:
            raise PermissionError("coding read requires matching active TaskWorkspace")
        return await asyncio.to_thread(
            _workspace_read_sync, workspace.worktree_path, path, offset, limit
        )
    return await asyncio.to_thread(_read_file_sync, path, offset, limit)


def _read_file_sync(path: str, offset: int, limit: int) -> dict[str, Any]:
    if _SECURITY_ENABLED:
        check = _PATH_GUARD.check_read(path)
        if not check.safe:
            return {
                "ok": False,
                "path": check.normalized_path,
                "error": f"File read blocked: {check.reason}",
                "risk_level": check.risk_level,
            }
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


async def write_file(path: str, content: str, workspace_manager=None, task_id: str | None = None, workspace_id: str | None = None) -> dict[str, Any]:
    """Overwrite a file, creating parent directories as needed."""
    if workspace_manager is not None:
        workspace = workspace_manager.get(workspace_id or "")
        if workspace is None or workspace.task_id != task_id:
            raise PermissionError("coding write requires matching active TaskWorkspace")
        return await _workspace_mutate(
            workspace_manager,
            workspace,
            task_id or "",
            lambda: _workspace_write_sync(
                workspace.worktree_path,
                workspace_manager.file_recovery_root(workspace.id),
                path,
                content,
            ),
        )
    return await asyncio.to_thread(_write_file_sync, path, content)


def _write_file_sync(path: str, content: str) -> dict[str, Any]:
    if _SECURITY_ENABLED:
        check = _PATH_GUARD.check_write(path)
        if not check.safe:
            return {
                "ok": False,
                "path": check.normalized_path,
                "error": f"File write blocked: {check.reason}",
                "risk_level": check.risk_level,
            }
    file_path = Path(path).expanduser().resolve()
    file_path.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write(file_path, content)
    return {"path": str(file_path), "bytes": len(content.encode("utf-8"))}


async def patch(path: str, old: str, new: str, fuzzy: bool = True, workspace_manager=None, task_id: str | None = None, workspace_id: str | None = None) -> dict[str, Any]:
    """Atomically replace text in a file, with optional fuzzy block matching."""
    if workspace_manager is not None:
        workspace = workspace_manager.get(workspace_id or "")
        if workspace is None or workspace.task_id != task_id:
            raise PermissionError("coding patch requires matching active TaskWorkspace")
        return await _workspace_mutate(
            workspace_manager,
            workspace,
            task_id or "",
            lambda: _workspace_patch_sync(
                workspace.worktree_path,
                workspace_manager.file_recovery_root(workspace.id),
                path, old, new, fuzzy,
            ),
        )
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


async def multi_edit(path: str, edits: list[dict], workspace_manager=None, task_id: str | None = None, workspace_id: str | None = None) -> str:
    """Apply multiple exact search-and-replace edits to one file atomically."""
    if workspace_manager is not None:
        workspace = workspace_manager.get(workspace_id or "")
        if workspace is None or workspace.task_id != task_id:
            raise PermissionError("coding edit requires matching active TaskWorkspace")
        return await _workspace_mutate(
            workspace_manager,
            workspace,
            task_id or "",
            lambda: _workspace_multi_edit_sync(
                workspace.worktree_path,
                workspace_manager.file_recovery_root(workspace.id),
                path, edits,
            ),
        )
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
    workspace_manager=None,
    task_id: str | None = None,
    workspace_id: str | None = None,
) -> dict[str, Any]:
    """Search file paths by glob or file contents by text."""
    if workspace_manager is not None:
        workspace = workspace_manager.get(workspace_id or "")
        if workspace is None or workspace.task_id != task_id:
            raise PermissionError("coding search requires matching active TaskWorkspace")
        return await asyncio.to_thread(
            _workspace_search_sync, workspace.worktree_path, root, query,
            glob, content, limit,
        )
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


async def list_directory(path: str = ".", include_hidden: bool = True, workspace_manager=None, task_id: str | None = None, workspace_id: str | None = None) -> dict[str, Any]:
    """List directory contents with structured metadata."""
    if workspace_manager is not None:
        workspace = workspace_manager.get(workspace_id or "")
        if workspace is None or workspace.task_id != task_id:
            raise PermissionError("coding list requires matching active TaskWorkspace")
        return await asyncio.to_thread(
            _workspace_list_sync, workspace.worktree_path, path, include_hidden
        )
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


async def file_info(path: str, workspace_manager=None, task_id: str | None = None, workspace_id: str | None = None) -> dict[str, Any]:
    """Get detailed file or directory metadata."""
    if workspace_manager is not None:
        workspace = workspace_manager.get(workspace_id or "")
        if workspace is None or workspace.task_id != task_id:
            raise PermissionError("coding info requires matching active TaskWorkspace")
        return await asyncio.to_thread(
            _workspace_info_sync, workspace.worktree_path, path
        )
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


async def tree_view(path: str = ".", max_depth: int = 3, workspace_manager=None, task_id: str | None = None, workspace_id: str | None = None) -> dict[str, Any]:
    """Generate a formatted directory tree view."""
    if workspace_manager is not None:
        workspace = workspace_manager.get(workspace_id or "")
        if workspace is None or workspace.task_id != task_id:
            raise PermissionError("coding tree requires matching active TaskWorkspace")
        return await asyncio.to_thread(
            _workspace_tree_sync, workspace.worktree_path, path, max_depth
        )
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


async def copy_file(src: str, dst: str, workspace_manager=None, task_id: str | None = None, workspace_id: str | None = None) -> dict[str, Any]:
    """Copy a file or directory."""
    if workspace_manager is not None:
        workspace = workspace_manager.get(workspace_id or "")
        if workspace is None or workspace.task_id != task_id:
            raise PermissionError("coding copy requires matching active TaskWorkspace")
        return await _workspace_mutate(
            workspace_manager,
            workspace,
            task_id or "",
            lambda: _workspace_copy_sync(
                workspace.worktree_path,
                workspace_manager.file_recovery_root(workspace.id),
                src, dst,
            ),
        )
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


async def move_file(src: str, dst: str, workspace_manager=None, task_id: str | None = None, workspace_id: str | None = None) -> dict[str, Any]:
    """Move or rename a file or directory."""
    if workspace_manager is not None:
        workspace = workspace_manager.get(workspace_id or "")
        if workspace is None or workspace.task_id != task_id:
            raise PermissionError("coding move requires matching active TaskWorkspace")
        return await _workspace_mutate(
            workspace_manager,
            workspace,
            task_id or "",
            lambda: _workspace_move_sync(workspace.worktree_path, src, dst),
        )
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
    workspace_manager=None,
    task_id: str | None = None,
    workspace_id: str | None = None,
) -> dict[str, Any]:
    """Search text file contents for a substring or basic regular expression."""
    if workspace_manager is not None:
        workspace = workspace_manager.get(workspace_id or "")
        if workspace is None or workspace.task_id != task_id:
            raise PermissionError("coding content search requires matching active TaskWorkspace")
        return await asyncio.to_thread(
            _workspace_content_search_sync,
            workspace.worktree_path,
            path,
            pattern,
            max_results,
        )
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


async def _workspace_mutate(
    workspace_manager,
    workspace,
    task_id: str,
    operation,
):
    """Require the shared storage authority for every Coding file write."""
    mutate = getattr(workspace_manager, "mutate_with_storage_authority", None)
    if mutate is None:
        raise PermissionError("WorkspaceStorageAuthority is required for writes")
    return await mutate(workspace.id, task_id, operation)


def _workspace_write_sync(
    root: Path, recovery_root: Path, path: str, content: str
) -> object:
    from khaos.coding.workspace.boundary import SafeWorkspaceFS
    from khaos.coding.workspace.storage import WorkspaceMutation

    with SafeWorkspaceFS(root) as filesystem:
        relative = filesystem.relative(path)
        before = filesystem.snapshot_file(path, recovery_root=recovery_root)
        try:
            encoded = content.encode("utf-8")
            filesystem.write_bytes(path, encoded)
            after = filesystem.snapshot_file(path)
        except Exception:
            before.cleanup()
            raise
        value = {
            "path": str(filesystem.root / relative),
            "bytes": len(encoded),
        }
    return WorkspaceMutation(
        value,
        lambda: _rollback_file(root, path, before, after),
        before.cleanup,
    )


def _workspace_read_sync(
    root: Path, path: str, offset: int, limit: int
) -> dict[str, Any]:
    from khaos.coding.workspace.boundary import SafeWorkspaceFS

    if offset < 1 or limit < 1:
        raise ValueError("offset and limit must be >= 1")
    with SafeWorkspaceFS(root) as filesystem:
        relative = filesystem.relative(path)
        lines = filesystem.read_bytes(path).decode("utf-8").splitlines()
        start = offset - 1
        selected = lines[start:start + limit]
        return {
            "path": str(filesystem.root / relative),
            "offset": offset,
            "limit": limit,
            "total_lines": len(lines),
            "content": "\n".join(
                f"{start + index + 1}: {line}"
                for index, line in enumerate(selected)
            ),
        }


def _workspace_search_sync(
    workspace_root: Path, root: str, query: str, glob: str,
    content: bool, limit: int,
) -> dict[str, Any]:
    from khaos.coding.workspace.boundary import SafeWorkspaceFS

    if limit < 1:
        raise ValueError("limit must be >= 1")
    with SafeWorkspaceFS(workspace_root) as filesystem:
        base = filesystem._directory_relative(root)
        matches: list[dict[str, Any]] = []
        for relative in filesystem.iter_files(root):
            display = relative[len(base) + 1:] if base else relative
            if not fnmatch.fnmatch(display, glob):
                continue
            if not content:
                if not query or query in display:
                    matches.append({"path": str(filesystem.root / relative)})
            else:
                try:
                    lines = filesystem.read_bytes(relative).decode("utf-8").splitlines()
                except UnicodeDecodeError:
                    continue
                for line_number, line in enumerate(lines, start=1):
                    if query in line:
                        matches.append({
                            "path": str(filesystem.root / relative),
                            "line": line_number,
                            "text": line,
                        })
                        break
            if len(matches) >= limit:
                break
        return {
            "root": str(filesystem.root / base),
            "matches": matches,
            "count": len(matches),
        }


def _workspace_list_sync(
    workspace_root: Path, path: str, include_hidden: bool
) -> dict[str, Any]:
    from khaos.coding.workspace.boundary import SafeWorkspaceFS

    with SafeWorkspaceFS(workspace_root) as filesystem:
        base = filesystem._directory_relative(path)
        direct_files: dict[str, dict[str, Any]] = {}
        directories: set[str] = set()
        for relative in filesystem.iter_files(path):
            display = relative[len(base) + 1:] if base else relative
            first, separator, remainder = display.partition("/")
            if not include_hidden and first.startswith("."):
                continue
            if separator:
                directories.add(first)
            else:
                info = filesystem.stat(relative)
                direct_files[first] = {
                    "name": first,
                    "size_bytes": info.st_size,
                    "extension": Path(first).suffix,
                }
        dirs = [{"name": name, "item_count": 0} for name in sorted(directories, key=str.lower)]
        files = [direct_files[name] for name in sorted(direct_files, key=str.lower)]
        return {
            "ok": True,
            "path": str(filesystem.root / base),
            "dirs": dirs,
            "files": files,
            "total_items": len(dirs) + len(files),
        }


def _workspace_info_sync(workspace_root: Path, path: str) -> dict[str, Any]:
    from khaos.coding.workspace.boundary import SafeWorkspaceFS

    with SafeWorkspaceFS(workspace_root) as filesystem:
        if path in {"", "."}:
            stat_result = os.fstat(filesystem._handle.root_fd)
            relative = ""
        else:
            relative = filesystem.relative(path)
            stat_result = filesystem.stat(path)
        is_directory = stat.S_ISDIR(stat_result.st_mode)
        modified = datetime.fromtimestamp(
            stat_result.st_mtime, tz=timezone.utc
        ).isoformat()
        return {
            "ok": True,
            "path": str(filesystem.root / relative),
            "type": "directory" if is_directory else "file",
            "size_bytes": stat_result.st_size,
            "extension": "" if is_directory else Path(relative).suffix,
            "modified": modified,
            "is_hidden": bool(relative and Path(relative).name.startswith(".")),
            "is_symlink": False,
            "mime_type": mimetypes.guess_type(relative)[0],
        }


def _workspace_tree_sync(
    workspace_root: Path, path: str, max_depth: int
) -> dict[str, Any]:
    from khaos.coding.workspace.boundary import SafeWorkspaceFS

    if max_depth < 0:
        raise ValueError("max_depth must be >= 0")
    with SafeWorkspaceFS(workspace_root) as filesystem:
        base = filesystem._directory_relative(path)
        visible: list[str] = []
        directories: set[str] = set()
        for relative in filesystem.iter_files(path):
            display = relative[len(base) + 1:] if base else relative
            parts = display.split("/")
            for depth in range(1, min(len(parts), max_depth + 1)):
                directories.add("/".join(parts[:depth]))
            if len(parts) <= max_depth:
                visible.append(display)
        lines = [f"{entry}/" for entry in sorted(directories)] + sorted(visible)
        return {
            "ok": True,
            "path": str(filesystem.root / base),
            "tree": "\n".join(lines),
            "total_files": len(visible),
            "total_dirs": len(directories),
        }


def _workspace_content_search_sync(
    workspace_root: Path, path: str, pattern: str, max_results: int
) -> dict[str, Any]:
    from khaos.coding.workspace.boundary import SafeWorkspaceFS

    if max_results < 1:
        raise ValueError("max_results must be >= 1")
    try:
        regex = re.compile(pattern)
    except re.error:
        regex = None
    with SafeWorkspaceFS(workspace_root) as filesystem:
        try:
            candidates = filesystem.iter_files(path)
        except (NotADirectoryError, FileNotFoundError):
            candidates = [filesystem.relative(path)]
        matches: list[dict[str, Any]] = []
        searched = 0
        for relative in candidates:
            try:
                lines = filesystem.read_bytes(relative).decode("utf-8").splitlines()
            except UnicodeDecodeError:
                continue
            searched += 1
            for line_number, line in enumerate(lines, start=1):
                matched = regex.search(line) is not None if regex else pattern in line
                if matched:
                    matches.append({
                        "file": str(filesystem.root / relative),
                        "line_number": line_number,
                        "line": line,
                    })
                    if len(matches) >= max_results:
                        return {"ok": True, "pattern": pattern, "matches": matches, "match_count": len(matches), "files_searched": searched}
        return {"ok": True, "pattern": pattern, "matches": matches, "match_count": len(matches), "files_searched": searched}


def _workspace_patch_sync(
    root: Path, recovery_root: Path, path: str,
    old: str, new: str, fuzzy: bool,
) -> object:
    from khaos.coding.workspace.boundary import SafeWorkspaceFS
    from khaos.coding.workspace.storage import WorkspaceMutation

    with SafeWorkspaceFS(root) as filesystem:
        relative = filesystem.relative(path)
        before = filesystem.snapshot_file(path, recovery_root=recovery_root)
        result: dict[str, Any] = {}

        def transform(original: str) -> str:
            if old in original:
                result.update(replaced=1, fuzzy=False)
                return original.replace(old, new, 1)
            if not fuzzy:
                raise ValueError("old text not found")
            match = _find_fuzzy_block(original, old)
            if match is None:
                raise ValueError("old text not found")
            start, end, score = match
            result.update(replaced=1, fuzzy=True, score=score)
            return original[:start] + new + original[end:]

        try:
            filesystem.transform_text(path, transform)
            after = filesystem.snapshot_file(path)
        except Exception:
            before.cleanup()
            raise
        value = {"path": str(filesystem.root / relative), **result}
    return WorkspaceMutation(
        value,
        lambda: _rollback_file(root, path, before, after),
        before.cleanup,
    )


def _workspace_multi_edit_sync(
    root: Path, recovery_root: Path, path: str, edits: list[dict]
) -> object:
    from khaos.coding.workspace.boundary import SafeWorkspaceFS
    from khaos.coding.workspace.storage import WorkspaceMutation

    normalized_edits = _normalize_multi_edits(edits)
    sorted_edits = sorted(
        enumerate(normalized_edits),
        key=lambda item: len(item[1]["old_text"]),
        reverse=True,
    )
    with SafeWorkspaceFS(root) as filesystem:
        relative = filesystem.relative(path)
        before = filesystem.snapshot_file(path, recovery_root=recovery_root)
        try:
            original = filesystem.read_bytes(path).decode("utf-8")
        except Exception:
            before.cleanup()
            raise
        failures: list[dict[str, Any]] = []
        for original_index, edit in sorted_edits:
            count = original.count(edit["old_text"])
            if count != 1:
                failures.append({
                    "index": original_index,
                    "old_text": edit["old_text"],
                    "matches": count,
                    "error": (
                        "old_text not found" if count == 0
                        else "old_text is not unique"
                    ),
                })
        if failures:
            return WorkspaceMutation(json.dumps({
                "path": str(filesystem.root / relative),
                "applied": 0,
                "failed": sorted(failures, key=lambda item: int(item["index"])),
            }, ensure_ascii=False), lambda: None, before.cleanup)
        updated = original
        applied: list[dict[str, Any]] = []
        for original_index, edit in sorted_edits:
            updated = updated.replace(edit["old_text"], edit["new_text"], 1)
            applied.append({"index": original_index, "old_text": edit["old_text"]})
        try:
            filesystem.write_bytes(path, updated.encode("utf-8"))
            after = filesystem.snapshot_file(path)
        except Exception:
            before.cleanup()
            raise
        value = json.dumps({
            "path": str(filesystem.root / relative),
            "applied": len(applied),
            "failed": [],
            "message": "All edits applied.",
        }, ensure_ascii=False)
    return WorkspaceMutation(
        value,
        lambda: _rollback_file(root, path, before, after),
        before.cleanup,
    )


def _workspace_copy_sync(
    root: Path, recovery_root: Path, source: str, destination: str
) -> object:
    from khaos.coding.workspace.boundary import SafeWorkspaceFS
    from khaos.coding.workspace.storage import WorkspaceMutation

    with SafeWorkspaceFS(root) as filesystem:
        source_relative = filesystem.relative(source)
        destination_relative = filesystem.relative(destination)
        before = filesystem.snapshot_file(
            destination, recovery_root=recovery_root
        )
        try:
            size = filesystem.copy_file(source, destination)
            after = filesystem.snapshot_file(destination)
        except Exception:
            before.cleanup()
            raise
        value = {
            "ok": True,
            "src": str(filesystem.root / source_relative),
            "dst": str(filesystem.root / destination_relative),
            "size_bytes": size,
        }
    return WorkspaceMutation(
        value,
        lambda: _rollback_file(root, destination, before, after),
        before.cleanup,
    )


def _workspace_move_sync(
    root: Path, source: str, destination: str
) -> object:
    from khaos.coding.workspace.boundary import SafeWorkspaceFS
    from khaos.coding.workspace.storage import WorkspaceMutation

    with SafeWorkspaceFS(root) as filesystem:
        source_relative = filesystem.relative(source)
        destination_relative = filesystem.relative(destination)
        source_before = filesystem.snapshot_file(source)
        destination_before = filesystem.snapshot_file(destination)
        filesystem.move_file(source, destination)
        destination_after = filesystem.snapshot_file(destination)
        value = {
            "ok": True,
            "src": str(filesystem.root / source_relative),
            "dst": str(filesystem.root / destination_relative),
        }
    return WorkspaceMutation(
        value,
        lambda: _rollback_move(
            root,
            source,
            destination,
            source_before,
            destination_before,
            destination_after,
        ),
    )


def _rollback_file(root: Path, path: str, before, after) -> None:
    from khaos.coding.workspace.boundary import (
        SafeWorkspaceFS,
        WorkspaceBoundaryError,
    )

    with SafeWorkspaceFS(root) as filesystem:
        current = filesystem.snapshot_file(path)
        if current != after:
            raise WorkspaceBoundaryError("rollback target changed concurrently")
        if before.exists:
            filesystem.restore_file(path, before, expected=after)
        else:
            filesystem.delete_file(path, expected=after)


def _rollback_move(
    root: Path,
    source: str,
    destination: str,
    source_before,
    destination_before,
    destination_after,
) -> None:
    from khaos.coding.workspace.boundary import (
        SafeWorkspaceFS,
        WorkspaceBoundaryError,
    )

    with SafeWorkspaceFS(root) as filesystem:
        if destination_before.exists:
            raise WorkspaceBoundaryError("move rollback destination was not empty")
        if filesystem.snapshot_file(source).exists:
            raise WorkspaceBoundaryError("move rollback source reappeared")
        if filesystem.snapshot_file(destination) != destination_after:
            raise WorkspaceBoundaryError("move rollback target changed concurrently")
        filesystem.move_file(destination, source)
        restored = filesystem.snapshot_file(source)
        if restored.digest != source_before.digest:
            raise WorkspaceBoundaryError("move rollback content mismatch")


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
