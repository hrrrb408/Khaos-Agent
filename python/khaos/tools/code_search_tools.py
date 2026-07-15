"""Code search and lightweight symbol extraction tools."""

from __future__ import annotations

import ast
import asyncio
from pathlib import Path
from typing import Any


async def code_search(root: str = ".", query: str = "", glob: str = "*.py", limit: int = 100, workspace_manager=None, task_id: str | None = None, workspace_id: str | None = None) -> dict[str, Any]:
    """Search source files for a text query."""
    if workspace_manager is not None:
        workspace = workspace_manager.get(workspace_id or "")
        if workspace is None or workspace.task_id != task_id:
            raise PermissionError("coding search requires matching active TaskWorkspace")
        return await asyncio.to_thread(
            _safe_code_search_sync,
            workspace.worktree_path,
            root,
            query,
            glob,
            limit,
        )
    return await asyncio.to_thread(_code_search_sync, root, query, glob, limit)


async def code_symbols(path: str, workspace_manager=None, task_id: str | None = None, workspace_id: str | None = None) -> dict[str, Any]:
    """Extract Python class/function symbols with line numbers."""
    if workspace_manager is not None:
        workspace = workspace_manager.get(workspace_id or "")
        if workspace is None or workspace.task_id != task_id:
            raise PermissionError("coding symbols require matching active TaskWorkspace")
        return await asyncio.to_thread(
            _safe_code_symbols_sync, workspace.worktree_path, path
        )
    return await asyncio.to_thread(_code_symbols_sync, path)


def _safe_code_search_sync(
    workspace_root: Path, root: str, query: str, glob: str, limit: int
) -> dict[str, Any]:
    from fnmatch import fnmatch
    from khaos.coding.workspace.boundary import SafeWorkspaceFS

    with SafeWorkspaceFS(workspace_root) as filesystem:
        base = filesystem._directory_relative(root)
        matches: list[dict[str, Any]] = []
        for relative in filesystem.iter_files(root):
            display = relative[len(base) + 1:] if base else relative
            if not fnmatch(display, glob):
                continue
            try:
                lines = filesystem.read_bytes(relative).decode("utf-8").splitlines()
            except UnicodeDecodeError:
                continue
            for line_no, line in enumerate(lines, start=1):
                if query in line:
                    matches.append({
                        "path": str(filesystem.root / relative),
                        "line": line_no,
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


def _safe_code_symbols_sync(workspace_root: Path, path: str) -> dict[str, Any]:
    from khaos.coding.workspace.boundary import SafeWorkspaceFS

    with SafeWorkspaceFS(workspace_root) as filesystem:
        relative = filesystem.relative(path)
        tree = ast.parse(filesystem.read_bytes(path).decode("utf-8"))
        symbols = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                symbols.append({
                    "name": node.name,
                    "kind": type(node).__name__,
                    "line": node.lineno,
                })
        symbols.sort(key=lambda item: item["line"])
        return {"path": str(filesystem.root / relative), "symbols": symbols}


def _code_search_sync(root: str, query: str, glob: str, limit: int) -> dict[str, Any]:
    root_path = Path(root).expanduser().resolve()
    matches = []
    for file_path in sorted(root_path.rglob(glob)):
        if not file_path.is_file():
            continue
        try:
            lines = file_path.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError:
            continue
        for line_no, line in enumerate(lines, start=1):
            if query in line:
                matches.append({"path": str(file_path), "line": line_no, "text": line})
                break
        if len(matches) >= limit:
            break
    return {"root": str(root_path), "matches": matches, "count": len(matches)}


def _code_symbols_sync(path: str) -> dict[str, Any]:
    file_path = Path(path).expanduser().resolve()
    tree = ast.parse(file_path.read_text(encoding="utf-8"))
    symbols = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            symbols.append({"name": node.name, "kind": type(node).__name__, "line": node.lineno})
    symbols.sort(key=lambda item: item["line"])
    return {"path": str(file_path), "symbols": symbols}
