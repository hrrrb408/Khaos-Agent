"""Code search and lightweight symbol extraction tools."""

from __future__ import annotations

import ast
import asyncio
from pathlib import Path
from typing import Any


async def code_search(root: str = ".", query: str = "", glob: str = "*.py", limit: int = 100) -> dict[str, Any]:
    """Search source files for a text query."""
    return await asyncio.to_thread(_code_search_sync, root, query, glob, limit)


async def code_symbols(path: str) -> dict[str, Any]:
    """Extract Python class/function symbols with line numbers."""
    return await asyncio.to_thread(_code_symbols_sync, path)


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

