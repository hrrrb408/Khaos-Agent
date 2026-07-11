"""Repository-level symbol table built from IndexStore persisted data.

Provides multi-index lookup for cross-file resolution:
  file → symbols, name → symbols, qualified_name → symbols,
  language/kind/name → symbols, module identity → file,
  file → imports, target file → reverse dependents.

Does not read ParseState, native Tree, or source code body.
"""
from __future__ import annotations

import json
import sqlite3
from collections import defaultdict
from pathlib import PurePosixPath
from typing import Any

from khaos.coding.intelligence.resolution.ids import symbol_id
from khaos.coding.intelligence.resolution.models import RepositorySymbol


class RepositorySymbolTable:
    """In-memory multi-index over repository symbols and imports."""

    def __init__(self, repository_id: str) -> None:
        self.repository_id = repository_id
        self._file_symbols: dict[str, list[RepositorySymbol]] = defaultdict(list)
        self._name_symbols: dict[str, list[RepositorySymbol]] = defaultdict(list)
        self._qualified_symbols: dict[str, list[RepositorySymbol]] = defaultdict(list)
        self._lang_kind_name: dict[tuple[str, str, str], list[RepositorySymbol]] = defaultdict(list)
        self._module_to_file: dict[str, str] = {}
        self._file_imports: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self._reverse_deps: dict[str, set[str]] = defaultdict(set)
        self._file_generations: dict[str, int] = {}
        self._file_languages: dict[str, str] = {}
        self._indexed_paths: set[str] = set()

    def add_file(self, path: str, language: str, generation: int) -> None:
        self._file_generations[path] = generation
        self._file_languages[path] = language
        self._indexed_paths.add(path)
        if language == "python":
            module = _python_module_identity(path)
            if module:
                self._module_to_file[module] = path
        elif language == "go":
            pass  # module mapping needs go.mod, handled by Go resolver
        elif language == "rust":
            module = _rust_module_identity(path)
            if module:
                self._module_to_file[module] = path

    def add_symbol(self, path: str, language: str, generation: int, name: str, kind: str, qualified_name: str, byte_start: int, byte_end: int, start_line: int) -> RepositorySymbol:
        sid = symbol_id(self.repository_id, path, language, kind, qualified_name, byte_start, byte_end, generation)
        sym = RepositorySymbol(sid, self.repository_id, path, language, kind, name, qualified_name, byte_start, byte_end, start_line, generation)
        self._file_symbols[path].append(sym)
        self._name_symbols[name].append(sym)
        self._qualified_symbols[qualified_name].append(sym)
        self._lang_kind_name[(language, kind, name)].append(sym)
        return sym

    def add_import(self, path: str, import_data: dict[str, Any]) -> None:
        self._file_imports[path].append(import_data)

    def register_reverse_dep(self, source_file: str, target_file: str) -> None:
        self._reverse_deps[target_file].add(source_file)

    def symbols_by_file(self, path: str) -> list[RepositorySymbol]:
        return list(self._file_symbols.get(path, ()))

    def symbols_by_name(self, name: str) -> list[RepositorySymbol]:
        return list(self._name_symbols.get(name, ()))

    def symbols_by_qualified_name(self, qualified_name: str) -> list[RepositorySymbol]:
        return list(self._qualified_symbols.get(qualified_name, ()))

    def symbols_by_lang_kind_name(self, language: str, kind: str, name: str) -> list[RepositorySymbol]:
        return list(self._lang_kind_name.get((language, kind, name), ()))

    def file_imports(self, path: str) -> list[dict[str, Any]]:
        return list(self._file_imports.get(path, ()))

    def file_generation(self, path: str) -> int:
        return self._file_generations.get(path, 0)

    def file_language(self, path: str) -> str | None:
        return self._file_languages.get(path)

    def module_to_file(self, module: str) -> str | None:
        return self._module_to_file.get(module)

    def reverse_deps(self, path: str) -> set[str]:
        return set(self._reverse_deps.get(path, set()))

    def indexed_paths(self) -> set[str]:
        return set(self._indexed_paths)

    def has_file(self, path: str) -> bool:
        return path in self._indexed_paths

    def remove_file(self, path: str) -> None:
        """Remove a file and its symbols from the table."""
        for sym in self._file_symbols.pop(path, ()):
            self._name_symbols.get(sym.name, []).remove(sym) if sym in self._name_symbols.get(sym.name, []) else None
            self._qualified_symbols.get(sym.qualified_name, []).remove(sym) if sym in self._qualified_symbols.get(sym.qualified_name, []) else None
            key = (sym.language, sym.kind, sym.name)
            if sym in self._lang_kind_name.get(key, []):
                self._lang_kind_name[key].remove(sym)
        self._file_imports.pop(path, None)
        self._file_generations.pop(path, None)
        self._file_languages.pop(path, None)
        self._indexed_paths.discard(path)
        # Remove module mappings pointing to this file
        self._module_to_file = {k: v for k, v in self._module_to_file.items() if v != path}
        self._reverse_deps.pop(path, None)

    def all_files(self) -> list[str]:
        return sorted(self._indexed_paths)

    def symbol_count(self) -> int:
        return sum(len(syms) for syms in self._file_symbols.values())

    def reverse_dep_closure(self, paths: set[str], *, max_depth: int = 64) -> set[str]:
        """Compute transitive closure of reverse dependents, with cycle termination."""
        result: set[str] = set()
        queue = list(paths)
        depth = 0
        while queue and depth < max_depth:
            next_queue: list[str] = []
            for path in queue:
                if path in result:
                    continue
                result.add(path)
                next_queue.extend(self._reverse_deps.get(path, set()))
            queue = [p for p in next_queue if p not in result]
            depth += 1
        return result


def build_symbol_table(conn: sqlite3.Connection, repository_id: str) -> RepositorySymbolTable:
    """Build a complete symbol table from IndexStore persisted data."""
    table = RepositorySymbolTable(repository_id)
    # Load file records
    for row in conn.execute("SELECT path, language, generation FROM code_files WHERE project_id=? ORDER BY path", (repository_id,)):
        table.add_file(row["path"] if isinstance(row, sqlite3.Row) else row[0],
                       row["language"] if isinstance(row, sqlite3.Row) else row[1],
                       row["generation"] if isinstance(row, sqlite3.Row) else row[2])
    # Load symbols
    for row in conn.execute("SELECT path, name, kind, line, payload_json FROM code_symbols WHERE project_id=? ORDER BY path, line", (repository_id,)):
        path = row["path"] if isinstance(row, sqlite3.Row) else row[0]
        name = row["name"] if isinstance(row, sqlite3.Row) else row[1]
        kind = row["kind"] if isinstance(row, sqlite3.Row) else row[2]
        line = row["line"] if isinstance(row, sqlite3.Row) else row[3]
        payload = json.loads(row["payload_json"] if isinstance(row, sqlite3.Row) else row[4])
        language = payload.get("language", "unknown")
        qualified_name = payload.get("qualified_name", name)
        location = payload.get("location", {})
        byte_start = location.get("byte_start", 0)
        byte_end = location.get("byte_end", 0)
        generation = table.file_generation(path)
        table.add_symbol(path, language, generation, name, kind, qualified_name, byte_start, byte_end, line - 1)
    # Load imports
    for row in conn.execute("SELECT path, import_name, payload_json FROM code_imports WHERE project_id=? ORDER BY path, import_name", (repository_id,)):
        path = row["path"] if isinstance(row, sqlite3.Row) else row[0]
        payload = json.loads(row["payload_json"] if isinstance(row, sqlite3.Row) else row[2])
        table.add_import(path, payload)
    return table


def _python_module_identity(path: str) -> str | None:
    """Map a Python file path to its module identity (e.g. 'a/b/c.py' → 'a.b.c')."""
    if not path.endswith(".py"):
        return None
    parts = PurePosixPath(path).with_suffix("").parts
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    if not parts:
        return None
    return ".".join(parts)


def _rust_module_identity(path: str) -> str | None:
    """Map a Rust file path to its module identity (e.g. 'src/a/b.rs' → 'a::b')."""
    if not path.endswith(".rs"):
        return None
    parts = PurePosixPath(path).with_suffix("").parts
    # Strip common root directories
    while parts and parts[0] in ("src", "source"):
        parts = parts[1:]
    if parts and parts[-1] == "mod":
        parts = parts[:-1]
    if not parts:
        return None
    return "::".join(parts)


def python_file_to_module(path: str) -> str | None:
    return _python_module_identity(path)


def rust_file_to_module(path: str) -> str | None:
    return _rust_module_identity(path)
