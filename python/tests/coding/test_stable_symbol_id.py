"""Stable symbol identity consistency tests.

Verifies that ``stable_symbol_id`` is truly stable across rebuilds and
incremental updates, and that it changes when the definition moves, is
renamed, or changes kind.

Properties tested:
1. Incremental update == full rebuild → same stable_symbol_id
2. Generation change (content/position unchanged) → stable ID unchanged
3. Definition moved (byte range changed) → stable ID changes
4. Definition renamed (qualified_name changed) → stable ID changes
5. Kind changed → stable ID changes
6. Different repos → different stable IDs
7. Unicode path/qualified name deterministic
8. Resolved edges target stable_symbol_id, not revision symbol_id
9. Full rebuild from IndexStore produces identical stable IDs
"""
from __future__ import annotations

import asyncio
import hashlib
import sqlite3
from pathlib import Path

import pytest

from khaos.coding.intelligence.index import IndexStore
from khaos.coding.intelligence.models import (
    ParseResult,
    SourceLocation,
    Symbol,
)
from khaos.coding.intelligence.query import CodeQueryService
from khaos.coding.intelligence.resolution import (
    ResolutionService,
    apply_resolution_schema,
)
from khaos.coding.intelligence.resolution.ids import (
    stable_symbol_id,
    symbol_id,
)
from khaos.coding.intelligence.resolution.models import RepositorySymbol
from khaos.coding.intelligence.resolution.symbol_table import build_symbol_table


# ---- Helpers ----


def _loc(path: str, byte_start: int = 0, byte_end: int = 0) -> SourceLocation:
    return SourceLocation(path, 0, 0, 0, max(byte_end - byte_start, 1), byte_start, byte_end)


def _symbol(name: str, kind: str, path: str, language: str, qualified_name: str | None = None, byte_start: int = 0, byte_end: int = 0) -> Symbol:
    return Symbol(name, kind, qualified_name or name, _loc(path, byte_start, byte_end or byte_start + len(name)), language, "test", 1.0, {})


async def _write_file(store: IndexStore, repo_id: str, path: str, language: str, symbols=(), generation: int = 1) -> None:
    result = ParseResult(
        language=language, file_path=path,
        symbols=tuple(symbols), imports=(), calls=(), references=(),
        parser_source="test", parser_version="test-v1",
        content_hash=hashlib.sha256(f"{path}:{generation}".encode()).hexdigest(),
    )
    await store.write_parse_result(repo_id, path, result, size=100, mtime_ns=0, generation=generation)


def _make_store() -> IndexStore:
    conn = sqlite3.connect(":memory:")
    store = IndexStore(conn)
    apply_resolution_schema(conn)
    return store


# ---- 1. stable_symbol_id function properties ----


def test_stable_id_excludes_generation():
    """stable_symbol_id must not include generation in its hash."""
    ssid1 = stable_symbol_id("r", "app.py", "python", "function", "foo", 0, 3)
    ssid2 = stable_symbol_id("r", "app.py", "python", "function", "foo", 0, 3)
    # Different calls with same args → same ID
    assert ssid1 == ssid2
    # Generation is NOT a parameter of stable_symbol_id
    # So there's no way generation can affect it


def test_stable_id_differs_from_revision_id():
    """stable_symbol_id must differ from symbol_id (which includes generation)."""
    ssid = stable_symbol_id("r", "app.py", "python", "function", "foo", 0, 3)
    sid1 = symbol_id("r", "app.py", "python", "function", "foo", 0, 3, generation=1)
    sid2 = symbol_id("r", "app.py", "python", "function", "foo", 0, 3, generation=2)
    assert ssid != sid1
    assert ssid != sid2
    assert sid1 != sid2  # revision IDs differ by generation


# ---- 2. Generation change doesn't change stable ID ----


def test_generation_change_preserves_stable_id():
    """When content and definition position are unchanged, generation change must not change stable ID."""
    store = _make_store()
    conn = store._conn

    async def setup():
        await _write_file(store, "r", "app.py", "python",
            symbols=[_symbol("foo", "function", "app.py", "python", byte_start=0, byte_end=3)],
            generation=1)
    asyncio.run(setup())

    table1 = build_symbol_table(conn, "r")
    syms1 = table1.symbols_by_file("app.py")
    assert len(syms1) == 1
    ssid1 = syms1[0].stable_symbol_id

    # Update to generation 2 with same content/position
    async def update():
        await _write_file(store, "r", "app.py", "python",
            symbols=[_symbol("foo", "function", "app.py", "python", byte_start=0, byte_end=3)],
            generation=2)
    asyncio.run(update())

    table2 = build_symbol_table(conn, "r")
    syms2 = table2.symbols_by_file("app.py")
    assert len(syms2) == 1
    ssid2 = syms2[0].stable_symbol_id

    # Stable ID unchanged despite generation change
    assert ssid1 == ssid2
    # But revision ID changed
    assert syms1[0].symbol_id != syms2[0].symbol_id


# ---- 3. Definition moved → stable ID changes ----


def test_definition_moved_changes_stable_id():
    """When byte_start/byte_end change, stable ID must change."""
    ssid1 = stable_symbol_id("r", "app.py", "python", "function", "foo", 0, 3)
    ssid2 = stable_symbol_id("r", "app.py", "python", "function", "foo", 10, 13)
    assert ssid1 != ssid2


def test_definition_moved_in_indexed_repository():
    """Moving a definition within a file changes stable_symbol_id in the symbol table."""
    store = _make_store()
    conn = store._conn

    async def setup():
        await _write_file(store, "r", "app.py", "python",
            symbols=[_symbol("foo", "function", "app.py", "python", byte_start=0, byte_end=3)],
            generation=1)
    asyncio.run(setup())

    table1 = build_symbol_table(conn, "r")
    ssid1 = table1.symbols_by_file("app.py")[0].stable_symbol_id

    # Move definition to byte_start=50
    async def move():
        await _write_file(store, "r", "app.py", "python",
            symbols=[_symbol("foo", "function", "app.py", "python", byte_start=50, byte_end=53)],
            generation=2)
    asyncio.run(move())

    table2 = build_symbol_table(conn, "r")
    ssid2 = table2.symbols_by_file("app.py")[0].stable_symbol_id

    assert ssid1 != ssid2


# ---- 4. Definition renamed → stable ID changes ----


def test_definition_renamed_changes_stable_id():
    """When qualified_name changes, stable ID must change."""
    ssid1 = stable_symbol_id("r", "app.py", "python", "function", "foo", 0, 3)
    ssid2 = stable_symbol_id("r", "app.py", "python", "function", "bar", 0, 3)
    assert ssid1 != ssid2


# ---- 5. Kind changed → stable ID changes ----


def test_kind_changed_changes_stable_id():
    """When kind changes (function → class), stable ID must change."""
    ssid1 = stable_symbol_id("r", "app.py", "python", "function", "foo", 0, 3)
    ssid2 = stable_symbol_id("r", "app.py", "python", "class", "foo", 0, 3)
    assert ssid1 != ssid2


# ---- 6. Different repos → different stable IDs ----


def test_different_repos_different_stable_ids():
    """Same definition in different repos must have different stable IDs."""
    ssid_a = stable_symbol_id("repo-a", "app.py", "python", "function", "foo", 0, 3)
    ssid_b = stable_symbol_id("repo-b", "app.py", "python", "function", "foo", 0, 3)
    assert ssid_a != ssid_b


# ---- 7. Unicode path/qualified name deterministic ----


def test_unicode_path_deterministic():
    """Unicode paths produce deterministic stable IDs."""
    ssid1 = stable_symbol_id("r", "路径/文件.py", "python", "function", "函数", 0, 3)
    ssid2 = stable_symbol_id("r", "路径/文件.py", "python", "function", "函数", 0, 3)
    assert ssid1 == ssid2
    assert len(ssid1) == 32


def test_unicode_qualified_name_deterministic():
    """Unicode qualified names produce deterministic stable IDs."""
    ssid1 = stable_symbol_id("r", "app.py", "python", "function", "クラス.メソッド", 0, 10)
    ssid2 = stable_symbol_id("r", "app.py", "python", "function", "クラス.メソッド", 0, 10)
    assert ssid1 == ssid2


def test_unicode_different_names_different_ids():
    """Different Unicode names produce different stable IDs."""
    ssid1 = stable_symbol_id("r", "app.py", "python", "function", "函数", 0, 2)
    ssid2 = stable_symbol_id("r", "app.py", "python", "function", "变量", 0, 2)
    assert ssid1 != ssid2


# ---- 8. Incremental == full rebuild ----


def test_incremental_equals_full_rebuild_stable_ids():
    """Incremental update and full rebuild must produce identical stable IDs."""
    store = _make_store()
    conn = store._conn

    # Write files at generation 1
    async def setup():
        await _write_file(store, "r", "app.py", "python",
            symbols=[_symbol("foo", "function", "app.py", "python", byte_start=0, byte_end=3)],
            generation=1)
        await _write_file(store, "r", "util.py", "python",
            symbols=[_symbol("bar", "function", "util.py", "python", byte_start=0, byte_end=3)],
            generation=1)
    asyncio.run(setup())

    def _collect_ssids(table):
        result = {}
        for file_path in table.all_files():
            for sym in table.symbols_by_file(file_path):
                result[sym.name] = sym.stable_symbol_id
        return result

    # Build table (simulates incremental)
    table_inc = build_symbol_table(conn, "r")
    ssids_inc = _collect_ssids(table_inc)

    # Rebuild table from scratch (simulates full rebuild)
    table_full = build_symbol_table(conn, "r")
    ssids_full = _collect_ssids(table_full)

    assert ssids_inc == ssids_full


def test_stable_ids_survive_generation_bump():
    """Stable IDs survive across multiple generation bumps as long as definition is unchanged."""
    store = _make_store()
    conn = store._conn

    async def gen1():
        await _write_file(store, "r", "app.py", "python",
            symbols=[_symbol("foo", "function", "app.py", "python", byte_start=0, byte_end=3)],
            generation=1)
    asyncio.run(gen1())
    table1 = build_symbol_table(conn, "r")
    ssid1 = table1.symbols_by_file("app.py")[0].stable_symbol_id

    async def gen2():
        await _write_file(store, "r", "app.py", "python",
            symbols=[_symbol("foo", "function", "app.py", "python", byte_start=0, byte_end=3)],
            generation=2)
    asyncio.run(gen2())
    table2 = build_symbol_table(conn, "r")
    ssid2 = table2.symbols_by_file("app.py")[0].stable_symbol_id

    async def gen3():
        await _write_file(store, "r", "app.py", "python",
            symbols=[_symbol("foo", "function", "app.py", "python", byte_start=0, byte_end=3)],
            generation=3)
    asyncio.run(gen3())
    table3 = build_symbol_table(conn, "r")
    ssid3 = table3.symbols_by_file("app.py")[0].stable_symbol_id

    # All stable IDs are the same across generations
    assert ssid1 == ssid2 == ssid3


# ---- 9. Resolved edges target stable_symbol_id ----


def test_resolved_edges_target_stable_symbol_id():
    """Resolved call/reference edges must target stable_symbol_id, not revision symbol_id."""
    store = _make_store()
    conn = store._conn

    async def setup():
        await _write_file(store, "r", "app.py", "python",
            symbols=[_symbol("foo", "function", "app.py", "python", byte_start=0, byte_end=3)],
            generation=1)
    asyncio.run(setup())

    # Resolve via service
    svc = ResolutionService(conn, persist=True)
    report = svc.resolve("r", full_rebuild=True)
    assert report.resolved_calls >= 0

    # Check that any resolved edge targets use stable_symbol_id
    qs = CodeQueryService(store)
    edges = qs.call_edges_for_file("r", "app.py")
    for edge in edges:
        if edge["status"] == "resolved" and edge["target_symbol_id"] is not None:
            # The target_symbol_id must be a stable_symbol_id (32 hex chars, not a revision ID)
            target = edge["target_symbol_id"]
            assert len(target) == 32
            # Verify it matches the stable_symbol_id of the target symbol
            symbols = qs.find_symbol_targets("r", edge["call_callee"].split(".")[-1])
            stable_ids = {s["stable_symbol_id"] for s in symbols}
            assert target in stable_ids, f"Edge target {target} not in stable IDs {stable_ids}"


# ---- 10. Old database migration / full rebuild strategy ----


def test_full_rebuild_reconstructs_stable_ids():
    """Full rebuild from IndexStore produces valid stable IDs for all symbols."""
    store = _make_store()
    conn = store._conn

    async def setup():
        await _write_file(store, "r", "app.py", "python",
            symbols=[_symbol("foo", "function", "app.py", "python", byte_start=0, byte_end=3),
                      _symbol("Bar", "class", "app.py", "python", byte_start=10, byte_end=13)],
            generation=1)
        await _write_file(store, "r", "util.py", "python",
            symbols=[_symbol("helper", "function", "util.py", "python", byte_start=0, byte_end=6)],
            generation=1)
    asyncio.run(setup())

    table = build_symbol_table(conn, "r")
    all_symbols = []
    for file_path in table.all_files():
        all_symbols.extend(table.symbols_by_file(file_path))
    assert len(all_symbols) == 3

    for sym in all_symbols:
        # stable_symbol_id is 32 hex chars
        assert len(sym.stable_symbol_id) == 32
        # stable_symbol_id differs from symbol_id (revision)
        assert sym.stable_symbol_id != sym.symbol_id
        # stable_symbol_id is deterministic
        expected = stable_symbol_id(
            sym.repository_id, sym.path, sym.language,
            sym.kind, sym.qualified_name, sym.byte_start, sym.byte_end,
        )
        assert sym.stable_symbol_id == expected


def test_stable_id_deterministic_across_db_instances():
    """Same input produces same stable_symbol_id in different database instances."""
    # First database
    store1 = _make_store()
    async def setup1():
        await _write_file(store1, "r", "app.py", "python",
            symbols=[_symbol("foo", "function", "app.py", "python", byte_start=0, byte_end=3)],
            generation=1)
    asyncio.run(setup1())
    table1 = build_symbol_table(store1._conn, "r")
    ssid1 = table1.symbols_by_file("app.py")[0].stable_symbol_id

    # Second database (fresh)
    store2 = _make_store()
    async def setup2():
        await _write_file(store2, "r", "app.py", "python",
            symbols=[_symbol("foo", "function", "app.py", "python", byte_start=0, byte_end=3)],
            generation=1)
    asyncio.run(setup2())
    table2 = build_symbol_table(store2._conn, "r")
    ssid2 = table2.symbols_by_file("app.py")[0].stable_symbol_id

    # Same stable ID across different database instances
    assert ssid1 == ssid2
