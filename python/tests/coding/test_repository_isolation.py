"""Cross-repository isolation tests for semantic graph edges.

Verifies that call/reference/import edges from different repositories
can coexist in the same database without collision, and that queries
are properly scoped by repository_id.

Covers:
1. Two repos with same file/byte range produce distinct edge IDs
2. Both edges coexist in the database
3. Querying one repo does not return the other's data
4. Reference edges are isolated the same way
5. Deleting one repo's data does not affect the other
"""
from __future__ import annotations

import asyncio
import hashlib
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from khaos.coding.intelligence.index import IndexStore
from khaos.coding.intelligence.models import (
    CallCandidate,
    ImportReference,
    ParseResult,
    ReferenceCandidate,
    SourceLocation,
    Symbol,
)
from khaos.coding.intelligence.query import CodeQueryService
from khaos.coding.intelligence.resolution import (
    ResolutionService,
    apply_resolution_schema,
)
from khaos.coding.intelligence.resolution.ids import (
    call_edge_id,
    reference_edge_id,
    stable_symbol_id,
    symbol_id,
)
from khaos.coding.intelligence.resolution.persistence import (
    commit_file_resolution,
    remove_file_resolution,
    resolution_counts,
)
from khaos.coding.intelligence.resolution.models import (
    FileResolutionResult,
    RepositorySymbol,
    ResolutionStatus,
    ResolvedCallEdge,
    ResolvedImport,
    ResolvedReferenceEdge,
)


# ---- Helpers ----


def _loc(file_path: str, line: int = 0, col: int = 0, byte_start: int = 0, byte_end: int = 0) -> SourceLocation:
    return SourceLocation(file_path, line, col, line, col + max(byte_end - byte_start, 1), byte_start, byte_end)


def _symbol(name: str, kind: str, path: str, language: str, qualified_name: str | None = None, byte_start: int = 0, byte_end: int = 0) -> Symbol:
    return Symbol(name, kind, qualified_name or name, _loc(path, 0, 0, byte_start, byte_end or byte_start + len(name)), language, "test", 1.0, {})


def _repo_symbol(repo_id: str, name: str, path: str, language: str, byte_start: int = 0, byte_end: int = 0, generation: int = 1) -> RepositorySymbol:
    b_end = byte_end or byte_start + len(name)
    sid = symbol_id(repo_id, path, language, "function", name, byte_start, b_end, generation)
    ssid = stable_symbol_id(repo_id, path, language, "function", name, byte_start, b_end)
    return RepositorySymbol(
        symbol_id=sid,
        stable_symbol_id=ssid,
        repository_id=repo_id,
        path=path,
        language=language,
        kind="function",
        name=name,
        qualified_name=name,
        byte_start=byte_start,
        byte_end=b_end,
        start_line=0,
        generation=generation,
    )


def _call_edge(repo_id: str, callee: str, source_file: str, byte_start: int = 10, byte_end: int = 14, generation: int = 1, target_symbol_id: str | None = None, target_file: str | None = None, status: ResolutionStatus = ResolutionStatus.RESOLVED) -> ResolvedCallEdge:
    eid = call_edge_id(repo_id, source_file, callee, byte_start, byte_end, generation)
    return ResolvedCallEdge(
        edge_id=eid,
        source_file=source_file,
        caller_symbol_id=None,
        call_callee=callee,
        status=status,
        target_symbol_id=target_symbol_id,
        target_file=target_file,
        confidence=1.0,
        resolution_rule="same-file-unique-function",
        ambiguity_reason=None,
        metadata={},
    )


def _ref_edge(repo_id: str, name: str, source_file: str, byte_start: int = 20, byte_end: int = 24, generation: int = 1, target_symbol_id: str | None = None, target_file: str | None = None, status: ResolutionStatus = ResolutionStatus.RESOLVED) -> ResolvedReferenceEdge:
    eid = reference_edge_id(repo_id, source_file, name, "read", byte_start, byte_end, generation)
    return ResolvedReferenceEdge(
        edge_id=eid,
        source_file=source_file,
        name=name,
        reference_kind="read",
        status=status,
        target_symbol_id=target_symbol_id,
        target_file=target_file,
        confidence=1.0,
        resolution_rule="same-file-unique-symbol",
        metadata={},
    )


def _file_result(repo_id: str, file_path: str, symbols=(), calls=(), refs=(), generation: int = 1) -> FileResolutionResult:
    return FileResolutionResult(
        source_file=file_path,
        generation=generation,
        symbols=tuple(symbols),
        resolved_imports=(),
        resolved_calls=tuple(calls),
        resolved_references=tuple(refs),
        diagnostics=(),
    )


def _make_store() -> IndexStore:
    conn = sqlite3.connect(":memory:")
    store = IndexStore(conn)
    apply_resolution_schema(conn)
    return store


def _seed_code_file(store: IndexStore, repo_id: str, path: str, generation: int = 1) -> None:
    """Insert a minimal code_files row so CAS can verify generation."""
    conn = store._conn
    conn.execute(
        "INSERT OR REPLACE INTO code_files VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (repo_id, path, "python", 100, 0, "abc", "test", "test", "{}", 0, generation, "source", "", "", ""),
    )
    conn.commit()


# ---- Tests ----


def test_distinct_edge_ids_for_same_file_in_different_repos():
    """Repo A and Repo B both have app.py:10's foo(). Edge IDs must differ."""
    eid_a = call_edge_id("repo-a", "app.py", "foo", 10, 14, 1)
    eid_b = call_edge_id("repo-b", "app.py", "foo", 10, 14, 1)
    assert eid_a != eid_b
    assert len(eid_a) == 32
    assert len(eid_b) == 32


def test_distinct_reference_edge_ids_for_different_repos():
    """Reference edge IDs are also scoped by repository."""
    eid_a = reference_edge_id("repo-a", "app.py", "value", "read", 20, 25, 1)
    eid_b = reference_edge_id("repo-b", "app.py", "value", "read", 20, 25, 1)
    assert eid_a != eid_b


def test_two_repos_same_file_coexist_in_database():
    """Both call edges can exist simultaneously in the same database."""
    store = _make_store()
    conn = store._conn
    _seed_code_file(store, "repo-a", "app.py")
    _seed_code_file(store, "repo-b", "app.py")

    sym_a = _repo_symbol("repo-a", "foo", "app.py", "python")
    sym_b = _repo_symbol("repo-b", "foo", "app.py", "python")
    edge_a = _call_edge("repo-a", "foo", "app.py", target_symbol_id=sym_a.stable_symbol_id, target_file="app.py")
    edge_b = _call_edge("repo-b", "foo", "app.py", target_symbol_id=sym_b.stable_symbol_id, target_file="app.py")

    assert commit_file_resolution(conn, "repo-a", _file_result("repo-a", "app.py", symbols=[sym_a], calls=[edge_a])) is None
    assert commit_file_resolution(conn, "repo-b", _file_result("repo-b", "app.py", symbols=[sym_b], calls=[edge_b])) is None

    qs = CodeQueryService(store)
    edges_a = qs.call_edges_for_file("repo-a", "app.py")
    edges_b = qs.call_edges_for_file("repo-b", "app.py")
    assert len(edges_a) == 1
    assert len(edges_b) == 1
    assert edges_a[0]["edge_id"] != edges_b[0]["edge_id"]
    assert edges_a[0]["repository_id"] == "repo-a"
    assert edges_b[0]["repository_id"] == "repo-b"


def test_querying_repo_a_does_not_return_repo_b_data():
    """Querying Repo A's symbols/edges must not return Repo B's data."""
    store = _make_store()
    conn = store._conn
    _seed_code_file(store, "repo-a", "app.py")
    _seed_code_file(store, "repo-b", "app.py")

    sym_a = _repo_symbol("repo-a", "foo", "app.py", "python")
    sym_b = _repo_symbol("repo-b", "foo", "app.py", "python")
    edge_a = _call_edge("repo-a", "foo", "app.py", target_symbol_id=sym_a.stable_symbol_id, target_file="app.py")
    edge_b = _call_edge("repo-b", "foo", "app.py", target_symbol_id=sym_b.stable_symbol_id, target_file="app.py")

    commit_file_resolution(conn, "repo-a", _file_result("repo-a", "app.py", symbols=[sym_a], calls=[edge_a]))
    commit_file_resolution(conn, "repo-b", _file_result("repo-b", "app.py", symbols=[sym_b], calls=[edge_b]))

    qs = CodeQueryService(store)
    # Symbol query
    symbols_a = qs.find_symbol_targets("repo-a", "foo")
    symbols_b = qs.find_symbol_targets("repo-b", "foo")
    assert len(symbols_a) == 1
    assert len(symbols_b) == 1
    assert symbols_a[0]["repository_id"] == "repo-a"
    assert symbols_b[0]["repository_id"] == "repo-b"
    assert symbols_a[0]["stable_symbol_id"] != symbols_b[0]["stable_symbol_id"]

    # Callers of the symbol
    callers_a = qs.callers_of("repo-a", sym_a.stable_symbol_id)
    callers_b = qs.callers_of("repo-b", sym_b.stable_symbol_id)
    assert len(callers_a) == 1
    assert len(callers_b) == 1
    assert callers_a[0]["repository_id"] == "repo-a"
    assert callers_b[0]["repository_id"] == "repo-b"

    # Cross-query: querying repo-a with repo-b's symbol_id should return nothing
    cross = qs.callers_of("repo-a", sym_b.stable_symbol_id)
    assert len(cross) == 0


def test_reference_edges_are_isolated():
    """Reference edges are scoped by repository_id."""
    store = _make_store()
    conn = store._conn
    _seed_code_file(store, "repo-a", "app.py")
    _seed_code_file(store, "repo-b", "app.py")

    sym_a = _repo_symbol("repo-a", "value", "app.py", "python")
    sym_b = _repo_symbol("repo-b", "value", "app.py", "python")
    ref_a = _ref_edge("repo-a", "value", "app.py", target_symbol_id=sym_a.stable_symbol_id, target_file="app.py")
    ref_b = _ref_edge("repo-b", "value", "app.py", target_symbol_id=sym_b.stable_symbol_id, target_file="app.py")

    commit_file_resolution(conn, "repo-a", _file_result("repo-a", "app.py", symbols=[sym_a], refs=[ref_a]))
    commit_file_resolution(conn, "repo-b", _file_result("repo-b", "app.py", symbols=[sym_b], refs=[ref_b]))

    qs = CodeQueryService(store)
    refs_a = qs.reference_edges_for_file("repo-a", "app.py")
    refs_b = qs.reference_edges_for_file("repo-b", "app.py")
    assert len(refs_a) == 1
    assert len(refs_b) == 1
    assert refs_a[0]["edge_id"] != refs_b[0]["edge_id"]
    assert refs_a[0]["repository_id"] == "repo-a"

    # References to symbol
    refs_to_a = qs.references_to("repo-a", sym_a.stable_symbol_id)
    refs_to_b = qs.references_to("repo-b", sym_b.stable_symbol_id)
    assert len(refs_to_a) == 1
    assert len(refs_to_b) == 1
    assert refs_to_a[0]["repository_id"] == "repo-a"


def test_deleting_repo_a_does_not_affect_repo_b():
    """Removing Repo A's file resolution must not affect Repo B's data."""
    store = _make_store()
    conn = store._conn
    _seed_code_file(store, "repo-a", "app.py")
    _seed_code_file(store, "repo-b", "app.py")

    sym_a = _repo_symbol("repo-a", "foo", "app.py", "python")
    sym_b = _repo_symbol("repo-b", "foo", "app.py", "python")
    edge_a = _call_edge("repo-a", "foo", "app.py", target_symbol_id=sym_a.stable_symbol_id, target_file="app.py")
    edge_b = _call_edge("repo-b", "foo", "app.py", target_symbol_id=sym_b.stable_symbol_id, target_file="app.py")

    commit_file_resolution(conn, "repo-a", _file_result("repo-a", "app.py", symbols=[sym_a], calls=[edge_a]))
    commit_file_resolution(conn, "repo-b", _file_result("repo-b", "app.py", symbols=[sym_b], calls=[edge_b]))

    # Delete repo-a's resolution
    remove_file_resolution(conn, "repo-a", "app.py")

    qs = CodeQueryService(store)
    # Repo A is gone
    assert len(qs.call_edges_for_file("repo-a", "app.py")) == 0
    assert len(qs.find_symbol_targets("repo-a", "foo")) == 0
    # Repo B is intact
    assert len(qs.call_edges_for_file("repo-b", "app.py")) == 1
    assert len(qs.find_symbol_targets("repo-b", "foo")) == 1
    assert qs.call_edges_for_file("repo-b", "app.py")[0]["repository_id"] == "repo-b"


def test_resolution_counts_are_scoped():
    """resolution_counts only counts edges for the specified repository."""
    store = _make_store()
    conn = store._conn
    _seed_code_file(store, "repo-a", "app.py")
    _seed_code_file(store, "repo-b", "app.py")

    sym_a = _repo_symbol("repo-a", "foo", "app.py", "python")
    sym_b = _repo_symbol("repo-b", "foo", "app.py", "python")
    edge_a = _call_edge("repo-a", "foo", "app.py", target_symbol_id=sym_a.stable_symbol_id, target_file="app.py")
    edge_b = _call_edge("repo-b", "foo", "app.py", target_symbol_id=sym_b.stable_symbol_id, target_file="app.py")

    commit_file_resolution(conn, "repo-a", _file_result("repo-a", "app.py", symbols=[sym_a], calls=[edge_a]))
    commit_file_resolution(conn, "repo-b", _file_result("repo-b", "app.py", symbols=[sym_b], calls=[edge_b]))

    counts_a = resolution_counts(conn, "repo-a")
    counts_b = resolution_counts(conn, "repo-b")
    assert counts_a["symbols"] == 1
    assert counts_a["call_edges"] == 1
    assert counts_b["symbols"] == 1
    assert counts_b["call_edges"] == 1


def test_composite_primary_key_includes_repository_id():
    """The database schema must have repository_id in the primary key."""
    store = _make_store()
    conn = store._conn

    for table in ("resolved_call_edges", "resolved_reference_edges"):
        pk_cols = {row[1] for row in conn.execute(f"PRAGMA table_info({table})") if row[5]}
        assert "repository_id" in pk_cols, f"{table} primary key must include repository_id"
        assert "edge_id" in pk_cols, f"{table} primary key must include edge_id"

    pk_symbols = {row[1] for row in conn.execute("PRAGMA table_info(repository_symbols)") if row[5]}
    assert "repository_id" in pk_symbols
    assert "symbol_id" in pk_symbols


def test_duplicate_edge_id_in_same_repo_rejected():
    """Inserting the same edge_id twice in the same repo must fail."""
    store = _make_store()
    conn = store._conn
    _seed_code_file(store, "repo-a", "app.py")

    sym = _repo_symbol("repo-a", "foo", "app.py", "python")
    edge = _call_edge("repo-a", "foo", "app.py", target_symbol_id=sym.stable_symbol_id, target_file="app.py")

    commit_file_resolution(conn, "repo-a", _file_result("repo-a", "app.py", symbols=[sym], calls=[edge]))

    # Manually try to insert the same edge_id again
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO resolved_call_edges VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (edge.edge_id, "repo-a", "app.py", None, "foo", "resolved",
             sym.stable_symbol_id, "app.py", 1.0, "test", None, "{}", 1),
        )
