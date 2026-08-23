"""Deterministic, rebuildable CodeGraph derived index for coding memory.

The graph stores repository structure separately from the canonical memory
ledger.  It is safe to delete and rebuild from the workspace; it never grants
authority to repository text and every model-facing hit still passes through
the MemoryBroker's late filtering gates.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections import deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from khaos.coding.parser import CodeParser, build_call_graph, build_dependency_graph
from khaos.memory.core.contracts import (
    MemoryHit,
    MemoryStatus,
    RuntimeMemoryContext,
    Sensitivity,
    SourceType,
    UsagePolicy,
)

logger = logging.getLogger(__name__)

_SUPPORTED_SUFFIXES = frozenset({".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".rs"})
_IGNORED_DIRS = frozenset({".git", ".venv", "node_modules", "__pycache__", ".pytest_cache", ".mypy_cache"})


@dataclass(frozen=True, slots=True)
class CodeGraphBuildReport:
    """Bounded result of one deterministic graph rebuild."""

    project_id: str
    repo_id: str
    commit_sha: str
    files: int
    nodes: int
    edges: int
    skipped_files: int
    duration_ms: int


@dataclass(frozen=True, slots=True)
class CodeGraphNode:
    """Portable graph node representation."""

    node_id: str
    project_id: str
    repo_id: str
    commit_sha: str
    path: str
    node_kind: str
    qualified_name: str
    display_name: str
    line_start: int
    line_end: int
    content_hash: str
    metadata: Mapping[str, Any]


class CodeGraphService:
    """Build and query a project-scoped CodeGraph using the shared DB owner."""

    provider_id = "khaos-codegraph"

    def __init__(
        self,
        db: Any,
        *,
        max_files: int = 20_000,
        max_file_bytes: int = 4 * 1024 * 1024,
    ) -> None:
        if max_files <= 0 or max_files > 100_000:
            raise ValueError("CodeGraph max_files must be between 1 and 100000")
        if max_file_bytes <= 0 or max_file_bytes > 16 * 1024 * 1024:
            raise ValueError("CodeGraph max_file_bytes is outside the bounded range")
        self._db = db
        self._max_files = max_files
        self._max_file_bytes = max_file_bytes
        self._parser = CodeParser()

    async def build(
        self,
        runtime: RuntimeMemoryContext,
        project_root: Path,
        *,
        repo_id: str | None = None,
        commit_sha: str | None = None,
    ) -> CodeGraphBuildReport:
        """Rebuild one repository snapshot atomically from local source files."""

        started = datetime.now(UTC)
        root = project_root.expanduser().resolve()
        if not root.is_dir():
            raise ValueError(f"CodeGraph root is not a directory: {root}")
        effective_repo = repo_id or runtime.repo_id or _repo_id(root)
        effective_commit = commit_sha or runtime.commit_sha or "working-tree"
        files = list(_iter_source_files(root, self._max_files))
        skipped = 0
        nodes: list[CodeGraphNode] = []
        path_nodes: dict[Path, str] = {}
        symbol_nodes: dict[str, list[str]] = {}
        for path in files:
            try:
                relative = path.relative_to(root).as_posix()
                if path.is_symlink() or path.stat().st_size > self._max_file_bytes:
                    skipped += 1
                    continue
                content = path.read_bytes()
            except (OSError, ValueError):
                skipped += 1
                continue
            file_node = _make_node(
                runtime.project_id,
                effective_repo,
                effective_commit,
                relative,
                "file",
                relative,
                path.name,
                1,
                max(1, content.count(b"\n") + 1),
                hashlib.sha256(content).hexdigest(),
                {"suffix": path.suffix.lower()},
            )
            nodes.append(file_node)
            path_nodes[path] = file_node.node_id
            try:
                symbols = self._parser.parse_symbols(path)
            except (OSError, SyntaxError, UnicodeDecodeError):
                symbols = []
            for symbol in symbols:
                name = str(symbol.get("name", ""))
                if not name:
                    continue
                symbol_node = _make_node(
                    runtime.project_id,
                    effective_repo,
                    effective_commit,
                    relative,
                    str(symbol.get("kind", "symbol")),
                    name,
                    name.rsplit(".", 1)[-1],
                    int(symbol.get("line", 1)),
                    int(symbol.get("line", 1)),
                    file_node.content_hash,
                    {"signature": str(symbol.get("signature", ""))},
                )
                nodes.append(symbol_node)
                symbol_nodes.setdefault(name, []).append(symbol_node.node_id)
                symbol_nodes.setdefault(symbol_node.display_name, []).append(symbol_node.node_id)

        edges: list[tuple[str, str, str, float, str]] = []
        dependency_graph = build_dependency_graph(root, files)
        for source, targets in dependency_graph.items():
            source_id = path_nodes.get(source)
            if source_id is None:
                continue
            for target in targets:
                target_id = path_nodes.get(target)
                if target_id is not None:
                    edges.append((source_id, target_id, "IMPORTS", 0.85, source.relative_to(root).as_posix()))

        call_graph = build_call_graph(root, files)
        callable_nodes: dict[str, list[str]] = {}
        for node in nodes:
            if node.node_kind in {"function", "async_function", "method", "async_method"}:
                callable_nodes.setdefault(node.qualified_name, []).append(node.node_id)
                callable_nodes.setdefault(node.display_name, []).append(node.node_id)
        for caller_name, callees in call_graph.items():
            caller_ids = callable_nodes.get(caller_name, ())
            if not caller_ids:
                continue
            for callee in callees:
                callee_ids = callable_nodes.get(callee, ()) or symbol_nodes.get(callee, ())
                for caller_id in caller_ids[:4]:
                    for callee_id in callee_ids[:4]:
                        if caller_id != callee_id:
                            edges.append((caller_id, callee_id, "CALLS", 0.65, caller_name))

        now = datetime.now(UTC).isoformat()
        async with self._db.transaction() as conn:
            await conn.execute(
                "DELETE FROM memory_code_edges WHERE project_id = ? AND repo_id = ? AND commit_sha = ?",
                (runtime.project_id, effective_repo, effective_commit),
            )
            await conn.execute(
                "DELETE FROM memory_code_nodes WHERE project_id = ? AND repo_id = ? AND commit_sha = ?",
                (runtime.project_id, effective_repo, effective_commit),
            )
            for node in nodes:
                await conn.execute(
                    "INSERT INTO memory_code_nodes ("
                    "node_id, project_id, repo_id, commit_sha, path, node_kind, "
                    "qualified_name, display_name, line_start, line_end, content_hash, "
                    "metadata_json, created_at, updated_at"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        node.node_id,
                        node.project_id,
                        node.repo_id,
                        node.commit_sha,
                        node.path,
                        node.node_kind,
                        node.qualified_name,
                        node.display_name,
                        node.line_start,
                        node.line_end,
                        node.content_hash,
                        json.dumps(node.metadata, ensure_ascii=False, sort_keys=True),
                        now,
                        now,
                    ),
                )
            seen_edges: set[tuple[str, str, str]] = set()
            for source_id, target_id, relation, confidence, source_ref in edges:
                key = (source_id, target_id, relation)
                if key in seen_edges:
                    continue
                seen_edges.add(key)
                await conn.execute(
                    "INSERT INTO memory_code_edges ("
                    "edge_id, project_id, repo_id, commit_sha, from_node_id, to_node_id, "
                    "relation, confidence, source_type, source_ref, created_at"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        _stable_id(runtime.project_id, effective_repo, effective_commit, *key),
                        runtime.project_id,
                        effective_repo,
                        effective_commit,
                        source_id,
                        target_id,
                        relation,
                        confidence,
                        SourceType.REPOSITORY.value,
                        source_ref,
                        now,
                    ),
                )
        elapsed = int((datetime.now(UTC) - started).total_seconds() * 1000)
        return CodeGraphBuildReport(
            runtime.project_id,
            effective_repo,
            effective_commit,
            len(files),
            len(nodes),
            len({(a, b, c) for a, b, c, _, _ in edges}),
            skipped,
            max(0, elapsed),
        )

    async def search(
        self,
        query: str,
        runtime: RuntimeMemoryContext,
        *,
        limit: int = 16,
        max_hops: int = 2,
    ) -> list[MemoryHit]:
        """Search paths/symbols and optionally expand their graph neighborhood."""

        if limit <= 0:
            return []
        bounded_hops = min(max(max_hops, 0), 4)
        terms = tuple(term.casefold() for term in query.split() if term)
        if not terms:
            return []
        like = f"%{query[:256]}%"
        async with self._db.read_connection() as conn:
            rows = await (
                await conn.execute(
                    "SELECT n.* FROM memory_code_nodes n "
                    "WHERE n.project_id = ? AND "
                    "(lower(n.path) LIKE lower(?) OR lower(n.qualified_name) LIKE lower(?) "
                    "OR lower(n.display_name) LIKE lower(?)) "
                    "ORDER BY CASE n.node_kind WHEN 'symbol' THEN 0 WHEN 'function' THEN 0 "
                    "WHEN 'method' THEN 0 ELSE 1 END, n.path, n.line_start LIMIT ?",
                    (runtime.project_id, like, like, like, min(limit, 64)),
                )
            ).fetchall()
            selected_ids = [str(row["node_id"]) for row in rows]
            if bounded_hops and selected_ids:
                selected_ids = await self._expand_ids(conn, selected_ids, runtime, bounded_hops, limit)
            if not selected_ids:
                return []
            placeholders = ",".join("?" for _ in selected_ids)
            node_rows = await (
                await conn.execute(
                    "SELECT * FROM memory_code_nodes WHERE project_id = ? "
                    f"AND node_id IN ({placeholders}) ORDER BY path, line_start LIMIT ?",
                    (runtime.project_id, *selected_ids, limit),
                )
            ).fetchall()
        hits: list[MemoryHit] = []
        for row in node_rows:
            content = _node_content(row)
            score = _node_score(row, terms)
            hits.append(
                MemoryHit(
                    provider_id=self.provider_id,
                    external_id=f"codegraph:{row['node_id']}",
                    memory_id=None,
                    content=content,
                    raw_score=score,
                    source_type=SourceType.REPOSITORY,
                    source_ref=f"{row['path']}:{row['line_start']}",
                    provider_metadata={
                        "canonical_record": False,
                        "codegraph_node_id": str(row["node_id"]),
                        "node_kind": str(row["node_kind"]),
                        "content_hash": str(row["content_hash"]),
                    },
                    authority_hint="REPOSITORY_OBSERVED",
                    confidence_hint=max(0.25, min(0.95, score)),
                    memory_type="CODE_MEMORY",
                    status=MemoryStatus.ACTIVE,
                    principal_id=runtime.principal_id,
                    project_id=runtime.project_id,
                    namespace="project",
                    scope="coding",
                    sensitivity=Sensitivity.INTERNAL,
                    usage_policy=UsagePolicy.PROJECT_ONLY,
                    applicability={"mode": "coding"},
                    environment=runtime.environment,
                )
            )
        return hits

    async def _expand_ids(
        self,
        conn: Any,
        seeds: list[str],
        runtime: RuntimeMemoryContext,
        max_hops: int,
        limit: int,
    ) -> list[str]:
        seen = set(seeds)
        queue = deque((node_id, 0) for node_id in seeds)
        while queue and len(seen) < limit:
            node_id, distance = queue.popleft()
            if distance >= max_hops:
                continue
            rows = await (
                await conn.execute(
                    "SELECT from_node_id, to_node_id FROM memory_code_edges "
                    "WHERE project_id = ? AND (from_node_id = ? OR to_node_id = ?) "
                    "LIMIT ?",
                    (runtime.project_id, node_id, node_id, limit),
                )
            ).fetchall()
            for row in rows:
                for neighbor in (str(row["from_node_id"]), str(row["to_node_id"])):
                    if neighbor not in seen:
                        seen.add(neighbor)
                        queue.append((neighbor, distance + 1))
                        if len(seen) >= limit:
                            break
                if len(seen) >= limit:
                    break
        return list(seen)[:limit]

    async def source(self, runtime: RuntimeMemoryContext, node_id: str) -> dict[str, Any] | None:
        """Return one scoped source node for user-facing provenance inspection."""

        async with self._db.read_connection() as conn:
            row = await (
                await conn.execute(
                    "SELECT * FROM memory_code_nodes WHERE project_id = ? AND node_id = ?",
                    (runtime.project_id, node_id),
                )
            ).fetchone()
            return dict(row) if row is not None else None

    async def evidence(self, runtime: RuntimeMemoryContext, node_id: str) -> list[dict[str, Any]]:
        """Return bounded graph edges for a scoped node."""

        async with self._db.read_connection() as conn:
            rows = await (
                await conn.execute(
                    "SELECT * FROM memory_code_edges WHERE project_id = ? "
                    "AND (from_node_id = ? OR to_node_id = ?) ORDER BY relation LIMIT 128",
                    (runtime.project_id, node_id, node_id),
                )
            ).fetchall()
            return [dict(row) for row in rows]


def _iter_source_files(root: Path, max_files: int) -> Iterable[Path]:
    count = 0
    for path in sorted(root.rglob("*")):
        if count >= max_files:
            break
        if path.is_symlink() or not path.is_file() or path.suffix.lower() not in _SUPPORTED_SUFFIXES:
            continue
        if any(part in _IGNORED_DIRS for part in path.relative_to(root).parts):
            continue
        count += 1
        yield path


def _make_node(
    project_id: str,
    repo_id: str,
    commit_sha: str,
    path: str,
    node_kind: str,
    qualified_name: str,
    display_name: str,
    line_start: int,
    line_end: int,
    content_hash: str,
    metadata: Mapping[str, Any],
) -> CodeGraphNode:
    node_id = _stable_id(project_id, repo_id, commit_sha, path, node_kind, qualified_name)
    return CodeGraphNode(
        node_id,
        project_id,
        repo_id,
        commit_sha,
        path,
        node_kind,
        qualified_name,
        display_name,
        max(1, line_start),
        max(line_start, line_end),
        content_hash,
        dict(metadata),
    )


def _stable_id(*parts: str) -> str:
    return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:32]


def _repo_id(root: Path) -> str:
    return hashlib.sha256(str(root).encode("utf-8")).hexdigest()[:32]


def _node_content(row: Any) -> str:
    kind = str(row["node_kind"])
    return (
        f"{kind} {row['qualified_name']} in {row['path']} "
        f"(line {row['line_start']}-{row['line_end']}, hash {row['content_hash']})"
    )


def _node_score(row: Any, terms: tuple[str, ...]) -> float:
    text = f"{row['path']} {row['qualified_name']} {row['display_name']}".casefold()
    matches = sum(term in text for term in terms)
    return min(1.0, 0.45 + 0.15 * matches + (0.15 if str(row["node_kind"]) != "file" else 0.0))


__all__ = ["CodeGraphBuildReport", "CodeGraphNode", "CodeGraphService"]
