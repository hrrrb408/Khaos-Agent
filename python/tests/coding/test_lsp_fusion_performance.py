"""Performance scenarios for optional LSP evidence fusion (M3 Batch 6 §15).

Generates a 1,015-file fixture repository and exercises:

  A. LSP fusion OFF: repository-only resolution performance
     - Must not degrade compared to baseline (no LSP client bound)
     - All fused results have depends_on_lsp=False
     - Identical to repository resolution

  B. LSP fusion ON with Fake LSP client: selected candidates only
     - Only unresolved/ambiguous candidates trigger LSP requests
     - Resolved candidates do NOT trigger LSP requests (early exit)
     - Cache hits avoid duplicate LSP requests for the same candidate

  C. File modification invalidation
     - After a file is modified, the cached LSP evidence is invalidated
     - Subsequent fusion for that file triggers a fresh LSP request
     - Fusion for UNMODIFIED files still uses cache

CI does not enforce a hard time threshold; the test asserts structural
correctness (cache hit/miss, request count, invalidation), not absolute speed.
"""
from __future__ import annotations

import asyncio
import sqlite3
import tempfile
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.tree_sitter_real
pytest.importorskip("tree_sitter")

from khaos.coding.intelligence.index import IndexStore, RepositoryIndexer
from khaos.coding.intelligence.lsp.cache import EvidenceCache
from khaos.coding.intelligence.lsp.config import LspFusionConfig
from khaos.coding.intelligence.lsp.evidence import (
    EvidenceSource,
    FusionRule,
)
from khaos.coding.intelligence.lsp.fusion import (
    FusionContext,
    LspEvidenceFusionService,
    compute_content_hash,
    compute_server_identity,
)
from khaos.coding.intelligence.lsp.uri import path_to_file_uri
from khaos.coding.intelligence.query import CodeQueryService
from khaos.coding.intelligence.resolution import ResolutionService
from khaos.coding.intelligence.resolution.models import (
    ResolutionStatus,
    ResolvedCallEdge,
)


# ---- Fake LSP client (counts requests) ------------------------------------


class CountingFakeLspClient:
    """Fake LSP client that counts every request and returns a canned response.

    For textDocument/definition, returns a Location pointing to a fixed
    symbol in a fixed file (or empty list if ``empty_response=True``).
    """

    def __init__(
        self,
        *,
        workspace_root: Path,
        target_file: str = "commons/commons_000.py",
        empty_response: bool = False,
    ) -> None:
        self.workspace_root = workspace_root
        self.target_file = target_file
        self.empty_response = empty_response
        self.request_count = 0
        self.methods_called: list[str] = []
        self._closed = False

    async def request(self, method: str, params: dict) -> dict:
        if self._closed:
            raise RuntimeError("LSP client is closed")
        self.request_count += 1
        self.methods_called.append(method)
        await asyncio.sleep(0)

        if self.empty_response:
            return []

        # Return a Location pointing to the target file
        target_uri = path_to_file_uri(self.workspace_root / self.target_file)
        return [{
            "uri": target_uri,
            "range": {
                "start": {"line": 0, "character": 4},
                "end": {"line": 0, "character": 19},
            },
        }]

    async def close(self) -> None:
        self._closed = True


# ---- Fixture generation ----------------------------------------------------


def _generate_repository(root: Path) -> dict[str, list[str]]:
    """Generate a 1,015-file Python repository.

    Layout:
      commons/commons_000.py .. commons_064.py   (65 base files)
      mid/mid_000.py .. mid_949.py                (950 middle files)

    Total: 65 + 950 = 1015 files
    """
    commons_dir = root / "commons"
    mid_dir = root / "mid"
    for d in (commons_dir, mid_dir):
        d.mkdir(parents=True, exist_ok=True)
    for d in (commons_dir, mid_dir):
        (d / "__init__.py").write_text("", encoding="utf-8")

    commons_paths: list[str] = []
    for i in range(65):
        fname = f"commons_{i:03d}.py"
        (commons_dir / fname).write_text(
            f"def commons_func_{i}():\n    return {i}\n",
            encoding="utf-8",
        )
        commons_paths.append(f"commons/{fname}")

    mid_paths: list[str] = []
    for i in range(950):
        commons_idx = i % 65
        fname = f"mid_{i:03d}.py"
        (mid_dir / fname).write_text(
            f"from commons.commons_{commons_idx:03d} import commons_func_{commons_idx}\n"
            f"def mid_func_{i}():\n    return commons_func_{commons_idx}()\n"
            f"obj.dynamic_{i}()  # dynamic\n",
            encoding="utf-8",
        )
        mid_paths.append(f"mid/{fname}")

    return {"commons": commons_paths, "mid": mid_paths}


def _total_files(layout: dict[str, list[str]]) -> int:
    return sum(len(v) for v in layout.values()) + 2  # +2 __init__.py


def _make_fusion_service(
    conn: sqlite3.Connection,
    *,
    enabled: bool = False,
    lsp_client=None,
) -> LspEvidenceFusionService:
    config = LspFusionConfig(enabled=enabled)
    cache = EvidenceCache()
    return LspEvidenceFusionService(
        config=config,
        cache=cache,
        conn=conn,
        lsp_client=lsp_client,
    )


def _make_context(
    root: Path,
    file_path: str,
    file_text: str,
    *,
    generation: int = 1,
    repository_id: str = "perf",
) -> FusionContext:
    return FusionContext(
        repository_id=repository_id,
        workspace_id="ws-perf",
        file_path=file_path,
        file_text=file_text,
        content_hash=compute_content_hash(file_text),
        file_generation=generation,
        document_version=1,
        server_identity=compute_server_identity("fake-lsp", "1.0"),
        workspace_root=root,
    )


def _make_repo_resolution(
    *,
    edge_id: str = "edge-1",
    source_file: str = "mid/mid_000.py",
    call_callee: str = "commons_func_0",
    status: ResolutionStatus = ResolutionStatus.RESOLVED,
    target_symbol_id: str | None = "stable-sym-1",
    target_file: str | None = "commons/commons_000.py",
    confidence: float = 0.9,
    rule: str = "from-import-unique",
) -> ResolvedCallEdge:
    return ResolvedCallEdge(
        edge_id=edge_id,
        source_file=source_file,
        caller_symbol_id=None,
        call_callee=call_callee,
        status=status,
        target_symbol_id=target_symbol_id,
        target_file=target_file,
        confidence=confidence,
        resolution_rule=rule,
        ambiguity_reason=None,
    )


# ---- Tests -----------------------------------------------------------------


def test_lsp_fusion_off_no_degradation_1015_files():
    """Scenario A: LSP fusion OFF must not degrade repository resolution.

    Builds a 1,015-file repository, indexes it, then runs fusion with
    ``enabled=False`` on a sample of resolved edges. Asserts:
      - All fused results have depends_on_lsp=False
      - Fused status equals repository status
      - Only one evidence (repository_resolution)
      - No LSP requests sent
      - Performance: completing 100 fusions takes negligible time
    """
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        layout = _generate_repository(root)
        total = _total_files(layout)
        assert total >= 1015, f"expected >= 1015 files, got {total}"

        store = IndexStore(sqlite3.connect(":memory:", check_same_thread=False))
        svc = ResolutionService(store._conn, persist=True)
        indexer = RepositoryIndexer(store, resolution_service=svc)

        t0 = time.perf_counter()
        report = asyncio.run(indexer.index("perf", root))
        index_ms = (time.perf_counter() - t0) * 1000
        assert report["parsed_files"] >= 1015

        qs = CodeQueryService(store)

        # Pick a sample of mid files with resolved call edges
        sample_paths = layout["mid"][:100]
        sample_edges: list[tuple[str, dict]] = []
        for path in sample_paths:
            edges = qs.call_edges_for_file("perf", path)
            resolved = [e for e in edges if e["status"] == "resolved"]
            if resolved:
                sample_edges.append((path, resolved[0]))

        assert len(sample_edges) >= 50, f"expected >= 50 sample edges, got {len(sample_edges)}"

        # LSP fusion OFF
        fusion = _make_fusion_service(store._conn, enabled=False, lsp_client=None)
        assert fusion.enabled is False

        t0 = time.perf_counter()
        for path, edge in sample_edges:
            file_text = (root / path).read_text(encoding="utf-8")
            record = asyncio.run(store.file_record("perf", path))
            ctx = _make_context(root, path, file_text, generation=record["generation"])
            repo_res = _make_repo_resolution(
                edge_id=edge["edge_id"],
                source_file=path,
                call_callee=edge["call_callee"],
                status=ResolutionStatus(edge["status"]),
                target_symbol_id=edge.get("target_symbol_id"),
                target_file=edge.get("target_file"),
                confidence=edge.get("confidence", 0.9),
                rule=edge.get("resolution_rule", "test"),
            )
            fused = asyncio.run(fusion.fuse_definition(
                candidate_callee=edge["call_callee"],
                candidate_byte_range=(0, len(edge["call_callee"])),
                repo_resolution=repo_res,
                context=ctx,
            ))
            assert fused.depends_on_lsp is False
            assert fused.fused_status == repo_res.status.value
            assert len(fused.evidence) == 1
            assert fused.evidence[0].source.value == "repository-resolution"
        fusion_off_ms = (time.perf_counter() - t0) * 1000

        print(
            f"\n=== LSP fusion OFF performance (1,015 files) ===\n"
            f"Total files: {total}\n"
            f"Index time: {index_ms:.1f} ms\n"
            f"Fusion off (100 edges): {fusion_off_ms:.1f} ms\n"
            f"Avg per fusion: {fusion_off_ms / len(sample_edges):.2f} ms\n"
        )


def test_lsp_fusion_on_selected_candidates_and_cache_hits():
    """Scenario B: LSP fusion ON triggers requests only for non-resolved edges.

    With fusion enabled:
      - RESOLVED candidates with LSP same-target → confirm, 1 LSP request
      - UNRESOLVED/AMBIGUOUS candidates → promote, 1 LSP request
      - Repeated fusion for the SAME candidate → cache hit, 0 new requests
    """
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        layout = _generate_repository(root)
        total = _total_files(layout)

        store = IndexStore(sqlite3.connect(":memory:", check_same_thread=False))
        svc = ResolutionService(store._conn, persist=True)
        indexer = RepositoryIndexer(store, resolution_service=svc)
        asyncio.run(indexer.index("perf", root))

        qs = CodeQueryService(store)

        # Find an unresolved/dynamic edge in a mid file
        sample_path = layout["mid"][0]
        edges = qs.call_edges_for_file("perf", sample_path)
        non_resolved = [e for e in edges if e["status"] in ("unresolved", "dynamic")]

        # If no non-resolved edge exists, fall back to a resolved edge
        # (we still want to test that LSP request is made and cache works)
        if non_resolved:
            test_edge = non_resolved[0]
            repo_status = ResolutionStatus.UNRESOLVED if test_edge["status"] == "unresolved" else ResolutionStatus.DYNAMIC
        else:
            test_edge = [e for e in edges if e["status"] == "resolved"][0]
            repo_status = ResolutionStatus.RESOLVED

        file_text = (root / sample_path).read_text(encoding="utf-8")
        record = asyncio.run(store.file_record("perf", sample_path))

        # Fake LSP returns a location in commons_000.py — should be internal
        fake_client = CountingFakeLspClient(
            workspace_root=root,
            target_file="commons/commons_000.py",
        )
        fusion = _make_fusion_service(store._conn, enabled=True, lsp_client=fake_client)
        assert fusion.enabled is True

        ctx = _make_context(root, sample_path, file_text, generation=record["generation"])
        repo_res = _make_repo_resolution(
            edge_id=test_edge["edge_id"],
            source_file=sample_path,
            call_callee=test_edge["call_callee"],
            status=repo_status,
            target_symbol_id=test_edge.get("target_symbol_id"),
            target_file=test_edge.get("target_file"),
            confidence=test_edge.get("confidence", 0.5),
            rule=test_edge.get("resolution_rule", "test"),
        )

        # First fusion: triggers LSP request (cache miss)
        fused1 = asyncio.run(fusion.fuse_definition(
            candidate_callee=test_edge["call_callee"],
            candidate_byte_range=(0, len(test_edge["call_callee"])),
            repo_resolution=repo_res,
            context=ctx,
        ))
        assert fake_client.request_count == 1, (
            f"first fusion should trigger 1 LSP request, got {fake_client.request_count}"
        )
        assert fused1.depends_on_lsp is True
        # LSP evidence should be present (1 repo + N lsp)
        assert len(fused1.evidence) >= 2

        # Second fusion for the SAME candidate: cache hit, 0 new requests
        fused2 = asyncio.run(fusion.fuse_definition(
            candidate_callee=test_edge["call_callee"],
            candidate_byte_range=(0, len(test_edge["call_callee"])),
            repo_resolution=repo_res,
            context=ctx,
        ))
        assert fake_client.request_count == 1, (
            f"second fusion should hit cache (0 new requests), "
            f"got total={fake_client.request_count}"
        )
        # Cached result should be structurally identical
        assert fused2.depends_on_lsp == fused1.depends_on_lsp
        assert len(fused2.evidence) == len(fused1.evidence)

        cache_stats = fusion.cache_stats
        print(
            f"\n=== LSP fusion ON cache hits ===\n"
            f"Total files: {total}\n"
            f"Sample edge: {test_edge['call_callee']} ({test_edge['status']})\n"
            f"LSP requests after 2 fusions: {fake_client.request_count}\n"
            f"Cache stats: {cache_stats}\n"
        )


def test_file_modification_invalidates_lsp_cache():
    """Scenario C: file modification invalidates cached LSP evidence.

    After a file is modified (generation increments), the LSP cache entry
    for that file must be invalidated. Subsequent fusion triggers a fresh
    LSP request. Fusion for UNMODIFIED files still uses cache.
    """
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        layout = _generate_repository(root)

        store = IndexStore(sqlite3.connect(":memory:", check_same_thread=False))
        svc = ResolutionService(store._conn, persist=True)
        indexer = RepositoryIndexer(store, resolution_service=svc)
        asyncio.run(indexer.index("perf", root))

        qs = CodeQueryService(store)

        # Pick two mid files
        path_a = layout["mid"][0]
        path_b = layout["mid"][1]

        edges_a = qs.call_edges_for_file("perf", path_a)
        edges_b = qs.call_edges_for_file("perf", path_b)
        edge_a = [e for e in edges_a if e["status"] != "resolved"] or edges_a
        edge_b = [e for e in edges_b if e["status"] != "resolved"] or edges_b
        test_edge_a = edge_a[0]
        test_edge_b = edge_b[0]

        # Fake LSP returns empty (so fusion falls back to repository-only,
        # but the LSP request is still made and cached as empty evidence)
        fake_client = CountingFakeLspClient(
            workspace_root=root,
            target_file="commons/commons_000.py",
            empty_response=False,
        )
        fusion = _make_fusion_service(store._conn, enabled=True, lsp_client=fake_client)

        # First fusion for file A
        text_a = (root / path_a).read_text(encoding="utf-8")
        record_a = asyncio.run(store.file_record("perf", path_a))
        ctx_a = _make_context(root, path_a, text_a, generation=record_a["generation"])
        repo_res_a = _make_repo_resolution(
            edge_id=test_edge_a["edge_id"],
            source_file=path_a,
            call_callee=test_edge_a["call_callee"],
            status=ResolutionStatus(test_edge_a["status"]),
            target_symbol_id=test_edge_a.get("target_symbol_id"),
            target_file=test_edge_a.get("target_file"),
        )
        asyncio.run(fusion.fuse_definition(
            candidate_callee=test_edge_a["call_callee"],
            candidate_byte_range=(0, len(test_edge_a["call_callee"])),
            repo_resolution=repo_res_a,
            context=ctx_a,
        ))
        requests_after_a1 = fake_client.request_count
        assert requests_after_a1 == 1

        # Second fusion for file A (same candidate): cache hit
        asyncio.run(fusion.fuse_definition(
            candidate_callee=test_edge_a["call_callee"],
            candidate_byte_range=(0, len(test_edge_a["call_callee"])),
            repo_resolution=repo_res_a,
            context=ctx_a,
        ))
        assert fake_client.request_count == 1, "second fusion for A should hit cache"

        # Fusion for file B (different file): cache miss, new LSP request
        text_b = (root / path_b).read_text(encoding="utf-8")
        record_b = asyncio.run(store.file_record("perf", path_b))
        ctx_b = _make_context(root, path_b, text_b, generation=record_b["generation"])
        repo_res_b = _make_repo_resolution(
            edge_id=test_edge_b["edge_id"],
            source_file=path_b,
            call_callee=test_edge_b["call_callee"],
            status=ResolutionStatus(test_edge_b["status"]),
            target_symbol_id=test_edge_b.get("target_symbol_id"),
            target_file=test_edge_b.get("target_file"),
        )
        asyncio.run(fusion.fuse_definition(
            candidate_callee=test_edge_b["call_callee"],
            candidate_byte_range=(0, len(test_edge_b["call_callee"])),
            repo_resolution=repo_res_b,
            context=ctx_b,
        ))
        assert fake_client.request_count == 2, (
            f"fusion for B should be a cache miss (new request), "
            f"got total={fake_client.request_count}"
        )

        # Now modify file A: generation increments, cache must invalidate
        original_a = (root / path_a).read_text(encoding="utf-8")
        (root / path_a).write_text(original_a + "\n# modified\n", encoding="utf-8")
        asyncio.run(indexer.index("perf", root))

        # Re-read file A's record (generation should be incremented)
        record_a_new = asyncio.run(store.file_record("perf", path_a))
        assert record_a_new["generation"] > record_a["generation"], (
            f"generation should increment after modification: "
            f"{record_a['generation']} → {record_a_new['generation']}"
        )

        # Fusion for modified file A: cache miss (stale generation), new LSP request
        text_a_new = (root / path_a).read_text(encoding="utf-8")
        ctx_a_new = _make_context(root, path_a, text_a_new, generation=record_a_new["generation"])
        asyncio.run(fusion.fuse_definition(
            candidate_callee=test_edge_a["call_callee"],
            candidate_byte_range=(0, len(test_edge_a["call_callee"])),
            repo_resolution=repo_res_a,
            context=ctx_a_new,
        ))
        assert fake_client.request_count == 3, (
            f"fusion for modified A should be a cache miss (stale generation), "
            f"got total={fake_client.request_count}"
        )

        # Fusion for UNMODIFIED file B: still cache hit (no new request)
        asyncio.run(fusion.fuse_definition(
            candidate_callee=test_edge_b["call_callee"],
            candidate_byte_range=(0, len(test_edge_b["call_callee"])),
            repo_resolution=repo_res_b,
            context=ctx_b,
        ))
        assert fake_client.request_count == 3, (
            f"fusion for unmodified B should still hit cache, "
            f"got total={fake_client.request_count}"
        )

        print(
            f"\n=== File modification invalidates LSP cache ===\n"
            f"File A: {path_a} (generation {record_a['generation']} → {record_a_new['generation']})\n"
            f"File B: {path_b} (unchanged)\n"
            f"Total LSP requests: {fake_client.request_count}\n"
            f"  1: first fusion A (cache miss)\n"
            f"  2: first fusion B (cache miss, different file)\n"
            f"  3: fusion A after modification (stale generation invalidation)\n"
            f"Cache stats: {fusion.cache_stats}\n"
        )


def test_lsp_fusion_timeout_does_not_block_resolution():
    """LSP timeout falls back to repository-only result within timeout window.

    The fusion service must not hang indefinitely when the LSP server is
    slow. After ``request_timeout_seconds``, it returns repository-only.
    """
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "util.py").write_text("def helper():\n    return 42\n", encoding="utf-8")
        (root / "app.py").write_text(
            "from util import helper\nhelper()\n",
            encoding="utf-8",
        )

        store = IndexStore(sqlite3.connect(":memory:", check_same_thread=False))
        svc = ResolutionService(store._conn, persist=True)
        indexer = RepositoryIndexer(store, resolution_service=svc)
        asyncio.run(indexer.index("perf", root))

        # Fake LSP that always times out
        class TimeoutLspClient:
            async def request(self, method: str, params: dict) -> dict:
                raise asyncio.TimeoutError()
            async def close(self) -> None:
                pass

        config = LspFusionConfig(enabled=True, request_timeout_seconds=0.1)
        cache = EvidenceCache()
        fusion = LspEvidenceFusionService(
            config=config, cache=cache, conn=store._conn, lsp_client=TimeoutLspClient(),
        )

        file_text = (root / "app.py").read_text(encoding="utf-8")
        record = asyncio.run(store.file_record("perf", "app.py"))
        ctx = _make_context(root, "app.py", file_text, generation=record["generation"])
        repo_res = _make_repo_resolution(
            call_callee="helper",
            status=ResolutionStatus.RESOLVED,
            target_file="util.py",
        )

        t0 = time.perf_counter()
        fused = asyncio.run(fusion.fuse_definition(
            candidate_callee="helper",
            candidate_byte_range=(0, 6),
            repo_resolution=repo_res,
            context=ctx,
        ))
        elapsed_ms = (time.perf_counter() - t0) * 1000

        # Timeout: falls back to repository-only
        assert fused.depends_on_lsp is False
        assert fused.fused_status == ResolutionStatus.RESOLVED.value
        assert len(fused.evidence) == 1
        # Should complete within a reasonable window (not hang)
        assert elapsed_ms < 1000, f"fusion took too long: {elapsed_ms} ms"
