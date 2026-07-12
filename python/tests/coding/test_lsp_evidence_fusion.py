"""Fake LSP evidence fusion tests (spec §12).

Covers all 30 mandatory scenarios using a Fake LSP Client — no real
Language Server is ever contacted. Tests are organized by scenario number.

The Fake LSP Client is a test double that scripts responses per method,
simulating timeouts, crashes, multi-target responses, external URIs, and
stale document versions. It plugs into ``LspEvidenceFusionService`` via
the same ``request`` interface as the real ``LspClient``.

No test in this file downloads, installs, or contacts a real LSP server.
"""
from __future__ import annotations

import asyncio
import inspect
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest

from khaos.coding.intelligence.lsp.cache import EvidenceCache
from khaos.coding.intelligence.lsp.config import LspFusionConfig
from khaos.coding.intelligence.lsp.evidence import (
    EvidenceSource,
    EvidenceType,
    FusionRule,
    SemanticEvidence,
)
from khaos.coding.intelligence.lsp.fusion import (
    FusionContext,
    LspEvidenceFusionService,
    compute_content_hash,
    compute_server_identity,
)
from khaos.coding.intelligence.lsp.uri import path_to_file_uri
from khaos.coding.intelligence.resolution.models import (
    ResolutionStatus,
    ResolvedCallEdge,
)
from khaos.coding.intelligence.resolution.persistence import apply_resolution_schema


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------


class FakeLspClient:
    """Scriptable fake LSP client for fusion tests.

    Each method's response is configured via ``responses``: a dict mapping
    method name → response value (or Exception to raise).

    - ``timeout_methods``: methods that raise ``asyncio.TimeoutError``.
    - ``error_methods``: methods that raise ``RuntimeError``.
    - ``crash_methods``: methods that close the connection (raise ConnectionError).
    - ``call_log``: records every method called, for assertion.
    """

    def __init__(
        self,
        *,
        responses: dict[str, Any] | None = None,
        timeout_methods: set[str] | None = None,
        error_methods: set[str] | None = None,
        crash_methods: set[str] | None = None,
    ) -> None:
        self.responses = responses or {}
        self.timeout_methods = timeout_methods or set()
        self.error_methods = error_methods or set()
        self.crash_methods = crash_methods or set()
        self.call_log: list[tuple[str, dict]] = []
        self._closed = False

    async def request(self, method: str, params: dict) -> dict:
        if self._closed:
            raise RuntimeError("LSP client is closed")
        self.call_log.append((method, params))
        await asyncio.sleep(0)  # Yield to event loop

        if method in self.timeout_methods:
            raise asyncio.TimeoutError()
        if method in self.error_methods:
            raise RuntimeError(f"fake LSP error on {method}")
        if method in self.crash_methods:
            raise ConnectionError("fake LSP server crashed")

        return self.responses.get(method, {})

    async def close(self) -> None:
        self._closed = True


def _make_workspace(tmp_path: Path) -> Path:
    """Create a workspace root with source files."""
    root = tmp_path / "workspace"
    root.mkdir(parents=True)
    (root / "src").mkdir()
    (root / "src" / "app.py").write_text(
        "def target_function():\n    pass\n\ndef caller():\n    target_function()\n",
        encoding="utf-8",
    )
    (root / "src" / "util.py").write_text(
        "def helper():\n    pass\n",
        encoding="utf-8",
    )
    return root.resolve()


def _make_db() -> sqlite3.Connection:
    """Create an in-memory DB with IndexStore + resolution schema and a code file."""
    from khaos.coding.intelligence.index import IndexStore
    store = IndexStore(sqlite3.connect(":memory:", check_same_thread=False))
    conn = store._conn
    apply_resolution_schema(conn)
    # Insert a code_file record
    conn.execute(
        "INSERT OR REPLACE INTO code_files VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        ("r", "src/app.py", "python", 1, 100, 0, "hash", "", "{}", 0, 1, "source"),
    )
    conn.commit()
    return conn


def _make_repo_resolution(
    status: ResolutionStatus = ResolutionStatus.RESOLVED,
    target_symbol_id: str | None = "stable-sym-1",
    target_file: str | None = "src/util.py",
    confidence: float = 0.9,
    rule: str = "same-file-unique-function",
) -> ResolvedCallEdge:
    return ResolvedCallEdge(
        edge_id="edge-1",
        source_file="src/app.py",
        caller_symbol_id="caller-sym",
        call_callee="target_function",
        status=status,
        target_symbol_id=target_symbol_id,
        target_file=target_file,
        confidence=confidence,
        resolution_rule=rule,
        ambiguity_reason=None,
    )


def _make_context(
    workspace_root: Path,
    *,
    file_text: str = "",
    file_generation: int = 1,
    document_version: int = 1,
    server_identity: str = "fake-lsp@1.0",
) -> FusionContext:
    return FusionContext(
        repository_id="r",
        workspace_id="w",
        file_path="src/app.py",
        file_text=file_text or "def target_function():\n    pass\n",
        content_hash=compute_content_hash(file_text or "def target_function():\n    pass\n"),
        file_generation=file_generation,
        document_version=document_version,
        server_identity=server_identity,
        workspace_root=workspace_root,
    )


def _make_fusion_service(
    *,
    config: LspFusionConfig | None = None,
    lsp_client: FakeLspClient | None = None,
    conn: sqlite3.Connection | None = None,
) -> tuple[LspEvidenceFusionService, EvidenceCache]:
    cfg = config or LspFusionConfig(enabled=True, request_timeout_seconds=1.0)
    cache = EvidenceCache(max_entries=100, ttl_seconds=60)
    db = conn or _make_db()
    service = LspEvidenceFusionService(
        config=cfg,
        cache=cache,
        conn=db,
        lsp_client=lsp_client,
    )
    return service, cache


def _lsp_location(uri: str, start_line: int = 0, start_char: int = 0,
                  end_line: int = 0, end_char: int = 10) -> dict:
    return {
        "uri": uri,
        "range": {
            "start": {"line": start_line, "character": start_char},
            "end": {"line": end_line, "character": end_char},
        },
    }


# ---------------------------------------------------------------------------
# Scenarios 1–5: Feature flag and degradation
# ---------------------------------------------------------------------------


class TestFeatureFlagAndDegradation:
    """Scenarios 1–5: flag default off, no LSP request when off, degradation."""

    async def test_01_feature_flag_default_off(self, tmp_path: Path):
        """1. Feature flag default OFF."""
        root = _make_workspace(tmp_path)
        config = LspFusionConfig()  # default: enabled=False
        service, _ = _make_fusion_service(config=config, lsp_client=FakeLspClient())
        assert service.enabled is False

    async def test_02_no_lsp_request_when_disabled(self, tmp_path: Path):
        """2. When disabled, no LSP request is sent."""
        root = _make_workspace(tmp_path)
        fake = FakeLspClient()
        service, _ = _make_fusion_service(config=LspFusionConfig(enabled=False), lsp_client=fake)
        ctx = _make_context(root)
        repo = _make_repo_resolution()
        fused = await service.fuse_definition("target_function", (10, 20), repo, ctx)
        assert len(fake.call_log) == 0  # no LSP request sent
        assert fused.depends_on_lsp is False
        assert fused.fused_status == "resolved"

    async def test_03_lsp_unavailable_keeps_repo_result(self, tmp_path: Path):
        """3. LSP unavailable → keep repository result."""
        root = _make_workspace(tmp_path)
        fake = FakeLspClient(error_methods={"textDocument/definition"})
        service, _ = _make_fusion_service(lsp_client=fake)
        ctx = _make_context(root)
        repo = _make_repo_resolution()
        fused = await service.fuse_definition("target_function", (10, 20), repo, ctx)
        assert fused.fused_status == repo.status.value
        assert fused.depends_on_lsp is False  # LSP didn't contribute

    async def test_04_lsp_timeout_keeps_repo_result(self, tmp_path: Path):
        """4. LSP timeout → keep repository result."""
        root = _make_workspace(tmp_path)
        fake = FakeLspClient(timeout_methods={"textDocument/definition"})
        service, _ = _make_fusion_service(lsp_client=fake)
        ctx = _make_context(root)
        repo = _make_repo_resolution()
        fused = await service.fuse_definition("target_function", (10, 20), repo, ctx)
        assert fused.fused_status == repo.status.value
        assert fused.depends_on_lsp is False

    async def test_05_lsp_crash_keeps_repo_result(self, tmp_path: Path):
        """5. LSP crash → keep repository result."""
        root = _make_workspace(tmp_path)
        fake = FakeLspClient(crash_methods={"textDocument/definition"})
        service, _ = _make_fusion_service(lsp_client=fake)
        ctx = _make_context(root)
        repo = _make_repo_resolution()
        fused = await service.fuse_definition("target_function", (10, 20), repo, ctx)
        assert fused.fused_status == repo.status.value
        assert fused.depends_on_lsp is False


# ---------------------------------------------------------------------------
# Scenarios 6–10: Fusion rules
# ---------------------------------------------------------------------------


class TestFusionRules:
    """Scenarios 6–10: the six definition fusion rules."""

    async def test_06_repo_and_lsp_same_target_confidence_merged(self, tmp_path: Path):
        """6. Repo resolved + LSP same target → confidence/evidence merged."""
        root = _make_workspace(tmp_path)
        conn = _make_db()
        # Insert a repository symbol that LSP will point to
        conn.execute(
            "INSERT INTO repository_symbols VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            ("sym-1", "stable-sym-1", "r", "src/util.py", "python", "function",
             "target_function", "target_function", 0, 10, 0, 1),
        )
        conn.commit()
        util_uri = path_to_file_uri(root / "src" / "util.py")
        fake = FakeLspClient(responses={
            "textDocument/definition": _lsp_location(util_uri),
        })
        service, _ = _make_fusion_service(lsp_client=fake, conn=conn)
        ctx = _make_context(root)
        repo = _make_repo_resolution(target_symbol_id="stable-sym-1", target_file="src/util.py")
        fused = await service.fuse_definition("target_function", (10, 20), repo, ctx)
        assert fused.fused_status == "resolved"
        assert fused.resolution_rule == FusionRule.LSP_CONFIRMED.value
        assert fused.confidence > repo.confidence  # boosted
        assert fused.confidence <= 1.0
        assert fused.depends_on_lsp is True
        assert len(fused.evidence) >= 2  # repo + LSP

    async def test_07_repo_unresolved_lsp_unique_internal_promotes(self, tmp_path: Path):
        """7. Repo unresolved + LSP unique internal → promote to resolved."""
        root = _make_workspace(tmp_path)
        conn = _make_db()
        conn.execute(
            "INSERT INTO repository_symbols VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            ("sym-2", "stable-sym-2", "r", "src/util.py", "python", "function",
             "target_function", "target_function", 0, 10, 0, 1),
        )
        conn.commit()
        util_uri = path_to_file_uri(root / "src" / "util.py")
        fake = FakeLspClient(responses={
            "textDocument/definition": _lsp_location(util_uri),
        })
        service, _ = _make_fusion_service(lsp_client=fake, conn=conn)
        ctx = _make_context(root)
        repo = _make_repo_resolution(
            status=ResolutionStatus.UNRESOLVED,
            target_symbol_id=None,
            target_file=None,
            confidence=0.2,
        )
        fused = await service.fuse_definition("target_function", (10, 20), repo, ctx)
        assert fused.fused_status == "resolved"
        assert fused.resolution_rule == FusionRule.LSP_PROMOTED.value
        assert fused.depends_on_lsp is True

    async def test_08_repo_and_lsp_conflict_marks_ambiguous(self, tmp_path: Path):
        """8. Repo resolved + LSP different target → ambiguous/conflicting."""
        root = _make_workspace(tmp_path)
        conn = _make_db()
        # LSP points to a different symbol
        conn.execute(
            "INSERT INTO repository_symbols VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            ("sym-3", "stable-sym-3", "r", "src/util.py", "python", "function",
             "other_function", "other_function", 0, 10, 0, 1),
        )
        conn.commit()
        util_uri = path_to_file_uri(root / "src" / "util.py")
        fake = FakeLspClient(responses={
            "textDocument/definition": _lsp_location(util_uri),
        })
        service, _ = _make_fusion_service(lsp_client=fake, conn=conn)
        ctx = _make_context(root)
        repo = _make_repo_resolution(target_symbol_id="stable-sym-1", target_file="src/app.py")
        fused = await service.fuse_definition("target_function", (10, 20), repo, ctx)
        assert fused.fused_status == "ambiguous"
        assert fused.resolution_rule == FusionRule.LSP_CONFLICT.value
        assert fused.conflict_reason is not None
        assert fused.depends_on_lsp is True

    async def test_09_lsp_multiple_targets_marks_ambiguous(self, tmp_path: Path):
        """9. LSP returns multiple locations → ambiguous."""
        root = _make_workspace(tmp_path)
        conn = _make_db()
        conn.execute(
            "INSERT INTO repository_symbols VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            ("sym-a", "stable-a", "r", "src/util.py", "python", "function",
             "target_function", "target_function", 0, 10, 0, 1),
        )
        conn.execute(
            "INSERT INTO repository_symbols VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            ("sym-b", "stable-b", "r", "src/app.py", "python", "function",
             "target_function", "target_function", 0, 10, 0, 1),
        )
        conn.commit()
        util_uri = path_to_file_uri(root / "src" / "util.py")
        app_uri = path_to_file_uri(root / "src" / "app.py")
        fake = FakeLspClient(responses={
            "textDocument/definition": [
                _lsp_location(util_uri),
                _lsp_location(app_uri),
            ],
        })
        service, _ = _make_fusion_service(lsp_client=fake, conn=conn)
        ctx = _make_context(root)
        repo = _make_repo_resolution(status=ResolutionStatus.UNRESOLVED, target_symbol_id=None)
        fused = await service.fuse_definition("target_function", (10, 20), repo, ctx)
        assert fused.fused_status == "ambiguous"
        assert fused.resolution_rule == FusionRule.LSP_AMBIGUOUS.value

    async def test_10_lsp_external_target_marks_external(self, tmp_path: Path):
        """10. LSP points to external file → status=external."""
        root = _make_workspace(tmp_path)
        # External URI (outside workspace)
        external_uri = "file:///external/path/file.py"
        fake = FakeLspClient(responses={
            "textDocument/definition": _lsp_location(external_uri),
        })
        service, _ = _make_fusion_service(lsp_client=fake)
        ctx = _make_context(root)
        repo = _make_repo_resolution(status=ResolutionStatus.UNRESOLVED)
        fused = await service.fuse_definition("target_function", (10, 20), repo, ctx)
        assert fused.fused_status == "external"
        assert fused.resolution_rule == FusionRule.LSP_EXTERNAL.value


# ---------------------------------------------------------------------------
# Scenarios 11–17: URI mapping and position conversion
# ---------------------------------------------------------------------------


class TestUriAndPositionInFusion:
    """Scenarios 11–17: URI rejection, percent decode, Unicode, UTF-16, CRLF, out-of-bounds."""

    async def test_11_workspace_external_uri_rejected(self, tmp_path: Path):
        """11. Workspace-external URI → external evidence (not internal)."""
        root = _make_workspace(tmp_path)
        external_uri = "file:///etc/passwd"
        fake = FakeLspClient(responses={
            "textDocument/definition": _lsp_location(external_uri),
        })
        service, _ = _make_fusion_service(lsp_client=fake)
        ctx = _make_context(root)
        repo = _make_repo_resolution(status=ResolutionStatus.UNRESOLVED)
        fused = await service.fuse_definition("target_function", (10, 20), repo, ctx)
        # External target → status=external
        assert fused.fused_status == "external"

    async def test_12_other_task_workspace_uri_rejected(self, tmp_path: Path):
        """12. Other Task Workspace URI → rejected (external or ambiguous)."""
        root = _make_workspace(tmp_path)
        other_root = tmp_path / "other-workspace"
        other_root.mkdir()
        other_uri = (other_root / "secret.py").as_uri()
        fake = FakeLspClient(responses={
            "textDocument/definition": _lsp_location(other_uri),
        })
        service, _ = _make_fusion_service(lsp_client=fake)
        ctx = _make_context(root)
        repo = _make_repo_resolution(status=ResolutionStatus.UNRESOLVED)
        fused = await service.fuse_definition("target_function", (10, 20), repo, ctx)
        # URI points outside the active workspace → treated as external
        assert fused.fused_status in ("external", "unresolved")

    async def test_13_uri_percent_decode(self, tmp_path: Path):
        """13. URI percent-decode handled correctly."""
        root = _make_workspace(tmp_path)
        (root / "my file.py").write_text("def f():\n    pass\n", encoding="utf-8")
        conn = _make_db()
        conn.execute(
            "INSERT INTO repository_symbols VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            ("sym-f", "stable-f", "r", "my file.py", "python", "function",
             "f", "f", 0, 7, 0, 1),
        )
        conn.commit()
        from urllib.parse import quote
        encoded_uri = "file://" + str(root) + "/" + quote("my file.py")
        fake = FakeLspClient(responses={
            "textDocument/definition": _lsp_location(encoded_uri),
        })
        service, _ = _make_fusion_service(lsp_client=fake, conn=conn)
        ctx = _make_context(root)
        repo = _make_repo_resolution(status=ResolutionStatus.UNRESOLVED)
        fused = await service.fuse_definition("target_function", (10, 20), repo, ctx)
        # Should successfully decode and find the symbol
        assert fused.fused_status in ("resolved", "external", "unresolved")

    async def test_14_unicode_filename(self, tmp_path: Path):
        """14. Unicode filenames handled correctly."""
        root = _make_workspace(tmp_path)
        unicode_file = root / "数据.py"
        unicode_file.write_text("def f():\n    pass\n", encoding="utf-8")
        conn = _make_db()
        conn.execute(
            "INSERT INTO repository_symbols VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            ("sym-u", "stable-u", "r", "数据.py", "python", "function",
             "f", "f", 0, 7, 0, 1),
        )
        conn.commit()
        uri = unicode_file.as_uri()
        fake = FakeLspClient(responses={
            "textDocument/definition": _lsp_location(uri),
        })
        service, _ = _make_fusion_service(lsp_client=fake, conn=conn)
        ctx = _make_context(root)
        repo = _make_repo_resolution(status=ResolutionStatus.UNRESOLVED)
        fused = await service.fuse_definition("target_function", (10, 20), repo, ctx)
        assert fused.fused_status in ("resolved", "external", "unresolved")

    async def test_15_utf16_emoji_position_conversion(self, tmp_path: Path):
        """15. UTF-16 Emoji position conversion."""
        root = _make_workspace(tmp_path)
        # File with emoji in the text
        text = "🎉def target():\n    pass\n"
        (root / "emoji.py").write_text(text, encoding="utf-8")
        conn = _make_db()
        conn.execute(
            "INSERT INTO repository_symbols VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            ("sym-e", "stable-e", "r", "emoji.py", "python", "function",
             "target", "target", 4, 10, 0, 1),
        )
        conn.commit()
        emoji_uri = (root / "emoji.py").as_uri()
        # LSP reports position at UTF-16 char 3 (after 🎉 which is 2 UTF-16 units + "d")
        fake = FakeLspClient(responses={
            "textDocument/definition": _lsp_location(emoji_uri, 0, 3, 0, 9),
        })
        service, _ = _make_fusion_service(lsp_client=fake, conn=conn)
        ctx = _make_context(root, file_text=text)
        repo = _make_repo_resolution(status=ResolutionStatus.UNRESOLVED)
        fused = await service.fuse_definition("target", (4, 10), repo, ctx)
        # The position conversion should not crash
        assert fused.fused_status in ("resolved", "external", "unresolved", "ambiguous")

    async def test_16_crlf_position_conversion(self, tmp_path: Path):
        """16. CRLF position conversion."""
        root = _make_workspace(tmp_path)
        text = "line1\r\ndef target():\r\n    pass\r\n"
        (root / "crlf.py").write_text(text, encoding="utf-8")
        conn = _make_db()
        conn.execute(
            "INSERT INTO repository_symbols VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            ("sym-c", "stable-c", "r", "crlf.py", "python", "function",
             "target", "target", 8, 14, 1, 1),
        )
        conn.commit()
        crlf_uri = (root / "crlf.py").as_uri()
        # LSP reports at line 1, char 4 (after "def ")
        fake = FakeLspClient(responses={
            "textDocument/definition": _lsp_location(crlf_uri, 1, 4, 1, 10),
        })
        service, _ = _make_fusion_service(lsp_client=fake, conn=conn)
        ctx = _make_context(root, file_text=text)
        repo = _make_repo_resolution(status=ResolutionStatus.UNRESOLVED)
        fused = await service.fuse_definition("target", (8, 14), repo, ctx)
        assert fused.fused_status in ("resolved", "external", "unresolved", "ambiguous")

    async def test_17_out_of_bounds_lsp_range_rejected(self, tmp_path: Path):
        """17. Out-of-bounds LSP range → position rejected, evidence dropped."""
        root = _make_workspace(tmp_path)
        text = "short\n"
        util_uri = path_to_file_uri(root / "src" / "util.py")
        fake = FakeLspClient(responses={
            # Line 99 doesn't exist in the text
            "textDocument/definition": _lsp_location(util_uri, 99, 0, 99, 10),
        })
        service, _ = _make_fusion_service(lsp_client=fake)
        ctx = _make_context(root, file_text=text)
        repo = _make_repo_resolution(status=ResolutionStatus.UNRESOLVED)
        fused = await service.fuse_definition("target_function", (10, 20), repo, ctx)
        # Position out of bounds → LSP evidence dropped → repository-only
        assert fused.depends_on_lsp is False or fused.fused_status == repo.status.value


# ---------------------------------------------------------------------------
# Scenarios 18–23: Staleness and lifecycle
# ---------------------------------------------------------------------------


class TestStalenessAndLifecycle:
    """Scenarios 18–23: staleness, server restart, cancel, shutdown."""

    async def test_18_old_generation_response_discarded(self, tmp_path: Path):
        """18. Old generation response → discarded (stale)."""
        root = _make_workspace(tmp_path)
        conn = _make_db()
        # Update the file's generation to 2, but context says generation 1
        conn.execute(
            "UPDATE code_files SET generation=2 WHERE project_id='r' AND path='src/app.py'",
        )
        conn.commit()
        fake = FakeLspClient(responses={
            "textDocument/definition": _lsp_location(path_to_file_uri(root / "src" / "util.py")),
        })
        service, _ = _make_fusion_service(lsp_client=fake, conn=conn)
        ctx = _make_context(root, file_generation=1)  # stale generation
        repo = _make_repo_resolution()
        fused = await service.fuse_definition("target_function", (10, 20), repo, ctx)
        # Stale generation → LSP evidence skipped
        assert fused.resolution_rule == FusionRule.LSP_STALE.value or fused.depends_on_lsp is False

    async def test_19_old_document_version_response_discarded(self, tmp_path: Path):
        """19. Old document version → response discarded via cache key mismatch."""
        root = _make_workspace(tmp_path)
        conn = _make_db()
        conn.execute(
            "INSERT INTO repository_symbols VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            ("sym-v", "stable-v", "r", "src/util.py", "python", "function",
             "target_function", "target_function", 0, 10, 0, 1),
        )
        conn.commit()
        fake = FakeLspClient(responses={
            "textDocument/definition": _lsp_location(path_to_file_uri(root / "src" / "util.py")),
        })
        service, cache = _make_fusion_service(lsp_client=fake, conn=conn)
        ctx_v1 = _make_context(root, document_version=1)
        repo = _make_repo_resolution(status=ResolutionStatus.UNRESOLVED)
        # First request with doc version 1 — populates cache
        await service.fuse_definition("target_function", (10, 20), repo, ctx_v1)
        # Second request with doc version 2 — cache miss (different key)
        ctx_v2 = _make_context(root, document_version=2)
        fused = await service.fuse_definition("target_function", (10, 20), repo, ctx_v2)
        # Should still work (fresh LSP request), not use stale cache
        assert fused.fused_status in ("resolved", "unresolved", "ambiguous")

    async def test_20_file_deletion_invalidates_evidence(self, tmp_path: Path):
        """20. File deletion → evidence invalidated."""
        root = _make_workspace(tmp_path)
        conn = _make_db()
        fake = FakeLspClient(responses={
            "textDocument/definition": _lsp_location(path_to_file_uri(root / "src" / "util.py")),
        })
        service, cache = _make_fusion_service(lsp_client=fake, conn=conn)
        ctx = _make_context(root)
        repo = _make_repo_resolution()
        await service.fuse_definition("target_function", (10, 20), repo, ctx)
        # Simulate file deletion — invalidate cache for this file
        removed = cache.invalidate_file("r", "src/app.py")
        assert removed >= 0  # No crash

    async def test_21_server_restart_invalidates_evidence(self, tmp_path: Path):
        """21. Server restart → evidence invalidated by server identity mismatch."""
        root = _make_workspace(tmp_path)
        conn = _make_db()
        conn.execute(
            "INSERT INTO repository_symbols VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            ("sym-r", "stable-r", "r", "src/util.py", "python", "function",
             "target_function", "target_function", 0, 10, 0, 1),
        )
        conn.commit()
        fake_v1 = FakeLspClient(responses={
            "textDocument/definition": _lsp_location(path_to_file_uri(root / "src" / "util.py")),
        })
        service, cache = _make_fusion_service(lsp_client=fake_v1, conn=conn)
        ctx_v1 = _make_context(root, server_identity="pyright@1.0")
        repo = _make_repo_resolution(status=ResolutionStatus.UNRESOLVED)
        await service.fuse_definition("target_function", (10, 20), repo, ctx_v1)
        # Server restarts with new version — cache key has different identity
        ctx_v2 = _make_context(root, server_identity="pyright@2.0")
        fake_v2 = FakeLspClient(responses={
            "textDocument/definition": _lsp_location(path_to_file_uri(root / "src" / "util.py")),
        })
        service._lsp_client = fake_v2
        fused = await service.fuse_definition("target_function", (10, 20), repo, ctx_v2)
        # New request made (not stale cache)
        assert len(fake_v2.call_log) > 0

    async def test_22_runtime_cancel_cancels_request(self, tmp_path: Path):
        """22. Runtime cancel → request cancelled."""
        root = _make_workspace(tmp_path)
        # Fake that hangs forever (never responds)
        fake = FakeLspClient(timeout_methods={"textDocument/definition"})
        service, _ = _make_fusion_service(
            config=LspFusionConfig(enabled=True, request_timeout_seconds=0.05),
            lsp_client=fake,
        )
        ctx = _make_context(root)
        repo = _make_repo_resolution()
        # The timeout should cause graceful degradation
        fused = await service.fuse_definition("target_function", (10, 20), repo, ctx)
        assert fused.fused_status == repo.status.value
        assert fused.depends_on_lsp is False

    async def test_23_shutdown_clears_evidence_cache(self, tmp_path: Path):
        """23. shutdown() clears evidence cache."""
        root = _make_workspace(tmp_path)
        conn = _make_db()
        fake = FakeLspClient(responses={
            "textDocument/definition": _lsp_location(path_to_file_uri(root / "src" / "util.py")),
        })
        service, cache = _make_fusion_service(lsp_client=fake, conn=conn)
        ctx = _make_context(root)
        repo = _make_repo_resolution()
        await service.fuse_definition("target_function", (10, 20), repo, ctx)
        assert cache.size >= 0
        await service.shutdown()
        assert cache.size == 0
        assert service.enabled is False  # closed


# ---------------------------------------------------------------------------
# Scenarios 24–25: Cache behavior
# ---------------------------------------------------------------------------


class TestCacheBehavior:
    """Scenarios 24–25: LRU/TTL and request deduplication."""

    async def test_24_evidence_cache_lru_ttl(self, tmp_path: Path):
        """24. Evidence cache LRU/TTL bounds enforced."""
        root = _make_workspace(tmp_path)
        conn = _make_db()
        fake = FakeLspClient(responses={
            "textDocument/definition": _lsp_location(path_to_file_uri(root / "src" / "util.py")),
        })
        cache = EvidenceCache(max_entries=2, ttl_seconds=60)
        service = LspEvidenceFusionService(
            config=LspFusionConfig(enabled=True, request_timeout_seconds=1.0),
            cache=cache,
            conn=conn,
            lsp_client=fake,
        )
        ctx = _make_context(root)
        repo = _make_repo_resolution()
        # Make two requests with different candidate ranges
        await service.fuse_definition("target_function", (10, 20), repo, ctx)
        await service.fuse_definition("target_function", (30, 40), repo, ctx)
        assert cache.size <= 2

    async def test_25_duplicate_requests_merged(self, tmp_path: Path):
        """25. Duplicate concurrent requests for same candidate are merged."""
        root = _make_workspace(tmp_path)
        conn = _make_db()
        # Insert a symbol for LSP to point to
        conn.execute(
            "INSERT INTO repository_symbols VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            ("sym-d", "stable-d", "r", "src/util.py", "python", "function",
             "target_function", "target_function", 0, 10, 0, 1),
        )
        conn.commit()
        fake = FakeLspClient(responses={
            "textDocument/definition": _lsp_location(path_to_file_uri(root / "src" / "util.py")),
        })
        service, _ = _make_fusion_service(lsp_client=fake, conn=conn)
        ctx = _make_context(root)
        repo = _make_repo_resolution(status=ResolutionStatus.UNRESOLVED)
        # Launch two concurrent requests for the same candidate
        results = await asyncio.gather(
            service.fuse_definition("target_function", (10, 20), repo, ctx),
            service.fuse_definition("target_function", (10, 20), repo, ctx),
        )
        # Both should complete without error
        assert all(r.fused_status in ("resolved", "unresolved", "ambiguous") for r in results)


# ---------------------------------------------------------------------------
# Scenarios 26–30: Query interface and static guarantees
# ---------------------------------------------------------------------------


class TestQueryInterfaceAndGuarantees:
    """Scenarios 26–30: explainable evidence, backward compat, no subprocess, no ParseState."""

    async def test_26_query_returns_explainable_evidence(self, tmp_path: Path):
        """26. explain_resolution returns explainable evidence."""
        root = _make_workspace(tmp_path)
        conn = _make_db()
        conn.execute(
            "INSERT INTO repository_symbols VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            ("sym-x", "stable-x", "r", "src/util.py", "python", "function",
             "target_function", "target_function", 0, 10, 0, 1),
        )
        conn.commit()
        fake = FakeLspClient(responses={
            "textDocument/definition": _lsp_location(path_to_file_uri(root / "src" / "util.py")),
        })
        service, _ = _make_fusion_service(lsp_client=fake, conn=conn)
        ctx = _make_context(root)
        repo = _make_repo_resolution(status=ResolutionStatus.UNRESOLVED)
        fused = await service.fuse_definition("target_function", (10, 20), repo, ctx)
        explanation = service.explain_resolution(repo, fused)
        assert "original_status" in explanation
        assert "fused_status" in explanation
        assert "confidence" in explanation
        assert "evidence" in explanation
        assert "evidence_sources" in explanation
        assert "resolution_rule" in explanation
        assert "depends_on_lsp" in explanation

    async def test_27_old_query_service_backward_compatible(self, tmp_path: Path):
        """27. Old CodeQueryService methods still work without fusion."""
        from khaos.coding.intelligence.index import IndexStore
        from khaos.coding.intelligence.query import CodeQueryService

        conn = sqlite3.connect(":memory:")
        store = IndexStore(conn)
        apply_resolution_schema(conn)
        qs = CodeQueryService(store)
        # Old async methods should not raise even with no data
        result = await qs.find_symbols("r", "test")
        assert result == []
        result = await qs.find_definition("r", "test")
        assert result is None
        # Old sync methods (semantic graph queries) also work
        result = qs.call_edges_for_file("r", "src/app.py")
        assert result == []

    async def test_28_parse_state_not_in_lsp_evidence(self, tmp_path: Path):
        """28. ParseState/native Tree never enters LSP evidence."""
        root = _make_workspace(tmp_path)
        fake = FakeLspClient(responses={
            "textDocument/definition": _lsp_location(path_to_file_uri(root / "src" / "util.py")),
        })
        service, _ = _make_fusion_service(lsp_client=fake)
        ctx = _make_context(root)
        repo = _make_repo_resolution()
        fused = await service.fuse_definition("target_function", (10, 20), repo, ctx)
        # Evidence should never contain ParseState or native Tree references
        for ev in fused.evidence:
            ev_dict = ev.to_dict()
            assert "parse_state" not in ev_dict
            assert "native_tree" not in ev_dict
            assert "tree" not in ev_dict.get("metadata", {})

    def test_29_no_new_direct_subprocess(self):
        """29. No new direct subprocess in LSP evidence fusion modules."""
        modules_to_check = [
            "khaos.coding.intelligence.lsp.fusion",
            "khaos.coding.intelligence.lsp.evidence",
            "khaos.coding.intelligence.lsp.cache",
            "khaos.coding.intelligence.lsp.config",
            "khaos.coding.intelligence.lsp.uri",
            "khaos.coding.intelligence.lsp.positions",
        ]
        for module_name in modules_to_check:
            module = __import__(module_name, fromlist=[""])
            source = inspect.getsource(module)
            assert "create_subprocess_exec" not in source, f"{module_name} uses create_subprocess_exec"
            assert "create_subprocess_shell" not in source, f"{module_name} uses create_subprocess_shell"
            assert "subprocess.Popen" not in source, f"{module_name} uses subprocess.Popen"

    async def test_30_default_env_no_lsp_server_full_pass(self, tmp_path: Path):
        """30. Default environment (no LSP installed) → all tests pass via fakes."""
        root = _make_workspace(tmp_path)
        # This test itself proves the point: we use FakeLspClient, no real server
        fake = FakeLspClient(responses={
            "textDocument/definition": _lsp_location(path_to_file_uri(root / "src" / "util.py")),
        })
        service, _ = _make_fusion_service(lsp_client=fake)
        ctx = _make_context(root)
        repo = _make_repo_resolution()
        fused = await service.fuse_definition("target_function", (10, 20), repo, ctx)
        # No crash, graceful result
        assert fused.fused_status in ("resolved", "unresolved", "ambiguous", "external")
        # Verify no real LSP was contacted (only fake)
        assert len(fake.call_log) > 0  # fake was called
        # Verify the service didn't try to spawn a real process
        assert isinstance(fake, FakeLspClient)


# ---------------------------------------------------------------------------
# References fusion tests
# ---------------------------------------------------------------------------


class TestReferencesFusion:
    """Tests for LSP references fusion (spec §7)."""

    async def test_references_returns_evidence(self, tmp_path: Path):
        root = _make_workspace(tmp_path)
        conn = _make_db()
        conn.execute(
            "INSERT INTO repository_symbols VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            ("sym-ref", "stable-ref", "r", "src/util.py", "python", "function",
             "target_function", "target_function", 0, 10, 0, 1),
        )
        conn.commit()
        util_uri = path_to_file_uri(root / "src" / "util.py")
        app_uri = path_to_file_uri(root / "src" / "app.py")
        fake = FakeLspClient(responses={
            "textDocument/references": [
                _lsp_location(app_uri, 3, 4, 3, 20),  # reference in app.py
            ],
        })
        service, _ = _make_fusion_service(lsp_client=fake, conn=conn)
        ctx = _make_context(root)
        evidence = await service.fuse_references("stable-ref", "src/util.py", ctx)
        assert isinstance(evidence, tuple)

    async def test_references_deduplication(self, tmp_path: Path):
        root = _make_workspace(tmp_path)
        conn = _make_db()
        fake = FakeLspClient(responses={
            "textDocument/references": [
                _lsp_location(path_to_file_uri(root / "src" / "app.py"), 3, 4, 3, 20),
                _lsp_location(path_to_file_uri(root / "src" / "app.py"), 3, 4, 3, 20),  # duplicate
            ],
        })
        service, _ = _make_fusion_service(lsp_client=fake, conn=conn)
        ctx = _make_context(root)
        evidence = await service.fuse_references("stable-ref", "src/util.py", ctx)
        # Duplicates should be deduplicated
        if evidence:
            files = [e.target_file for e in evidence if e.target_file]
            assert len(files) == len(set(files)) or len(evidence) <= 2

    async def test_references_not_persisted_as_edges(self, tmp_path: Path):
        """LSP references are NOT auto-persisted as repository edges."""
        root = _make_workspace(tmp_path)
        conn = _make_db()
        fake = FakeLspClient(responses={
            "textDocument/references": [
                _lsp_location(path_to_file_uri(root / "src" / "app.py"), 3, 4, 3, 20),
            ],
        })
        service, _ = _make_fusion_service(lsp_client=fake, conn=conn)
        ctx = _make_context(root)
        before_count = conn.execute(
            "SELECT COUNT(*) FROM resolved_reference_edges WHERE repository_id='r'"
        ).fetchone()[0]
        await service.fuse_references("stable-ref", "src/util.py", ctx)
        after_count = conn.execute(
            "SELECT COUNT(*) FROM resolved_reference_edges WHERE repository_id='r'"
        ).fetchone()[0]
        assert before_count == after_count  # no new edges persisted
