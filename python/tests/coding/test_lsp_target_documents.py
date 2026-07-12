"""LSP target document and reference identity closure tests (Batch 6.1).

Verifies the three correctness fixes:
1. Cross-file Definition position conversion uses the TARGET file's text
   (loaded via WorkspaceDocumentProvider), not the source file's text.
2. References requests use the target symbol's actual definition position
   (queried from repository_symbols), not a fixed 0:0.
3. References cache keys bind to the TARGET symbol's identity and the
   TARGET file's state — different symbols never share cache entries.

Also verifies:
4. Full Location and LocationLink[] support (targetSelectionRange preferred).
5. other-task-workspace URIs are completely rejected (no external evidence).
6. External/missing target files are never falsely promoted to resolved.
"""
from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from khaos.coding.intelligence.lsp.cache import EvidenceCache
from khaos.coding.intelligence.lsp.config import LspFusionConfig
from khaos.coding.intelligence.lsp.documents import (
    DiskWorkspaceDocumentProvider,
    WorkspaceDocument,
    WorkspaceDocumentProvider,
)
from khaos.coding.intelligence.lsp.evidence import (
    EvidenceSource,
    EvidenceType,
    FusionRule,
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
    """Scriptable fake LSP client that records all requests."""

    def __init__(self, *, responses: dict[str, Any] | None = None) -> None:
        self.responses = responses or {}
        self.call_log: list[tuple[str, dict]] = []
        self._closed = False

    async def request(self, method: str, params: dict) -> Any:
        if self._closed:
            raise RuntimeError("LSP client is closed")
        self.call_log.append((method, params))
        await asyncio.sleep(0)
        return self.responses.get(method, [])

    async def close(self) -> None:
        self._closed = True


class FakeDocumentProvider:
    """In-memory document provider for testing without disk I/O.

    Documents are pre-registered via ``documents`` dict mapping
    repository-relative path → WorkspaceDocument.
    """

    def __init__(self, documents: dict[str, WorkspaceDocument]) -> None:
        self.documents = documents
        self.load_count = 0

    async def load_document(
        self,
        repository_id: str,
        workspace_root: Path,
        file_path: str,
        *,
        other_workspace_roots: tuple[Path, ...] = (),
    ) -> WorkspaceDocument | None:
        self.load_count += 1
        return self.documents.get(file_path)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_db() -> sqlite3.Connection:
    from khaos.coding.intelligence.index import IndexStore
    store = IndexStore(sqlite3.connect(":memory:", check_same_thread=False))
    conn = store._conn
    apply_resolution_schema(conn)
    return conn


def _insert_code_file(conn: sqlite3.Connection, repo_id: str, path: str, generation: int = 1) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO code_files VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (repo_id, path, "python", 1, 100, 0, "hash", "", "{}", 0, generation),
    )
    conn.commit()


def _insert_symbol(
    conn: sqlite3.Connection,
    repo_id: str,
    path: str,
    stable_id: str,
    name: str,
    byte_start: int,
    byte_end: int,
    generation: int = 1,
    qualified_name: str | None = None,
) -> None:
    conn.execute(
        "INSERT INTO repository_symbols VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (f"sym-{stable_id}", stable_id, repo_id, path, "python", "function",
         name, qualified_name or name, byte_start, byte_end, 0, generation),
    )
    conn.commit()


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
    file_text: str = "def target_function():\n    pass\n",
    file_path: str = "src/app.py",
    file_generation: int = 1,
    server_identity: str = "fake-lsp@1.0",
    other_workspace_roots: tuple[Path, ...] = (),
) -> FusionContext:
    return FusionContext(
        repository_id="r",
        workspace_id="w",
        file_path=file_path,
        file_text=file_text,
        content_hash=compute_content_hash(file_text),
        file_generation=file_generation,
        document_version=1,
        server_identity=server_identity,
        workspace_root=workspace_root,
        other_workspace_roots=other_workspace_roots,
    )


def _make_fusion_service(
    *,
    conn: sqlite3.Connection,
    lsp_client: FakeLspClient | None = None,
    document_provider: WorkspaceDocumentProvider | None = None,
    config: LspFusionConfig | None = None,
) -> tuple[LspEvidenceFusionService, EvidenceCache]:
    cfg = config or LspFusionConfig(enabled=True, request_timeout_seconds=1.0)
    cache = EvidenceCache(max_entries=100, ttl_seconds=60)
    service = LspEvidenceFusionService(
        config=cfg,
        cache=cache,
        conn=conn,
        lsp_client=lsp_client,
        document_provider=document_provider,
    )
    return service, cache


def _lsp_location(uri: str, sl: int = 0, sc: int = 0, el: int = 0, ec: int = 10) -> dict:
    return {
        "uri": uri,
        "range": {
            "start": {"line": sl, "character": sc},
            "end": {"line": el, "character": ec},
        },
    }


def _lsp_location_link(
    uri: str,
    sel_sl: int = 0, sel_sc: int = 0, sel_el: int = 0, sel_ec: int = 10,
    tgt_sl: int = 0, tgt_sc: int = 0, tgt_el: int = 0, tgt_ec: int = 20,
) -> dict:
    return {
        "targetUri": uri,
        "targetSelectionRange": {
            "start": {"line": sel_sl, "character": sel_sc},
            "end": {"line": sel_el, "character": sel_ec},
        },
        "targetRange": {
            "start": {"line": tgt_sl, "character": tgt_sc},
            "end": {"line": tgt_el, "character": tgt_ec},
        },
    }


def _make_doc(path: str, text: str, *, generation: int = 1, indexed: bool = True) -> WorkspaceDocument:
    return WorkspaceDocument(
        path=path,
        text=text,
        content_hash=compute_content_hash(text),
        generation=generation,
        indexed=indexed,
    )


# ---------------------------------------------------------------------------
# 1. Cross-file Definition position conversion
# ---------------------------------------------------------------------------


class TestCrossFileDefinitionPositionConversion:
    """Verify definition position conversion uses the TARGET file's text."""

    async def test_different_line_lengths_source_vs_target(self, tmp_path: Path):
        """Source and target files have different line lengths.

        If the source file's text were used, the byte offset would be wrong.
        """
        root = tmp_path / "ws"
        root.mkdir()
        # Source file has very long first line
        source_text = "x" * 100 + "\ndef caller():\n    target()\n"
        (root / "src").mkdir()
        (root / "src" / "app.py").write_text(source_text, encoding="utf-8")
        # Target file has short first line; definition on line 1
        target_text = "import os\n\ndef target():\n    pass\n"
        (root / "src" / "util.py").write_text(target_text, encoding="utf-8")

        conn = _make_db()
        _insert_code_file(conn, "r", "src/app.py")
        _insert_code_file(conn, "r", "src/util.py")
        # Symbol at line 2, char 4 to char 10
        # "import os\n" = 10 bytes, "\n" = 1 byte, "def " = 4 bytes → byte 15
        _insert_symbol(conn, "r", "src/util.py", "stable-target", "target",
                       byte_start=15, byte_end=21)

        target_doc = _make_doc("src/util.py", target_text)
        provider = FakeDocumentProvider({"src/util.py": target_doc})

        util_uri = path_to_file_uri(root / "src" / "util.py")
        # LSP says definition is at line 2, char 4 to char 10
        fake = FakeLspClient(responses={
            "textDocument/definition": _lsp_location(util_uri, sl=2, sc=4, el=2, ec=10),
        })
        service, _ = _make_fusion_service(
            conn=conn, lsp_client=fake, document_provider=provider,
        )
        ctx = _make_context(root, file_text=source_text)
        repo = _make_repo_resolution(
            status=ResolutionStatus.UNRESOLVED,
            target_symbol_id=None,
            target_file=None,
        )
        fused = await service.fuse_definition("target", (110, 116), repo, ctx)

        # LSP should have produced internal evidence pointing to src/util.py
        lsp_evidence = [e for e in fused.evidence if e.source.value == "lsp-definition"]
        assert len(lsp_evidence) == 1
        ev = lsp_evidence[0]
        assert ev.target_file == "src/util.py"
        # Byte offset must be based on TARGET file text, not source text
        # In target_text: "import os\n\ndef target():\n    pass\n"
        # Line 2, char 4 → byte offset 15 (after "import os\n\ndef ")
        assert ev.metadata["byte_start"] == 15
        assert ev.metadata["byte_end"] == 21
        # Symbol lookup should find stable-target
        assert ev.target_symbol_id == "stable-target"
        # Should promote to resolved
        assert fused.fused_status == "resolved"
        assert fused.resolution_rule == FusionRule.LSP_PROMOTED.value

    async def test_definition_not_on_first_line(self, tmp_path: Path):
        """Definition is on line 3, not line 0."""
        root = tmp_path / "ws"
        root.mkdir()
        target_text = "# header\n# comment\n\ndef target():\n    return 42\n"
        (root / "src").mkdir()
        (root / "src" / "util.py").write_text(target_text, encoding="utf-8")
        (root / "src" / "app.py").write_text("def caller():\n    target()\n")

        conn = _make_db()
        _insert_code_file(conn, "r", "src/app.py")
        _insert_code_file(conn, "r", "src/util.py")
        # "def target()" starts at byte 24 (after "# header\n# comment\n\n")
        # "# header\n" = 9, "# comment\n" = 10, "\n" = 1, "def " = 4 → byte 24
        _insert_symbol(conn, "r", "src/util.py", "stable-target", "target",
                       byte_start=24, byte_end=30)

        target_doc = _make_doc("src/util.py", target_text)
        provider = FakeDocumentProvider({"src/util.py": target_doc})

        util_uri = path_to_file_uri(root / "src" / "util.py")
        fake = FakeLspClient(responses={
            "textDocument/definition": _lsp_location(util_uri, sl=3, sc=4, el=3, ec=10),
        })
        service, _ = _make_fusion_service(
            conn=conn, lsp_client=fake, document_provider=provider,
        )
        ctx = _make_context(root)
        repo = _make_repo_resolution(status=ResolutionStatus.UNRESOLVED, target_symbol_id=None)
        fused = await service.fuse_definition("target", (10, 16), repo, ctx)

        lsp_evidence = [e for e in fused.evidence if e.source.value == "lsp-definition"]
        assert len(lsp_evidence) == 1
        ev = lsp_evidence[0]
        # Byte offset must be 24, not 4 (which is what source-text conversion would give)
        assert ev.metadata["byte_start"] == 24
        assert ev.target_symbol_id == "stable-target"
        assert fused.fused_status == "resolved"

    async def test_target_file_with_chinese_and_emoji(self, tmp_path: Path):
        """Target file contains Chinese characters and Emoji.

        UTF-16 position conversion must handle CJK (BMP) and Emoji
        (supplementary plane) correctly using the TARGET file's text.
        """
        root = tmp_path / "ws"
        root.mkdir()
        # Target file: Chinese comment, then function definition
        # "中文注释\n😀emoji\n\ndef target():\n    pass\n"
        target_text = "中文注释\n😀emoji\n\ndef target():\n    pass\n"
        (root / "src").mkdir()
        (root / "src" / "util.py").write_text(target_text, encoding="utf-8")
        (root / "src" / "app.py").write_text("def caller():\n    target()\n")

        conn = _make_db()
        _insert_code_file(conn, "r", "src/app.py")
        _insert_code_file(conn, "r", "src/util.py")
        # "def target()" starts after "中文注释\n😀emoji\n\n"
        # "中文注释" = 4*3=12 bytes, "\n" = 1, "😀emoji" = 4+5=9 bytes, "\n\n" = 2
        # Total prefix: 12 + 1 + 9 + 2 = 24 bytes, + "def " = 4 → byte 28
        _insert_symbol(conn, "r", "src/util.py", "stable-target", "target",
                       byte_start=28, byte_end=34)

        target_doc = _make_doc("src/util.py", target_text)
        provider = FakeDocumentProvider({"src/util.py": target_doc})

        util_uri = path_to_file_uri(root / "src" / "util.py")
        # LSP position: line 3, char 4 (UTF-16 code units)
        # "def target()" → char 4 = byte 4 within the line
        fake = FakeLspClient(responses={
            "textDocument/definition": _lsp_location(util_uri, sl=3, sc=4, el=3, ec=10),
        })
        service, _ = _make_fusion_service(
            conn=conn, lsp_client=fake, document_provider=provider,
        )
        ctx = _make_context(root)
        repo = _make_repo_resolution(status=ResolutionStatus.UNRESOLVED, target_symbol_id=None)
        fused = await service.fuse_definition("target", (10, 16), repo, ctx)

        lsp_evidence = [e for e in fused.evidence if e.source.value == "lsp-definition"]
        assert len(lsp_evidence) == 1
        ev = lsp_evidence[0]
        # Byte offset must be 28 (based on target file's UTF-8 bytes)
        assert ev.metadata["byte_start"] == 28
        assert ev.target_symbol_id == "stable-target"
        assert fused.fused_status == "resolved"

    async def test_crlf_target_file(self, tmp_path: Path):
        """Target file uses CRLF line endings.

        Position conversion must handle CRLF correctly using the TARGET
        file's text.
        """
        root = tmp_path / "ws"
        root.mkdir()
        # Target file with CRLF
        target_text = "# header\r\ndef target():\r\n    pass\r\n"
        (root / "src").mkdir()
        (root / "src" / "util.py").write_text(target_text, encoding="utf-8")
        (root / "src" / "app.py").write_text("def caller():\n    target()\n")

        conn = _make_db()
        _insert_code_file(conn, "r", "src/app.py")
        _insert_code_file(conn, "r", "src/util.py")
        # "def target()" starts after "# header\r\n" = 10 bytes, + "def " = 4 → byte 14
        _insert_symbol(conn, "r", "src/util.py", "stable-target", "target",
                       byte_start=14, byte_end=20)

        target_doc = _make_doc("src/util.py", target_text)
        provider = FakeDocumentProvider({"src/util.py": target_doc})

        util_uri = path_to_file_uri(root / "src" / "util.py")
        # LSP position: line 1, char 4
        fake = FakeLspClient(responses={
            "textDocument/definition": _lsp_location(util_uri, sl=1, sc=4, el=1, ec=10),
        })
        service, _ = _make_fusion_service(
            conn=conn, lsp_client=fake, document_provider=provider,
        )
        ctx = _make_context(root)
        repo = _make_repo_resolution(status=ResolutionStatus.UNRESOLVED, target_symbol_id=None)
        fused = await service.fuse_definition("target", (10, 16), repo, ctx)

        lsp_evidence = [e for e in fused.evidence if e.source.value == "lsp-definition"]
        assert len(lsp_evidence) == 1
        ev = lsp_evidence[0]
        # Byte offset must be 14 (after "# header\r\n" + "def ")
        assert ev.metadata["byte_start"] == 14
        assert ev.target_symbol_id == "stable-target"
        assert fused.fused_status == "resolved"

    async def test_correct_stable_symbol_id(self, tmp_path: Path):
        """The correct stable_symbol_id is resolved from the target file."""
        root = tmp_path / "ws"
        root.mkdir()
        target_text = "def target():\n    pass\n"
        (root / "src").mkdir()
        (root / "src" / "util.py").write_text(target_text, encoding="utf-8")
        (root / "src" / "app.py").write_text("def caller():\n    target()\n")

        conn = _make_db()
        _insert_code_file(conn, "r", "src/app.py")
        _insert_code_file(conn, "r", "src/util.py")
        _insert_symbol(conn, "r", "src/util.py", "stable-target", "target",
                       byte_start=4, byte_end=10)

        target_doc = _make_doc("src/util.py", target_text)
        provider = FakeDocumentProvider({"src/util.py": target_doc})

        util_uri = path_to_file_uri(root / "src" / "util.py")
        fake = FakeLspClient(responses={
            "textDocument/definition": _lsp_location(util_uri, sl=0, sc=4, el=0, ec=10),
        })
        service, _ = _make_fusion_service(
            conn=conn, lsp_client=fake, document_provider=provider,
        )
        ctx = _make_context(root)
        repo = _make_repo_resolution(
            status=ResolutionStatus.RESOLVED,
            target_symbol_id="stable-target",
            target_file="src/util.py",
        )
        fused = await service.fuse_definition("target", (10, 16), repo, ctx)

        # LSP confirmed: same target
        assert fused.resolution_rule == FusionRule.LSP_CONFIRMED.value
        assert fused.target_symbol_id == "stable-target"

    async def test_source_text_conversion_would_be_wrong(self, tmp_path: Path):
        """Counter-example: using source file text would give wrong byte offset.

        Source file has CJK on line 0, target file has ASCII. If the source
        file's text were used for position conversion, the byte offset
        would be wrong because CJK takes 3 bytes in UTF-8 but 1 UTF-16
        code unit in LSP.
        """
        root = tmp_path / "ws"
        root.mkdir()
        # Source file has CJK — line 0 is "中文"
        source_text = "中文\ndef caller():\n    target()\n"
        # Target file is pure ASCII
        target_text = "def target():\n    pass\n"
        (root / "src").mkdir()
        (root / "src" / "app.py").write_text(source_text, encoding="utf-8")
        (root / "src" / "util.py").write_text(target_text, encoding="utf-8")

        conn = _make_db()
        _insert_code_file(conn, "r", "src/app.py")
        _insert_code_file(conn, "r", "src/util.py")
        _insert_symbol(conn, "r", "src/util.py", "stable-target", "target",
                       byte_start=4, byte_end=10)

        target_doc = _make_doc("src/util.py", target_text)
        provider = FakeDocumentProvider({"src/util.py": target_doc})

        util_uri = path_to_file_uri(root / "src" / "util.py")
        # LSP says line 0, char 4 to 10 (pointing at "target" in target file)
        fake = FakeLspClient(responses={
            "textDocument/definition": _lsp_location(util_uri, sl=0, sc=4, el=0, ec=10),
        })
        service, _ = _make_fusion_service(
            conn=conn, lsp_client=fake, document_provider=provider,
        )
        ctx = _make_context(root, file_text=source_text)
        repo = _make_repo_resolution(status=ResolutionStatus.UNRESOLVED, target_symbol_id=None)
        fused = await service.fuse_definition("target", (20, 26), repo, ctx)

        lsp_evidence = [e for e in fused.evidence if e.source.value == "lsp-definition"]
        assert len(lsp_evidence) == 1
        ev = lsp_evidence[0]
        # Correct: byte_start=4 (using target text "def target():\n...")
        # Wrong (if source text were used): "中文\n" has 7 bytes, char 4 → byte 7
        assert ev.metadata["byte_start"] == 4
        assert ev.target_symbol_id == "stable-target"


# ---------------------------------------------------------------------------
# 2. LocationLink support
# ---------------------------------------------------------------------------


class TestLocationLinkSupport:
    """Verify full Location and LocationLink[] support."""

    async def test_location_link_single(self, tmp_path: Path):
        """Single LocationLink is normalized correctly."""
        root = tmp_path / "ws"
        root.mkdir()
        target_text = "def target():\n    pass\n"
        (root / "src").mkdir()
        (root / "src" / "util.py").write_text(target_text, encoding="utf-8")
        (root / "src" / "app.py").write_text("def caller():\n    target()\n")

        conn = _make_db()
        _insert_code_file(conn, "r", "src/app.py")
        _insert_code_file(conn, "r", "src/util.py")
        # Symbol at the selection range (char 4 to 10)
        _insert_symbol(conn, "r", "src/util.py", "stable-target", "target",
                       byte_start=4, byte_end=10)

        target_doc = _make_doc("src/util.py", target_text)
        provider = FakeDocumentProvider({"src/util.py": target_doc})

        util_uri = path_to_file_uri(root / "src" / "util.py")
        # LocationLink: targetSelectionRange = char 4-10, targetRange = char 0-16
        fake = FakeLspClient(responses={
            "textDocument/definition": _lsp_location_link(
                util_uri,
                sel_sl=0, sel_sc=4, sel_el=0, sel_ec=10,  # selection range
                tgt_sl=0, tgt_sc=0, tgt_el=0, tgt_ec=16,  # full range
            ),
        })
        service, _ = _make_fusion_service(
            conn=conn, lsp_client=fake, document_provider=provider,
        )
        ctx = _make_context(root)
        repo = _make_repo_resolution(status=ResolutionStatus.UNRESOLVED, target_symbol_id=None)
        fused = await service.fuse_definition("target", (10, 16), repo, ctx)

        lsp_evidence = [e for e in fused.evidence if e.source.value == "lsp-definition"]
        assert len(lsp_evidence) == 1
        # Should use targetSelectionRange (char 4-10), not targetRange (char 0-16)
        assert ev_metadata_byte_start(lsp_evidence[0]) == 4
        assert ev_metadata_byte_end(lsp_evidence[0]) == 10
        assert fused.fused_status == "resolved"

    async def test_location_link_array(self, tmp_path: Path):
        """LocationLink[] (array of LocationLink) is normalized correctly."""
        root = tmp_path / "ws"
        root.mkdir()
        target_text = "def target():\n    pass\n"
        (root / "src").mkdir()
        (root / "src" / "util.py").write_text(target_text, encoding="utf-8")
        (root / "src" / "app.py").write_text("def caller():\n    target()\n")

        conn = _make_db()
        _insert_code_file(conn, "r", "src/app.py")
        _insert_code_file(conn, "r", "src/util.py")
        _insert_symbol(conn, "r", "src/util.py", "stable-target", "target",
                       byte_start=4, byte_end=10)

        target_doc = _make_doc("src/util.py", target_text)
        provider = FakeDocumentProvider({"src/util.py": target_doc})

        util_uri = path_to_file_uri(root / "src" / "util.py")
        # LocationLink[] with one valid and one invalid entry
        fake = FakeLspClient(responses={
            "textDocument/definition": [
                _lsp_location_link(util_uri, sel_sc=4, sel_ec=10),
                {"targetUri": None, "targetSelectionRange": {}},  # invalid
            ],
        })
        service, _ = _make_fusion_service(
            conn=conn, lsp_client=fake, document_provider=provider,
        )
        ctx = _make_context(root)
        repo = _make_repo_resolution(status=ResolutionStatus.UNRESOLVED, target_symbol_id=None)
        fused = await service.fuse_definition("target", (10, 16), repo, ctx)

        # Only the valid LocationLink should produce evidence
        lsp_evidence = [e for e in fused.evidence if e.source.value == "lsp-definition"]
        assert len(lsp_evidence) == 1
        assert fused.fused_status == "resolved"

    async def test_location_link_falls_back_to_target_range(self, tmp_path: Path):
        """LocationLink without targetSelectionRange falls back to targetRange."""
        root = tmp_path / "ws"
        root.mkdir()
        target_text = "def target():\n    pass\n"
        (root / "src").mkdir()
        (root / "src" / "util.py").write_text(target_text, encoding="utf-8")
        (root / "src" / "app.py").write_text("def caller():\n    target()\n")

        conn = _make_db()
        _insert_code_file(conn, "r", "src/app.py")
        _insert_code_file(conn, "r", "src/util.py")
        _insert_symbol(conn, "r", "src/util.py", "stable-target", "target",
                       byte_start=4, byte_end=10)

        target_doc = _make_doc("src/util.py", target_text)
        provider = FakeDocumentProvider({"src/util.py": target_doc})

        util_uri = path_to_file_uri(root / "src" / "util.py")
        # LocationLink with only targetRange (no targetSelectionRange)
        link = {
            "targetUri": util_uri,
            "targetRange": {
                "start": {"line": 0, "character": 4},
                "end": {"line": 0, "character": 10},
            },
        }
        fake = FakeLspClient(responses={"textDocument/definition": link})
        service, _ = _make_fusion_service(
            conn=conn, lsp_client=fake, document_provider=provider,
        )
        ctx = _make_context(root)
        repo = _make_repo_resolution(status=ResolutionStatus.UNRESOLVED, target_symbol_id=None)
        fused = await service.fuse_definition("target", (10, 16), repo, ctx)

        lsp_evidence = [e for e in fused.evidence if e.source.value == "lsp-definition"]
        assert len(lsp_evidence) == 1
        assert ev_metadata_byte_start(lsp_evidence[0]) == 4

    async def test_invalid_location_entries_discarded(self, tmp_path: Path):
        """Invalid entries in Location[] are silently discarded."""
        root = tmp_path / "ws"
        root.mkdir()
        (root / "src").mkdir()
        (root / "src" / "app.py").write_text("def caller():\n    target()\n")

        conn = _make_db()
        _insert_code_file(conn, "r", "src/app.py")

        fake = FakeLspClient(responses={
            "textDocument/definition": [
                "not a dict",  # invalid
                {"uri": None, "range": {}},  # invalid
                {"range": {}},  # missing uri
                42,  # invalid
            ],
        })
        service, _ = _make_fusion_service(conn=conn, lsp_client=fake)
        ctx = _make_context(root)
        repo = _make_repo_resolution(status=ResolutionStatus.UNRESOLVED)
        fused = await service.fuse_definition("target", (10, 16), repo, ctx)

        # No valid evidence → repository-only
        assert fused.depends_on_lsp is False
        assert len(fused.evidence) == 1  # only repo evidence


def ev_metadata_byte_start(evidence) -> int:
    return evidence.metadata.get("byte_start", -1)

def ev_metadata_byte_end(evidence) -> int:
    return evidence.metadata.get("byte_end", -1)


# ---------------------------------------------------------------------------
# 3. References request positioning
# ---------------------------------------------------------------------------


class TestReferencesRequestPositioning:
    """Verify references requests use the target symbol's actual position."""

    async def test_references_uses_symbol_definition_position(self, tmp_path: Path):
        """References request is sent at the symbol's definition position."""
        root = tmp_path / "ws"
        root.mkdir()
        target_text = "# header\ndef target():\n    pass\n"
        (root / "src").mkdir()
        (root / "src" / "util.py").write_text(target_text, encoding="utf-8")
        (root / "src" / "app.py").write_text("def caller():\n    target()\n")

        conn = _make_db()
        _insert_code_file(conn, "r", "src/app.py")
        _insert_code_file(conn, "r", "src/util.py")
        # Symbol "target" starts at byte 13 (after "# header\ndef "), line 1, char 4
        _insert_symbol(conn, "r", "src/util.py", "stable-target", "target",
                       byte_start=13, byte_end=19)

        target_doc = _make_doc("src/util.py", target_text)
        provider = FakeDocumentProvider({"src/util.py": target_doc})

        fake = FakeLspClient(responses={
            "textDocument/references": [],
        })
        service, _ = _make_fusion_service(
            conn=conn, lsp_client=fake, document_provider=provider,
        )
        ctx = _make_context(root)
        evidence = await service.fuse_references("stable-target", "src/util.py", ctx)

        # Verify the LSP request was sent at the correct position
        assert len(fake.call_log) == 1
        method, params = fake.call_log[0]
        assert method == "textDocument/references"
        # Position should be line 1, char 4 (the definition position)
        assert params["position"]["line"] == 1
        assert params["position"]["character"] == 4

    async def test_references_not_at_zero_zero(self, tmp_path: Path):
        """References request must NOT use fixed 0:0 position."""
        root = tmp_path / "ws"
        root.mkdir()
        target_text = "class Foo:\n    def method(self):\n        pass\n"
        (root / "src").mkdir()
        (root / "src" / "util.py").write_text(target_text, encoding="utf-8")
        (root / "src" / "app.py").write_text("f = Foo()\nf.method()\n")

        conn = _make_db()
        _insert_code_file(conn, "r", "src/app.py")
        _insert_code_file(conn, "r", "src/util.py")
        # "method" starts at byte 19 (after "class Foo:\n    def "), line 1, char 8
        _insert_symbol(conn, "r", "src/util.py", "stable-method", "method",
                       byte_start=19, byte_end=25)

        target_doc = _make_doc("src/util.py", target_text)
        provider = FakeDocumentProvider({"src/util.py": target_doc})

        fake = FakeLspClient(responses={"textDocument/references": []})
        service, _ = _make_fusion_service(
            conn=conn, lsp_client=fake, document_provider=provider,
        )
        ctx = _make_context(root)
        await service.fuse_references("stable-method", "src/util.py", ctx)

        assert len(fake.call_log) == 1
        _, params = fake.call_log[0]
        # Must NOT be 0:0
        assert not (params["position"]["line"] == 0 and params["position"]["character"] == 0)
        # Should be line 1, char 8
        assert params["position"]["line"] == 1
        assert params["position"]["character"] == 8

    async def test_references_deleted_symbol_returns_empty(self, tmp_path: Path):
        """When the target symbol is deleted, references returns empty."""
        root = tmp_path / "ws"
        root.mkdir()
        (root / "src").mkdir()
        (root / "src" / "app.py").write_text("def caller():\n    pass\n")

        conn = _make_db()
        _insert_code_file(conn, "r", "src/app.py")
        # No symbol inserted — symbol is "deleted"

        fake = FakeLspClient(responses={"textDocument/references": []})
        service, _ = _make_fusion_service(conn=conn, lsp_client=fake)
        ctx = _make_context(root)
        evidence = await service.fuse_references("stable-deleted", "src/util.py", ctx)

        assert evidence == ()
        # No LSP request should be sent for a deleted symbol
        assert len(fake.call_log) == 0

    async def test_references_stale_target_generation_returns_empty(self, tmp_path: Path):
        """When target file generation changed, references returns empty."""
        root = tmp_path / "ws"
        root.mkdir()
        target_text = "def target():\n    pass\n"
        (root / "src").mkdir()
        (root / "src" / "util.py").write_text(target_text, encoding="utf-8")
        (root / "src" / "app.py").write_text("def caller():\n    target()\n")

        conn = _make_db()
        _insert_code_file(conn, "r", "src/app.py")
        _insert_code_file(conn, "r", "src/util.py", generation=1)
        # Symbol indexed at generation 1
        _insert_symbol(conn, "r", "src/util.py", "stable-target", "target",
                       byte_start=4, byte_end=10, generation=1)

        # But the document provider returns generation 2 (file was re-indexed)
        target_doc = _make_doc("src/util.py", target_text, generation=2)
        provider = FakeDocumentProvider({"src/util.py": target_doc})

        fake = FakeLspClient(responses={"textDocument/references": []})
        service, _ = _make_fusion_service(
            conn=conn, lsp_client=fake, document_provider=provider,
        )
        ctx = _make_context(root)
        evidence = await service.fuse_references("stable-target", "src/util.py", ctx)

        # Stale generation → no LSP request, empty evidence
        assert evidence == ()
        assert len(fake.call_log) == 0


# ---------------------------------------------------------------------------
# 4. References cache identity
# ---------------------------------------------------------------------------


class TestReferencesCacheIdentity:
    """Verify references cache keys bind to the target symbol identity."""

    async def test_two_symbols_produce_different_cache_keys(self, tmp_path: Path):
        """Symbol A and B in the same file produce different cache keys."""
        root = tmp_path / "ws"
        root.mkdir()
        target_text = "def alpha():\n    pass\n\ndef beta():\n    pass\n"
        (root / "src").mkdir()
        (root / "src" / "util.py").write_text(target_text, encoding="utf-8")
        (root / "src" / "app.py").write_text("alpha()\nbeta()\n")

        conn = _make_db()
        _insert_code_file(conn, "r", "src/app.py")
        _insert_code_file(conn, "r", "src/util.py")
        _insert_symbol(conn, "r", "src/util.py", "stable-alpha", "alpha",
                       byte_start=4, byte_end=9)
        _insert_symbol(conn, "r", "src/util.py", "stable-beta", "beta",
                       byte_start=25, byte_end=29)

        target_doc = _make_doc("src/util.py", target_text)
        provider = FakeDocumentProvider({"src/util.py": target_doc})

        fake = FakeLspClient(responses={"textDocument/references": []})
        service, _ = _make_fusion_service(
            conn=conn, lsp_client=fake, document_provider=provider,
        )
        ctx = _make_context(root)

        # Query references for alpha
        await service.fuse_references("stable-alpha", "src/util.py", ctx)
        assert len(fake.call_log) == 1

        # Query references for beta — must send a second request
        await service.fuse_references("stable-beta", "src/util.py", ctx)
        assert len(fake.call_log) == 2

    async def test_repeat_query_hits_cache(self, tmp_path: Path):
        """Repeated query for the same symbol hits the cache."""
        root = tmp_path / "ws"
        root.mkdir()
        target_text = "def alpha():\n    pass\n"
        (root / "src").mkdir()
        (root / "src" / "util.py").write_text(target_text, encoding="utf-8")
        (root / "src" / "app.py").write_text("alpha()\n")

        conn = _make_db()
        _insert_code_file(conn, "r", "src/app.py")
        _insert_code_file(conn, "r", "src/util.py")
        _insert_symbol(conn, "r", "src/util.py", "stable-alpha", "alpha",
                       byte_start=4, byte_end=9)

        target_doc = _make_doc("src/util.py", target_text)
        provider = FakeDocumentProvider({"src/util.py": target_doc})

        fake = FakeLspClient(responses={"textDocument/references": []})
        service, _ = _make_fusion_service(
            conn=conn, lsp_client=fake, document_provider=provider,
        )
        ctx = _make_context(root)

        # First query — cache miss
        await service.fuse_references("stable-alpha", "src/util.py", ctx)
        assert len(fake.call_log) == 1

        # Second query — cache hit, no new request
        await service.fuse_references("stable-alpha", "src/util.py", ctx)
        assert len(fake.call_log) == 1

    async def test_target_file_generation_change_invalidates_cache(self, tmp_path: Path):
        """When target file generation changes, cache is invalidated."""
        root = tmp_path / "ws"
        root.mkdir()
        target_text = "def alpha():\n    pass\n"
        (root / "src").mkdir()
        (root / "src" / "util.py").write_text(target_text, encoding="utf-8")
        (root / "src" / "app.py").write_text("alpha()\n")

        conn = _make_db()
        _insert_code_file(conn, "r", "src/app.py")
        _insert_code_file(conn, "r", "src/util.py", generation=1)
        _insert_symbol(conn, "r", "src/util.py", "stable-alpha", "alpha",
                       byte_start=4, byte_end=9, generation=1)

        # First load: generation 1
        doc_gen1 = _make_doc("src/util.py", target_text, generation=1)
        provider = FakeDocumentProvider({"src/util.py": doc_gen1})

        fake = FakeLspClient(responses={"textDocument/references": []})
        service, _ = _make_fusion_service(
            conn=conn, lsp_client=fake, document_provider=provider,
        )
        ctx = _make_context(root)

        # First query — cache miss
        await service.fuse_references("stable-alpha", "src/util.py", ctx)
        assert len(fake.call_log) == 1

        # Update the document provider to return generation 2
        provider.documents["src/util.py"] = _make_doc("src/util.py", target_text, generation=2)
        # Also update the DB symbol to generation 2
        conn.execute("DELETE FROM repository_symbols WHERE stable_symbol_id='stable-alpha'")
        _insert_symbol(conn, "r", "src/util.py", "stable-alpha", "alpha",
                       byte_start=4, byte_end=9, generation=2)

        # Second query — generation changed, cache invalidated, new request
        await service.fuse_references("stable-alpha", "src/util.py", ctx)
        assert len(fake.call_log) == 2

    async def test_server_restart_invalidates_cache(self, tmp_path: Path):
        """When server identity changes, cache is invalidated."""
        root = tmp_path / "ws"
        root.mkdir()
        target_text = "def alpha():\n    pass\n"
        (root / "src").mkdir()
        (root / "src" / "util.py").write_text(target_text, encoding="utf-8")
        (root / "src" / "app.py").write_text("alpha()\n")

        conn = _make_db()
        _insert_code_file(conn, "r", "src/app.py")
        _insert_code_file(conn, "r", "src/util.py")
        _insert_symbol(conn, "r", "src/util.py", "stable-alpha", "alpha",
                       byte_start=4, byte_end=9)

        target_doc = _make_doc("src/util.py", target_text)
        provider = FakeDocumentProvider({"src/util.py": target_doc})

        fake = FakeLspClient(responses={"textDocument/references": []})
        service, _ = _make_fusion_service(
            conn=conn, lsp_client=fake, document_provider=provider,
        )

        # First query with server "fake-lsp@1.0"
        ctx1 = _make_context(root, server_identity="fake-lsp@1.0")
        await service.fuse_references("stable-alpha", "src/util.py", ctx1)
        assert len(fake.call_log) == 1

        # Second query with server "fake-lsp@2.0" — server restarted
        ctx2 = _make_context(root, server_identity="fake-lsp@2.0")
        await service.fuse_references("stable-alpha", "src/util.py", ctx2)
        assert len(fake.call_log) == 2

    async def test_symbol_deleted_invalidates_old_cache(self, tmp_path: Path):
        """When a symbol is deleted, old cache is not used."""
        root = tmp_path / "ws"
        root.mkdir()
        target_text = "def alpha():\n    pass\n"
        (root / "src").mkdir()
        (root / "src" / "util.py").write_text(target_text, encoding="utf-8")
        (root / "src" / "app.py").write_text("alpha()\n")

        conn = _make_db()
        _insert_code_file(conn, "r", "src/app.py")
        _insert_code_file(conn, "r", "src/util.py")
        _insert_symbol(conn, "r", "src/util.py", "stable-alpha", "alpha",
                       byte_start=4, byte_end=9)

        target_doc = _make_doc("src/util.py", target_text)
        provider = FakeDocumentProvider({"src/util.py": target_doc})

        fake = FakeLspClient(responses={"textDocument/references": []})
        service, _ = _make_fusion_service(
            conn=conn, lsp_client=fake, document_provider=provider,
        )
        ctx = _make_context(root)

        # First query — caches result
        await service.fuse_references("stable-alpha", "src/util.py", ctx)
        assert len(fake.call_log) == 1

        # Delete the symbol from the DB
        conn.execute("DELETE FROM repository_symbols WHERE stable_symbol_id='stable-alpha'")
        conn.commit()

        # Second query — symbol deleted, returns empty, no new LSP request
        evidence = await service.fuse_references("stable-alpha", "src/util.py", ctx)
        assert evidence == ()
        # No new LSP request (symbol not found, returns early)
        assert len(fake.call_log) == 1


# ---------------------------------------------------------------------------
# 5. other-task-workspace strict rejection
# ---------------------------------------------------------------------------


class TestOtherTaskWorkspaceStrictRejection:
    """Verify other-task-workspace URIs are completely rejected."""

    async def test_other_task_workspace_no_external_evidence(self, tmp_path: Path):
        """other-task-workspace URI produces NO evidence (not external)."""
        root = tmp_path / "ws"
        root.mkdir()
        other_root = tmp_path / "other-ws"
        other_root.mkdir()
        (root / "src").mkdir()
        (root / "src" / "app.py").write_text("def caller():\n    target()\n")

        conn = _make_db()
        _insert_code_file(conn, "r", "src/app.py")

        # URI pointing to the other workspace
        other_uri = path_to_file_uri(other_root / "secret.py")
        fake = FakeLspClient(responses={
            "textDocument/definition": _lsp_location(other_uri),
        })
        service, _ = _make_fusion_service(conn=conn, lsp_client=fake)
        ctx = _make_context(root, other_workspace_roots=(other_root,))
        repo = _make_repo_resolution(status=ResolutionStatus.UNRESOLVED)
        fused = await service.fuse_definition("target", (10, 16), repo, ctx)

        # other-task-workspace → completely rejected, no evidence
        # Should fall back to repository-only (unresolved)
        assert fused.depends_on_lsp is False
        assert fused.fused_status == "unresolved"
        # Only repository evidence — no external evidence
        assert len(fused.evidence) == 1
        assert fused.evidence[0].source.value == "repository-resolution"

    async def test_other_task_workspace_not_in_fused_status(self, tmp_path: Path):
        """other-task-workspace does not participate in fused status."""
        root = tmp_path / "ws"
        root.mkdir()
        other_root = tmp_path / "other-ws"
        other_root.mkdir()
        (root / "src").mkdir()
        (root / "src" / "app.py").write_text("def caller():\n    target()\n")

        conn = _make_db()
        _insert_code_file(conn, "r", "src/app.py")

        other_uri = path_to_file_uri(other_root / "secret.py")
        fake = FakeLspClient(responses={
            "textDocument/definition": _lsp_location(other_uri),
        })
        service, _ = _make_fusion_service(conn=conn, lsp_client=fake)
        ctx = _make_context(root, other_workspace_roots=(other_root,))
        # Even if repo says resolved, other-task-workspace should NOT
        # produce external status or override the repository result
        repo = _make_repo_resolution(
            status=ResolutionStatus.RESOLVED,
            target_symbol_id="stable-target",
            target_file="src/util.py",
        )
        fused = await service.fuse_definition("target", (10, 16), repo, ctx)

        # Should keep the repository resolution (resolved), not external
        assert fused.fused_status == "resolved"
        assert fused.depends_on_lsp is False

    async def test_other_task_workspace_no_absolute_uri_in_metadata(self, tmp_path: Path):
        """other-task-workspace: no absolute URI is stored in evidence metadata."""
        root = tmp_path / "ws"
        root.mkdir()
        other_root = tmp_path / "other-ws"
        other_root.mkdir()
        (root / "src").mkdir()
        (root / "src" / "app.py").write_text("def caller():\n    target()\n")

        conn = _make_db()
        _insert_code_file(conn, "r", "src/app.py")

        other_uri = path_to_file_uri(other_root / "secret.py")
        fake = FakeLspClient(responses={
            "textDocument/definition": _lsp_location(other_uri),
        })
        service, _ = _make_fusion_service(conn=conn, lsp_client=fake)
        ctx = _make_context(root, other_workspace_roots=(other_root,))
        repo = _make_repo_resolution(status=ResolutionStatus.UNRESOLVED)
        fused = await service.fuse_definition("target", (10, 16), repo, ctx)

        # Check that no evidence contains the absolute URI
        for ev in fused.evidence:
            metadata_str = str(ev.metadata)
            assert str(other_root) not in metadata_str
            assert other_uri not in metadata_str


# ---------------------------------------------------------------------------
# 6. External file not incorrectly promoted to resolved
# ---------------------------------------------------------------------------


class TestNoFalsePromotion:
    """Verify missing/external target files are never falsely promoted."""

    async def test_target_file_missing_no_promotion(self, tmp_path: Path):
        """When the target file is missing, no evidence is produced."""
        root = tmp_path / "ws"
        root.mkdir()
        (root / "src").mkdir()
        (root / "src" / "app.py").write_text("def caller():\n    target()\n")

        conn = _make_db()
        _insert_code_file(conn, "r", "src/app.py")

        # LSP points to a file that doesn't exist in the workspace
        missing_uri = path_to_file_uri(root / "src" / "missing.py")
        fake = FakeLspClient(responses={
            "textDocument/definition": _lsp_location(missing_uri),
        })
        # Use a provider that returns None for missing files
        provider = FakeDocumentProvider({})  # no documents registered
        service, _ = _make_fusion_service(
            conn=conn, lsp_client=fake, document_provider=provider,
        )
        ctx = _make_context(root)
        repo = _make_repo_resolution(status=ResolutionStatus.UNRESOLVED)
        fused = await service.fuse_definition("target", (10, 16), repo, ctx)

        # No evidence → repository-only (unresolved)
        assert fused.fused_status == "unresolved"
        assert fused.depends_on_lsp is False
        assert len(fused.evidence) == 1

    async def test_external_file_not_internal_target(self, tmp_path: Path):
        """workspace-external file is marked external, not internal target."""
        root = tmp_path / "ws"
        root.mkdir()
        (root / "src").mkdir()
        (root / "src" / "app.py").write_text("def caller():\n    target()\n")

        conn = _make_db()
        _insert_code_file(conn, "r", "src/app.py")

        # External URI (outside workspace, not another task workspace)
        external_uri = "file:///external/path/file.py"
        fake = FakeLspClient(responses={
            "textDocument/definition": _lsp_location(external_uri),
        })
        service, _ = _make_fusion_service(conn=conn, lsp_client=fake)
        ctx = _make_context(root)
        repo = _make_repo_resolution(status=ResolutionStatus.UNRESOLVED)
        fused = await service.fuse_definition("target", (10, 16), repo, ctx)

        # External → status=external, NOT resolved
        assert fused.fused_status == "external"
        assert fused.resolution_rule == FusionRule.LSP_EXTERNAL.value
        # No internal target_symbol_id
        assert fused.target_symbol_id is None
        assert fused.target_file is None


# ---------------------------------------------------------------------------
# 7. Regression: original 33 Fake LSP scenarios still pass
# ---------------------------------------------------------------------------


class TestOriginalScenariosRegression:
    """Verify the original 33 Fake LSP scenarios still pass with the new code.

    This is a smoke test — the full regression is in test_lsp_evidence_fusion.py.
    Here we verify a few key scenarios to ensure the API changes don't break
    existing behavior.
    """

    async def test_feature_flag_off_returns_repository_only(self, tmp_path: Path):
        """Feature flag OFF → repository-only result."""
        root = tmp_path / "ws"
        root.mkdir()
        (root / "src").mkdir()
        (root / "src" / "app.py").write_text("def f():\n    pass\n")

        conn = _make_db()
        _insert_code_file(conn, "r", "src/app.py")

        fake = FakeLspClient()
        service, _ = _make_fusion_service(
            conn=conn, lsp_client=fake,
            config=LspFusionConfig(enabled=False),
        )
        ctx = _make_context(root)
        repo = _make_repo_resolution(status=ResolutionStatus.RESOLVED)
        fused = await service.fuse_definition("f", (10, 16), repo, ctx)

        assert fused.depends_on_lsp is False
        assert len(fake.call_log) == 0

    async def test_lsp_confirmed_when_same_target(self, tmp_path: Path):
        """LSP confirmed when repo and LSP point to the same target."""
        root = tmp_path / "ws"
        root.mkdir()
        target_text = "def target():\n    pass\n"
        (root / "src").mkdir()
        (root / "src" / "util.py").write_text(target_text, encoding="utf-8")
        (root / "src" / "app.py").write_text("def caller():\n    target()\n")

        conn = _make_db()
        _insert_code_file(conn, "r", "src/app.py")
        _insert_code_file(conn, "r", "src/util.py")
        _insert_symbol(conn, "r", "src/util.py", "stable-target", "target",
                       byte_start=4, byte_end=10)

        target_doc = _make_doc("src/util.py", target_text)
        provider = FakeDocumentProvider({"src/util.py": target_doc})

        util_uri = path_to_file_uri(root / "src" / "util.py")
        fake = FakeLspClient(responses={
            "textDocument/definition": _lsp_location(util_uri, sc=4, ec=10),
        })
        service, _ = _make_fusion_service(
            conn=conn, lsp_client=fake, document_provider=provider,
        )
        ctx = _make_context(root)
        repo = _make_repo_resolution(
            status=ResolutionStatus.RESOLVED,
            target_symbol_id="stable-target",
            target_file="src/util.py",
        )
        fused = await service.fuse_definition("target", (10, 16), repo, ctx)

        assert fused.resolution_rule == FusionRule.LSP_CONFIRMED.value
        assert fused.depends_on_lsp is True
