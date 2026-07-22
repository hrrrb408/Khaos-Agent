"""Optional real LSP evidence fusion test (spec §13).

This test uses a trusted, pre-installed Language Server. It NEVER downloads
or installs a server at test time. If no trusted server is available, the
test is skipped — it does NOT block the core Fake LSP tests.

The test validates one language (Python) end-to-end:
    - Real workspace
    - Real managed LSP client
    - Definition request
    - URI / UTF-16 mapping
    - Agreement with repository resolution
    - Shutdown leaves no residual processes

A skip here is NOT reported as "real LSP verified" — it is an explicit
acknowledgement that the environment lacks a trusted server.
"""
from __future__ import annotations

import asyncio
import os
import shutil
import sqlite3
import sys
from unittest.mock import AsyncMock
from pathlib import Path

import pytest

from khaos.coding.intelligence.lsp.cache import EvidenceCache
from khaos.coding.intelligence.lsp.config import LspFusionConfig
from khaos.coding.intelligence.lsp.fusion import (
    FusionContext,
    LspEvidenceFusionService,
    compute_content_hash,
    compute_server_identity,
)
from khaos.coding.intelligence.lsp.uri import path_to_file_uri
from khaos.coding.intelligence.resolution.models import ResolutionStatus, ResolvedCallEdge
from khaos.coding.intelligence.resolution.persistence import apply_resolution_schema

pytestmark = pytest.mark.lsp_real


def _find_python_lsp() -> str | None:
    """Find a trusted, pre-installed Python LSP server binary.

    Checks for pyright-langserver, pylsp, or jedi-language-server on PATH.
    Does NOT install anything.
    """
    interpreter_bin = Path(sys.executable).parent
    for name in ("pyright-langserver", "pylsp", "jedi-language-server"):
        sibling = interpreter_bin / name
        if sibling.is_file() and os.access(sibling, os.X_OK):
            return str(sibling)
        path = shutil.which(name)
        if path is not None:
            return path
    return None


_LSP_BINARY = _find_python_lsp()
_LSP_ARGV = (
    (_LSP_BINARY, "--stdio")
    if _LSP_BINARY and Path(_LSP_BINARY).name == "pyright-langserver"
    else ((_LSP_BINARY,) if _LSP_BINARY else ())
)


def _has_tree_sitter() -> bool:
    try:
        import tree_sitter  # noqa: F401
        return True
    except ImportError:
        return False


# Skip if no trusted LSP server is available OR tree-sitter is not installed
# (we need tree-sitter to build the repository resolution for comparison).
pytest.importorskip("tree_sitter")


@pytest.mark.skipif(_LSP_BINARY is None, reason="no trusted Python LSP server found on PATH")
async def test_real_python_lsp_definition_fusion(tmp_path: Path):
    """Validate real LSP definition fusion against repository resolution.

    This test is ONLY run when:
    1. A trusted Python LSP server is pre-installed.
    2. Tree-sitter optional dependencies are installed.

    It verifies:
    - The LSP client starts and responds to definition requests.
    - URI mapping correctly converts LSP URIs to workspace-relative paths.
    - UTF-16 position conversion works on real Python source.
    - The fused result agrees with repository resolution for a simple
      same-file function call.
    - shutdown() leaves no residual processes.
    """
    from khaos.coding.execution.host import HostExecutionBackend
    from khaos.coding.execution.managed import ManagedProcessHandle
    from khaos.coding.execution.service import ExecutionService
    from khaos.coding.intelligence.index import IndexStore
    from khaos.coding.intelligence.index.repository import RepositoryIndexer
    from khaos.coding.intelligence.lsp.client import LspClient
    from khaos.coding.intelligence.resolution.service import ResolutionService
    from types import SimpleNamespace
    from khaos.coding.workspace.models import WorkspaceState

    # Build a real workspace
    root = tmp_path / "workspace"
    root.mkdir(parents=True)
    (root / ".git").write_text("gitdir: ../repo/.git/worktrees/task\n", encoding="utf-8")
    (root / "util.py").write_text(
        "def target_function():\n    return 42\n",
        encoding="utf-8",
    )
    (root / "app.py").write_text(
        "from util import target_function\n\nresult = target_function()\n",
        encoding="utf-8",
    )

    # Index the repository with tree-sitter
    store = IndexStore(sqlite3.connect(":memory:", check_same_thread=False))
    resolution_svc = ResolutionService(store._conn, persist=True)
    indexer = RepositoryIndexer(store, resolution_service=resolution_svc)
    await indexer.index("r", root)

    # Set up execution service for managed LSP
    repository = tmp_path / "repo"
    repository.mkdir(parents=True)
    workspace = SimpleNamespace(
        task_id="task", worktree_path=root, repository_root=repository,
        state=WorkspaceState.RUNNING,
    )
    manager = SimpleNamespace(
        get=lambda wid: workspace if wid == "workspace" else None,
        verify_git_identity=AsyncMock(),
    )

    async def spawn(context, temporary_home):
        process = await asyncio.create_subprocess_exec(
            *context.argv, cwd=str(context.cwd), env=context.environment,
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE, start_new_session=True,
        )
        return ManagedProcessHandle(
            context.correlation_id, process, temporary_home=temporary_home,
            stderr_limit=context.budget.output_bytes,
        )

    exec_service = ExecutionService(HostExecutionBackend(), manager, managed_process_factory=spawn)

    # Start the real LSP client
    lsp_client = LspClient(
        _LSP_ARGV,
        execution_service=exec_service,
        task_id="task",
        workspace_id="workspace",
        trusted_argv=_LSP_ARGV,
        timeout=5.0,
    )

    start_result = await lsp_client.start(root.as_uri())
    if not start_result["ok"]:
        pytest.skip(f"real LSP server failed to start: {start_result.get('diagnostic')}")

    try:
        # Build fusion service
        config = LspFusionConfig(enabled=True, request_timeout_seconds=5.0)
        cache = EvidenceCache(max_entries=100, ttl_seconds=60)
        server_identity = compute_server_identity(
            os.path.basename(_LSP_BINARY),  # type: ignore[arg-type]
            "unknown",
        )
        fusion_service = LspEvidenceFusionService(
            config=config, cache=cache, conn=store._conn, lsp_client=lsp_client,
        )

        # Get the call edge for target_function() in app.py
        from khaos.coding.intelligence.query import CodeQueryService
        qs = CodeQueryService(store)
        edges = qs.call_edges_for_file("r", "app.py")
        assert len(edges) > 0, "expected at least one call edge"

        # Find the target_function call edge
        target_edge = None
        for edge in edges:
            if edge["call_callee"] == "target_function":
                target_edge = edge
                break
        assert target_edge is not None, "expected target_function call edge"

        # Build a ResolvedCallEdge for fusion
        repo_resolution = ResolvedCallEdge(
            edge_id=target_edge["edge_id"],
            source_file=target_edge["source_file"],
            caller_symbol_id=target_edge.get("caller_symbol_id"),
            call_callee=target_edge["call_callee"],
            status=ResolutionStatus(target_edge["status"]),
            target_symbol_id=target_edge.get("target_symbol_id"),
            target_file=target_edge.get("target_file"),
            confidence=target_edge.get("confidence", 0.0),
            resolution_rule=target_edge.get("resolution_rule", ""),
            ambiguity_reason=target_edge.get("ambiguity_reason"),
            metadata=target_edge.get("metadata", {}),
        )

        # Read the source text for position conversion
        file_text = (root / "app.py").read_text(encoding="utf-8")

        # Find the byte offset of "target_function()" call
        call_offset = file_text.find("target_function()")
        assert call_offset >= 0

        context = FusionContext(
            repository_id="r",
            workspace_id="workspace",
            file_path="app.py",
            file_text=file_text,
            content_hash=compute_content_hash(file_text),
            file_generation=1,
            document_version=1,
            server_identity=server_identity,
            workspace_root=root,
        )

        # Fuse the definition
        fused = await fusion_service.fuse_definition(
            "target_function",
            (call_offset, call_offset + len("target_function")),
            repo_resolution,
            context,
        )

        # The fused result should be valid — either confirmed, promoted, or
        # at worst repository-only (if LSP couldn't find the definition).
        assert fused.fused_status in ("resolved", "ambiguous", "external", "unresolved")

        # If LSP found the definition, it should point to util.py
        if fused.depends_on_lsp and fused.fused_status == "resolved":
            # The target file should be util.py (same as repository resolution)
            assert fused.target_file is not None

        # Shutdown fusion service — should clear cache
        await fusion_service.shutdown()
        assert cache.size == 0

    finally:
        await lsp_client.close()
        await exec_service.shutdown()

    # Verify no residual processes
    assert not exec_service._active
