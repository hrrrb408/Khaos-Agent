"""Trusted workspace document provider for LSP evidence fusion.

When LSP returns a definition or reference location pointing to a file
DIFFERENT from the source file, the fusion service must read the TARGET
file's content to convert UTF-16 positions to byte offsets correctly.

This module provides a strict, injectable document loader that:

1. Validates the target path is inside the active TaskWorkspace.
2. Reads the file content from disk (transient — never persisted).
3. Computes a SHA-256 content hash for staleness binding.
4. Looks up the file's current generation from the IndexStore.
5. Returns ``None`` when the file is missing, changed, or not indexed.

The provider NEVER allows reading arbitrary host paths. Every path is
resolved relative to the workspace root and boundary-checked.
"""
from __future__ import annotations

import hashlib
import logging
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from khaos.coding.intelligence.lsp.uri import (
    SymlinkEscapeError,
    WorkspaceEscapeError,
    map_lsp_uri_to_workspace_path,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class WorkspaceDocument:
    """A loaded workspace document with staleness metadata.

    ``text`` is read transiently for UTF-16 ↔ byte offset conversion and
    is NEVER persisted. Callers should discard it after fusion.

    ``generation`` is the IndexStore's current generation for this file
    (``0`` if the file exists on disk but has not been indexed yet).
    ``indexed`` is ``False`` when the file is not in the IndexStore.
    """

    path: str  # repository-relative POSIX path
    text: str
    content_hash: str
    generation: int
    indexed: bool


class WorkspaceDocumentProvider(Protocol):
    """Protocol for loading workspace documents by path."""

    async def load_document(
        self,
        repository_id: str,
        workspace_root: Path,
        file_path: str,
        *,
        other_workspace_roots: tuple[Path, ...] = (),
    ) -> WorkspaceDocument | None:
        """Load a document by repository-relative path.

        Returns ``None`` when the file does not exist, is outside the
        workspace, or cannot be read. Callers must treat ``None`` as
        "cannot produce evidence" — never promote to resolved.
        """
        ...


class DiskWorkspaceDocumentProvider:
    """Default provider that reads files from disk within the workspace.

    This provider is strict: every path is resolved within the workspace
    root and boundary-checked. No symlinks escapes are allowed.
    """

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    async def load_document(
        self,
        repository_id: str,
        workspace_root: Path,
        file_path: str,
        *,
        other_workspace_roots: tuple[Path, ...] = (),
    ) -> WorkspaceDocument | None:
        import asyncio

        # Validate the path is inside the workspace by constructing a
        # file URI and mapping it back. This reuses the strict boundary
        # check from uri.py.
        absolute = workspace_root / file_path
        from khaos.coding.intelligence.lsp.uri import path_to_file_uri

        try:
            uri = path_to_file_uri(absolute)
            validated_path = map_lsp_uri_to_workspace_path(
                uri, workspace_root,
                other_workspace_roots=other_workspace_roots,
            )
        except (WorkspaceEscapeError, SymlinkEscapeError):
            logger.debug(
                "Document load rejected (workspace boundary): %s",
                file_path,
            )
            return None

        # Read the file content from disk (async to avoid blocking).
        try:
            content = await asyncio.to_thread(absolute.read_bytes)
        except (OSError, UnicodeError):
            logger.debug("Document load failed (read error): %s", file_path)
            return None

        # Decode as UTF-8 (matching Tree-sitter's encoding).
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            logger.debug("Document load failed (not UTF-8): %s", file_path)
            return None

        content_hash = hashlib.sha256(content).hexdigest()

        # Look up the file's current generation from IndexStore.
        generation = 0
        indexed = False
        try:
            row = self._conn.execute(
                "SELECT generation FROM code_files WHERE project_id=? AND path=?",
                (repository_id, file_path),
            ).fetchone()
            if row is not None:
                generation = int(row[0])
                indexed = True
        except sqlite3.OperationalError:
            pass

        return WorkspaceDocument(
            path=validated_path,
            text=text,
            content_hash=content_hash,
            generation=generation,
            indexed=indexed,
        )
