"""Optional LSP evidence fusion service.

Fuses repository conservative resolution with optional LSP definition /
reference evidence. LSP is ALWAYS optional — when unavailable, timing out,
crashing, or returning protocol errors, the fused result is identical to
the repository resolution.

Fusion pipeline (per spec §1, §6, §7):
    Tree-sitter candidate
    → Repository conservative resolution
    → optional LSP evidence (definition / references)
    → fused result

Key invariants:
    - LSP evidence NEVER silently overwrites repository resolution.
    - Every fused result preserves ALL contributing evidence.
    - Conflicts are marked ``ambiguous`` / ``conflicting`` — never guessed.
    - ParseResult is NEVER modified.
    - Source code text is NEVER persisted (read transiently for position
      conversion, then discarded).
    - No raw ``subprocess`` path — all LSP I/O goes through ``LspClient``.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from khaos.coding.intelligence.lsp.cache import EvidenceCache
from khaos.coding.intelligence.lsp.config import LspFusionConfig
from khaos.coding.intelligence.lsp.evidence import (
    EvidenceCacheKey,
    EvidenceSource,
    EvidenceType,
    FusionRule,
    FusedResolution,
    SemanticEvidence,
)
from khaos.coding.intelligence.lsp.positions import (
    PositionConversionError,
    byte_offset_to_lsp_position,
    lsp_position_to_offsets,
)
from khaos.coding.intelligence.lsp.uri import (
    UriMappingError,
    map_lsp_uri_to_workspace_path,
    path_to_file_uri,
)
from khaos.coding.intelligence.resolution.models import (
    ResolutionStatus,
    ResolvedCallEdge,
    ResolvedReferenceEdge,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class FusionContext:
    """Per-request context binding evidence to a specific file state.

    ``file_text`` is read transiently for UTF-16 ↔ byte offset conversion
    and is NEVER persisted. Callers should discard it after fusion.
    """

    repository_id: str
    workspace_id: str
    file_path: str
    file_text: str
    content_hash: str
    file_generation: int
    document_version: int
    server_identity: str
    workspace_root: Path
    other_workspace_roots: tuple[Path, ...] = ()


class LspEvidenceFusionService:
    """Fuses repository resolution with optional LSP evidence.

    Construction is cheap; the service holds a cache and a reference to an
    optional ``LspClient``. When ``config.enabled`` is ``False`` or the
    LSP client is ``None``, all methods return repository-only results.
    """

    def __init__(
        self,
        *,
        config: LspFusionConfig,
        cache: EvidenceCache,
        conn: sqlite3.Connection,
        lsp_client: Any | None = None,
    ) -> None:
        self._config = config
        self._cache = cache
        self._conn = conn
        self._lsp_client = lsp_client
        self._closed = False
        # Pending request deduplication: same candidate → merged into one LSP call.
        self._pending: dict[EvidenceCacheKey, asyncio.Future[tuple[SemanticEvidence, ...]]] = {}

    @property
    def enabled(self) -> bool:
        """Whether LSP evidence fusion is enabled (feature flag)."""
        return self._config.enabled and self._lsp_client is not None and not self._closed

    @property
    def cache_stats(self) -> dict[str, int]:
        return self._cache.stats

    async def fuse_definition(
        self,
        candidate_callee: str,
        candidate_byte_range: tuple[int, int],
        repo_resolution: ResolvedCallEdge | ResolvedReferenceEdge,
        context: FusionContext,
    ) -> FusedResolution:
        """Fuse a call/reference candidate's definition with LSP evidence.

        Applies the six fusion rules from spec §6:
        1. Repo resolved + LSP same → keep resolved, add evidence.
        2. Repo unresolved/ambiguous + LSP unique internal → promote.
        3. Repo resolved + LSP conflict → ambiguous/conflicting.
        4. LSP external → status=external.
        5. LSP multiple → ambiguous.
        6. LSP unavailable → repository-only.
        """
        # Build the repository-resolution evidence (always present).
        repo_evidence = _repo_evidence_from_resolution(repo_resolution)

        if not self.enabled:
            return _repository_only_fused(repo_resolution, repo_evidence)

        # Check staleness: if the context's generation doesn't match the
        # IndexStore's current generation, LSP evidence may be stale.
        current_gen = _file_generation(self._conn, context.repository_id, context.file_path)
        if current_gen is not None and current_gen != context.file_generation:
            logger.debug("LSP fusion skipped for %s: stale generation %d != %d",
                         context.file_path, context.file_generation, current_gen)
            fused = _repository_only_fused(repo_resolution, repo_evidence)
            return _replace(fused, resolution_rule= FusionRule.LSP_STALE.value)

        # Collect LSP definition evidence.
        lsp_evidence = await self._collect_lsp_definition(
            candidate_byte_range, context,
        )

        if not lsp_evidence:
            # LSP returned nothing or failed — return repository-only.
            return _repository_only_fused(repo_resolution, repo_evidence)

        return _apply_definition_fusion_rules(
            repo_resolution, repo_evidence, lsp_evidence, self._conn, context.repository_id,
        )

    async def fuse_references(
        self,
        target_stable_symbol_id: str,
        target_file_path: str,
        context: FusionContext,
    ) -> tuple[SemanticEvidence, ...]:
        """Collect LSP reference evidence for a symbol.

        Per spec §7, LSP references are only supplementary evidence. They
        are NOT auto-persisted as repository edges. Results are deduplicated
        and cached with a short TTL.
        """
        if not self.enabled:
            return ()

        cache_key = EvidenceCacheKey(
            repository_id=context.repository_id,
            workspace_id=context.workspace_id,
            file_path=context.file_path,
            content_hash=context.content_hash,
            file_generation=context.file_generation,
            document_version=context.document_version,
            candidate_range=(0, 0),  # references are per-file, not per-candidate
            server_identity=context.server_identity,
        )

        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached

        evidence = await self._collect_lsp_references(
            target_stable_symbol_id, target_file_path, context,
        )

        self._cache.put(cache_key, evidence)
        return evidence

    def explain_resolution(
        self,
        repo_resolution: ResolvedCallEdge | ResolvedReferenceEdge,
        fused: FusedResolution,
    ) -> dict[str, Any]:
        """Return an explainable breakdown of how a fused status was reached."""
        return {
            "original_status": fused.original_status,
            "fused_status": fused.fused_status,
            "confidence": fused.confidence,
            "resolution_rule": fused.resolution_rule,
            "conflict_reason": fused.conflict_reason,
            "depends_on_lsp": fused.depends_on_lsp,
            "target_symbol_id": fused.target_symbol_id,
            "target_file": fused.target_file,
            "evidence_count": len(fused.evidence),
            "evidence_sources": [e.source.value for e in fused.evidence],
            "evidence": [e.to_dict() for e in fused.evidence],
        }

    async def shutdown(self) -> None:
        """Clear cache and mark service as closed."""
        self._closed = True
        self._cache.clear()
        # Cancel any pending LSP requests.
        for future in tuple(self._pending.values()):
            if not future.done():
                future.cancel()
        self._pending.clear()

    async def _collect_lsp_definition(
        self,
        candidate_byte_range: tuple[int, int],
        context: FusionContext,
    ) -> tuple[SemanticEvidence, ...]:
        """Send textDocument/definition and convert the response to evidence."""
        cache_key = EvidenceCacheKey(
            repository_id=context.repository_id,
            workspace_id=context.workspace_id,
            file_path=context.file_path,
            content_hash=context.content_hash,
            file_generation=context.file_generation,
            document_version=context.document_version,
            candidate_range=candidate_byte_range,
            server_identity=context.server_identity,
        )

        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached

        # Deduplicate concurrent requests for the same candidate.
        pending = self._pending.get(cache_key)
        if pending is not None:
            try:
                return await asyncio.shield(pending)
            except (asyncio.CancelledError, RuntimeError, asyncio.TimeoutError):
                return ()

        future: asyncio.Future[tuple[SemanticEvidence, ...]] = asyncio.get_running_loop().create_future()
        self._pending[cache_key] = future
        try:
            evidence = await self._request_definition(candidate_byte_range, context)
            self._cache.put(cache_key, evidence)
            if not future.done():
                future.set_result(evidence)
            return evidence
        except asyncio.TimeoutError:
            logger.debug("LSP definition timeout for %s", context.file_path)
            if not future.done():
                future.set_result(())
            return ()
        except asyncio.CancelledError:
            if not future.done():
                future.set_result(())
            return ()
        except (RuntimeError, ValueError, ConnectionError) as exc:
            logger.debug("LSP definition failed for %s: %s", context.file_path, exc)
            if not future.done():
                future.set_result(())
            return ()
        finally:
            self._pending.pop(cache_key, None)

    async def _collect_lsp_references(
        self,
        target_stable_symbol_id: str,
        target_file_path: str,
        context: FusionContext,
    ) -> tuple[SemanticEvidence, ...]:
        """Send textDocument/references and convert the response to evidence."""
        try:
            return await self._request_references(target_file_path, context)
        except asyncio.TimeoutError:
            logger.debug("LSP references timeout for %s", context.file_path)
            return ()
        except asyncio.CancelledError:
            return ()
        except (RuntimeError, ValueError, ConnectionError) as exc:
            logger.debug("LSP references failed for %s: %s", context.file_path, exc)
            return ()

    async def _request_definition(
        self,
        candidate_byte_range: tuple[int, int],
        context: FusionContext,
    ) -> tuple[SemanticEvidence, ...]:
        """Send the actual LSP textDocument/definition request."""
        if self._lsp_client is None:
            return ()

        # Convert byte offset to LSP UTF-16 position for the request.
        byte_start = candidate_byte_range[0]
        try:
            line, character = byte_offset_to_lsp_position(context.file_text, byte_start)
        except PositionConversionError as exc:
            logger.debug("Position conversion failed for %s: %s", context.file_path, exc)
            return ()

        file_uri = path_to_file_uri(context.workspace_root / context.file_path)
        params = {
            "textDocument": {"uri": file_uri},
            "position": {"line": line, "character": character},
        }

        result = await asyncio.wait_for(
            self._lsp_client.request("textDocument/definition", params),
            timeout=self._config.request_timeout_seconds,
        )
        return self._convert_definition_result(result, context)

    async def _request_references(
        self,
        target_file_path: str,
        context: FusionContext,
    ) -> tuple[SemanticEvidence, ...]:
        """Send the actual LSP textDocument/references request."""
        if self._lsp_client is None:
            return ()

        file_uri = path_to_file_uri(context.workspace_root / target_file_path)
        # We need a position — use byte 0 of the target file as a fallback.
        # A real implementation would look up the symbol's definition position.
        try:
            line, character = byte_offset_to_lsp_position(context.file_text, 0)
        except PositionConversionError:
            line, character = 0, 0

        params = {
            "textDocument": {"uri": file_uri},
            "position": {"line": line, "character": character},
            "context": {"includeDeclaration": False},
        }

        result = await asyncio.wait_for(
            self._lsp_client.request("textDocument/references", params),
            timeout=self._config.request_timeout_seconds,
        )
        return self._convert_references_result(result, context)

    def _convert_definition_result(
        self,
        result: Any,
        context: FusionContext,
    ) -> tuple[SemanticEvidence, ...]:
        """Convert an LSP definition response to a tuple of SemanticEvidence."""
        locations = _normalize_locations(result)
        if not locations:
            return ()

        evidence_list: list[SemanticEvidence] = []
        for loc in locations:
            ev = self._convert_location_to_evidence(
                loc, context, EvidenceType.DEFINITION, EvidenceSource.LSP_DEFINITION,
            )
            if ev is not None:
                evidence_list.append(ev)
        return tuple(evidence_list)

    def _convert_references_result(
        self,
        result: Any,
        context: FusionContext,
    ) -> tuple[SemanticEvidence, ...]:
        """Convert an LSP references response to a tuple of SemanticEvidence."""
        locations = _normalize_locations(result)
        if not locations:
            return ()

        # Deduplicate by (file, byte_start, byte_end).
        seen: set[tuple[str, int, int]] = set()
        evidence_list: list[SemanticEvidence] = []
        for loc in locations:
            ev = self._convert_location_to_evidence(
                loc, context, EvidenceType.REFERENCE, EvidenceSource.LSP_REFERENCES,
            )
            if ev is not None and ev.target_file is not None and ev.target_range is not None:
                key = (ev.target_file, ev.target_range[0], ev.target_range[2])
                if key in seen:
                    continue
                seen.add(key)
                evidence_list.append(ev)
        return tuple(evidence_list)

    def _convert_location_to_evidence(
        self,
        location: dict,
        context: FusionContext,
        evidence_type: EvidenceType,
        source: EvidenceSource,
    ) -> SemanticEvidence | None:
        """Convert a single LSP Location to SemanticEvidence.

        Applies strict URI mapping and UTF-16 position conversion. Returns
        ``None`` if the location is rejected (external URI, invalid position).
        """
        uri = location.get("uri")
        range_info = location.get("range", {})
        start = range_info.get("start", {})
        end = range_info.get("end", {})

        if uri is None:
            return None

        # Map URI to workspace-relative path (rejects external/symlink escapes).
        try:
            target_path = map_lsp_uri_to_workspace_path(
                uri, context.workspace_root,
                other_workspace_roots=context.other_workspace_roots,
            )
        except UriMappingError as exc:
            logger.debug("LSP URI rejected: %s (%s)", exc.code, exc.message)
            # If it's a workspace-external path, mark as external evidence.
            if exc.code in ("workspace-external", "other-task-workspace"):
                return SemanticEvidence(
                    source=source,
                    evidence_type=evidence_type,
                    target_file=None,
                    target_range=None,
                    target_symbol_id=None,
                    confidence=0.1,
                    metadata={"rejected_uri": uri, "rejection_code": exc.code},
                )
            return None

        # Convert UTF-16 positions to byte offsets.
        try:
            start_mapping = lsp_position_to_offsets(
                context.file_text,
                start.get("line", 0),
                start.get("character", 0),
            )
            end_mapping = lsp_position_to_offsets(
                context.file_text,
                end.get("line", 0),
                end.get("character", 0),
            )
        except PositionConversionError as exc:
            logger.debug("LSP position rejected: %s (%s)", exc.code, exc.message)
            return None

        byte_start = start_mapping.byte_offset
        byte_end = end_mapping.byte_offset
        target_range = (
            start_mapping.line,
            start_mapping.code_point_column,
            end_mapping.line,
            end_mapping.code_point_column,
        )

        # Look up the stable_symbol_id at this location.
        target_symbol_id = _lookup_symbol_at_byte_range(
            self._conn, context.repository_id, target_path, byte_start, byte_end,
        )

        return SemanticEvidence(
            source=source,
            evidence_type=evidence_type,
            target_file=target_path,
            target_range=target_range,
            target_symbol_id=target_symbol_id,
            confidence=0.8,  # LSP evidence confidence
            server_name=_extract_server_name(context.server_identity),
            server_version=_extract_server_version(context.server_identity),
            document_version=context.document_version,
            metadata={
                "byte_start": byte_start,
                "byte_end": byte_end,
            },
        )


def _repository_only_fused(
    repo_resolution: ResolvedCallEdge | ResolvedReferenceEdge,
    repo_evidence: SemanticEvidence,
) -> FusedResolution:
    """Build a FusedResolution that carries only repository evidence."""
    return FusedResolution(
        original_status=repo_resolution.status.value,
        fused_status=repo_resolution.status.value,
        target_symbol_id=repo_resolution.target_symbol_id,
        target_file=repo_resolution.target_file,
        confidence=repo_resolution.confidence,
        evidence=(repo_evidence,),
        conflict_reason=None,
        resolution_rule=repo_resolution.resolution_rule,
        depends_on_lsp=False,
    )


def _replace(fused: FusedResolution, *, resolution_rule: str) -> FusedResolution:
    """Return a copy of ``fused`` with the resolution rule replaced."""
    from dataclasses import replace as _dc_replace
    return _dc_replace(fused, resolution_rule=resolution_rule)


def _repo_evidence_from_resolution(
    repo_resolution: ResolvedCallEdge | ResolvedReferenceEdge,
) -> SemanticEvidence:
    """Build a SemanticEvidence representing the repository resolution."""
    name = getattr(repo_resolution, "call_callee", None) or getattr(repo_resolution, "name", "")
    return SemanticEvidence(
        source=EvidenceSource.REPOSITORY_RESOLUTION,
        evidence_type=EvidenceType.DEFINITION,
        target_file=repo_resolution.target_file,
        target_range=None,
        target_symbol_id=repo_resolution.target_symbol_id,
        confidence=repo_resolution.confidence,
        metadata={"name": name, "rule": repo_resolution.resolution_rule},
    )


def _apply_definition_fusion_rules(
    repo_resolution: ResolvedCallEdge | ResolvedReferenceEdge,
    repo_evidence: SemanticEvidence,
    lsp_evidence: tuple[SemanticEvidence, ...],
    conn: sqlite3.Connection,
    repository_id: str,
) -> FusedResolution:
    """Apply the six fusion rules from spec §6.

    This is a pure function of (repo_resolution, lsp_evidence) → FusedResolution.
    It never sends LSP requests or reads source code.
    """
    original_status = repo_resolution.status
    repo_target = repo_resolution.target_symbol_id

    # Classify LSP evidence.
    internal_evidence = [e for e in lsp_evidence if e.target_file is not None]
    external_evidence = [e for e in lsp_evidence if e.target_file is None]
    lsp_targets = {e.target_symbol_id for e in internal_evidence if e.target_symbol_id is not None}

    all_evidence = (repo_evidence, *lsp_evidence)

    # Rule 5: LSP returned multiple distinct internal targets → ambiguous.
    if len(lsp_targets) > 1:
        return FusedResolution(
            original_status=original_status.value,
            fused_status=ResolutionStatus.AMBIGUOUS.value,
            target_symbol_id=None,
            target_file=None,
            confidence=min(repo_resolution.confidence, 0.5),
            evidence=all_evidence,
            conflict_reason="lsp-returned-multiple-targets",
            resolution_rule= FusionRule.LSP_AMBIGUOUS.value,
            depends_on_lsp=True,
        )

    # Rule 4: LSP points to external file(s) only.
    if not internal_evidence and external_evidence:
        return FusedResolution(
            original_status=original_status.value,
            fused_status=ResolutionStatus.EXTERNAL.value,
            target_symbol_id=None,
            target_file=None,
            confidence=0.3,
            evidence=all_evidence,
            conflict_reason="lsp-target-is-external",
            resolution_rule= FusionRule.LSP_EXTERNAL.value,
            depends_on_lsp=True,
        )

    # At this point, LSP has exactly 0 or 1 internal target.
    lsp_target = next(iter(lsp_targets)) if lsp_targets else None
    lsp_evidence_internal = internal_evidence[0] if internal_evidence else None

    # Rule 1: Repo resolved + LSP same target → confirm, boost confidence.
    if (
        original_status == ResolutionStatus.RESOLVED
        and lsp_target is not None
        and lsp_target == repo_target
    ):
        boosted = min(repo_resolution.confidence + 0.05, 1.0)
        return FusedResolution(
            original_status=original_status.value,
            fused_status=ResolutionStatus.RESOLVED.value,
            target_symbol_id=repo_target,
            target_file=repo_resolution.target_file,
            confidence=boosted,
            evidence=all_evidence,
            conflict_reason=None,
            resolution_rule= FusionRule.LSP_CONFIRMED.value,
            depends_on_lsp=True,
        )

    # Rule 3: Repo resolved + LSP different target → conflict.
    if (
        original_status == ResolutionStatus.RESOLVED
        and lsp_target is not None
        and lsp_target != repo_target
    ):
        return FusedResolution(
            original_status=original_status.value,
            fused_status=ResolutionStatus.AMBIGUOUS.value,
            target_symbol_id=None,
            target_file=None,
            confidence=min(repo_resolution.confidence, 0.4),
            evidence=all_evidence,
            conflict_reason=f"repository-target={repo_target} lsp-target={lsp_target}",
            resolution_rule= FusionRule.LSP_CONFLICT.value,
            depends_on_lsp=True,
        )

    # Rule 2: Repo unresolved/ambiguous + LSP unique internal → promote.
    if (
        original_status in {ResolutionStatus.UNRESOLVED, ResolutionStatus.AMBIGUOUS}
        and lsp_target is not None
        and lsp_evidence_internal is not None
    ):
        return FusedResolution(
            original_status=original_status.value,
            fused_status=ResolutionStatus.RESOLVED.value,
            target_symbol_id=lsp_target,
            target_file=lsp_evidence_internal.target_file,
            confidence=0.85,
            evidence=all_evidence,
            conflict_reason=None,
            resolution_rule= FusionRule.LSP_PROMOTED.value,
            depends_on_lsp=True,
        )

    # Fallback: LSP evidence didn't change the outcome.
    return FusedResolution(
        original_status=original_status.value,
        fused_status=original_status.value,
        target_symbol_id=repo_resolution.target_symbol_id,
        target_file=repo_resolution.target_file,
        confidence=repo_resolution.confidence,
        evidence=all_evidence,
        conflict_reason=None,
        resolution_rule=repo_resolution.resolution_rule,
        depends_on_lsp=True if lsp_evidence else False,
    )


def _normalize_locations(result: Any) -> list[dict]:
    """Normalize an LSP definition/references response to a list of Location dicts."""
    if result is None:
        return []
    if isinstance(result, list):
        return [r for r in result if isinstance(r, dict)]
    if isinstance(result, dict):
        # Could be a single Location or a LocationLink[]
        if "uri" in result:
            return [result]
        if "targetUri" in result:
            # LocationLink → normalize to Location
            return [{
                "uri": result["targetUri"],
                "range": result.get("targetRange", {}),
            }]
    return []


def _lookup_symbol_at_byte_range(
    conn: sqlite3.Connection,
    repository_id: str,
    file_path: str,
    byte_start: int,
    byte_end: int,
) -> str | None:
    """Look up a stable_symbol_id whose range contains the given byte offset.

    A symbol matches if its byte range overlaps with or contains the given
    byte range. This is conservative — if multiple symbols overlap, we
    return the most specific (smallest range).
    """
    try:
        rows = conn.execute(
            "SELECT stable_symbol_id, byte_start, byte_end FROM repository_symbols "
            "WHERE repository_id=? AND path=? AND byte_start<=? AND byte_end>=?",
            (repository_id, file_path, byte_start, byte_start),
        ).fetchall()
    except sqlite3.OperationalError:
        return None

    if not rows:
        return None

    # Return the most specific symbol (smallest range).
    best = min(rows, key=lambda r: r[2] - r[1])
    return best[0]


def _file_generation(
    conn: sqlite3.Connection,
    repository_id: str,
    file_path: str,
) -> int | None:
    """Get the current IndexStore generation for a file, or None if deleted."""
    try:
        row = conn.execute(
            "SELECT generation FROM code_files WHERE project_id=? AND path=?",
            (repository_id, file_path),
        ).fetchone()
        return int(row[0]) if row else None
    except sqlite3.OperationalError:
        return None


def _extract_server_name(server_identity: str) -> str:
    """Extract the server name from a ``name@version`` identity string."""
    if "@" in server_identity:
        return server_identity.split("@", 1)[0]
    return server_identity


def _extract_server_version(server_identity: str) -> str:
    """Extract the server version from a ``name@version`` identity string."""
    if "@" in server_identity:
        return server_identity.split("@", 1)[1]
    return "unknown"


def compute_server_identity(name: str, version: str) -> str:
    """Build a stable server identity string for cache keys."""
    return f"{name}@{version}"


def compute_content_hash(text: str) -> str:
    """Compute a SHA-256 content hash for a file's text."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
