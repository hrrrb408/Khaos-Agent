"""Optional Language Server Protocol enrichment.

Exports the managed ``LspClient`` and the optional evidence fusion
components. Fusion is always opt-in via ``LspFusionConfig.enabled``
(default ``False``).
"""

from khaos.coding.intelligence.lsp.cache import EvidenceCache
from khaos.coding.intelligence.lsp.client import LspClient, LspDiagnostic
from khaos.coding.intelligence.lsp.config import DEFAULT_CONFIG, LspFusionConfig
from khaos.coding.intelligence.lsp.documents import (
    DiskWorkspaceDocumentProvider,
    WorkspaceDocument,
    WorkspaceDocumentProvider,
)
from khaos.coding.intelligence.lsp.evidence import (
    EvidenceCacheEntry,
    EvidenceCacheKey,
    EvidenceSource,
    EvidenceType,
    FusedResolution,
    FusionRule,
    SemanticEvidence,
)
from khaos.coding.intelligence.lsp.fusion import (
    FusionContext,
    LspEvidenceFusionService,
    compute_content_hash,
    compute_server_identity,
)
from khaos.coding.intelligence.lsp.positions import (
    PositionConversionError,
    PositionMapping,
    byte_offset_to_lsp_position,
    lsp_position_to_offsets,
    lsp_range_to_byte_offsets,
)
from khaos.coding.intelligence.lsp.uri import (
    NonFileUriError,
    SymlinkEscapeError,
    UriMappingError,
    WorkspaceEscapeError,
    map_lsp_uri_to_workspace_path,
    path_to_file_uri,
)

__all__ = [
    "DEFAULT_CONFIG",
    "DiskWorkspaceDocumentProvider",
    # Cache
    "EvidenceCache",
    "EvidenceCacheEntry",
    "EvidenceCacheKey",
    "EvidenceSource",
    "EvidenceType",
    "FusedResolution",
    "FusionContext",
    "FusionRule",
    # Client
    "LspClient",
    "LspDiagnostic",
    # Fusion service
    "LspEvidenceFusionService",
    # Config
    "LspFusionConfig",
    "NonFileUriError",
    "PositionConversionError",
    # Position conversion
    "PositionMapping",
    # Evidence models
    "SemanticEvidence",
    "SymlinkEscapeError",
    "UriMappingError",
    # Document provider
    "WorkspaceDocument",
    "WorkspaceDocumentProvider",
    "WorkspaceEscapeError",
    "byte_offset_to_lsp_position",
    "compute_content_hash",
    "compute_server_identity",
    "lsp_position_to_offsets",
    "lsp_range_to_byte_offsets",
    # URI mapping
    "map_lsp_uri_to_workspace_path",
    "path_to_file_uri",
]
