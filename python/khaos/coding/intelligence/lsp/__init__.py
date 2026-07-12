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
    FusionRule,
    FusedResolution,
    SemanticEvidence,
)
from khaos.coding.intelligence.lsp.fusion import (
    FusionContext,
    LspEvidenceFusionService,
    compute_content_hash,
    compute_server_identity,
)
from khaos.coding.intelligence.lsp.positions import (
    PositionMapping,
    PositionConversionError,
    byte_offset_to_lsp_position,
    lsp_position_to_offsets,
    lsp_range_to_byte_offsets,
)
from khaos.coding.intelligence.lsp.uri import (
    SymlinkEscapeError,
    UriMappingError,
    WorkspaceEscapeError,
    NonFileUriError,
    map_lsp_uri_to_workspace_path,
    path_to_file_uri,
)

__all__ = [
    # Client
    "LspClient",
    "LspDiagnostic",
    # Config
    "LspFusionConfig",
    "DEFAULT_CONFIG",
    # Document provider
    "WorkspaceDocument",
    "WorkspaceDocumentProvider",
    "DiskWorkspaceDocumentProvider",
    # Evidence models
    "SemanticEvidence",
    "FusedResolution",
    "EvidenceSource",
    "EvidenceType",
    "FusionRule",
    "EvidenceCacheKey",
    "EvidenceCacheEntry",
    # Cache
    "EvidenceCache",
    # Fusion service
    "LspEvidenceFusionService",
    "FusionContext",
    "compute_server_identity",
    "compute_content_hash",
    # URI mapping
    "map_lsp_uri_to_workspace_path",
    "path_to_file_uri",
    "UriMappingError",
    "NonFileUriError",
    "WorkspaceEscapeError",
    "SymlinkEscapeError",
    # Position conversion
    "PositionMapping",
    "PositionConversionError",
    "lsp_position_to_offsets",
    "byte_offset_to_lsp_position",
    "lsp_range_to_byte_offsets",
]
