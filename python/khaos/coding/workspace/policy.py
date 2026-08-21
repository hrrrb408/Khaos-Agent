"""Shared workspace policy constants and component checks.

Filesystem, workspace bootstrap, and platform execution must agree on which
metadata is protected.  Keeping this policy separate from the implementation
of ``SafeWorkspaceFS`` prevents a backend from silently inventing a weaker
protected-name list.
"""

from __future__ import annotations

from pathlib import Path

PROTECTED_WORKSPACE_NAMES = frozenset(
    {".git", ".agents", ".codex", ".khaos", "khaos_policy.yaml"}
)
PROTECTED_WORKSPACE_NAMES_CASEFOLD = frozenset(
    name.casefold() for name in PROTECTED_WORKSPACE_NAMES
)

DEFAULT_FILE_TOOL_BYTES = 16 * 1024 * 1024
DEFAULT_TREE_BYTES = 64 * 1024 * 1024
DEFAULT_TREE_ENTRIES = 4096
DEFAULT_TREE_DEPTH = 32


def is_protected_workspace_name(name: str) -> bool:
    """Return whether one path component is protected, case-insensitively."""
    return str(name).casefold() in PROTECTED_WORKSPACE_NAMES_CASEFOLD


def path_reaches_protected_metadata(path: str | Path) -> bool:
    """Return whether any component of ``path`` reaches protected metadata."""
    return any(is_protected_workspace_name(part) for part in Path(path).parts)


__all__ = [
    "DEFAULT_FILE_TOOL_BYTES",
    "DEFAULT_TREE_BYTES",
    "DEFAULT_TREE_DEPTH",
    "DEFAULT_TREE_ENTRIES",
    "PROTECTED_WORKSPACE_NAMES",
    "PROTECTED_WORKSPACE_NAMES_CASEFOLD",
    "is_protected_workspace_name",
    "path_reaches_protected_metadata",
]
