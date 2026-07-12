"""Strict LSP URI → workspace-relative path mapping.

Enforces that every LSP definition/reference location points inside the
active TaskWorkspace. No path that escapes the workspace, crosses into
another task workspace, or uses a non-``file:`` scheme is ever accepted.

Mapping pipeline (per spec §4):
    LSP URI
    → file URI decode (percent-decoded)
    → canonical absolute path (symlinks resolved)
    → current TaskWorkspace boundary check
    → repository-relative POSIX path

Rejected conditions:
    - non-``file:`` URI (unless explicitly supported — never, by default)
    - workspace-external path
    - another Task Workspace's path
    - ``..`` traversal that escapes the workspace
    - symlink whose target leaves the workspace
    - path that is not inside the active workspace's worktree
"""
from __future__ import annotations

from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlparse


class UriMappingError(Exception):
    """Base for URI mapping rejections."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class NonFileUriError(UriMappingError):
    """URI scheme is not ``file:``."""


class WorkspaceEscapeError(UriMappingError):
    """Resolved path is outside the active TaskWorkspace."""


class SymlinkEscapeError(UriMappingError):
    """A symlink component resolves outside the workspace."""


def map_lsp_uri_to_workspace_path(
    uri: str,
    workspace_root: Path,
    *,
    other_workspace_roots: tuple[Path, ...] = (),
) -> str:
    """Map an LSP ``file:`` URI to a repository-relative POSIX path.

    Args:
        uri: The LSP document URI (must be ``file:`` scheme).
        workspace_root: The active TaskWorkspace's worktree path
            (already resolved to an absolute canonical path).
        other_workspace_roots: Roots of other Task Workspaces, used to
            reject URIs that point into a different task's workspace.

    Returns:
        Repository-relative POSIX path (e.g. ``"src/app.py"``).

    Raises:
        NonFileUriError: URI is not a ``file:`` URI.
        WorkspaceEscapeError: Path is outside the active workspace.
        SymlinkEscapeError: A symlink target escapes the workspace.
    """
    parsed = urlparse(uri)
    if parsed.scheme != "file":
        raise NonFileUriError(
            "non-file-uri",
            f"LSP URI must be a file URI, got scheme {parsed.scheme!r}",
        )

    # Percent-decode the path component. urlparse already splits the path,
    # but does NOT decode percent-encoding — we do that explicitly to handle
    # Unicode filenames and spaces.
    decoded_path = unquote(parsed.path)

    # On macOS, file URIs for the root disk may carry a leading empty
    # component (e.g. ``file:///Users/...`` → path ``/Users/...``), which
    # is correct. On Windows the path would include a drive letter; we do
    # not support Windows LSP URIs in this iteration.
    raw = Path(decoded_path)

    # Reject ``..`` traversal before resolution. ``resolve()`` would
    # neutralise it, but we want an explicit rejection so callers know
    # the input was suspicious.
    if any(part == ".." for part in raw.parts):
        raise WorkspaceEscapeError(
            "dotdot-traversal",
            "LSP URI path contains '..' traversal",
        )

    # Expand user (defensive — LSP should never send ``~``) and resolve
    # symlinks. ``strict=False`` allows the path to not yet exist (LSP
    # may report a definition in a file that was just created but not
    # yet re-indexed); we still resolve the longest existing prefix.
    resolved = _resolve_within_workspace(raw, workspace_root)

    # Boundary check: the resolved path must be inside workspace_root.
    root = workspace_root.expanduser().resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        # Check if it points into another task workspace — that is a
        # distinct rejection reason so callers can detect cross-task leaks.
        for other in other_workspace_roots:
            other_resolved = other.expanduser().resolve()
            try:
                resolved.relative_to(other_resolved)
                raise WorkspaceEscapeError(
                    "other-task-workspace",
                    f"LSP URI points into another task workspace: {other}",
                ) from exc
            except ValueError:
                continue
        raise WorkspaceEscapeError(
            "workspace-external",
            f"LSP URI resolves outside the active workspace: {resolved} not in {root}",
        ) from exc

    # Return repository-relative POSIX path.
    relative = resolved.relative_to(root)
    return relative.as_posix()


def workspace_root_from_uri(uri: str) -> Path:
    """Decode a ``file:`` URI to an absolute ``Path`` without boundary checks.

    Used by callers that need the raw decoded path for logging before
    applying boundary checks via :func:`map_lsp_uri_to_workspace_path`.
    """
    parsed = urlparse(uri)
    if parsed.scheme != "file":
        raise NonFileUriError(
            "non-file-uri",
            f"LSP URI must be a file URI, got scheme {parsed.scheme!r}",
        )
    return Path(unquote(parsed.path))


def _resolve_within_workspace(path: Path, workspace_root: Path) -> Path:
    """Resolve symlinks, rejecting any target that escapes the workspace.

    We walk the path component-by-component. If a component is a symlink,
    we resolve it and verify the target remains inside the workspace root.
    This prevents a symlink inside the workspace from pointing at a file
    outside it (a classic LSP URI escape vector).
    """
    root = workspace_root.expanduser().resolve()
    # If the path is relative, anchor it at the workspace root.
    anchored = path if path.is_absolute() else (root / path)

    # If the path does not exist, resolve the existing prefix and append
    # the non-existent tail. This matches LSP semantics where a definition
    # may be reported in a file that was just created.
    existing = anchored
    tail: list[str] = []
    while not existing.exists() and existing != existing.parent:
        tail.insert(0, existing.name)
        existing = existing.parent

    try:
        resolved_prefix = existing.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        # If strict resolution fails (broken symlink, permission), fall
        # back to a lexical resolution — the boundary check below will
        # catch any escape.
        resolved_prefix = anchored

    # Re-attach the non-existent tail lexically.
    resolved = resolved_prefix
    for part in tail:
        resolved = resolved / part

    # Symlink escape check: walk each existing parent and confirm it is
    # inside the workspace. This catches symlinks that point outside even
    # when the final path does not exist yet.
    check = resolved
    while check.exists() and check != check.parent:
        try:
            real = check.resolve(strict=True)
            # If real is outside root and check is inside root, a symlink
            # is escaping — reject it.
            try:
                real.relative_to(root)
            except ValueError:
                # The real target is outside root. Was ``check`` inside
                # root? If yes, this is a symlink escape.
                try:
                    check.relative_to(root)
                    raise SymlinkEscapeError(
                        "symlink-escape",
                        f"symlink at {check} resolves outside workspace to {real}",
                    )
                except ValueError:
                    # check itself is outside root — handled by the
                    # outer boundary check.
                    pass
        except (OSError, RuntimeError):
            pass
        check = check.parent

    return resolved


def path_to_file_uri(path: Path) -> str:
    """Encode an absolute ``Path`` as a ``file:`` URI (for LSP requests)."""
    resolved = path.expanduser().resolve()
    # PurePosixPath is used to ensure forward slashes regardless of platform.
    return "file://" + PurePosixPath(str(resolved)).as_posix()
