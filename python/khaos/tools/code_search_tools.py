"""Workspace-bound code search and repository-backed symbol tools."""

from __future__ import annotations

import ast
import asyncio
from fnmatch import fnmatch
from pathlib import Path, PurePosixPath
from typing import Any

from khaos.coding.intelligence.repository import (
    RepoIntelligenceService,
    RepoIntelligenceIndexUnavailableError,
    RepoQueryKind,
    RepoQueryRequest,
    RepoIntelligenceUnavailableError,
)


def _workspace_for_tool(workspace_manager: Any, workspace_id: str | None, task_id: str | None) -> Any:
    if workspace_manager is None:
        raise PermissionError("coding search requires active TaskWorkspace")
    workspace = workspace_manager.get(workspace_id or "")
    if workspace is None or getattr(workspace, "task_id", None) != task_id:
        raise PermissionError("coding search requires matching active TaskWorkspace")
    return workspace


def _can_use_repo_service(workspace: Any) -> bool:
    return bool(
        getattr(workspace, "id", None)
        and getattr(workspace, "principal_id", None)
        and getattr(workspace, "project_id", None)
    )


async def code_search(
    root: str = ".",
    query: str = "",
    glob: str = "*.py",
    limit: int = 100,
    language: str | None = None,
    workspace_manager=None,
    task_id: str | None = None,
    workspace_id: str | None = None,
    principal_id: str = "",
    project_id: str = "",
    repo_intelligence: RepoIntelligenceService | None = None,
) -> dict[str, Any]:
    """Search indexed semantic code first, then bounded lexical source text."""
    workspace = _workspace_for_tool(workspace_manager, workspace_id, task_id)
    if repo_intelligence is None and _can_use_repo_service(workspace):
        raise PermissionError("runtime repository intelligence is required")
    if repo_intelligence is None:
        result = await asyncio.to_thread(
            _safe_code_search_sync,
            workspace.worktree_path,
            root,
            query,
            glob,
            limit,
            language,
        )
        result.update(
            {
                "freshness": "unavailable",
                "semantic_support": False,
                "lexical_fallback": True,
                "fallback_reason": "legacy_compatibility_boundary",
            }
        )
        return result
    with _safe_root(workspace.worktree_path, root) as (_, search_base):
        pass
    owner_principal = principal_id or str(getattr(workspace, "principal_id", "") or "")
    owner_project = project_id or str(getattr(workspace, "project_id", "") or "")
    try:
        result = await repo_intelligence.query(
            RepoQueryRequest(
                workspace_id=str(workspace.id),
                task_id=str(workspace.task_id),
                principal_id=owner_principal,
                project_id=owner_project,
                kind=RepoQueryKind.SEARCH_TEXT,
                query=query,
                path_prefix=search_base,
                path_glob=glob,
                language=language or "",
                limit=max(1, min(int(limit), 256)),
            )
        )
    except RepoIntelligenceIndexUnavailableError:
        # The normal path remains repository-service-backed.  If that
        # advisory index cannot be produced, expose a separately bounded,
        # safe lexical scan with explicit degraded-freshness telemetry rather
        # than silently presenting source text as semantic evidence.
        repo_intelligence.record_lexical_fallback()
        result = await asyncio.to_thread(
            _safe_code_search_sync,
            workspace.worktree_path,
            root,
            query,
            glob,
            limit,
            language,
        )
        result.update(
            {
                "freshness": "unavailable",
                "semantic_support": False,
                "lexical_fallback": True,
                "fallback_reason": "semantic_repository_unavailable",
            }
        )
        return result
    with _safe_root(workspace.worktree_path, root) as (root_path, base):
        matches: list[dict[str, Any]] = []
        for item in result.text_matches:
            if language and item.language.casefold() != language.casefold():
                continue
            if not fnmatch(_path_for_glob(item.path, base), glob):
                continue
            matches.append({"path": str(workspace_root_path(workspace) / item.path), "line": item.line, "text": item.text})
            if len(matches) >= limit:
                break
        # A semantic symbol match is still useful to the legacy tool shape;
        # source text is not read again here, so the tool cannot bypass the
        # repository service's bounded source and generation contract.
        if not matches:
            for item in result.symbols:
                if language and item.language.casefold() != language.casefold():
                    continue
                if not fnmatch(_path_for_glob(item.path, base), glob):
                    continue
                matches.append({"path": str(workspace_root_path(workspace) / item.path), "line": item.start_line + 1, "text": item.name})
                if len(matches) >= limit:
                    break
        return {
            "root": str(root_path),
            "matches": matches,
            "count": len(matches),
            "freshness": result.freshness.value,
            "semantic_support": result.semantic_support,
            "lexical_fallback": result.lexical_fallback,
            "truncated": result.truncated,
        }


async def code_symbols(
    path: str,
    workspace_manager=None,
    task_id: str | None = None,
    workspace_id: str | None = None,
    principal_id: str = "",
    project_id: str = "",
    repo_intelligence: RepoIntelligenceService | None = None,
) -> dict[str, Any]:
    """Return Tree-sitter/repository-backed symbols for any registered language."""
    workspace = _workspace_for_tool(workspace_manager, workspace_id, task_id)
    if repo_intelligence is None and _can_use_repo_service(workspace):
        raise PermissionError("runtime repository intelligence is required")
    if repo_intelligence is None:
        return await asyncio.to_thread(_safe_code_symbols_sync, workspace.worktree_path, path)
    owner_principal = principal_id or str(getattr(workspace, "principal_id", "") or "")
    owner_project = project_id or str(getattr(workspace, "project_id", "") or "")
    root = workspace_root_path(workspace)
    relative = _relative_for_display(root, path)
    try:
        result = await repo_intelligence.query(
            RepoQueryRequest(
                workspace_id=str(workspace.id),
                task_id=str(workspace.task_id),
                principal_id=owner_principal,
                project_id=owner_project,
                kind=RepoQueryKind.SYMBOLS,
                path=relative,
                limit=256,
            )
        )
    except RepoIntelligenceUnavailableError as exc:
        raise PermissionError("safe repository intelligence is unavailable") from exc
    return {
        "path": str(root / relative),
        "symbols": [
            {
                "name": item.name,
                "kind": item.kind,
                "line": item.start_line + 1,
                "language": item.language,
                "qualified_name": item.qualified_name,
                "symbol_id": item.symbol_id,
                "stable_symbol_id": item.stable_symbol_id,
            }
            for item in result.symbols
        ],
        "freshness": result.freshness.value,
        "semantic_support": result.semantic_support,
        "truncated": result.truncated,
    }


def workspace_root_path(workspace: Any) -> Path:
    return Path(workspace.worktree_path).expanduser().resolve(strict=True)


def _relative_for_display(root: Path, target: str) -> str:
    from khaos.coding.workspace.boundary import SafeWorkspaceFS

    with SafeWorkspaceFS(root) as filesystem:
        return filesystem.relative(target)


def _path_for_glob(path: str, base: str) -> str:
    """Return a repository-relative path for legacy glob matching."""
    if not base:
        return path
    prefix = base.rstrip("/") + "/"
    return path[len(prefix):] if path.startswith(prefix) else path


class _SafeRoot:
    def __init__(self, root: Path, relative: str) -> None:
        from khaos.coding.workspace.boundary import SafeWorkspaceFS

        self._filesystem = SafeWorkspaceFS(root)
        self._relative = self._filesystem._directory_relative(relative)

    def __enter__(self) -> tuple[Path, str]:
        return self._filesystem.root / self._relative, self._relative

    def __exit__(self, *_args: object) -> None:
        self._filesystem.close()


def _safe_root(root: Path, relative: str) -> _SafeRoot:
    return _SafeRoot(root, relative)


def _safe_code_search_sync(
    workspace_root: Path,
    root: str,
    query: str,
    glob: str,
    limit: int,
    language: str | None = None,
) -> dict[str, Any]:
    from khaos.coding.workspace.boundary import SafeWorkspaceFS, WorkspaceBoundaryError

    bounded_limit = max(1, min(int(limit), 256))
    max_total_bytes = 256 * 1024
    max_file_bytes = 64 * 1024
    ignored_dirs = {
        ".cache",
        ".venv",
        "__pycache__",
        "build",
        "coverage",
        "dist",
        "generated",
        "node_modules",
        "target",
        "vendor",
    }
    with SafeWorkspaceFS(workspace_root) as filesystem:
        base = filesystem._directory_relative(root)
        fallback_max_depth = 32
        base_depth = len(PurePosixPath(base).parts) if base else 0
        matches: list[dict[str, Any]] = []
        total_bytes = 0
        truncated = False
        truncation_reasons: list[str] = []
        try:
            entries = filesystem.iter_entries(
                root,
                max_entries=4096,
                # Ask for one sentinel level so the bounded result can report
                # that the walk stopped at the depth boundary instead of silently
                # presenting an incomplete lexical search as exhaustive.
                max_depth=fallback_max_depth + 1,
                ignored_dirs=ignored_dirs,
            )
        except WorkspaceBoundaryError as exc:
            message = str(exc).casefold()
            if "entry limit" not in message and "duration limit" not in message:
                raise
            reason = (
                "max_fallback_entries"
                if "entry limit" in message
                else "max_fallback_duration"
            )
            return {
                "root": str(filesystem.root / base),
                "matches": [],
                "count": 0,
                "truncated": True,
                "truncation_reasons": (reason,),
            }
        for relative, is_directory in entries:
            relative_depth = len(PurePosixPath(relative).parts) - base_depth
            if relative_depth > fallback_max_depth:
                truncated = True
                truncation_reasons.append("max_fallback_depth")
                continue
            if is_directory:
                continue
            display = relative[len(base) + 1:] if base else relative
            if not fnmatch(display, glob):
                continue
            if language and _legacy_language(relative) != language.casefold():
                continue
            try:
                remaining = max_total_bytes - total_bytes
                if remaining <= 0:
                    truncated = True
                    truncation_reasons.append("max_fallback_bytes")
                    break
                raw = filesystem.read_bytes(
                    relative, max_bytes=min(max_file_bytes, remaining)
                )
                total_bytes += len(raw)
                lines = raw.decode("utf-8").splitlines()
            except UnicodeDecodeError:
                continue
            except (OSError, PermissionError):
                truncated = True
                truncation_reasons.append(f"unreadable:{relative}")
                continue
            for line_no, line in enumerate(lines, start=1):
                if query in line:
                    matches.append({
                        "path": str(filesystem.root / relative),
                        "line": line_no,
                        "text": line,
                    })
                    break
            if len(matches) >= bounded_limit:
                break
        return {
            "root": str(filesystem.root / base),
            "matches": matches,
            "count": len(matches),
            "truncated": truncated,
            "truncation_reasons": tuple(sorted(set(truncation_reasons))),
        }


def _legacy_language(path: str) -> str:
    suffix = Path(path).suffix.casefold()
    return {
        ".py": "python",
        ".js": "javascript",
        ".jsx": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".go": "go",
        ".rs": "rust",
    }.get(suffix, "text")


def _safe_code_symbols_sync(workspace_root: Path, path: str) -> dict[str, Any]:
    from khaos.coding.workspace.boundary import SafeWorkspaceFS

    with SafeWorkspaceFS(workspace_root) as filesystem:
        relative = filesystem.relative(path)
        tree = ast.parse(filesystem.read_bytes(path).decode("utf-8"))
        symbols = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                symbols.append({"name": node.name, "kind": type(node).__name__, "line": node.lineno})
        symbols.sort(key=lambda item: item["line"])
        return {"path": str(filesystem.root / relative), "symbols": symbols}


__all__ = ["code_search", "code_symbols"]
