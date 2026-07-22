"""File operation tools."""

from __future__ import annotations

import asyncio
import fnmatch
import json
import mimetypes
import os
import stat
import tempfile
from difflib import SequenceMatcher
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

TREE_EXCLUDE_DIRS = {
    ".git",
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    ".next",
    "target",
    "dist",
    "build",
}

# B1: the previous module-global ``_office_authority`` (set by
# ``set_office_authority``) has been REMOVED.  Concurrent ``build_runtime``
# calls overwrote it without coordination, so a ``copy_file`` direct call
# could land on an unrelated runtime's authority — losing the baseline and
# the fence.  The authority is now injected explicitly through the
# ToolScheduler's ``office_authority`` instance attribute (set in
# ``build_runtime``) and threaded into ``copy_file`` / ``move_file`` via the
# scheduler's ``invocation_context``.  Mutations fail closed when that
# authority is absent; there is no unfenced production or test fallback.

async def read_file(path: str, offset: int = 1, limit: int = 500, workspace_manager=None, task_id: str | None = None, workspace_id: str | None = None, workspace_root: Path | None = None) -> dict[str, Any]:
    """Read a file page with one-based line numbers."""
    if workspace_manager is not None:
        workspace = workspace_manager.get(workspace_id or "")
        if workspace is None or workspace.task_id != task_id:
            raise PermissionError("coding read requires matching active TaskWorkspace")
        return await asyncio.to_thread(
            _workspace_read_sync, workspace.worktree_path, path, offset, limit
        )
    if workspace_root is not None:
        return await asyncio.to_thread(
            _workspace_read_sync, workspace_root, path, offset, limit
        )
    raise PermissionError("read_file requires a Workspace root capability")


async def write_file(path: str, content: str, workspace_manager=None, task_id: str | None = None, workspace_id: str | None = None, workspace_root: Path | None = None, office_authority=None) -> dict[str, Any]:
    """Overwrite a file, creating parent directories as needed."""
    if workspace_manager is not None:
        workspace = workspace_manager.get(workspace_id or "")
        if workspace is None or workspace.task_id != task_id:
            raise PermissionError("coding write requires matching active TaskWorkspace")
        return await _workspace_mutate(
            workspace_manager,
            workspace,
            task_id or "",
            lambda: _workspace_write_sync(
                workspace.worktree_path,
                workspace_manager.file_recovery_root(workspace.id),
                path,
                content,
            ),
        )
    if workspace_root is not None:
        if office_authority is None:
            raise PermissionError("OfficeMutationAuthority is required for writes")
        workspace = await office_authority.workspace_for_root(workspace_root)
        return await office_authority.mutate(
            workspace,
            lambda cancel_event: _office_write_mutation(
                workspace_root, path, content, cancel_event=cancel_event
            ),
        )
    raise PermissionError("write_file requires a Workspace root capability")


async def patch(path: str, old: str, new: str, fuzzy: bool = True, workspace_manager=None, task_id: str | None = None, workspace_id: str | None = None, workspace_root: Path | None = None, office_authority=None) -> dict[str, Any]:
    """Atomically replace text in a file, with optional fuzzy block matching."""
    if workspace_manager is not None:
        workspace = workspace_manager.get(workspace_id or "")
        if workspace is None or workspace.task_id != task_id:
            raise PermissionError("coding patch requires matching active TaskWorkspace")
        return await _workspace_mutate(
            workspace_manager,
            workspace,
            task_id or "",
            lambda: _workspace_patch_sync(
                workspace.worktree_path,
                workspace_manager.file_recovery_root(workspace.id),
                path, old, new, fuzzy,
            ),
        )
    if workspace_root is not None:
        if office_authority is None:
            raise PermissionError("OfficeMutationAuthority is required for patch")
        workspace = await office_authority.workspace_for_root(workspace_root)
        return await office_authority.mutate(
            workspace,
            lambda cancel_event: _office_patch_mutation(
                workspace_root,
                path,
                old,
                new,
                fuzzy,
                cancel_event=cancel_event,
            ),
        )
    raise PermissionError("patch requires a Workspace root capability")


async def multi_edit(path: str, edits: list[dict], workspace_manager=None, task_id: str | None = None, workspace_id: str | None = None, workspace_root: Path | None = None, office_authority=None) -> str:
    """Apply multiple exact search-and-replace edits to one file atomically."""
    if workspace_manager is not None:
        workspace = workspace_manager.get(workspace_id or "")
        if workspace is None or workspace.task_id != task_id:
            raise PermissionError("coding edit requires matching active TaskWorkspace")
        return await _workspace_mutate(
            workspace_manager,
            workspace,
            task_id or "",
            lambda: _workspace_multi_edit_sync(
                workspace.worktree_path,
                workspace_manager.file_recovery_root(workspace.id),
                path, edits,
            ),
        )
    if workspace_root is not None:
        if office_authority is None:
            raise PermissionError("OfficeMutationAuthority is required for edits")
        workspace = await office_authority.workspace_for_root(workspace_root)
        return await office_authority.mutate(
            workspace,
            lambda cancel_event: _office_multi_edit_mutation(
                workspace_root, path, edits, cancel_event=cancel_event
            ),
        )
    raise PermissionError("multi_edit requires a Workspace root capability")


def _normalize_multi_edits(edits: list[dict]) -> list[dict[str, str]]:
    if not isinstance(edits, list):
        raise ValueError("edits must be a list")
    normalized: list[dict[str, str]] = []
    for index, edit in enumerate(edits):
        if not isinstance(edit, dict):
            raise ValueError(f"edit at index {index} must be an object")
        old_text = edit.get("old_text")
        new_text = edit.get("new_text")
        if not isinstance(old_text, str) or not isinstance(new_text, str):
            raise ValueError(f"edit at index {index} must include string old_text and new_text")
        if old_text == "":
            raise ValueError(f"edit at index {index} old_text must not be empty")
        normalized.append({"old_text": old_text, "new_text": new_text})
    return normalized


async def search_files(
    root: str = ".",
    query: str = "",
    glob: str = "*",
    content: bool = False,
    limit: int = 100,
    workspace_manager=None,
    task_id: str | None = None,
    workspace_id: str | None = None,
    workspace_root: Path | None = None,
) -> dict[str, Any]:
    """Search file paths by glob or file contents by text."""
    if workspace_manager is not None:
        workspace = workspace_manager.get(workspace_id or "")
        if workspace is None or workspace.task_id != task_id:
            raise PermissionError("coding search requires matching active TaskWorkspace")
        return await asyncio.to_thread(
            _workspace_search_sync, workspace.worktree_path, root, query,
            glob, content, limit,
        )
    if workspace_root is not None:
        return await asyncio.to_thread(
            _workspace_search_sync, workspace_root, root, query, glob,
            content, limit,
        )
    raise PermissionError("search_files requires a Workspace root capability")


async def list_directory(path: str = ".", include_hidden: bool = True, workspace_manager=None, task_id: str | None = None, workspace_id: str | None = None, workspace_root: Path | None = None) -> dict[str, Any]:
    """List directory contents with structured metadata."""
    if workspace_manager is not None:
        workspace = workspace_manager.get(workspace_id or "")
        if workspace is None or workspace.task_id != task_id:
            raise PermissionError("coding list requires matching active TaskWorkspace")
        return await asyncio.to_thread(
            _workspace_list_sync, workspace.worktree_path, path, include_hidden
        )
    if workspace_root is not None:
        return await asyncio.to_thread(
            _office_list_sync, workspace_root, path, include_hidden
        )
    raise PermissionError("list_directory requires a Workspace root capability")


async def file_info(path: str, workspace_manager=None, task_id: str | None = None, workspace_id: str | None = None, workspace_root: Path | None = None) -> dict[str, Any]:
    """Get detailed file or directory metadata."""
    if workspace_manager is not None:
        workspace = workspace_manager.get(workspace_id or "")
        if workspace is None or workspace.task_id != task_id:
            raise PermissionError("coding info requires matching active TaskWorkspace")
        return await asyncio.to_thread(
            _workspace_info_sync, workspace.worktree_path, path
        )
    if workspace_root is not None:
        return await asyncio.to_thread(_office_info_sync, workspace_root, path)
    raise PermissionError("file_info requires a Workspace root capability")


async def tree_view(path: str = ".", max_depth: int = 3, workspace_manager=None, task_id: str | None = None, workspace_id: str | None = None, workspace_root: Path | None = None) -> dict[str, Any]:
    """Generate a formatted directory tree view."""
    if workspace_manager is not None:
        workspace = workspace_manager.get(workspace_id or "")
        if workspace is None or workspace.task_id != task_id:
            raise PermissionError("coding tree requires matching active TaskWorkspace")
        return await asyncio.to_thread(
            _workspace_tree_sync, workspace.worktree_path, path, max_depth
        )
    if workspace_root is not None:
        return await asyncio.to_thread(
            _office_tree_sync, workspace_root, path, max_depth
        )
    raise PermissionError("tree_view requires a Workspace root capability")


async def copy_file(src: str, dst: str, workspace_manager=None, task_id: str | None = None, workspace_id: str | None = None, workspace_root: Path | None = None, office_authority=None) -> dict[str, Any]:
    """Copy a file or directory."""
    if workspace_manager is not None:
        workspace = workspace_manager.get(workspace_id or "")
        if workspace is None or workspace.task_id != task_id:
            raise PermissionError("coding copy requires matching active TaskWorkspace")
        return await _workspace_mutate(
            workspace_manager,
            workspace,
            task_id or "",
            lambda: _workspace_copy_sync(
                workspace.worktree_path,
                workspace_manager.file_recovery_root(workspace.id),
                src, dst,
            ),
        )
    if workspace_root is not None:
        if office_authority is not None:
            # H1: route through the mutation fence so cancellation / timeout
            # cannot abandon a running copy thread that later commits a side
            # effect via the final atomic rename.
            workspace = await office_authority.workspace_for_root(workspace_root)
            return await office_authority.mutate(
                workspace,
                lambda cancel_event: _office_copy_mutation(
                    workspace_root, src, dst, cancel_event=cancel_event,
                ),
            )
        raise PermissionError("OfficeMutationAuthority is required for copy")
    raise PermissionError("copy_file requires a Workspace root capability")


async def move_file(src: str, dst: str, workspace_manager=None, task_id: str | None = None, workspace_id: str | None = None, workspace_root: Path | None = None, office_authority=None) -> dict[str, Any]:
    """Move or rename a file or directory."""
    if workspace_manager is not None:
        workspace = workspace_manager.get(workspace_id or "")
        if workspace is None or workspace.task_id != task_id:
            raise PermissionError("coding move requires matching active TaskWorkspace")
        return await _workspace_mutate(
            workspace_manager,
            workspace,
            task_id or "",
            lambda: _workspace_move_sync(workspace.worktree_path, src, dst),
        )
    if workspace_root is not None:
        if office_authority is not None:
            workspace = await office_authority.workspace_for_root(workspace_root)
            return await office_authority.mutate(
                workspace,
                lambda cancel_event: _office_move_mutation(
                    workspace_root, src, dst, cancel_event=cancel_event,
                ),
            )
        raise PermissionError("OfficeMutationAuthority is required for move")
    raise PermissionError("move_file requires a Workspace root capability")


async def file_search_content(
    path: str,
    pattern: str,
    max_results: int = 50,
    workspace_manager=None,
    task_id: str | None = None,
    workspace_id: str | None = None,
    workspace_root: Path | None = None,
) -> dict[str, Any]:
    """Search text file contents for a substring or basic regular expression."""
    if workspace_manager is not None:
        workspace = workspace_manager.get(workspace_id or "")
        if workspace is None or workspace.task_id != task_id:
            raise PermissionError("coding content search requires matching active TaskWorkspace")
        return await asyncio.to_thread(
            _workspace_content_search_sync,
            workspace.worktree_path,
            path,
            pattern,
            max_results,
        )
    if workspace_root is not None:
        return await asyncio.to_thread(
            _workspace_content_search_sync,
            workspace_root,
            path,
            pattern,
            max_results,
        )
    raise PermissionError(
        "file_search_content requires a Workspace root capability"
    )


async def _workspace_mutate(
    workspace_manager,
    workspace,
    task_id: str,
    operation,
):
    """Require the shared storage authority for every Coding file write."""
    mutate = getattr(workspace_manager, "mutate_with_storage_authority", None)
    if mutate is None:
        raise PermissionError("WorkspaceStorageAuthority is required for writes")
    return await mutate(workspace.id, task_id, operation)


def _workspace_write_sync(
    root: Path,
    recovery_root: Path,
    path: str,
    content: str,
    *,
    cancel_event=None,
) -> object:
    from khaos.coding.workspace.boundary import SafeWorkspaceFS
    from khaos.coding.workspace.storage import WorkspaceMutation

    with SafeWorkspaceFS(root) as filesystem:
        relative = filesystem.relative(path)
        before = filesystem.snapshot_file(path, recovery_root=recovery_root)
        try:
            encoded = content.encode("utf-8")
            filesystem.write_bytes(path, encoded, cancel_event=cancel_event)
            after = filesystem.snapshot_file(path)
        except Exception:
            before.cleanup()
            raise
        value = {
            "path": str(filesystem.root / relative),
            "bytes": len(encoded),
        }
    return WorkspaceMutation(
        value,
        lambda: _rollback_file(root, path, before, after),
        before.cleanup,
    )


def _office_write_sync(root: Path, path: str, content: str) -> dict[str, Any]:
    from khaos.coding.workspace.boundary import SafeWorkspaceFS

    encoded = content.encode("utf-8")
    with SafeWorkspaceFS(root) as filesystem:
        relative = filesystem.relative(path)
        filesystem.ensure_parent_directories(path)
        filesystem.write_bytes(path, encoded)
        return {
            "path": str(filesystem.root / relative),
            "bytes": len(encoded),
        }


def _office_patch_sync(
    root: Path, path: str, old: str, new: str, fuzzy: bool
) -> dict[str, Any]:
    from khaos.coding.workspace.boundary import SafeWorkspaceFS

    result: dict[str, Any] = {}
    with SafeWorkspaceFS(root) as filesystem:
        relative = filesystem.relative(path)

        def transform(original: str) -> str:
            if old in original:
                result.update(replaced=1, fuzzy=False)
                return original.replace(old, new, 1)
            if not fuzzy:
                raise ValueError("old text not found")
            match = _find_fuzzy_block(original, old)
            if match is None:
                raise ValueError("old text not found")
            start, end, score = match
            result.update(replaced=1, fuzzy=True, score=score)
            return original[:start] + new + original[end:]

        filesystem.transform_text(path, transform)
        return {"path": str(filesystem.root / relative), **result}


def _office_multi_edit_sync(
    root: Path, path: str, edits: list[dict]
) -> str:
    from khaos.coding.workspace.boundary import SafeWorkspaceFS

    normalized_edits = _normalize_multi_edits(edits)
    sorted_edits = sorted(
        enumerate(normalized_edits),
        key=lambda item: len(item[1]["old_text"]),
        reverse=True,
    )
    with SafeWorkspaceFS(root) as filesystem:
        relative = filesystem.relative(path)
        original = filesystem.read_bytes(path).decode("utf-8")
        failures: list[dict[str, Any]] = []
        for original_index, edit in sorted_edits:
            count = original.count(edit["old_text"])
            if count != 1:
                failures.append({
                    "index": original_index,
                    "old_text": edit["old_text"],
                    "matches": count,
                    "error": (
                        "old_text not found" if count == 0
                        else "old_text is not unique"
                    ),
                })
        if failures:
            return json.dumps({
                "path": str(filesystem.root / relative),
                "applied": 0,
                "failed": sorted(
                    failures, key=lambda item: int(item["index"])
                ),
            }, ensure_ascii=False)
        updated = original
        for _, edit in sorted_edits:
            updated = updated.replace(edit["old_text"], edit["new_text"], 1)
        filesystem.write_bytes(path, updated.encode("utf-8"))
        return json.dumps({
            "path": str(filesystem.root / relative),
            "applied": len(sorted_edits),
            "failed": [],
            "message": "All edits applied.",
        }, ensure_ascii=False)


def _office_copy_sync(
    root: Path, source: str, destination: str,
    *, cancel_event=None, identity_out=None,
) -> dict[str, Any]:
    from khaos.coding.workspace.boundary import SafeWorkspaceFS

    with SafeWorkspaceFS(root) as filesystem:
        source_relative = filesystem.relative(source)
        destination_relative = filesystem.relative(destination)
        try:
            size = filesystem.copy_path(
                source, destination,
                cancel_event=cancel_event, identity_out=identity_out,
            )
        except (FileNotFoundError, OSError) as exc:
            return {
                "ok": False,
                "src": str(filesystem.root / source_relative),
                "dst": str(filesystem.root / destination_relative),
                "error": "source does not exist" if isinstance(
                    exc, FileNotFoundError
                ) else str(exc),
            }
        return {
            "ok": True,
            "src": str(filesystem.root / source_relative),
            "dst": str(filesystem.root / destination_relative),
            "size_bytes": size,
        }


def _office_move_sync(
    root: Path, source: str, destination: str,
    *, cancel_event=None, identity_out=None,
) -> dict[str, Any]:
    from khaos.coding.workspace.boundary import SafeWorkspaceFS

    with SafeWorkspaceFS(root) as filesystem:
        source_relative = filesystem.relative(source)
        destination_relative = filesystem.relative(destination)
        try:
            filesystem.move_path(
                source, destination,
                cancel_event=cancel_event, identity_out=identity_out,
            )
        except (FileNotFoundError, OSError) as exc:
            return {
                "ok": False,
                "src": str(filesystem.root / source_relative),
                "dst": str(filesystem.root / destination_relative),
                "error": "source does not exist" if isinstance(
                    exc, FileNotFoundError
                ) else str(exc),
            }
        return {
            "ok": True,
            "src": str(filesystem.root / source_relative),
            "dst": str(filesystem.root / destination_relative),
        }


def _office_copy_mutation(
    root: Path, source: str, destination: str, *, cancel_event=None,
) -> object:
    """Office copy wrapped as a WorkspaceMutation for storage accounting.

    The copy itself goes through the existing ``copy_path`` atomic-publish
    path.  The rollback closure removes the published destination if a
    post-mutation storage violation is raised (e.g. aggregate budget blown),
    and the fence's ``asyncio.shield`` guarantees cancellation waits for the
    atomic rename to settle before propagating.

    H2: ``cancel_event`` is checked inside ``copy_path`` just before the
    final atomic rename.  If set, ``MutationCancelled`` is raised, the
    temporary tree is cleaned up, and no side effect lands.

    H4: the published destination's ``(st_dev, st_ino, st_mode)`` is
    captured *inside the same dirfd critical section* as the atomic
    rename (via ``identity_out``), eliminating the post-publish TOCTOU
    window that a separate ``capture_path_identity`` call would
    introduce.  The rollback closure then uses ``remove_published`` —
    which re-opens the parent through ``O_NOFOLLOW`` dirfds, ``lstat`` s
    the leaf *without* following it, verifies the identity still matches,
    and only then removes it.
    """
    from khaos.coding.workspace.storage import WorkspaceMutation

    identity_out: list = []
    value = _office_copy_sync(
        root, source, destination,
        cancel_event=cancel_event, identity_out=identity_out,
    )
    destination_relative = _destination_relative(root, destination)

    # H4: identity was captured in the same dirfd critical section as the
    # publish — no re-open window.  ``None`` (empty list) means the publish
    # did not actually land; rollback then becomes a no-op.
    published_identity: "tuple[int, int, int] | None" = (
        identity_out[0] if identity_out else None
    )

    def rollback() -> None:
        if not value.get("ok") or published_identity is None:
            return
        from khaos.coding.workspace.boundary import SafeWorkspaceFS
        with SafeWorkspaceFS(root) as filesystem:
            filesystem.remove_published(destination_relative, published_identity)

    return WorkspaceMutation(value=value, rollback=rollback, finalize=lambda: None)


def _office_move_mutation(
    root: Path, source: str, destination: str, *, cancel_event=None,
) -> object:
    """Office move wrapped as a WorkspaceMutation for storage accounting.

    Rollback moves the tree back to the source path.  If the source no longer
    exists (e.g. a concurrent change), rollback is a no-op rather than raising
    — the storage authority already flags ``quarantine_required`` from the
    residual violation.

    H2: ``cancel_event`` is checked inside ``move_path`` just before the
    final atomic rename.  If set, ``MutationCancelled`` is raised and the
    source is untouched.

    H4: the published destination's ``(st_dev, st_ino, st_mode)`` is
    captured inside the same dirfd critical section as the atomic rename
    (via ``identity_out``), eliminating the post-publish TOCTOU window.
    The rollback closure uses ``move_published_back`` — which re-opens
    the parent through ``O_NOFOLLOW`` dirfds, verifies the leaf's
    identity still matches, and only then performs an identity-bound
    ``move_path`` back to the source.
    """
    from khaos.coding.workspace.storage import WorkspaceMutation

    identity_out: list = []
    value = _office_move_sync(
        root, source, destination,
        cancel_event=cancel_event, identity_out=identity_out,
    )
    source_relative = _destination_relative(root, source)
    destination_relative = _destination_relative(root, destination)

    published_identity: "tuple[int, int, int] | None" = (
        identity_out[0] if identity_out else None
    )

    def rollback() -> None:
        if not value.get("ok") or published_identity is None:
            return
        from khaos.coding.workspace.boundary import SafeWorkspaceFS
        with SafeWorkspaceFS(root) as filesystem:
            filesystem.move_published_back(
                destination_relative, source_relative, published_identity
            )

    return WorkspaceMutation(value=value, rollback=rollback, finalize=lambda: None)


def _private_recovery_root() -> Path:
    root = Path(tempfile.mkdtemp(prefix="khaos-office-recovery-"))
    root.chmod(0o700)
    return root


def _with_recovery_cleanup(
    mutation,
    recovery_root: Path,
    *,
    rollback_created_parents=lambda: None,
):
    from khaos.coding.workspace.storage import WorkspaceMutation

    def cleanup() -> None:
        mutation.finalize()
        try:
            recovery_root.rmdir()
        except FileNotFoundError:
            pass

    def rollback() -> None:
        try:
            mutation.rollback()
            rollback_created_parents()
        finally:
            cleanup()

    return WorkspaceMutation(mutation.value, rollback, cleanup)


def _office_write_mutation(
    root: Path, path: str, content: str, *, cancel_event=None
) -> object:
    recovery_root = _private_recovery_root()
    created_parents = ()
    try:
        from khaos.coding.workspace.boundary import SafeWorkspaceFS

        with SafeWorkspaceFS(root) as filesystem:
            created_parents = filesystem.ensure_parent_directories(path)
        mutation = _workspace_write_sync(
            root,
            recovery_root,
            path,
            content,
            cancel_event=cancel_event,
        )
    except Exception:
        if created_parents:
            with SafeWorkspaceFS(root) as filesystem:
                filesystem.remove_empty_directories(created_parents)
        recovery_root.rmdir()
        raise

    def rollback_created_parents() -> None:
        if created_parents:
            with SafeWorkspaceFS(root) as filesystem:
                filesystem.remove_empty_directories(created_parents)

    return _with_recovery_cleanup(
        mutation,
        recovery_root,
        rollback_created_parents=rollback_created_parents,
    )


def _office_patch_mutation(
    root: Path,
    path: str,
    old: str,
    new: str,
    fuzzy: bool,
    *,
    cancel_event=None,
) -> object:
    recovery_root = _private_recovery_root()
    try:
        mutation = _workspace_patch_sync(
            root,
            recovery_root,
            path,
            old,
            new,
            fuzzy,
            cancel_event=cancel_event,
        )
    except Exception:
        recovery_root.rmdir()
        raise
    return _with_recovery_cleanup(mutation, recovery_root)


def _office_multi_edit_mutation(
    root: Path, path: str, edits: list[dict], *, cancel_event=None
) -> object:
    recovery_root = _private_recovery_root()
    try:
        mutation = _workspace_multi_edit_sync(
            root,
            recovery_root,
            path,
            edits,
            cancel_event=cancel_event,
        )
    except Exception:
        recovery_root.rmdir()
        raise
    return _with_recovery_cleanup(mutation, recovery_root)


def _destination_relative(root: Path, target: str) -> str:
    """Resolve an office target to its root-relative posix path."""
    from khaos.coding.workspace.boundary import SafeWorkspaceFS

    with SafeWorkspaceFS(root) as filesystem:
        return filesystem.relative(target)


def _office_list_sync(
    root: Path, path: str, include_hidden: bool
) -> dict[str, Any]:
    try:
        return _workspace_list_sync(root, path, include_hidden)
    except (FileNotFoundError, NotADirectoryError, OSError) as exc:
        display = Path(path) if Path(path).is_absolute() else root / path
        return {"ok": False, "path": str(display), "error": (
            "path does not exist" if isinstance(exc, FileNotFoundError)
            else str(exc)
        )}


def _office_info_sync(root: Path, path: str) -> dict[str, Any]:
    try:
        return _workspace_info_sync(root, path)
    except (FileNotFoundError, OSError) as exc:
        display = Path(path) if Path(path).is_absolute() else root / path
        return {"ok": False, "path": str(display), "error": (
            "path does not exist" if isinstance(exc, FileNotFoundError)
            else str(exc)
        )}


def _office_tree_sync(
    root: Path, path: str, max_depth: int
) -> dict[str, Any]:
    try:
        return _workspace_tree_sync(root, path, max_depth)
    except (FileNotFoundError, NotADirectoryError, OSError) as exc:
        display = Path(path) if Path(path).is_absolute() else root / path
        return {"ok": False, "path": str(display), "error": (
            "path does not exist" if isinstance(exc, FileNotFoundError)
            else str(exc)
        )}


def _workspace_read_sync(
    root: Path, path: str, offset: int, limit: int
) -> dict[str, Any]:
    from khaos.coding.workspace.boundary import SafeWorkspaceFS

    if offset < 1 or limit < 1:
        raise ValueError("offset and limit must be >= 1")
    with SafeWorkspaceFS(root) as filesystem:
        relative = filesystem.relative(path)
        lines = filesystem.read_bytes(path).decode("utf-8").splitlines()
        start = offset - 1
        selected = lines[start:start + limit]
        return {
            "path": str(filesystem.root / relative),
            "offset": offset,
            "limit": limit,
            "total_lines": len(lines),
            "content": "\n".join(
                f"{start + index + 1}: {line}"
                for index, line in enumerate(selected)
            ),
        }


def _workspace_search_sync(
    workspace_root: Path, root: str, query: str, glob: str,
    content: bool, limit: int,
) -> dict[str, Any]:
    from khaos.coding.workspace.boundary import SafeWorkspaceFS

    if limit < 1:
        raise ValueError("limit must be >= 1")
    with SafeWorkspaceFS(workspace_root) as filesystem:
        base = filesystem._directory_relative(root)
        matches: list[dict[str, Any]] = []
        bytes_examined = 0
        for relative in filesystem.iter_files(root):
            display = relative[len(base) + 1:] if base else relative
            if not fnmatch.fnmatch(display, glob):
                continue
            if not content:
                if not query or query in display:
                    matches.append({"path": str(filesystem.root / relative)})
            else:
                try:
                    info = filesystem.stat(relative)
                    bytes_examined += info.st_size
                    if bytes_examined > 64 * 1024 * 1024:
                        raise PermissionError(
                            "content search exceeds the aggregate byte limit"
                        )
                    lines = filesystem.read_bytes(relative).decode("utf-8").splitlines()
                except UnicodeDecodeError:
                    continue
                for line_number, line in enumerate(lines, start=1):
                    if query in line:
                        matches.append({
                            "path": str(filesystem.root / relative),
                            "line": line_number,
                            "text": line,
                        })
                        break
            if len(matches) >= limit:
                break
        return {
            "root": str(filesystem.root / base),
            "matches": matches,
            "count": len(matches),
        }


def _workspace_list_sync(
    workspace_root: Path, path: str, include_hidden: bool
) -> dict[str, Any]:
    from khaos.coding.workspace.boundary import SafeWorkspaceFS

    with SafeWorkspaceFS(workspace_root) as filesystem:
        base = filesystem._directory_relative(path)
        direct_files: dict[str, dict[str, Any]] = {}
        directories: dict[str, int] = {}
        for relative, is_directory in filesystem.iter_entries(
            path, max_depth=2
        ):
            display = relative[len(base) + 1:] if base else relative
            first, separator, remainder = display.partition("/")
            if not include_hidden and first.startswith("."):
                continue
            if separator:
                directories[first] = directories.get(first, 0) + 1
            elif is_directory:
                directories.setdefault(first, 0)
            else:
                info = filesystem.stat(relative)
                direct_files[first] = {
                    "name": first,
                    "size_bytes": info.st_size,
                    "extension": Path(first).suffix,
                }
        dirs = [
            {"name": name, "item_count": directories[name]}
            for name in sorted(directories, key=str.lower)
        ]
        files = [direct_files[name] for name in sorted(direct_files, key=str.lower)]
        return {
            "ok": True,
            "path": str(filesystem.root / base),
            "dirs": dirs,
            "files": files,
            "total_items": len(dirs) + len(files),
        }


def _workspace_info_sync(workspace_root: Path, path: str) -> dict[str, Any]:
    from khaos.coding.workspace.boundary import SafeWorkspaceFS

    with SafeWorkspaceFS(workspace_root) as filesystem:
        if path in {"", "."}:
            stat_result = os.fstat(filesystem._handle.root_fd)
            relative = ""
        else:
            relative = filesystem.relative(path)
            stat_result = filesystem.stat(path)
        is_directory = stat.S_ISDIR(stat_result.st_mode)
        modified = datetime.fromtimestamp(
            stat_result.st_mtime, tz=timezone.utc
        ).isoformat()
        return {
            "ok": True,
            "path": str(filesystem.root / relative),
            "type": "directory" if is_directory else "file",
            "size_bytes": stat_result.st_size,
            "extension": "" if is_directory else Path(relative).suffix,
            "modified": modified,
            "is_hidden": bool(relative and Path(relative).name.startswith(".")),
            "is_symlink": False,
            "mime_type": mimetypes.guess_type(relative)[0],
        }


def _workspace_tree_sync(
    workspace_root: Path, path: str, max_depth: int
) -> dict[str, Any]:
    from khaos.coding.workspace.boundary import SafeWorkspaceFS

    if max_depth < 0:
        raise ValueError("max_depth must be >= 0")
    with SafeWorkspaceFS(workspace_root) as filesystem:
        base = filesystem._directory_relative(path)
        if max_depth == 0:
            return {
                "ok": True,
                "path": str(filesystem.root / base),
                "tree": "",
                "total_files": 0,
                "total_dirs": 0,
            }
        entries: list[tuple[str, bool]] = []
        for relative, is_directory in filesystem.iter_entries(
            path, max_depth=max_depth
        ):
            display = relative[len(base) + 1:] if base else relative
            if any(part in TREE_EXCLUDE_DIRS for part in display.split("/")):
                continue
            entries.append((display, is_directory))
        children: dict[str, list[tuple[str, bool]]] = {}
        for relative, is_directory in entries:
            parent, _, name = relative.rpartition("/")
            children.setdefault(parent, []).append((name, is_directory))
        lines: list[str] = []

        def render(parent: str, prefix: str) -> None:
            items = sorted(
                children.get(parent, []),
                key=lambda item: (not item[1], item[0].lower()),
            )
            for index, (name, is_directory) in enumerate(items):
                last = index == len(items) - 1
                connector = "└── " if last else "├── "
                lines.append(
                    f"{prefix}{connector}{name}{'/' if is_directory else ''}"
                )
                if is_directory:
                    child_path = f"{parent}/{name}" if parent else name
                    render(child_path, prefix + ("    " if last else "│   "))

        render("", "")
        return {
            "ok": True,
            "path": str(filesystem.root / base),
            "tree": "\n".join(lines),
            "total_files": sum(not is_dir for _, is_dir in entries),
            "total_dirs": sum(is_dir for _, is_dir in entries),
        }


def _workspace_content_search_sync(
    workspace_root: Path, path: str, pattern: str, max_results: int
) -> dict[str, Any]:
    from khaos.coding.workspace.boundary import SafeWorkspaceFS

    if max_results < 1:
        raise ValueError("max_results must be >= 1")
    # H2: compile through the linear-time engine (RE2).  A pattern that would
    # require catastrophic backtracking is rejected at compile time; an
    # invalid/unavailable pattern falls back to a literal substring match.
    # Python's ``re`` is never used here, so a hostile pattern cannot pin a
    # worker thread past the scheduler timeout.
    regex = _compile_search_pattern(pattern)
    with SafeWorkspaceFS(workspace_root) as filesystem:
        try:
            candidates = filesystem.iter_files(path)
        except (NotADirectoryError, FileNotFoundError):
            candidates = [filesystem.relative(path)]
        matches: list[dict[str, Any]] = []
        searched = 0
        bytes_examined = 0
        for relative in candidates:
            try:
                info = filesystem.stat(relative)
                bytes_examined += info.st_size
                if bytes_examined > 64 * 1024 * 1024:
                    raise PermissionError(
                        "content search exceeds the aggregate byte limit"
                    )
                lines = filesystem.read_bytes(relative).decode("utf-8").splitlines()
            except UnicodeDecodeError:
                continue
            searched += 1
            for line_number, line in enumerate(lines, start=1):
                # Cap per-line work to bound memory/CPU on pathological inputs.
                if len(line) > _SEARCH_MAX_LINE_LEN:
                    line = line[:_SEARCH_MAX_LINE_LEN]
                matched = regex.search(line) is not None if regex else pattern in line
                if matched:
                    matches.append({
                        "file": str(filesystem.root / relative),
                        "line_number": line_number,
                        "line": line,
                    })
                    if len(matches) >= max_results:
                        return {"ok": True, "pattern": pattern, "matches": matches, "match_count": len(matches), "files_searched": searched}
        return {"ok": True, "pattern": pattern, "matches": matches, "match_count": len(matches), "files_searched": searched}


# H2: bounds that protect the content-search worker from ReDoS and oversized
# inputs.  ``re2`` already guarantees linear matching time and rejects
# backtracking patterns at compile time; these limits are defense in depth.
_SEARCH_MAX_PATTERN_LEN = 256
_SEARCH_MAX_LINE_LEN = 64 * 1024


def _compile_search_pattern(pattern: str):
    """Compile a search pattern with the linear-time RE2 engine.

    Returns ``None`` when the pattern is invalid or RE2 is unavailable, in
    which case the caller falls back to a literal substring match.  Python's
    backtracking ``re`` is deliberately never used for user-supplied patterns.
    """
    if not isinstance(pattern, str) or len(pattern) > _SEARCH_MAX_PATTERN_LEN:
        raise ValueError("search pattern is missing or exceeds the length limit")
    try:
        import re2
    except ImportError:
        # Defensive: re2 is a declared dependency.  If it is somehow missing,
        # fall back to literal substring search rather than the unsafe Python
        # re engine.
        return None
    try:
        return re2.compile(pattern)
    except re2.error:
        return None


def _workspace_patch_sync(
    root: Path, recovery_root: Path, path: str,
    old: str, new: str, fuzzy: bool, *, cancel_event=None,
) -> object:
    from khaos.coding.workspace.boundary import SafeWorkspaceFS
    from khaos.coding.workspace.storage import WorkspaceMutation

    with SafeWorkspaceFS(root) as filesystem:
        relative = filesystem.relative(path)
        before = filesystem.snapshot_file(path, recovery_root=recovery_root)
        result: dict[str, Any] = {}

        def transform(original: str) -> str:
            if old in original:
                result.update(replaced=1, fuzzy=False)
                return original.replace(old, new, 1)
            if not fuzzy:
                raise ValueError("old text not found")
            match = _find_fuzzy_block(original, old)
            if match is None:
                raise ValueError("old text not found")
            start, end, score = match
            result.update(replaced=1, fuzzy=True, score=score)
            return original[:start] + new + original[end:]

        try:
            filesystem.transform_text(
                path, transform, cancel_event=cancel_event
            )
            after = filesystem.snapshot_file(path)
        except Exception:
            before.cleanup()
            raise
        value = {"path": str(filesystem.root / relative), **result}
    return WorkspaceMutation(
        value,
        lambda: _rollback_file(root, path, before, after),
        before.cleanup,
    )


def _workspace_multi_edit_sync(
    root: Path,
    recovery_root: Path,
    path: str,
    edits: list[dict],
    *,
    cancel_event=None,
) -> object:
    from khaos.coding.workspace.boundary import SafeWorkspaceFS
    from khaos.coding.workspace.storage import WorkspaceMutation

    normalized_edits = _normalize_multi_edits(edits)
    sorted_edits = sorted(
        enumerate(normalized_edits),
        key=lambda item: len(item[1]["old_text"]),
        reverse=True,
    )
    with SafeWorkspaceFS(root) as filesystem:
        relative = filesystem.relative(path)
        before = filesystem.snapshot_file(path, recovery_root=recovery_root)
        try:
            original = filesystem.read_bytes(path).decode("utf-8")
        except Exception:
            before.cleanup()
            raise
        failures: list[dict[str, Any]] = []
        for original_index, edit in sorted_edits:
            count = original.count(edit["old_text"])
            if count != 1:
                failures.append({
                    "index": original_index,
                    "old_text": edit["old_text"],
                    "matches": count,
                    "error": (
                        "old_text not found" if count == 0
                        else "old_text is not unique"
                    ),
                })
        if failures:
            return WorkspaceMutation(json.dumps({
                "path": str(filesystem.root / relative),
                "applied": 0,
                "failed": sorted(failures, key=lambda item: int(item["index"])),
            }, ensure_ascii=False), lambda: None, before.cleanup)
        updated = original
        applied: list[dict[str, Any]] = []
        for original_index, edit in sorted_edits:
            updated = updated.replace(edit["old_text"], edit["new_text"], 1)
            applied.append({"index": original_index, "old_text": edit["old_text"]})
        try:
            filesystem.write_bytes(
                path,
                updated.encode("utf-8"),
                cancel_event=cancel_event,
            )
            after = filesystem.snapshot_file(path)
        except Exception:
            before.cleanup()
            raise
        value = json.dumps({
            "path": str(filesystem.root / relative),
            "applied": len(applied),
            "failed": [],
            "message": "All edits applied.",
        }, ensure_ascii=False)
    return WorkspaceMutation(
        value,
        lambda: _rollback_file(root, path, before, after),
        before.cleanup,
    )


def _workspace_copy_sync(
    root: Path, recovery_root: Path, source: str, destination: str
) -> object:
    from khaos.coding.workspace.boundary import SafeWorkspaceFS
    from khaos.coding.workspace.storage import WorkspaceMutation

    with SafeWorkspaceFS(root) as filesystem:
        source_relative = filesystem.relative(source)
        destination_relative = filesystem.relative(destination)
        before = filesystem.snapshot_file(
            destination, recovery_root=recovery_root
        )
        try:
            size = filesystem.copy_file(source, destination)
            after = filesystem.snapshot_file(destination)
        except Exception:
            before.cleanup()
            raise
        value = {
            "ok": True,
            "src": str(filesystem.root / source_relative),
            "dst": str(filesystem.root / destination_relative),
            "size_bytes": size,
        }
    return WorkspaceMutation(
        value,
        lambda: _rollback_file(root, destination, before, after),
        before.cleanup,
    )


def _workspace_move_sync(
    root: Path, source: str, destination: str
) -> object:
    from khaos.coding.workspace.boundary import SafeWorkspaceFS
    from khaos.coding.workspace.storage import WorkspaceMutation

    with SafeWorkspaceFS(root) as filesystem:
        source_relative = filesystem.relative(source)
        destination_relative = filesystem.relative(destination)
        source_before = filesystem.snapshot_file(source)
        destination_before = filesystem.snapshot_file(destination)
        filesystem.move_file(source, destination)
        destination_after = filesystem.snapshot_file(destination)
        value = {
            "ok": True,
            "src": str(filesystem.root / source_relative),
            "dst": str(filesystem.root / destination_relative),
        }
    return WorkspaceMutation(
        value,
        lambda: _rollback_move(
            root,
            source,
            destination,
            source_before,
            destination_before,
            destination_after,
        ),
    )


def _rollback_file(root: Path, path: str, before, after) -> None:
    from khaos.coding.workspace.boundary import (
        SafeWorkspaceFS,
        WorkspaceBoundaryError,
    )

    with SafeWorkspaceFS(root) as filesystem:
        current = filesystem.snapshot_file(path)
        if current != after:
            raise WorkspaceBoundaryError("rollback target changed concurrently")
        if before.exists:
            filesystem.restore_file(path, before, expected=after)
        else:
            filesystem.delete_file(path, expected=after)


def _rollback_move(
    root: Path,
    source: str,
    destination: str,
    source_before,
    destination_before,
    destination_after,
) -> None:
    from khaos.coding.workspace.boundary import (
        SafeWorkspaceFS,
        WorkspaceBoundaryError,
    )

    with SafeWorkspaceFS(root) as filesystem:
        if destination_before.exists:
            raise WorkspaceBoundaryError("move rollback destination was not empty")
        if filesystem.snapshot_file(source).exists:
            raise WorkspaceBoundaryError("move rollback source reappeared")
        if filesystem.snapshot_file(destination) != destination_after:
            raise WorkspaceBoundaryError("move rollback target changed concurrently")
        filesystem.move_file(destination, source)
        restored = filesystem.snapshot_file(source)
        if restored.digest != source_before.digest:
            raise WorkspaceBoundaryError("move rollback content mismatch")


def _find_fuzzy_block(content: str, old: str) -> tuple[int, int, float] | None:
    old_lines = old.splitlines()
    if not old_lines:
        return None
    content_lines = content.splitlines(keepends=True)
    plain_lines = [line.rstrip("\n") for line in content_lines]
    window_size = len(old_lines)
    best: tuple[int, int, float] | None = None
    cursor_offsets: list[int] = []
    cursor = 0
    for line in content_lines:
        cursor_offsets.append(cursor)
        cursor += len(line)
    for index in range(0, max(len(plain_lines) - window_size + 1, 0)):
        candidate = "\n".join(plain_lines[index : index + window_size])
        score = SequenceMatcher(None, old, candidate).ratio()
        if best is None or score > best[2]:
            start = cursor_offsets[index]
            end_index = index + window_size
            end = cursor_offsets[end_index] if end_index < len(cursor_offsets) else len(content)
            best = (start, end, score)
    if best is None or best[2] < 0.72:
        return None
    return best
