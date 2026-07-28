"""Workspace-bound authorization resource identities.

Model-supplied arguments are never trusted as canonical identities.  The
runtime resolves the active :class:`TaskWorkspace`, anchors path resolution to
its worktree, and emits one immutable resource shared by permission, approval,
dispatch revalidation, and audit.
"""

from __future__ import annotations

import hashlib
import json
import os
import shlex
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit


_PATH_KEYS: dict[str, tuple[str, ...]] = {
    "read_file": ("path",),
    "write_file": ("path",),
    "patch": ("path",),
    "multi_edit": ("path",),
    "search_files": ("root",),
    "file_info": ("path",),
    "list_directory": ("path",),
    "directory_tree": ("path",),
    "copy_file": ("source", "destination"),
    "move_file": ("source", "destination"),
}


@dataclass(frozen=True)
class AuthorizationResource:
    kind: str
    principal_id: str
    project_id: str
    task_id: str
    workspace_id: str
    workspace_generation: int
    canonical_target: str
    root_device: int | None
    root_inode: int | None

    def __post_init__(self) -> None:
        required = (
            self.kind,
            self.principal_id,
            self.project_id,
            self.task_id,
            self.workspace_id,
            self.canonical_target,
        )
        if any(not value for value in required):
            raise ValueError("authorization resource identity is incomplete")
        if self.workspace_generation <= 0:
            raise ValueError("workspace generation must be positive")

    def digest(self) -> str:
        encoded = json.dumps(
            asdict(self), sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


def resolve_authorization_resource(
    tool_name: str,
    arguments: dict[str, Any],
    *,
    principal_id: str,
    project_id: str,
    task_id: str,
    workspace_id: str,
    workspace_manager: Any,
) -> AuthorizationResource:
    """Resolve one production tool call against its active TaskWorkspace."""
    if not principal_id or not project_id or not task_id or not workspace_id:
        raise PermissionError("tool authorization requires complete workspace identity")
    if workspace_manager is None:
        raise PermissionError("tool authorization requires WorkspaceManager")
    workspace = workspace_manager.get(workspace_id)
    if workspace is None or workspace.task_id != task_id:
        raise PermissionError("active TaskWorkspace identity does not match tool call")

    root = workspace.worktree_path.resolve(strict=True)
    root_stat = root.stat()
    generation = int(getattr(workspace, "generation", 0))
    target, kind = _canonical_target(tool_name, arguments, root)
    return AuthorizationResource(
        kind=kind,
        principal_id=principal_id,
        project_id=project_id,
        task_id=task_id,
        workspace_id=workspace_id,
        workspace_generation=generation,
        canonical_target=target,
        root_device=int(root_stat.st_dev),
        root_inode=int(root_stat.st_ino),
    )


def _canonical_target(
    tool_name: str, arguments: dict[str, Any], root: Path
) -> tuple[str, str]:
    keys = _PATH_KEYS.get(tool_name)
    if keys:
        paths = [_resolve_workspace_path(root, arguments.get(key, ".")) for key in keys]
        value: str | list[str] = paths[0] if len(paths) == 1 else paths
        return _canonical_json({"tool": tool_name, "paths": value}), "workspace-path"

    if tool_name in {"terminal_argv", "terminal"} and "argv" in arguments:
        argv = arguments.get("argv")
        if not isinstance(argv, list) or not argv or not all(
            isinstance(item, str) and item for item in argv
        ):
            raise PermissionError("terminal argv is invalid")
        cwd = _resolve_workspace_path(root, arguments.get("cwd", "."))
        return _canonical_json({"tool": tool_name, "argv": argv, "cwd": cwd}), "process-argv"

    if tool_name in {"terminal_shell", "terminal", "process"}:
        script = arguments.get("script", arguments.get("command", ""))
        if not isinstance(script, str) or not script.strip():
            raise PermissionError("shell script is empty")
        cwd = _resolve_workspace_path(root, arguments.get("cwd", "."))
        segments = _normalize_shell_segments(script)
        return _canonical_json(
            {"tool": tool_name, "shell": arguments.get("shell", ""), "segments": segments, "cwd": cwd}
        ), "process-shell"

    if "url" in arguments:
        parsed = urlsplit(str(arguments["url"]))
        if not parsed.scheme or not parsed.hostname:
            raise PermissionError("network target is invalid")
        host = parsed.hostname.encode("idna").decode("ascii").lower()
        port = f":{parsed.port}" if parsed.port is not None else ""
        authority = f"{host}{port}"
        return urlunsplit((parsed.scheme.lower(), authority, "", "", "")), "network-origin"

    return _canonical_json({"tool": tool_name, "arguments": arguments}), "tool-call"


def _resolve_workspace_path(root: Path, value: Any) -> str:
    candidate = Path(str(value))
    if candidate.is_absolute():
        resolved = candidate.resolve(strict=False)
    else:
        resolved = (root / candidate).resolve(strict=False)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise PermissionError("tool target escapes active TaskWorkspace") from exc
    return os.fspath(resolved)


def _normalize_shell_segments(script: str) -> list[list[str]]:
    lexer = shlex.shlex(script, posix=True, punctuation_chars="|&;")
    lexer.whitespace_split = True
    tokens = list(lexer)
    segments: list[list[str]] = []
    current: list[str] = []
    for token in tokens:
        if token in {"|", "||", "&", "&&", ";"}:
            if current:
                segments.append(current)
                current = []
            continue
        current.append(token)
    if current:
        segments.append(current)
    if not segments:
        raise PermissionError("shell script has no executable segment")
    return segments


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
