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
from typing import Any, Callable
from urllib.parse import urlsplit, urlunsplit


ResourceResolver = Callable[[str, dict[str, Any], Path], tuple[str, str]]


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
    runtime_id: str,
    task_id: str,
    workspace_id: str,
    workspace_manager: Any,
    resource_resolver: ResourceResolver | None = None,
) -> AuthorizationResource:
    """Resolve one production tool call against its active TaskWorkspace."""
    if not principal_id or not project_id or not runtime_id or not task_id or not workspace_id:
        raise PermissionError("tool authorization requires complete workspace identity")
    if workspace_manager is None:
        raise PermissionError("tool authorization requires WorkspaceManager")
    require = getattr(workspace_manager, "require", None)
    if callable(require):
        workspace = require(
            workspace_id,
            task_id=task_id,
            principal_id=principal_id,
            project_id=project_id,
            runtime_id=runtime_id,
        )
    else:
        workspace = workspace_manager.get(workspace_id)
        if workspace is None or workspace.task_id != task_id:
            raise PermissionError("active TaskWorkspace identity does not match tool call")
        workspace_principal = getattr(workspace, "principal_id", principal_id)
        workspace_project = getattr(workspace, "project_id", project_id)
        workspace_runtime = getattr(workspace, "creator_runtime_id", runtime_id)
        if workspace_principal != principal_id or workspace_project != project_id:
            raise PermissionError("TaskWorkspace owner does not match tool call")
        if workspace_runtime != runtime_id:
            raise PermissionError("TaskWorkspace runtime owner does not match tool call")

    root = workspace.worktree_path.resolve(strict=True)
    root_stat = root.stat()
    generation = int(getattr(workspace, "generation", 0))
    if resource_resolver is None:
        raise PermissionError(f"tool {tool_name} has no authorization resource resolver")
    target, kind = resource_resolver(tool_name, arguments, root)
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


def resolve_single_workspace_path(
    tool_name: str, arguments: dict[str, Any], root: Path
) -> tuple[str, str]:
    """Resolve the standard one-path workspace capability."""
    field = next(
        (
            name
            for name in ("path", "root", "file_path", "cwd", "project_dir", "context")
            if name in arguments
        ),
        "path",
    )
    path = _resolve_workspace_path(root, arguments.get(field, "."))
    return _canonical_json({"tool": tool_name, "path": path}), "workspace-path"


def resolve_copy_or_move(
    tool_name: str, arguments: dict[str, Any], root: Path
) -> tuple[str, str]:
    """Resolve the exact read and write paths of a copy or move operation."""
    source = _resolve_workspace_path(root, arguments.get("src", ""))
    destination = _resolve_workspace_path(root, arguments.get("dst", ""))
    return _canonical_json(
        {"tool": tool_name, "source": source, "destination": destination}
    ), "workspace-copy-move"


def resolve_terminal_argv(
    tool_name: str, arguments: dict[str, Any], root: Path
) -> tuple[str, str]:
    """Resolve argv execution without applying shell interpretation."""
    argv = arguments.get("argv")
    if not isinstance(argv, list) or not argv or not all(
        isinstance(item, str) and item for item in argv
    ):
        raise PermissionError("terminal argv is invalid")
    cwd = _resolve_workspace_path(root, arguments.get("cwd", "."))
    return _canonical_json({"tool": tool_name, "argv": argv, "cwd": cwd}), "process-argv"


def resolve_terminal_shell(
    tool_name: str, arguments: dict[str, Any], root: Path
) -> tuple[str, str]:
    """Bind shell approval to the complete script, including control flow."""
    script = arguments.get("script", arguments.get("command", ""))
    if not isinstance(script, str) or not script.strip():
        raise PermissionError("shell script is empty")
    cwd = _resolve_workspace_path(root, arguments.get("cwd", "."))
    tokens = _shell_tokens(script)
    return _canonical_json(
        {
            "tool": tool_name,
            "shell": arguments.get("shell", ""),
            "script_digest": hashlib.sha256(script.encode("utf-8")).hexdigest(),
            "tokens": tokens,
            "cwd": cwd,
        }
    ), "process-shell"


def resolve_process_control(
    tool_name: str, arguments: dict[str, Any], root: Path
) -> tuple[str, str]:
    """Resolve an existing process handle; process control is never shell code."""
    action = arguments.get("action")
    process_id = arguments.get("id")
    if action not in {"poll", "wait", "kill", "log"} or not isinstance(process_id, str) or not process_id:
        raise PermissionError("process control target is invalid")
    return _canonical_json(
        {"tool": tool_name, "action": action, "process_id": process_id}
    ), "process-control"


def resolve_network_origin(
    tool_name: str, arguments: dict[str, Any], root: Path
) -> tuple[str, str]:
    """Resolve the origin that a network-capable tool will contact."""
    parsed = urlsplit(str(arguments.get("url", "")))
    if not parsed.scheme or not parsed.hostname:
        raise PermissionError("network target is invalid")
    host = parsed.hostname.encode("idna").decode("ascii").lower()
    port = f":{parsed.port}" if parsed.port is not None else ""
    authority = f"{host}{port}"
    return urlunsplit((parsed.scheme.lower(), authority, "", "", "")), "network-origin"


def resolve_workspace_root(
    tool_name: str, arguments: dict[str, Any], root: Path
) -> tuple[str, str]:
    """Resolve workspace-scoped operations without a more specific target."""
    return _canonical_json({"tool": tool_name, "workspace_root": os.fspath(root)}), "workspace"


def _resolve_workspace_path(root: Path, value: Any) -> str:
    candidate = Path(str(value))
    if candidate.is_absolute():
        resolved = candidate.resolve(strict=False)
    else:
        resolved = (root / candidate).resolve(strict=False)
    try:
        relative = resolved.relative_to(root)
    except ValueError as exc:
        raise PermissionError("tool target escapes active TaskWorkspace") from exc
    from khaos.coding.workspace.boundary import PROTECTED_WORKSPACE_NAMES

    protected = {name.casefold() for name in PROTECTED_WORKSPACE_NAMES}
    if any(part.casefold() in protected for part in relative.parts):
        raise PermissionError("tool target is protected workspace metadata")
    return os.fspath(resolved)


def _shell_tokens(script: str) -> list[str]:
    lexer = shlex.shlex(script, posix=True, punctuation_chars="|&;<>")
    lexer.whitespace_split = True
    tokens = list(lexer)
    if not any(token not in {"|", "||", "&", "&&", ";", "<", ">", "<<", ">>"} for token in tokens):
        raise PermissionError("shell script has no executable segment")
    return tokens


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
