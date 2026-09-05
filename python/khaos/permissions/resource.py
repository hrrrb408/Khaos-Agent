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
import unicodedata
from collections.abc import Callable
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from khaos.security.shell_semantics import (
    ShellSemanticStatus,
    analyze_argv,
    analyze_shell_script,
)


class AuthorizationResourceKind(str, Enum):
    WORKSPACE_PATH = "workspace-path"
    WORKSPACE_COPY_MOVE = "workspace-copy-move"
    PROCESS_ARGV = "process-argv"
    PROCESS_SHELL = "process-shell"
    PROCESS_CONTROL = "process-control"
    NETWORK_ORIGIN = "network-origin"
    WORKSPACE = "workspace"


ResourceResolver = Callable[
    [str, dict[str, Any], Path], tuple[str, AuthorizationResourceKind]
]


@dataclass(frozen=True)
class AuthorizationResource:
    kind: AuthorizationResourceKind
    principal_id: str
    project_id: str
    task_id: str
    workspace_id: str
    workspace_generation: int
    canonical_target: str
    root_device: int | None
    root_inode: int | None
    workspace_root: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", AuthorizationResourceKind(self.kind))
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
    workspace: Any
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
        workspace_root=os.fspath(root),
    )


def resolve_single_workspace_path(
    tool_name: str, arguments: dict[str, Any], root: Path
) -> tuple[str, AuthorizationResourceKind]:
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
    return (
        _canonical_json({"tool": tool_name, "path": path}),
        AuthorizationResourceKind.WORKSPACE_PATH,
    )


def resolve_copy_or_move(
    tool_name: str, arguments: dict[str, Any], root: Path
) -> tuple[str, AuthorizationResourceKind]:
    """Resolve the exact read and write paths of a copy or move operation."""
    source = _resolve_workspace_path(root, arguments.get("src", ""))
    destination = _resolve_workspace_path(root, arguments.get("dst", ""))
    return _canonical_json(
        {"tool": tool_name, "source": source, "destination": destination}
    ), AuthorizationResourceKind.WORKSPACE_COPY_MOVE


def resolve_edit_transaction(
    tool_name: str, arguments: dict[str, Any], root: Path
) -> tuple[str, AuthorizationResourceKind]:
    """Bind edit approval to the complete bounded transaction identity.

    File contents are never emitted into the authorization resource. Their
    hashes are included so an approval cannot be reused for a different
    payload with the same paths and base generation.
    """
    transaction_id = arguments.get("transaction_id")
    base_generation = arguments.get("base_generation")
    operations = arguments.get("operations")
    if (
        not isinstance(transaction_id, str)
        or not transaction_id
        or len(transaction_id) > 128
        or "\x00" in transaction_id
        or type(base_generation) is not int
        or base_generation <= 0
        or not isinstance(operations, list)
        or not operations
        or len(operations) > 64
    ):
        raise PermissionError("edit transaction identity is invalid")
    expected_workspace_digest = arguments.get("expected_workspace_digest")
    if expected_workspace_digest is not None and (
        not isinstance(expected_workspace_digest, str)
        or len(expected_workspace_digest) != 64
        or any(
            character not in "0123456789abcdef"
            for character in expected_workspace_digest
        )
    ):
        raise PermissionError("edit transaction workspace digest is invalid")
    intent = arguments.get("intent", "")
    if not isinstance(intent, str) or len(intent) > 512 or "\x00" in intent:
        raise PermissionError("edit transaction intent is invalid")
    identity_operations: list[dict[str, object]] = []
    touched: set[str] = set()
    for raw in operations:
        if not isinstance(raw, dict):
            raise PermissionError("edit transaction operation is invalid")
        operation = raw.get("operation")
        if operation not in {"create", "update", "delete", "rename"}:
            raise PermissionError("edit transaction operation kind is invalid")
        path = _resolve_edit_transaction_path(root, raw.get("path"))
        destination = None
        if operation == "rename":
            destination = _resolve_edit_transaction_path(
                root,
                raw.get("destination_path"),
            )
            if destination == path:
                raise PermissionError("edit transaction rename target is invalid")
        elif raw.get("destination_path") is not None:
            raise PermissionError("edit transaction destination is invalid")
        for touched_path in (path, destination):
            if touched_path is None:
                continue
            folded = touched_path.casefold()
            if folded in touched:
                raise PermissionError("edit transaction touches a path twice")
            touched.add(folded)
        expected_exists = raw.get("expected_exists")
        if expected_exists is not None and type(expected_exists) is not bool:
            raise PermissionError("edit transaction expected_exists is invalid")
        expected_digest = raw.get("expected_digest")
        if expected_digest is not None and (
            not isinstance(expected_digest, str)
            or len(expected_digest) != 64
            or any(
                character not in "0123456789abcdef"
                for character in expected_digest
            )
        ):
            raise PermissionError("edit transaction expected_digest is invalid")
        content = raw.get("content")
        if content is not None and (
            not isinstance(content, str)
            or "\x00" in content
            or len(content.encode("utf-8")) > 16 * 1024 * 1024
        ):
            raise PermissionError("edit transaction content is invalid")
        raw_text_edits = raw.get("text_edits", [])
        if not isinstance(raw_text_edits, list) or len(raw_text_edits) > 256:
            raise PermissionError("edit transaction text_edits is invalid")
        for raw_edit in raw_text_edits:
            if (
                not isinstance(raw_edit, dict)
                or set(raw_edit) != {"start", "end", "replacement"}
            ):
                raise PermissionError("edit transaction text edit is invalid")
            start = raw_edit["start"]
            end = raw_edit["end"]
            replacement = raw_edit["replacement"]
            if (
                type(start) is not int
                or type(end) is not int
                or start < 0
                or end < start
                or not isinstance(replacement, str)
                or "\x00" in replacement
                or len(replacement.encode("utf-8")) > 16 * 1024 * 1024
            ):
                raise PermissionError("edit transaction text edit bounds are invalid")
        if operation == "create":
            if (
                content is None
                or raw_text_edits
                or expected_exists is True
                or expected_digest is not None
            ):
                raise PermissionError("edit transaction create contract is invalid")
            if tool_name == "apply_edit_transaction" and expected_exists is not False:
                raise PermissionError("edit transaction create precondition is missing")
        elif operation == "update":
            if (
                destination is not None
                or (content is None) == (not raw_text_edits)
            ):
                raise PermissionError("edit transaction update contract is invalid")
            if tool_name == "apply_edit_transaction" and (
                expected_exists is not True or expected_digest is None
            ):
                raise PermissionError("edit transaction update precondition is missing")
        elif operation == "delete":
            if content is not None or raw_text_edits:
                raise PermissionError("edit transaction delete contract is invalid")
            if tool_name == "apply_edit_transaction" and (
                expected_exists is not True or expected_digest is None
            ):
                raise PermissionError("edit transaction delete precondition is missing")
        elif operation == "rename":
            if content is not None or raw_text_edits:
                raise PermissionError("edit transaction rename contract is invalid")
            if tool_name == "apply_edit_transaction" and (
                expected_exists is not True or expected_digest is None
            ):
                raise PermissionError("edit transaction rename precondition is missing")
        payload_digest = hashlib.sha256(
            _canonical_json(
                {
                    "operation": operation,
                    "path": path,
                    "destination_path": destination,
                    "expected_exists": expected_exists,
                    "expected_digest": expected_digest,
                    "content": content,
                    "text_edits": raw_text_edits,
                }
            ).encode("utf-8")
        ).hexdigest()
        identity_operations.append(
            {
                "operation": operation,
                "path": path,
                "destination_path": destination,
                "expected_exists": expected_exists,
                "expected_digest": expected_digest,
                "payload_digest": payload_digest,
            }
        )
    transaction_identity = {
        "tool": tool_name,
        "transaction_id": transaction_id,
        "base_generation": base_generation,
        "expected_workspace_digest": expected_workspace_digest,
        "intent_digest": hashlib.sha256(intent.encode("utf-8")).hexdigest(),
        "intent_bytes": len(intent.encode("utf-8")),
        "operations": identity_operations,
    }
    return (
        _canonical_json(transaction_identity),
        AuthorizationResourceKind.WORKSPACE,
    )


def _resolve_edit_transaction_path(root: Path, value: Any) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise PermissionError("edit transaction path is invalid")
    if (
        "\\" in value
        or value.startswith("/")
        or value.endswith("/")
        or (len(value) >= 2 and value[1] == ":")
    ):
        raise PermissionError("edit transaction path is not normalized")
    if PureWindowsPath(value).is_absolute() or PureWindowsPath(value).drive:
        raise PermissionError("edit transaction path is absolute")
    if any(part in {"", ".", ".."} for part in value.split("/")):
        raise PermissionError("edit transaction path contains dot components")
    normalized = unicodedata.normalize("NFC", value)
    if PurePosixPath(normalized).as_posix() != normalized:
        raise PermissionError("edit transaction path is not canonical")
    return _resolve_workspace_path(root, normalized)


def resolve_terminal_argv(
    tool_name: str, arguments: dict[str, Any], root: Path
) -> tuple[str, AuthorizationResourceKind]:
    """Resolve argv execution without applying shell interpretation."""
    argv = arguments.get("argv")
    if not isinstance(argv, list) or not argv or not all(
        isinstance(item, str) and item for item in argv
    ):
        raise PermissionError("terminal argv is invalid")
    cwd = _resolve_workspace_path(root, arguments.get("cwd", "."))
    semantic = analyze_argv(argv)
    if semantic.status is ShellSemanticStatus.BLOCKED:
        raise PermissionError(semantic.reason)
    return (
        _canonical_json(
            {
                "tool": tool_name,
                "argv": argv,
                "cwd": cwd,
                "semantic_status": semantic.status.value,
                "semantic_digest": semantic.semantic_digest,
            }
        ),
        AuthorizationResourceKind.PROCESS_ARGV,
    )


def resolve_test_command(
    tool_name: str, arguments: dict[str, Any], root: Path
) -> tuple[str, AuthorizationResourceKind]:
    """Resolve ``test_run`` exactly as the handler executes it.

    ``test_run`` uses ``shlex.split`` and the supervised argv execution
    service; it never invokes a shell.  The resource therefore carries an
    argv identity, so routing compares the exact executed vector rather than
    treating a command string as shell authority.
    """
    command = arguments.get("command")
    if not isinstance(command, str) or not command.strip():
        raise PermissionError("test command is invalid")
    try:
        argv = shlex.split(command)
    except ValueError as exc:
        raise PermissionError("test command is invalid") from exc
    if not argv or not all(isinstance(item, str) and item for item in argv):
        raise PermissionError("test command is invalid")
    cwd = _resolve_workspace_path(root, arguments.get("cwd", "."))
    semantic = analyze_argv(argv)
    if semantic.status is ShellSemanticStatus.BLOCKED:
        raise PermissionError(semantic.reason)
    return (
        _canonical_json(
            {
                "tool": tool_name,
                "argv": argv,
                "cwd": cwd,
                "semantic_status": semantic.status.value,
                "semantic_digest": semantic.semantic_digest,
            }
        ),
        AuthorizationResourceKind.PROCESS_ARGV,
    )


def resolve_terminal_shell(
    tool_name: str, arguments: dict[str, Any], root: Path
) -> tuple[str, AuthorizationResourceKind]:
    """Bind shell approval to the complete script, including control flow."""
    script = arguments.get("script", arguments.get("command", ""))
    if not isinstance(script, str) or not script.strip():
        raise PermissionError("shell script is empty")
    cwd = _resolve_workspace_path(root, arguments.get("cwd", "."))
    semantic = analyze_shell_script(script)
    if semantic.status is ShellSemanticStatus.BLOCKED:
        raise PermissionError(semantic.reason)
    tokens = _semantic_tokens(semantic)
    return _canonical_json(
        {
            "tool": tool_name,
            "shell": arguments.get("shell", ""),
            "script_digest": hashlib.sha256(script.encode("utf-8")).hexdigest(),
            "tokens": tokens,
            "semantic_status": semantic.status.value,
            "semantic_digest": semantic.semantic_digest,
            "semantic_ast": semantic.ast.canonical(),
            "cwd": cwd,
        }
    ), AuthorizationResourceKind.PROCESS_SHELL


def resolve_process_control(
    tool_name: str, arguments: dict[str, Any], root: Path
) -> tuple[str, AuthorizationResourceKind]:
    """Resolve an existing process handle; process control is never shell code."""
    action = arguments.get("action")
    process_id = arguments.get("id")
    if action not in {"poll", "wait", "kill", "log"} or not isinstance(process_id, str) or not process_id:
        raise PermissionError("process control target is invalid")
    return _canonical_json(
        {"tool": tool_name, "action": action, "process_id": process_id}
    ), AuthorizationResourceKind.PROCESS_CONTROL


def resolve_network_origin(
    tool_name: str, arguments: dict[str, Any], root: Path
) -> tuple[str, AuthorizationResourceKind]:
    """Resolve the canonical network URL used by typed permission rules.

    The previous target intentionally kept only the origin.  Typed network
    rules need the path as well so a grant for ``/repos`` cannot silently
    become a grant for every endpoint on the same host.  Query and fragment
    are excluded because they are request data, not an authority boundary.
    """
    parsed = urlsplit(str(arguments.get("url", "")))
    if not parsed.scheme or not parsed.hostname:
        raise PermissionError("network target is invalid")
    host = parsed.hostname.encode("idna").decode("ascii").lower()
    port = f":{parsed.port}" if parsed.port is not None else ""
    authority = f"{host}{port}"
    return (
        urlunsplit((parsed.scheme.lower(), authority, parsed.path or "/", "", "")),
        AuthorizationResourceKind.NETWORK_ORIGIN,
    )


def resolve_workspace_root(
    tool_name: str, arguments: dict[str, Any], root: Path
) -> tuple[str, AuthorizationResourceKind]:
    """Resolve workspace-scoped operations without a more specific target."""
    return (
        _canonical_json({"tool": tool_name, "workspace_root": os.fspath(root)}),
        AuthorizationResourceKind.WORKSPACE,
    )


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
    from khaos.coding.workspace.policy import PROTECTED_WORKSPACE_NAMES

    protected = {name.casefold() for name in PROTECTED_WORKSPACE_NAMES}
    if any(part.casefold() in protected for part in relative.parts):
        raise PermissionError("tool target is protected workspace metadata")
    return os.fspath(resolved)


def _semantic_tokens(analysis: Any) -> list[str]:
    """Flatten the semantic AST for legacy display/audit compatibility.

    This is intentionally not a security decision path.  Approval and
    read-only decisions consume ``semantic_status``/``semantic_digest`` and
    the canonical AST emitted by ``shell_semantics``.
    """
    tokens: list[str] = []
    for index, command in enumerate(analysis.ast.commands):
        if index and command.operator_before:
            tokens.append(command.operator_before)
        tokens.extend(word.text for word in command.words)
    return tokens


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
