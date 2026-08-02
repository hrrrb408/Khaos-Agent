"""Typed persistent permission resources.

Persistent approval rules used to share one ``fnmatch`` grammar even though
file paths, processes, and network origins have different security semantics.
This module defines the small, canonical rule language used by relaxing
(``AUTO_APPROVE`` / ``SUGGEST``) grants.  Generic glob matching remains
available to non-relaxing rules only.

The matcher is intentionally conservative: a rule that cannot be parsed into
one of the supported resource types is rejected or quarantined.  Exact
resource observations are emitted from :mod:`khaos.permissions.resource` and
are also derivable for legacy unit/library callers that do not construct an
``AuthorizationResource`` yet.
"""

from __future__ import annotations

import hashlib
import json
import os
import shlex
from enum import Enum
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import urlsplit

from khaos.permissions.resource import AuthorizationResource, AuthorizationResourceKind


class PermissionResourceType(str, Enum):
    """Resource families supported by persistent typed rules."""

    FILESYSTEM = "filesystem"
    EXEC = "exec"
    NETWORK = "network"
    PROCESS = "process"
    WORKSPACE = "workspace"
    GENERIC = "generic"


_RELAXING_APPROVALS = frozenset({"auto-approve", "suggest"})
_GLOB_META = frozenset("*?[")
_RESOURCE_TYPES = frozenset(item.value for item in PermissionResourceType)


def _approval_value(approval: Any) -> str:
    return str(getattr(approval, "value", approval))


def is_relaxing_approval(approval: Any) -> bool:
    """Return whether an approval mode can widen authority."""
    return _approval_value(approval) in _RELAXING_APPROVALS


def _has_glob_meta(value: str) -> bool:
    return any(char in value for char in _GLOB_META)


def _require_string(spec: dict[str, Any], name: str, *, source: str) -> str:
    value = spec.get(name)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{source}: typed resource field {name!r} must be a non-empty string")
    return value.strip()


def _require_absolute_path(value: str, *, name: str, source: str) -> str:
    if not os.path.isabs(value):
        raise ValueError(f"{source}: typed resource field {name!r} must be absolute")
    if _has_glob_meta(value):
        raise ValueError(f"{source}: typed resource field {name!r} must not contain glob syntax")
    normalized = os.path.normpath(value)
    if not os.path.isabs(normalized):
        raise ValueError(f"{source}: typed resource field {name!r} is not a valid path")
    return normalized


def _canonical_host(value: str, *, source: str) -> str:
    host = value.strip().rstrip(".").lower()
    if not host or _has_glob_meta(host) or any(char.isspace() for char in host):
        raise ValueError(f"{source}: network host must be a concrete hostname")
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"{source}: network host is not valid IDNA") from exc


def _validate_operation(spec: dict[str, Any], *, source: str) -> None:
    if "operation" in spec and (
        not isinstance(spec["operation"], str) or not spec["operation"].strip()
    ):
        raise ValueError(f"{source}: operation must be a non-empty string")


def validate_typed_rule(
    resource_type: str,
    resource_spec: dict[str, Any],
    approval: Any,
    *,
    source: str = "permission",
) -> dict[str, Any]:
    """Validate and canonicalize a typed permission specification.

    The returned mapping is a new, JSON-safe canonical object.  Unknown
    fields are rejected so a future caller cannot accidentally smuggle a
    field that the matcher ignores.  Relaxing grants receive additional
    narrowness checks; deny/ask rules may intentionally be broader.
    """
    resource_type = str(getattr(resource_type, "value", resource_type)).strip().lower()
    if resource_type not in _RESOURCE_TYPES:
        raise ValueError(f"{source}: unknown typed resource type {resource_type!r}")
    if not isinstance(resource_spec, dict):
        raise ValueError(  # noqa: TRY004 - validation API preserves ValueError
            f"{source}: typed resource spec must be an object"
        )

    allowed: dict[str, set[str]] = {
        PermissionResourceType.FILESYSTEM.value: {
            "operation", "tool", "path", "root", "recursive", "source", "destination",
        },
        PermissionResourceType.EXEC.value: {
            "operation", "tool", "executable", "argv_prefix", "argv_exact", "cwd",
            "workspace_root", "cwd_scope", "allow_shell", "shell", "script_digest",
        },
        PermissionResourceType.NETWORK.value: {
            "operation", "tool", "scheme", "host", "port", "path_prefix",
        },
        PermissionResourceType.PROCESS.value: {
            "operation", "tool", "process_id",
        },
        PermissionResourceType.WORKSPACE.value: {
            "operation", "tool", "workspace_root",
        },
        PermissionResourceType.GENERIC.value: {"operation", "tool", "target"},
    }
    unknown = set(resource_spec) - allowed[resource_type]
    if unknown:
        raise ValueError(f"{source}: unknown fields for {resource_type}: {sorted(unknown)}")

    spec = dict(resource_spec)
    _validate_operation(spec, source=source)
    for name in ("operation", "tool"):
        if name in spec:
            spec[name] = _require_string(spec, name, source=source)

    relaxing = is_relaxing_approval(approval)
    if resource_type == PermissionResourceType.FILESYSTEM.value:
        selectors = [name for name in ("path", "root", "source") if name in spec]
        if "destination" in spec and "source" not in spec:
            raise ValueError(f"{source}: filesystem destination requires source")
        if len(selectors) != 1 or (selectors == ["source"] and "destination" not in spec):
            raise ValueError(
                f"{source}: filesystem rule needs path, root, or source+destination"
            )
        for name in selectors:
            spec[name] = _require_absolute_path(str(spec[name]), name=name, source=source)
        if "destination" in spec:
            spec["destination"] = _require_absolute_path(
                str(spec["destination"]), name="destination", source=source
            )
        if "recursive" in spec and not isinstance(spec["recursive"], bool):
            raise ValueError(f"{source}: filesystem recursive must be boolean")
        if "root" in spec:
            spec["recursive"] = bool(spec.get("recursive", True))
            if relaxing and spec["root"] == os.path.sep:
                raise ValueError(f"{source}: relaxing filesystem root cannot be '/'")
        elif "path" in spec:
            spec["recursive"] = bool(spec.get("recursive", False))

    elif resource_type == PermissionResourceType.EXEC.value:
        executable = _require_string(spec, "executable", source=source)
        if _has_glob_meta(executable) or any(char in executable for char in ";&|<>\n"):
            raise ValueError(f"{source}: executable must be a concrete program name")
        spec["executable"] = executable
        argv_prefix = spec.get("argv_prefix", [])
        if not isinstance(argv_prefix, list) or not all(
            isinstance(item, str) and item and not _has_glob_meta(item)
            for item in argv_prefix
        ):
            raise ValueError(f"{source}: argv_prefix must be a list of concrete strings")
        spec["argv_prefix"] = list(argv_prefix)
        if "argv_exact" in spec and not isinstance(spec["argv_exact"], bool):
            raise ValueError(f"{source}: argv_exact must be boolean")
        if "cwd" in spec:
            spec["cwd"] = _require_absolute_path(str(spec["cwd"]), name="cwd", source=source)
        cwd_scope = spec.get("cwd_scope", "exact" if "cwd" in spec else "any")
        if cwd_scope not in {"exact", "workspace", "any"}:
            raise ValueError(f"{source}: cwd_scope must be exact, workspace, or any")
        if cwd_scope == "exact" and "cwd" not in spec:
            raise ValueError(f"{source}: exact cwd_scope requires cwd")
        if "workspace_root" in spec:
            spec["workspace_root"] = _require_absolute_path(
                str(spec["workspace_root"]), name="workspace_root", source=source
            )
        if cwd_scope == "workspace" and "workspace_root" not in spec:
            raise ValueError(
                f"{source}: workspace cwd_scope requires workspace_root"
            )
        spec["cwd_scope"] = cwd_scope
        allow_shell = spec.get("allow_shell", False)
        if not isinstance(allow_shell, bool):
            raise ValueError(f"{source}: allow_shell must be boolean")
        spec["allow_shell"] = allow_shell
        if "shell" in spec:
            spec["shell"] = _require_string(spec, "shell", source=source)
        if "script_digest" in spec:
            digest = _require_string(spec, "script_digest", source=source)
            if len(digest) != hashlib.sha256().digest_size * 2:
                raise ValueError(f"{source}: script_digest must be a SHA-256 hex digest")
            try:
                int(digest, 16)
            except ValueError as exc:
                raise ValueError(f"{source}: script_digest must be hexadecimal") from exc
            spec["script_digest"] = digest.lower()
        if relaxing and allow_shell and "script_digest" not in spec:
            raise ValueError(f"{source}: relaxing shell rules require script_digest")

    elif resource_type == PermissionResourceType.NETWORK.value:
        scheme = _require_string(spec, "scheme", source=source).lower()
        if scheme not in {"http", "https", "ws", "wss"}:
            raise ValueError(f"{source}: unsupported network scheme {scheme!r}")
        spec["scheme"] = scheme
        spec["host"] = _canonical_host(_require_string(spec, "host", source=source), source=source)
        if "port" in spec:
            if not isinstance(spec["port"], int) or isinstance(spec["port"], bool):
                raise ValueError(f"{source}: network port must be an integer")
            if not 1 <= spec["port"] <= 65535:
                raise ValueError(f"{source}: network port is out of range")
        prefix = spec.get("path_prefix", "/")
        if not isinstance(prefix, str) or not prefix.startswith("/") or _has_glob_meta(prefix):
            raise ValueError(f"{source}: path_prefix must be an absolute concrete URL path")
        spec["path_prefix"] = str(PurePosixPath(prefix))
        if not spec["path_prefix"].startswith("/"):
            spec["path_prefix"] = "/" + spec["path_prefix"]

    elif resource_type == PermissionResourceType.PROCESS.value:
        spec["process_id"] = _require_string(spec, "process_id", source=source)
        if "process_id" in spec and _has_glob_meta(spec["process_id"]):
            raise ValueError(f"{source}: process_id must be concrete")

    elif resource_type == PermissionResourceType.WORKSPACE.value:
        spec["workspace_root"] = _require_absolute_path(
            _require_string(spec, "workspace_root", source=source),
            name="workspace_root",
            source=source,
        )
        if relaxing and spec["workspace_root"] == os.path.sep:
            raise ValueError(f"{source}: relaxing workspace root cannot be '/'")

    elif resource_type == PermissionResourceType.GENERIC.value:
        spec["target"] = _require_string(spec, "target", source=source)
        if _has_glob_meta(spec["target"]):
            raise ValueError(f"{source}: generic typed targets must be exact")

    return {key: spec[key] for key in sorted(spec)}


def _path_contains(root: str, path: str) -> bool:
    try:
        return os.path.commonpath((root, path)) == root
    except ValueError:
        return False


def _network_observation(target: str) -> dict[str, Any] | None:
    parsed = urlsplit(target)
    if not parsed.scheme or not parsed.hostname:
        return None
    host = parsed.hostname.encode("idna").decode("ascii").lower()
    return {
        "scheme": parsed.scheme.lower(),
        "host": host,
        "port": parsed.port,
        "path": parsed.path or "/",
    }


def _typed_observation_from_resource(
    resource: AuthorizationResource,
    operation: str,
) -> tuple[str, dict[str, Any]]:
    kind = AuthorizationResourceKind(resource.kind)
    target = resource.canonical_target
    if kind is AuthorizationResourceKind.NETWORK_ORIGIN:
        observation = _network_observation(target)
        if observation is None:
            raise ValueError("authorization resource has an invalid network target")
        return PermissionResourceType.NETWORK.value, observation

    try:
        decoded = json.loads(target)
    except (TypeError, ValueError) as exc:
        raise ValueError("authorization resource target is not canonical JSON") from exc
    if not isinstance(decoded, dict):
        raise ValueError("authorization resource target must be an object")  # noqa: TRY004 - parser compatibility

    if kind is AuthorizationResourceKind.WORKSPACE_PATH:
        return PermissionResourceType.FILESYSTEM.value, {
            "operation": operation,
            "tool": decoded.get("tool", ""),
            "path": decoded.get("path", ""),
        }
    if kind is AuthorizationResourceKind.WORKSPACE_COPY_MOVE:
        return PermissionResourceType.FILESYSTEM.value, {
            "operation": operation,
            "tool": decoded.get("tool", ""),
            "source": decoded.get("source", ""),
            "destination": decoded.get("destination", ""),
        }
    if kind is AuthorizationResourceKind.PROCESS_ARGV:
        argv = decoded.get("argv")
        return PermissionResourceType.EXEC.value, {
            "operation": operation,
            "tool": decoded.get("tool", ""),
            "executable": argv[0] if isinstance(argv, list) and argv else "",
            "argv": argv if isinstance(argv, list) else [],
            "cwd": decoded.get("cwd", ""),
            "workspace_root": resource.workspace_root,
            "is_shell": False,
        }
    if kind is AuthorizationResourceKind.PROCESS_SHELL:
        tokens = decoded.get("tokens")
        executable = ""
        argv: list[str] = []
        if isinstance(tokens, list):
            executable = next(
                (item for item in tokens if isinstance(item, str) and item not in {"|", "||", "&", "&&", ";", "<", ">", "<<", ">>"}),
                "",
            )
        return PermissionResourceType.EXEC.value, {
            "operation": operation,
            "tool": decoded.get("tool", ""),
            "executable": executable,
            "argv": argv,
            "cwd": decoded.get("cwd", ""),
            "workspace_root": resource.workspace_root,
            "is_shell": True,
            "shell": decoded.get("shell", ""),
            "script_digest": decoded.get("script_digest", ""),
        }
    if kind is AuthorizationResourceKind.PROCESS_CONTROL:
        return PermissionResourceType.PROCESS.value, {
            "operation": decoded.get("action", operation),
            "tool": decoded.get("tool", ""),
            "process_id": decoded.get("process_id", ""),
        }
    if kind is AuthorizationResourceKind.WORKSPACE:
        return PermissionResourceType.WORKSPACE.value, {
            "operation": operation,
            "tool": decoded.get("tool", ""),
            "workspace_root": decoded.get("workspace_root", ""),
        }
    raise ValueError(f"unsupported authorization resource kind: {kind.value}")


def typed_rule_from_authorization_resource(
    resource: AuthorizationResource,
    operation: str,
) -> tuple[str, dict[str, Any]]:
    """Create an exact typed rule from the immutable authorization resource."""
    resource_type, observation = _typed_observation_from_resource(resource, operation)
    if resource_type == PermissionResourceType.FILESYSTEM.value:
        if "path" in observation:
            spec = {key: observation[key] for key in ("operation", "tool", "path")}
        else:
            spec = {key: observation[key] for key in ("operation", "tool", "source", "destination")}
    elif resource_type == PermissionResourceType.EXEC.value:
        if observation["is_shell"]:
            spec = {
                "operation": observation["operation"],
                "tool": observation["tool"],
                "executable": observation["executable"] or "shell",
                "argv_prefix": [],
                "allow_shell": True,
                "shell": observation["shell"] or "/bin/sh",
                "script_digest": observation["script_digest"],
                "cwd": observation["cwd"],
                "workspace_root": observation["workspace_root"],
            }
        else:
            argv = observation["argv"]
            spec = {
                "operation": observation["operation"],
                "tool": observation["tool"],
                "executable": observation["executable"],
                "argv_prefix": argv[1:] if argv else [],
                "argv_exact": True,
                "allow_shell": False,
                "cwd": observation["cwd"],
                "workspace_root": observation["workspace_root"],
            }
    elif resource_type == PermissionResourceType.NETWORK.value:
        spec = {
            "scheme": observation["scheme"],
            "host": observation["host"],
            "path_prefix": observation["path"],
        }
        if observation["port"] is not None:
            spec["port"] = observation["port"]
    else:
        spec = dict(observation)
    return resource_type, validate_typed_rule(
        resource_type, spec, "auto-approve", source="resource rule"
    )


def _split_path_pattern(pattern: str) -> tuple[str, str] | None:
    first = next((index for index, char in enumerate(pattern) if char in _GLOB_META), -1)
    if first < 0:
        return None
    suffix = pattern[first:]
    if suffix not in {"*", "**"}:
        return None
    prefix = pattern[:first].rstrip(os.path.sep)
    if not prefix or prefix == os.path.sep or not os.path.isabs(prefix):
        return None
    return prefix, suffix


def legacy_pattern_to_typed(
    pattern: str,
    permission_level: str,
    approval: Any,
    *,
    source: str = "legacy permission rule",
) -> tuple[str, dict[str, Any]]:
    """Safely translate a legacy pattern into the typed rule language.

    Only unambiguous forms are translated: concrete paths, a path subtree
    ending in ``/*``/``/**``, concrete network origins/path prefixes, and a
    command prefix ending in ``*``.  Ambiguous character classes, embedded
    globs, root-wide paths, and unknown targets fail closed.
    """
    text = str(pattern or "").strip()
    if not text:
        raise ValueError(f"{source}: relaxing grants require a typed resource rule")
    if not any(char not in _GLOB_META and not char.isspace() for char in text):
        raise ValueError(
            f"{source}: auto-approve pattern {pattern!r} is too broad; "
            "a typed resource scope is required"
        )
    tool = ""
    for prefix in (
        "read_file:", "write_file:", "search_files:", "terminal:", "process:",
    ):
        if text.startswith(prefix):
            tool = prefix[:-1]
            text = text[len(prefix):].strip()
            break

    parsed = urlsplit(text)
    if parsed.scheme and parsed.hostname:
        if _has_glob_meta(parsed.hostname) or any(char in text for char in "[]?"):
            raise ValueError(f"{source}: network pattern contains ambiguous glob syntax")
        first_meta = next((idx for idx, char in enumerate(parsed.path) if char in _GLOB_META), -1)
        if first_meta >= 0 and parsed.path[first_meta:] not in {"*", "**"}:
            raise ValueError(f"{source}: network path glob must be a trailing subtree")
        path_prefix = parsed.path[:first_meta].rstrip("/") if first_meta >= 0 else parsed.path
        spec: dict[str, Any] = {
            "scheme": parsed.scheme,
            "host": parsed.hostname,
            "path_prefix": path_prefix or "/",
        }
        if parsed.port is not None:
            spec["port"] = parsed.port
        return PermissionResourceType.NETWORK.value, validate_typed_rule(
            PermissionResourceType.NETWORK.value, spec, approval, source=source
        )

    path_pattern = _split_path_pattern(text)
    # ``os.path.sep`` only catches rooted paths on the current platform.  A
    # Windows drive-qualified path (``C:\\workspace\\file``) is absolute but
    # does not start with ``\\``; use the platform-aware predicate so legacy
    # path grants are materialized as filesystem rules on every supported OS.
    if os.path.isabs(text) or (not _has_glob_meta(text) and "/" in text):
        if path_pattern is not None:
            root, _ = path_pattern
            spec = {"path": root, "recursive": True}
        elif _has_glob_meta(text):
            raise ValueError(f"{source}: filesystem pattern is not a trailing subtree")
        else:
            spec = {"path": text}
        if tool:
            spec["tool"] = tool
        return PermissionResourceType.FILESYSTEM.value, validate_typed_rule(
            PermissionResourceType.FILESYSTEM.value, spec, approval, source=source
        )

    command = text
    if not (permission_level == "execute" or tool in {"terminal", "process"} or _has_glob_meta(command)):
        spec = {"target": text}
        if tool:
            spec["tool"] = tool
        return PermissionResourceType.GENERIC.value, validate_typed_rule(
            PermissionResourceType.GENERIC.value,
            spec,
            approval,
            source=source,
        )
    if _has_glob_meta(command):
        if not command.endswith("*") or any(char in command[:-1] for char in _GLOB_META):
            raise ValueError(f"{source}: command pattern must end with one '*'")
        command = command[:-1].rstrip()
    try:
        argv = shlex.split(command)
    except ValueError as exc:
        raise ValueError(f"{source}: command pattern is not valid argv") from exc
    if not argv or any(any(char in item for char in ";&|<>\n") for item in argv):
        raise ValueError(f"{source}: command pattern has no executable")
    if _has_glob_meta(text) and len(argv) == 1:
        # With an empty ``argv_prefix``, the typed matcher would turn
        # ``rm*`` (and even ``git *``) into an approval for every invocation
        # of that executable. A legacy wildcard must name at least one
        # concrete argument; callers that truly need an exact executable
        # grant can use an explicit typed rule with ``argv_exact``.
        raise ValueError(
            f"{source}: command wildcard must include a concrete argv prefix"
        )
    spec = {
        "executable": argv[0],
        "argv_prefix": argv[1:],
        "allow_shell": False,
    }
    return PermissionResourceType.EXEC.value, validate_typed_rule(
        PermissionResourceType.EXEC.value, spec, approval, source=source
    )


def request_observation(
    tool_name: str,
    params: dict[str, Any],
    target: str,
    operation: str,
) -> tuple[str, dict[str, Any]]:
    """Derive a conservative typed observation for legacy callers."""
    if tool_name in {
        "read_file", "write_file", "patch", "search_files", "list_directory",
        "file_info", "tree_view", "file_search_content", "multi_edit", "code_search",
        "code_symbols", "copy_file", "move_file",
    }:
        if tool_name in {"copy_file", "move_file"}:
            return PermissionResourceType.FILESYSTEM.value, {
                "operation": operation,
                "tool": tool_name,
                "source": os.path.realpath(str(params.get("src", ""))),
                "destination": os.path.realpath(str(params.get("dst", ""))),
            }
        return PermissionResourceType.FILESYSTEM.value, {
            "operation": operation,
            "tool": tool_name,
            "path": target,
        }
    if tool_name in {"terminal", "terminal_argv", "terminal_shell", "test_run"}:
        argv = params.get("argv")
        if not isinstance(argv, list):
            try:
                argv = shlex.split(str(params.get("command") or params.get("script") or ""))
            except ValueError:
                argv = []
        argv = [item for item in argv if isinstance(item, str)]
        return PermissionResourceType.EXEC.value, {
            "operation": operation,
            "tool": tool_name,
            "executable": argv[0] if argv else "",
            "argv": argv,
            "cwd": os.path.realpath(str(params.get("cwd", "."))),
            "workspace_root": (
                os.path.realpath(str(params["workspace_root"]))
                if params.get("workspace_root") else ""
            ),
            "is_shell": False,
            "shell": "",
            "script_digest": "",
        }
    if "url" in params:
        observation = _network_observation(str(params.get("url", "")))
        if observation is not None:
            return PermissionResourceType.NETWORK.value, observation
    if tool_name == "process":
        return PermissionResourceType.PROCESS.value, {
            "operation": str(params.get("action") or operation),
            "tool": tool_name,
            "process_id": str(params.get("id") or ""),
        }
    return PermissionResourceType.GENERIC.value, {
        "operation": operation,
        "tool": tool_name,
        "target": target,
    }


def match_typed_rule(
    resource_type: str,
    resource_spec: dict[str, Any],
    *,
    resource: AuthorizationResource | None,
    tool_name: str,
    params: dict[str, Any],
    target: str,
    operation: str,
) -> bool:
    """Match a typed rule against the immutable/current request resource."""
    if resource is not None:
        observed_type, observed = _typed_observation_from_resource(resource, operation)
    else:
        observed_type, observed = request_observation(tool_name, params, target, operation)
    if observed_type != resource_type:
        return False
    if resource_type == PermissionResourceType.FILESYSTEM.value:
        if resource_spec.get("operation") and resource_spec["operation"] != operation:
            return False
        if resource_spec.get("tool") and resource_spec["tool"] != observed.get("tool"):
            return False
        if "source" in resource_spec:
            return (
                observed.get("source") == resource_spec["source"]
                and observed.get("destination") == resource_spec.get("destination")
            )
        path = str(observed.get("path", ""))
        if "path" in resource_spec and not resource_spec.get("recursive", False):
            return path == resource_spec["path"]
        root = resource_spec.get("root", resource_spec.get("path", ""))
        return bool(root) and _path_contains(str(root), path)
    if resource_type == PermissionResourceType.EXEC.value:
        if resource_spec.get("operation") and resource_spec["operation"] != operation:
            return False
        if resource_spec.get("tool") and resource_spec["tool"] != observed.get("tool"):
            return False
        is_shell = bool(observed.get("is_shell"))
        if is_shell and not resource_spec.get("allow_shell", False):
            return False
        if not is_shell and resource_spec.get("allow_shell", False):
            return False
        if resource_spec.get("executable") != observed.get("executable"):
            return False
        argv = list(observed.get("argv") or [])
        prefix = list(resource_spec.get("argv_prefix") or [])
        if argv and argv[0] == observed.get("executable"):
            argv = argv[1:]
        if resource_spec.get("argv_exact"):
            if argv != prefix:
                return False
        elif argv[: len(prefix)] != prefix:
            return False
        if resource_spec.get("cwd_scope") == "exact" and resource_spec.get("cwd") != observed.get("cwd"):
            return False
        if resource_spec.get("cwd_scope") == "workspace":
            workspace_root = str(resource_spec.get("workspace_root") or "")
            observed_root = str(observed.get("workspace_root") or "")
            cwd = str(observed.get("cwd") or "")
            if (
                not workspace_root
                or observed_root != workspace_root
                or not cwd
                or not _path_contains(workspace_root, cwd)
            ):
                return False
        if resource_spec.get("shell") and resource_spec["shell"] != observed.get("shell"):
            return False
        return not (resource_spec.get("script_digest") and resource_spec["script_digest"] != observed.get("script_digest"))
    if resource_type == PermissionResourceType.NETWORK.value:
        for name in ("scheme", "host", "port"):
            if name in resource_spec and resource_spec[name] != observed.get(name):
                return False
        prefix = resource_spec.get("path_prefix", "/")
        path = str(observed.get("path", "/"))
        return path == prefix or path.startswith(prefix.rstrip("/") + "/") or prefix == "/"
    if resource_type == PermissionResourceType.PROCESS.value:
        return all(
            resource_spec.get(name) == observed.get(name)
            for name in ("process_id", "tool")
            if name in resource_spec
        ) and (
            not resource_spec.get("operation")
            or resource_spec["operation"] == observed.get("operation")
        )
    if resource_type == PermissionResourceType.WORKSPACE.value:
        return (
            resource_spec.get("workspace_root") == observed.get("workspace_root")
            and (
                not resource_spec.get("operation")
                or resource_spec["operation"] == observed.get("operation")
            )
            and (
                not resource_spec.get("tool")
                or resource_spec["tool"] == observed.get("tool")
            )
        )
    if resource_type == PermissionResourceType.GENERIC.value:
        return (
            resource_spec.get("target") == target
            and (
                not resource_spec.get("tool")
                or resource_spec["tool"] == tool_name
            )
        )
    return False
