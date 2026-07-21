"""Load and apply sandbox policy from YAML configuration.

The policy file (``khaos_policy.yaml``) is the single user-editable source of
truth for Khaos's permission boundary: sandbox mode, network access, allowed /
denied paths, command approval lists, secret-scan toggles, and audit settings.

When no policy file is found — or a file fails to parse — a safe default
policy (``workspace-write``, network off) is returned. A bad file never blocks
Khaos from starting.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

DEFAULT_POLICY_PATHS = [
    Path("khaos_policy.yaml"),
    Path("~/.khaos/policy.yaml"),
]

# Defaults mirror the template in khaos_policy.yaml so that a missing file and
# an empty file behave identically.
_DEFAULT_DENIED_PATHS = [
    "~/.ssh",
    "~/.aws",
    "~/.gnupg",
    "~/.config/gcloud",
    "/etc/shadow",
    "/etc/passwd",
    "/etc/sudoers",
]

_DEFAULT_REQUIRE_APPROVAL = [
    "git push",
    "rm",
    "curl",
    "wget",
    "docker",
    "npm publish",
    "pip install",
    "cargo publish",
]


@dataclass
class SandboxPolicy:
    """Global sandbox policy loaded from YAML."""

    # sandbox 模式: "workspace-write" | "read-only" | "full-access" | "yolo"
    mode: str = "workspace-write"

    # 网络控制
    network_enabled: bool = False
    # H3: three-state — ``None`` means "this layer does not configure an
    # allowlist" (unrestricted subject to blocklist when network is on);
    # an empty list means "this layer explicitly denies all domains"; a
    # non-empty list is the whitelist.  This mirrors ``commands_allowed``
    # and closes the fail-open hole where the default empty list collided
    # with "deny all" and silently erased the other layer's whitelist
    # during intersection.
    network_allowed_domains: list[str] | None = None
    network_blocked_domains: list[str] = field(default_factory=list)

    # 文件系统控制
    allowed_paths: list[str] = field(default_factory=lambda: ["."])
    denied_paths: list[str] = field(default_factory=lambda: list(_DEFAULT_DENIED_PATHS))

    # 命令控制
    # H2: ``commands_allowed`` uses ``None`` to mean "this layer does not
    # configure an allow-list" (distinct from an empty list which means
    # "this layer explicitly denies all commands").  The effective policy
    # compiler uses three-state semantics: None = unset, empty = deny all,
    # non-empty = whitelist.
    commands_allowed: list[str] | None = None
    commands_require_approval: list[str] = field(
        default_factory=lambda: list(_DEFAULT_REQUIRE_APPROVAL)
    )
    commands_blocked: list[str] = field(default_factory=list)

    # 敏感信息扫描
    secrets_scan_on_output: bool = True
    secrets_scan_before_tool_result: bool = True
    secrets_block_env_dump: bool = True

    # 审计
    audit_enabled: bool = True
    audit_log_path: str | None = None

    # M4 batch 3.1.16A-4-4-3: channel admin principals — the set of
    # principals allowed to mutate (enable / disable) registered
    # communication channels via the channel tools.  ``None`` means
    # "this layer does not configure an admin list" (the effective
    # policy compiler uses OR semantics across layers — user ∪ project);
    # an empty list means "this layer explicitly denies all admins"
    # (still contributes nothing to the union, but is distinct from
    # "unset" for digest / audit purposes).  Default ``None`` so the
    # *effective* policy defaults to an empty frozenset — fail-closed
    # for channel mutations until an admin is explicitly declared.
    channel_admins: list[str] | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SandboxPolicy":
        """从字典构建策略。

        H3: unknown top-level / section keys raise ``ValueError`` so a typo in
        ``khaos_policy.yaml`` fails closed at parse time rather than being
        silently ignored.  Empty input still yields the safe default policy.

        H1: non-mapping input (e.g. a YAML list or scalar) raises
        ``ValueError`` instead of silently returning the default policy.
        """
        if not isinstance(data, dict):
            raise ValueError(
                "policy must be a mapping at the top level, "
                f"got {type(data).__name__}"
            )
        _reject_unknown_keys(data)
        sandbox = data.get("sandbox", {}) or {}
        commands = data.get("commands", {}) or {}
        secrets = data.get("secrets", {}) or {}
        audit = data.get("audit", {}) or {}
        channels = data.get("channels", {}) or {}

        return cls(
            mode=sandbox.get("mode", "workspace-write"),
            network_enabled=sandbox.get("network", False),
            # H3: ``sandbox.get("allowed_domains")`` returns None when the
            # key is absent (layer does not configure an allowlist) or the
            # list when present (including an explicitly empty list = deny
            # all).  This is the same three-state pattern as
            # ``commands_allowed``.
            network_allowed_domains=sandbox.get("allowed_domains"),
            network_blocked_domains=sandbox.get("blocked_domains", []),
            allowed_paths=sandbox.get("allowed_paths", ["."]),
            denied_paths=sandbox.get("denied_paths", list(_DEFAULT_DENIED_PATHS)),
            # H2: ``commands.get("allow")`` returns None when the key is
            # absent (layer does not configure an allow-list) or the list
            # when present (including an explicitly empty list = deny all).
            commands_allowed=commands.get("allow"),
            commands_require_approval=commands.get(
                "require_approval", list(_DEFAULT_REQUIRE_APPROVAL)
            ),
            commands_blocked=commands.get("block", []),
            secrets_scan_on_output=secrets.get("scan_on_output", True),
            secrets_scan_before_tool_result=secrets.get(
                "scan_before_tool_result", True
            ),
            secrets_block_env_dump=secrets.get("block_env_dump", True),
            audit_enabled=audit.get("enabled", True),
            audit_log_path=audit.get("log_path"),
            # M4 batch 3.1.16A-4-4-3: ``channels.admin_principals`` — None
            # when the key is absent (layer does not configure an admin
            # list), the list when present (including an explicitly empty
            # list = this layer contributes no admins).
            channel_admins=channels.get("admin_principals"),
        )


def load_policy(path: Path | None = None) -> SandboxPolicy:
    """Load a policy from a YAML file.

    Priority: explicit path > khaos_policy.yaml > ~/.khaos/policy.yaml > default.

    H3: a missing or empty file still yields the safe default policy, but a
    *malformed* YAML file or a file with *unknown keys* now raises rather
    than silently degrading to the more-permissive workspace-write default.
    A user who mistypes the mode field or breaks YAML while trying to lock
    down to read-only must see the failure at startup, not silently gain
    write/terminal access.

    H5: the parsed YAML is run through ``validate_policy_dict`` *before*
    ``SandboxPolicy.from_dict`` so strict scalar type checks (booleans must
    be real booleans, not the truthy string ``"false"``; lists of paths
    must be lists, not bare strings; etc.) reach every production
    ``khaos_policy.yaml`` load, not just direct callers of the compiler.
    """
    candidates: list[Path] = [path] if path else DEFAULT_POLICY_PATHS
    for candidate in candidates:
        if candidate is None:
            continue
        try:
            resolved = candidate.expanduser().resolve()
        except (OSError, RuntimeError) as exc:
            logger.warning("cannot resolve policy path %s: %s", candidate, exc)
            continue
        if not resolved.is_file():
            continue
        logger.info("Loading sandbox policy from %s", resolved)
        # Let yaml.YAMLError propagate (fail closed on malformed YAML).
        with open(resolved, encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
        if data is None:
            data = {}
        # H1: a valid-but-non-mapping YAML (e.g. a bare list or scalar like
        # ``read-only``) must fail closed.  Previously it silently degraded
        # to the default ``workspace-write`` policy, so a user who mistyped
        # the structure while trying to lock down to read-only would
        # silently gain write and terminal access.  ``validate_policy_dict``
        # raises ``PolicyCompilationError`` for non-dict input.
        from khaos.security.effective_policy import validate_policy_dict

        validate_policy_dict(data, source=str(resolved))
        return SandboxPolicy.from_dict(data)
    logger.info("No policy file found, using defaults")
    return SandboxPolicy()


# Valid keys at each nesting level.  Used to fail closed on typos.
_ALLOWED_TOP_LEVEL = frozenset({"sandbox", "commands", "secrets", "audit", "channels"})
_ALLOWED_SANDBOX_KEYS = frozenset({
    "mode", "network", "allowed_domains", "blocked_domains",
    "allowed_paths", "denied_paths",
})
_ALLOWED_COMMANDS_KEYS = frozenset({"allow", "require_approval", "block"})
_ALLOWED_SECRETS_KEYS = frozenset({
    "scan_on_output", "scan_before_tool_result", "block_env_dump",
})
_ALLOWED_AUDIT_KEYS = frozenset({"enabled", "log_path"})
# M4 batch 3.1.16A-4-4-3: ``channels`` section currently carries only the
# admin principal allowlist.  Extend here when new channel-scoped fields
# are added.
_ALLOWED_CHANNELS_KEYS = frozenset({"admin_principals"})


def _reject_unknown_keys(data: dict[str, Any]) -> None:
    """Raise ValueError if ``data`` has any unknown top-level or section keys."""
    _check_section(data, _ALLOWED_TOP_LEVEL, "policy")
    _check_section(data.get("sandbox") or {}, _ALLOWED_SANDBOX_KEYS, "sandbox")
    _check_section(data.get("commands") or {}, _ALLOWED_COMMANDS_KEYS, "commands")
    _check_section(data.get("secrets") or {}, _ALLOWED_SECRETS_KEYS, "secrets")
    _check_section(data.get("audit") or {}, _ALLOWED_AUDIT_KEYS, "audit")
    _check_section(data.get("channels") or {}, _ALLOWED_CHANNELS_KEYS, "channels")


def _check_section(mapping: object, allowed: frozenset[str], where: str) -> None:
    if not isinstance(mapping, dict):
        return
    unknown = set(mapping) - allowed
    if unknown:
        raise ValueError(
            f"unknown {where} key(s): {sorted(unknown)}; "
            f"allowed: {sorted(allowed)}"
        )
