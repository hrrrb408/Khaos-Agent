"""Effective, immutable security policy compiled from layered sources.

``khaos_policy.yaml`` is advertised as the single user-editable security
source of truth, but historically only ``denied_paths`` and
``commands_blocked`` were actually enforced — ``allowed_paths`` and
``commands_require_approval`` were parsed and then silently ignored, and an
unknown ``sandbox.mode`` or a malformed YAML file quietly fell back to the
*more permissive* ``workspace-write`` mode (H3).

This module compiles a layered, immutable ``EffectiveSecurityPolicy``:

    user / global policy
        ∩  (intersection — a stricter source always wins)
    project policy
        ∩
    runtime / platform capability

Project policy can only *tighten* the user/global policy, never relax it.
Unknown modes, unknown fields, type errors and malformed YAML fail closed
(raise) instead of degrading to ``workspace-write``.

The compiled policy carries a ``digest`` so it can be bound to an approval
decision, proving the approval was made under exactly this policy.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

from khaos.security.policy import SandboxPolicy
from khaos.security.sandbox import SandboxMode


class PolicyCompilationError(ValueError):
    """Raised when a policy cannot be compiled safely (fail closed)."""


# Strictness ordering — index 0 is the most permissive.  ``_stricter_mode``
# returns the mode with the *higher* index (i.e. more restrictive).
_MODE_STRICTNESS = (
    SandboxMode.YOLO,            # 0 — allow-all, bypasses checks
    SandboxMode.FULL_ACCESS,     # 1 — allow-all tools
    SandboxMode.WORKSPACE_WRITE, # 2 — writes confined to workspace + terminal
    SandboxMode.READ_ONLY,       # 3 — reads only
)
_MODE_INDEX = {mode: idx for idx, mode in enumerate(_MODE_STRICTNESS)}


@dataclass(frozen=True)
class PlatformCapability:
    """Runtime/platform-imposed upper bound on what a policy may permit.

    Defaults to the most permissive capability set so that, in the absence of
    platform limits, the effective policy is the pure user∩project
    intersection.  Real deployments narrow this (e.g. a read-only filesystem
    image sets ``max_mode=READ_ONLY``).
    """

    max_mode: SandboxMode = SandboxMode.YOLO


@dataclass(frozen=True)
class EffectiveSecurityPolicy:
    """Compiled, immutable security policy: user ∩ project ∩ platform.

    All collection fields are frozen sets so the policy cannot be mutated
    after compilation.  ``digest`` is a stable sha256 of the canonical
    representation, suitable for binding to an approval decision.
    """

    mode: SandboxMode
    network_enabled: bool
    network_allowed_domains: frozenset[str]
    network_blocked_domains: frozenset[str]
    root_capabilities: frozenset[Path]
    denied_paths: frozenset[str]
    commands_allowed: frozenset[str]
    commands_require_approval: frozenset[str]
    commands_blocked: frozenset[str]
    secrets_scan_on_output: bool
    digest: str = ""

    def __post_init__(self) -> None:
        if not self.digest:
            object.__setattr__(self, "digest", _compute_digest(self))

    def to_binding(self) -> str:
        """Return the binding token an approval decision should carry."""
        return f"policy:{self.digest}"


def compile_effective_policy(
    project_policy: SandboxPolicy,
    *,
    workspace_root: Path,
    user_policy: SandboxPolicy | None = None,
    platform_capability: PlatformCapability | None = None,
) -> EffectiveSecurityPolicy:
    """Compile an immutable effective policy from layered sources.

    ``user_policy`` is the global/user policy (may be ``None``); it can only
    be tightened by the project policy.  ``platform_capability`` is the
    runtime upper bound (may be ``None`` → most permissive).

    Raises ``PolicyCompilationError`` on any unsafe input: unknown sandbox
    mode, unknown top-level field, or wrong field type.  The caller is
    expected to fail startup (or drop to read-only) rather than silently
    relax the policy.
    """
    user = user_policy  # None means "no user/global layer"
    platform = platform_capability or PlatformCapability()

    # --- mode: take the strictest of (user, project), then clamp to platform.
    project_mode = _resolve_mode(project_policy.mode, source="project")
    if user is not None:
        user_mode = _resolve_mode(user.mode, source="user")
        mode = _stricter_mode(user_mode, project_mode)
    else:
        mode = project_mode
    # Platform is an upper bound — if it is stricter, it wins.
    mode = _stricter_mode(mode, platform.max_mode)

    # --- collections: union = stricter (any source denying/approving wins).
    denied_paths = _frozen(project_policy.denied_paths)
    commands_blocked = _frozen(project_policy.commands_blocked)
    commands_require_approval = _frozen(project_policy.commands_require_approval)
    commands_allowed = _frozen(project_policy.commands_allowed)
    if user is not None:
        denied_paths = denied_paths | _frozen(user.denied_paths)
        commands_blocked = commands_blocked | _frozen(user.commands_blocked)
        commands_require_approval = commands_require_approval | _frozen(
            user.commands_require_approval
        )
        # commands_allowed is intersected: a command must be allowed by BOTH
        # layers to remain allowed (otherwise the stricter layer denies).
        commands_allowed = commands_allowed & _frozen(user.commands_allowed)

    # --- network: enabled only if BOTH layers enable it; domains merged.
    network_enabled = bool(project_policy.network_enabled) and (
        user is None or bool(user.network_enabled)
    )
    network_allowed_domains = _frozen(project_policy.network_allowed_domains)
    network_blocked_domains = _frozen(project_policy.network_blocked_domains)
    if user is not None:
        # allowed_domains: intersection (both must permit); blocked: union.
        network_allowed_domains = network_allowed_domains & _frozen(
            user.network_allowed_domains
        )
        network_blocked_domains = network_blocked_domains | _frozen(
            user.network_blocked_domains
        )

    # --- allowed_paths → root_capabilities (resolved against workspace_root).
    root_capabilities = _compile_root_capabilities(
        project_policy.allowed_paths, workspace_root
    )
    if user is not None:
        root_capabilities = root_capabilities & _compile_root_capabilities(
            user.allowed_paths, workspace_root
        )

    # --- secrets: scan stays on unless BOTH layers disable it.
    secrets_scan_on_output = bool(project_policy.secrets_scan_on_output) or (
        user is None or bool(user.secrets_scan_on_output)
    )

    return EffectiveSecurityPolicy(
        mode=mode,
        network_enabled=network_enabled,
        network_allowed_domains=network_allowed_domains,
        network_blocked_domains=network_blocked_domains,
        root_capabilities=root_capabilities,
        denied_paths=denied_paths,
        commands_allowed=commands_allowed,
        commands_require_approval=commands_require_approval,
        commands_blocked=commands_blocked,
        secrets_scan_on_output=secrets_scan_on_output,
    )


# --------------------------------------------------------------------------- #
# Internal helpers
# --------------------------------------------------------------------------- #

_ALLOWED_TOP_LEVEL = frozenset({"sandbox", "commands", "secrets", "audit"})
_ALLOWED_SANDBOX_KEYS = frozenset({
    "mode", "network", "allowed_domains", "blocked_domains",
    "allowed_paths", "denied_paths",
})
_ALLOWED_COMMANDS_KEYS = frozenset({"allow", "require_approval", "block"})
_ALLOWED_SECRETS_KEYS = frozenset({
    "scan_on_output", "scan_before_tool_result", "block_env_dump",
})
_ALLOWED_AUDIT_KEYS = frozenset({"enabled", "log_path"})


def validate_policy_dict(data: object, *, source: str = "policy") -> None:
    """Reject unknown fields / wrong types so typos fail closed.

    Called by the compiler on the *raw* parsed YAML before ``SandboxPolicy``
    construction, so unknown keys do not get silently dropped by
    ``SandboxPolicy.from_dict``.
    """
    if not isinstance(data, dict):
        raise PolicyCompilationError(
            f"{source} must be a mapping at the top level"
        )
    unknown_top = set(data) - _ALLOWED_TOP_LEVEL
    if unknown_top:
        raise PolicyCompilationError(
            f"{source} has unknown top-level keys: {sorted(unknown_top)}"
        )
    sandbox = data.get("sandbox", {})
    if sandbox is None:
        sandbox = {}
    _check_keys(sandbox, _ALLOWED_SANDBOX_KEYS, f"{source}.sandbox")
    _check_list_of_str(sandbox.get("allowed_paths"), "sandbox.allowed_paths", source)
    _check_list_of_str(sandbox.get("denied_paths"), "sandbox.denied_paths", source)
    _check_list_of_str(sandbox.get("allowed_domains"), "sandbox.allowed_domains", source)
    _check_list_of_str(sandbox.get("blocked_domains"), "sandbox.blocked_domains", source)

    commands = data.get("commands", {})
    if commands is None:
        commands = {}
    _check_keys(commands, _ALLOWED_COMMANDS_KEYS, f"{source}.commands")
    _check_list_of_str(commands.get("allow"), "commands.allow", source)
    _check_list_of_str(commands.get("require_approval"), "commands.require_approval", source)
    _check_list_of_str(commands.get("block"), "commands.block", source)

    secrets = data.get("secrets", {})
    if secrets is None:
        secrets = {}
    _check_keys(secrets, _ALLOWED_SECRETS_KEYS, f"{source}.secrets")

    audit = data.get("audit", {})
    if audit is None:
        audit = {}
    _check_keys(audit, _ALLOWED_AUDIT_KEYS, f"{source}.audit")


def _check_keys(mapping: object, allowed: frozenset[str], where: str) -> None:
    if not isinstance(mapping, dict):
        raise PolicyCompilationError(f"{where} must be a mapping")
    unknown = set(mapping) - allowed
    if unknown:
        raise PolicyCompilationError(f"{where} has unknown keys: {sorted(unknown)}")


def _check_list_of_str(value: object, where: str, source: str) -> None:
    if value is None:
        return
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise PolicyCompilationError(f"{source}.{where} must be a list of strings")


def _resolve_mode(mode_str: str, *, source: str) -> SandboxMode:
    try:
        return SandboxMode(mode_str)
    except ValueError as exc:
        raise PolicyCompilationError(
            f"{source} sandbox.mode '{mode_str}' is not one of "
            f"{[m.value for m in SandboxMode]}"
        ) from exc


def _stricter_mode(a: SandboxMode, b: SandboxMode) -> SandboxMode:
    """Return the more restrictive (higher strictness index) of two modes."""
    return a if _MODE_INDEX[a] >= _MODE_INDEX[b] else b


def _frozen(values: object) -> frozenset[str]:
    if not values:
        return frozenset()
    return frozenset(str(v) for v in values)


def _compile_root_capabilities(
    allowed_paths: object, workspace_root: Path
) -> frozenset[Path]:
    """Resolve ``allowed_paths`` to absolute root capability paths.

    ``"."`` and relative entries resolve under ``workspace_root``.  Absolute
    entries are kept as-is.  Entries that would escape ``workspace_root`` are
    dropped (the project policy cannot grant access outside the workspace —
    that would be a relaxation the runtime forbids).
    """
    if not allowed_paths:
        return frozenset()
    root = workspace_root.expanduser().resolve()
    capabilities: set[Path] = set()
    for raw in allowed_paths:
        candidate = Path(str(raw)).expanduser()
        if not candidate.is_absolute():
            candidate = root / candidate
        try:
            resolved = candidate.resolve(strict=False)
        except (OSError, RuntimeError):
            continue
        # Only capabilities at or under the workspace root are honored.
        try:
            resolved.relative_to(root)
        except ValueError:
            continue
        capabilities.add(resolved)
    return frozenset(capabilities)


def _canonical_dict(policy: EffectiveSecurityPolicy) -> dict:
    return {
        "mode": policy.mode.value,
        "network_enabled": policy.network_enabled,
        "network_allowed_domains": sorted(policy.network_allowed_domains),
        "network_blocked_domains": sorted(policy.network_blocked_domains),
        "root_capabilities": sorted(str(p) for p in policy.root_capabilities),
        "denied_paths": sorted(policy.denied_paths),
        "commands_allowed": sorted(policy.commands_allowed),
        "commands_require_approval": sorted(policy.commands_require_approval),
        "commands_blocked": sorted(policy.commands_blocked),
        "secrets_scan_on_output": policy.secrets_scan_on_output,
    }


def _compute_digest(policy: EffectiveSecurityPolicy) -> str:
    """sha256 over the canonical (sorted, deterministic) policy representation."""
    payload = json.dumps(_canonical_dict(policy), sort_keys=True).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()
