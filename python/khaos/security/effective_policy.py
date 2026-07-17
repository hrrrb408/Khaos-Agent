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

B2: ``allowed_paths`` intersection uses *directory containment*, not plain
set ``&``.  ``intersection(/repo, /repo/src) = /repo/src`` (the stricter
subdirectory wins); ``intersection(/repo/src, /repo/docs) = empty`` (deny).
An empty intersection is treated as "deny all" by the Sandbox, never as
"no restriction" — closing the fail-open hole where ``allowed_paths: []``
or ``allowed_paths: [../outside]`` silently granted the whole workspace.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

from khaos.security.policy import SandboxPolicy, load_policy
from khaos.security.sandbox import SandboxMode

logger = logging.getLogger(__name__)

# Default user/global policy path.  Loaded as a separate layer so the
# effective policy is the true ``user ∩ project ∩ platform`` intersection.
USER_POLICY_PATH = Path("~/.khaos/policy.yaml")


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

    B2: defaults to ``WORKSPACE_WRITE`` — the safe baseline — so that in the
    absence of an explicit platform capability, a project policy cannot
    elevate to ``YOLO`` or ``FULL_ACCESS``.  Real deployments that need a
    wider envelope (e.g. a trusted CI runner) must pass an explicit
    ``PlatformCapability(max_mode=SandboxMode.YOLO)``.
    """

    max_mode: SandboxMode = SandboxMode.WORKSPACE_WRITE


@dataclass(frozen=True)
class EffectiveSecurityPolicy:
    """Compiled, immutable security policy: user ∩ project ∩ platform.

    All collection fields are frozen sets so the policy cannot be mutated
    after compilation.  ``digest`` is a stable sha256 of the canonical
    representation, suitable for binding to an approval decision.

    ``root_capabilities`` is ``frozenset[Path]`` — possibly empty.  An empty
    set means "explicitly no path is allowed" (deny all).  The Sandbox
    distinguishes this from ``None`` (unset → use workspace default) via
    the factory wiring: when the effective policy is compiled, its
    ``root_capabilities`` (even empty) is always installed on the Sandbox,
    so an empty set becomes a hard deny rather than a fail-open.

    H2: ``audit_enabled`` / ``audit_log_path`` /
    ``secrets_scan_before_tool_result`` / ``secrets_block_env_dump`` are
    compiled here (OR semantics — if user OR project requires audit / scan,
    the project cannot disable it) so an untrusted project can no longer
    silently turn off production audit or secret scanning by setting
    ``audit.enabled: false`` in its ``khaos_policy.yaml``.  The AgentService
    consumes these fields from the *effective* policy, never from the raw
    project policy.
    """

    mode: SandboxMode
    network_enabled: bool
    network_allowed_domains: frozenset[str]
    network_blocked_domains: frozenset[str]
    root_capabilities: frozenset[Path]
    denied_paths: frozenset[str]
    # H2: three-state — ``None`` means no layer configured an allow-list
    # (no whitelist enforced); an empty frozenset means a layer explicitly
    # set ``commands.allow: []`` (deny all commands); a non-empty frozenset
    # is the whitelist.
    commands_allowed: frozenset[str] | None
    commands_require_approval: frozenset[str]
    commands_blocked: frozenset[str]
    secrets_scan_on_output: bool
    # H2: audit + secret-scan fields compiled from the layered policies.
    # ``audit_enabled`` uses OR semantics: if the user OR project layer
    # requires audit, the project layer cannot disable it.
    audit_enabled: bool = True
    audit_log_path: str | None = None
    secrets_scan_before_tool_result: bool = True
    secrets_block_env_dump: bool = True
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

    B2: ``root_capabilities`` uses directory-containment intersection, not
    plain set ``&``.  An empty result means "deny all", not "no restriction".
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
    # H2: three-state commands_allowed — None means "this layer does not
    # configure an allow-list".  Only intersect when BOTH layers configure
    # one; if only one layer configures it, use that layer's list; if
    # neither does, the result is None (no whitelist enforced).
    project_allowed = project_policy.commands_allowed
    user_allowed = user.commands_allowed if user is not None else None
    if project_allowed is not None and user_allowed is not None:
        # Both layers configure a whitelist — intersect (stricter).
        commands_allowed: frozenset[str] | None = _frozen(project_allowed) & _frozen(user_allowed)
    elif project_allowed is not None:
        commands_allowed = _frozen(project_allowed)
    elif user_allowed is not None:
        commands_allowed = _frozen(user_allowed)
    else:
        commands_allowed = None
    if user is not None:
        denied_paths = denied_paths | _frozen(user.denied_paths)
        commands_blocked = commands_blocked | _frozen(user.commands_blocked)
        commands_require_approval = commands_require_approval | _frozen(
            user.commands_require_approval
        )

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
    # B2: use directory-containment intersection so intersection(/repo,
    # /repo/src) = /repo/src (the stricter subdirectory wins), and an empty
    # intersection means "deny all" (not "no restriction").
    project_caps = _compile_root_capabilities(
        project_policy.allowed_paths, workspace_root
    )
    if user is not None:
        user_caps = _compile_root_capabilities(
            user.allowed_paths, workspace_root
        )
        root_capabilities = _intersect_path_capabilities(project_caps, user_caps)
    else:
        root_capabilities = project_caps

    # --- secrets: scan stays on unless BOTH layers disable it.
    secrets_scan_on_output = bool(project_policy.secrets_scan_on_output) or (
        user is None or bool(user.secrets_scan_on_output)
    )
    # H2: the other secret-scan toggles use the same OR semantics — if
    # either layer requires scanning, the project cannot disable it.
    secrets_scan_before_tool_result = bool(
        project_policy.secrets_scan_before_tool_result
    ) or (user is None or bool(user.secrets_scan_before_tool_result))
    secrets_block_env_dump = bool(project_policy.secrets_block_env_dump) or (
        user is None or bool(user.secrets_block_env_dump)
    )

    # H2: audit uses OR semantics — if the user OR project layer requires
    # audit, the project layer cannot disable it.  This closes the hole
    # where an untrusted repo could submit ``audit.enabled: false`` and
    # silently turn off production audit.  ``audit_log_path``: the user
    # layer's path wins if set (user is the trust root), otherwise the
    # project layer's path, otherwise None (default db-backed audit).
    audit_enabled = bool(project_policy.audit_enabled) or (
        user is None or bool(user.audit_enabled)
    )
    if user is not None and user.audit_log_path:
        audit_log_path = user.audit_log_path
    else:
        audit_log_path = project_policy.audit_log_path

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
        audit_enabled=audit_enabled,
        audit_log_path=audit_log_path,
        secrets_scan_before_tool_result=secrets_scan_before_tool_result,
        secrets_block_env_dump=secrets_block_env_dump,
    )


def default_user_policy() -> SandboxPolicy:
    """Return the trusted default user/global policy layer (B2).

    When ``~/.khaos/policy.yaml`` does not exist, this safe baseline is used
    as the *user* layer instead of ``None``.  It enforces:

    * ``workspace-write`` mode (no YOLO / FULL_ACCESS elevation);
    * network off;
    * the default denied-paths list (``~/.ssh``, ``~/.aws``, …);
    * the default require-approval command list (``git push``, ``rm``, …).

    A project policy can only *tighten* this baseline (intersection), never
    relax it.  This closes the hole where an untrusted repository could set
    ``mode: yolo`` and become its own security authority.
    """
    return SandboxPolicy()


def load_effective_policy(
    workspace_root: Path,
    *,
    project_policy_path: Path | None = None,
    user_policy_path: Path | None = None,
    platform_capability: PlatformCapability | None = None,
) -> EffectiveSecurityPolicy:
    """Load and compile the layered effective policy (B1).

    This is the production entry point: it loads the *project* policy from
    ``<workspace_root>/khaos_policy.yaml`` and the *user/global* policy from
    ``~/.khaos/policy.yaml`` as independent layers, then compiles them into
    a single ``EffectiveSecurityPolicy`` that drives every runtime component.

    Both layers are validated (``validate_policy_dict``) and fail closed on
    unknown fields / wrong types.

    B2: a missing user policy file does **not** degrade to the project-only
    intersection — that would let an untrusted project elevate to ``yolo``.
    Instead, the safe ``default_user_policy()`` baseline is installed as the
    user layer, so the project can only tighten it.
    """
    project_path = project_policy_path or (workspace_root / "khaos_policy.yaml")
    user_path = user_policy_path or USER_POLICY_PATH

    project_policy = load_policy(project_path)
    expanded_user = user_path.expanduser()
    if expanded_user.is_file():
        logger.info("Loading user policy from %s", expanded_user)
        user_policy: SandboxPolicy = load_policy(expanded_user)
    else:
        # B2: install the trusted default user layer so the project policy
        # cannot elevate beyond ``workspace-write`` / network-off.
        user_policy = default_user_policy()

    return compile_effective_policy(
        project_policy,
        workspace_root=workspace_root,
        user_policy=user_policy,
        platform_capability=platform_capability,
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

    H5: also enforces strict scalar types — booleans must be actual booleans
    (not the string ``"false"``, which is truthy in Python and would silently
    enable network), ``mode`` must be a string, and ``log_path`` must be a
    string.  Production ``load_policy()`` now calls this so the strict checks
    reach every real ``khaos_policy.yaml``, not just direct callers of the
    compiler.
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
    _check_str(sandbox.get("mode"), "sandbox.mode", source)
    # H5: ``network: "false"`` is a string and is truthy in Python — without
    # this check it would silently enable network access.
    _check_bool(sandbox.get("network"), "sandbox.network", source)
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
    _check_bool(secrets.get("scan_on_output"), "secrets.scan_on_output", source)
    _check_bool(
        secrets.get("scan_before_tool_result"),
        "secrets.scan_before_tool_result",
        source,
    )
    _check_bool(secrets.get("block_env_dump"), "secrets.block_env_dump", source)

    audit = data.get("audit", {})
    if audit is None:
        audit = {}
    _check_keys(audit, _ALLOWED_AUDIT_KEYS, f"{source}.audit")
    _check_bool(audit.get("enabled"), "audit.enabled", source)
    _check_str(audit.get("log_path"), "audit.log_path", source)


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


def _check_bool(value: object, where: str, source: str) -> None:
    """Reject anything that is not a real Python bool.

    YAML ``true`` / ``false`` parse to ``bool``; the strings ``"true"`` /
    ``"false"`` parse to ``str`` and would be silently truthy.  ``None`` means
    the key was omitted, which is fine (the default applies).
    """
    if value is None:
        return
    # NOTE: ``bool`` is a subclass of ``int``; the explicit ``type`` check
    # rejects ``int`` (e.g. ``0`` / ``1``) which YAML would never produce
    # for a real boolean field but a careless hand-edit might.
    if type(value) is not bool:
        raise PolicyCompilationError(
            f"{source}.{where} must be a boolean (true/false), "
            f"got {type(value).__name__}: {value!r}"
        )


def _check_str(value: object, where: str, source: str) -> None:
    if value is None:
        return
    if not isinstance(value, str):
        raise PolicyCompilationError(
            f"{source}.{where} must be a string, got {type(value).__name__}: {value!r}"
        )


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

    B2: an explicit empty ``allowed_paths`` (``[]``) returns an empty
    frozenset, which the Sandbox treats as "deny all".  An entry list where
    *every* entry is dropped (e.g. all outside the workspace) likewise
    returns an empty frozenset — deny all, not fail-open.
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


def _is_under_or_equal(child: Path, parent: Path) -> bool:
    """Return True if ``child == parent`` or ``parent`` is an ancestor of ``child``."""
    if child == parent:
        return True
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def _intersect_path_capabilities(
    project_caps: frozenset[Path], user_caps: frozenset[Path]
) -> frozenset[Path]:
    """Intersect two path-capability sets by directory containment (B2).

    Unlike plain set ``&``, this understands that ``/repo`` *contains*
    ``/repo/src``.  The intersection of ``{/repo}`` and ``{/repo/src}`` is
    ``{/repo/src}`` (the stricter subdirectory wins).  The intersection of
    ``{/repo/src}`` and ``{/repo/docs}`` is empty (disjoint → deny).

    For each pair ``(p, u)`` where one contains the other, the deeper
    (more restrictive) path is kept.  Disjoint pairs contribute nothing.
    The result may contain redundant entries (e.g. both ``/repo`` and
    ``/repo/src``), but the Sandbox's ``_capability_denial_reason`` accepts
    any containing capability, so redundancy is harmless.
    """
    if not project_caps or not user_caps:
        # If either side is empty (explicit deny), the intersection is empty
        # (deny all).  This is the key fix for B2: empty ∩ anything = empty.
        return frozenset()
    result: set[Path] = set()
    for p in project_caps:
        for u in user_caps:
            if _is_under_or_equal(p, u):
                # p is under u (or equal) → p is the stricter (or equal) cap.
                result.add(p)
            elif _is_under_or_equal(u, p):
                # u is under p → u is the stricter cap.
                result.add(u)
            # else: disjoint — neither contributes.
    return frozenset(result)


def _canonical_dict(policy: EffectiveSecurityPolicy) -> dict:
    return {
        "mode": policy.mode.value,
        "network_enabled": policy.network_enabled,
        "network_allowed_domains": sorted(policy.network_allowed_domains),
        "network_blocked_domains": sorted(policy.network_blocked_domains),
        "root_capabilities": sorted(str(p) for p in policy.root_capabilities),
        "denied_paths": sorted(policy.denied_paths),
        "commands_allowed": sorted(policy.commands_allowed) if policy.commands_allowed is not None else None,
        "commands_require_approval": sorted(policy.commands_require_approval),
        "commands_blocked": sorted(policy.commands_blocked),
        "secrets_scan_on_output": policy.secrets_scan_on_output,
        # H2: audit + secret-scan fields are part of the binding digest so
        # an approval made under one audit configuration is invalidated if
        # the project later tries to disable audit.
        "audit_enabled": policy.audit_enabled,
        "audit_log_path": policy.audit_log_path,
        "secrets_scan_before_tool_result": policy.secrets_scan_before_tool_result,
        "secrets_block_env_dump": policy.secrets_block_env_dump,
    }


def _compute_digest(policy: EffectiveSecurityPolicy) -> str:
    """sha256 over the canonical (sorted, deterministic) policy representation."""
    payload = json.dumps(_canonical_dict(policy), sort_keys=True).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()
