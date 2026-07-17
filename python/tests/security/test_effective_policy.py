"""Unit tests for EffectiveSecurityPolicy compilation (H3).

These tests prove the compiler enforces the "only tighten" lattice:
user ∩ project ∩ platform, with fail-closed handling of unknown modes,
unknown fields, and type errors.  They also verify ``allowed_paths`` compiles
to root capabilities and that ``commands_require_approval`` survives into the
effective policy (so the wiring commit can enforce it).
"""

from pathlib import Path

import pytest

from khaos.security.effective_policy import (
    EffectiveSecurityPolicy,
    PlatformCapability,
    PolicyCompilationError,
    compile_effective_policy,
    validate_policy_dict,
)
from khaos.security.policy import SandboxPolicy
from khaos.security.sandbox import SandboxMode


def _policy(mode="workspace-write", **kw) -> SandboxPolicy:
    base = SandboxPolicy()
    return SandboxPolicy(
        mode=mode,
        network_enabled=kw.get("network_enabled", base.network_enabled),
        network_allowed_domains=kw.get(
            "network_allowed_domains", base.network_allowed_domains
        ),
        network_blocked_domains=kw.get(
            "network_blocked_domains", base.network_blocked_domains
        ),
        allowed_paths=kw.get("allowed_paths", base.allowed_paths),
        denied_paths=kw.get("denied_paths", base.denied_paths),
        commands_allowed=kw.get("commands_allowed", base.commands_allowed),
        commands_require_approval=kw.get(
            "commands_require_approval", base.commands_require_approval
        ),
        commands_blocked=kw.get("commands_blocked", base.commands_blocked),
        secrets_scan_on_output=kw.get(
            "secrets_scan_on_output", base.secrets_scan_on_output
        ),
    )


def test_project_only_defaults_to_workspace_write(tmp_path):
    eff = compile_effective_policy(
        _policy("workspace-write"), workspace_root=tmp_path
    )
    assert eff.mode == SandboxMode.WORKSPACE_WRITE
    # allowed_paths ["."] → the workspace root itself.
    assert tmp_path.resolve() in eff.root_capabilities


def test_user_can_only_tighten_project(tmp_path):
    """user read-only + project workspace-write → effective read-only."""
    eff = compile_effective_policy(
        _policy("workspace-write"),
        workspace_root=tmp_path,
        user_policy=_policy("read-only"),
    )
    assert eff.mode == SandboxMode.READ_ONLY


def test_project_cannot_relax_user(tmp_path):
    """user workspace-write + project yolo → effective workspace-write."""
    eff = compile_effective_policy(
        _policy("yolo"),
        workspace_root=tmp_path,
        user_policy=_policy("workspace-write"),
    )
    assert eff.mode == SandboxMode.WORKSPACE_WRITE


def test_platform_capability_clamps(tmp_path):
    eff = compile_effective_policy(
        _policy("yolo"),
        workspace_root=tmp_path,
        platform_capability=PlatformCapability(max_mode=SandboxMode.READ_ONLY),
    )
    assert eff.mode == SandboxMode.READ_ONLY


def test_unknown_mode_fails_closed(tmp_path):
    with pytest.raises(PolicyCompilationError, match="not one of"):
        compile_effective_policy(
            _policy("super-yolo"), workspace_root=tmp_path
        )


def test_unknown_mode_in_user_fails_closed(tmp_path):
    with pytest.raises(PolicyCompilationError, match="user"):
        compile_effective_policy(
            _policy("workspace-write"),
            workspace_root=tmp_path,
            user_policy=_policy("read-onlyy"),
        )


def test_allowed_paths_compiled_to_root_capabilities(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "docs").mkdir()
    eff = compile_effective_policy(
        _policy("workspace-write", allowed_paths=["src", "docs"]),
        workspace_root=tmp_path,
    )
    caps = eff.root_capabilities
    assert (tmp_path / "src").resolve() in caps
    assert (tmp_path / "docs").resolve() in caps
    # An entry outside the workspace root is dropped (cannot be relaxed).
    outside = tmp_path.parent / "outside"
    eff2 = compile_effective_policy(
        _policy("workspace-write", allowed_paths=[str(outside), "src"]),
        workspace_root=tmp_path,
    )
    assert (tmp_path / "src").resolve() in eff2.root_capabilities
    assert outside.resolve() not in eff2.root_capabilities


def test_commands_require_approval_unioned(tmp_path):
    eff = compile_effective_policy(
        _policy(
            "workspace-write",
            commands_require_approval=["rm", "git push"],
        ),
        workspace_root=tmp_path,
        user_policy=_policy(
            "workspace-write", commands_require_approval=["docker"]
        ),
    )
    assert {"rm", "git push", "docker"} <= eff.commands_require_approval


def test_network_enabled_requires_both_layers(tmp_path):
    eff = compile_effective_policy(
        _policy("workspace-write", network_enabled=True),
        workspace_root=tmp_path,
        user_policy=_policy("workspace-write", network_enabled=False),
    )
    assert eff.network_enabled is False


def test_denied_paths_unioned(tmp_path):
    eff = compile_effective_policy(
        _policy("workspace-write", denied_paths=["/etc/shadow"]),
        workspace_root=tmp_path,
        user_policy=_policy("workspace-write", denied_paths=["/etc/passwd"]),
    )
    assert "/etc/shadow" in eff.denied_paths
    assert "/etc/passwd" in eff.denied_paths


def test_digest_is_stable_and_deterministic(tmp_path):
    eff1 = compile_effective_policy(_policy("read-only"), workspace_root=tmp_path)
    eff2 = compile_effective_policy(_policy("read-only"), workspace_root=tmp_path)
    assert eff1.digest == eff2.digest
    assert len(eff1.digest) == 64  # sha256 hex
    assert eff1.to_binding() == f"policy:{eff1.digest}"


def test_digest_differs_for_different_policies(tmp_path):
    eff1 = compile_effective_policy(
        _policy("read-only"), workspace_root=tmp_path
    )
    eff2 = compile_effective_policy(
        _policy("workspace-write"), workspace_root=tmp_path
    )
    assert eff1.digest != eff2.digest


def test_immutable_frozen_sets(tmp_path):
    eff = compile_effective_policy(_policy("read-only"), workspace_root=tmp_path)
    with pytest.raises(AttributeError):
        eff.denied_paths = frozenset({"x"})  # type: ignore[misc]
    with pytest.raises(AttributeError):
        eff.mode = SandboxMode.YOLO  # type: ignore[misc]


# ---- validate_policy_dict (fail closed on unknown fields / bad types) ---- #


def test_validate_rejects_unknown_top_level_key():
    with pytest.raises(PolicyCompilationError, match="unknown top-level"):
        validate_policy_dict({"sandbox": {"mode": "read-only"}, "oops": {}})


def test_validate_rejects_unknown_sandbox_key():
    with pytest.raises(PolicyCompilationError, match="unknown keys"):
        validate_policy_dict({"sandbox": {"mode": "read-only", "colour": "red"}})


def test_validate_rejects_non_list_allowed_paths():
    with pytest.raises(PolicyCompilationError, match="list of strings"):
        validate_policy_dict({"sandbox": {"allowed_paths": "src"}})


def test_validate_rejects_non_string_in_require_approval():
    with pytest.raises(PolicyCompilationError, match="list of strings"):
        validate_policy_dict({"commands": {"require_approval": ["rm", 42]}})


def test_validate_accepts_well_formed_policy():
    validate_policy_dict(
        {
            "sandbox": {
                "mode": "read-only",
                "network": False,
                "allowed_paths": ["src"],
                "denied_paths": ["/etc/shadow"],
            },
            "commands": {"require_approval": ["rm"]},
            "secrets": {"scan_on_output": True},
            "audit": {"enabled": True},
        }
    )  # no raise


def test_missing_user_policy_installs_safe_default_layer(tmp_path):
    """B2: a missing user policy file must NOT let the project self-elevate.

    Previously ``load_effective_policy`` set ``user_policy = None`` when
    ``~/.khaos/policy.yaml`` did not exist, and ``PlatformCapability``
    defaulted to ``YOLO`` — so an untrusted repo with ``mode: yolo`` became
    its own security authority.  Now the safe ``default_user_policy()``
    baseline is installed as the user layer, and ``PlatformCapability``
    defaults to ``WORKSPACE_WRITE``.
    """
    from khaos.security.effective_policy import (
        default_user_policy,
        load_effective_policy,
    )
    from khaos.security.sandbox import SandboxMode

    # Project tries to elevate to yolo + network.
    project_policy = tmp_path / "khaos_policy.yaml"
    project_policy.write_text(
        "sandbox:\n  mode: yolo\n  network: true\n", encoding="utf-8"
    )
    # User policy path does not exist — B2 must install the safe default.
    eff = load_effective_policy(
        tmp_path,
        user_policy_path=tmp_path / "nonexistent_user_policy.yaml",
    )
    # The effective mode must be clamped to WORKSPACE_WRITE (the platform
    # default), NOT yolo — the project cannot self-elevate.
    assert eff.mode == SandboxMode.WORKSPACE_WRITE
    # Network must be off — the default user layer has network off, and
    # network requires BOTH layers to enable it.
    assert eff.network_enabled is False


def test_default_platform_capability_is_workspace_write():
    """B2: ``PlatformCapability`` defaults to WORKSPACE_WRITE, not YOLO.

    This prevents an untrusted project from elevating to YOLO/FULL_ACCESS
    when no explicit platform capability is provided.
    """
    cap = PlatformCapability()
    assert cap.max_mode == SandboxMode.WORKSPACE_WRITE


def test_default_user_policy_is_safe_baseline():
    """B2: ``default_user_policy()`` returns a workspace-write, network-off policy."""
    from khaos.security.effective_policy import default_user_policy

    policy = default_user_policy()
    assert policy.mode == "workspace-write"
    assert policy.network_enabled is False
