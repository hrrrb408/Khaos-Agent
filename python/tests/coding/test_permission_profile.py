from pathlib import Path

import pytest

from khaos.coding.execution import (
    ExecutionRequest,
    FileSystemAccess,
    NetworkPolicy,
    PermissionProfile,
    ResourceBudget,
)


def test_legacy_read_only_request_builds_immutable_profile(tmp_path: Path):
    request = ExecutionRequest(("rg", "needle"), tmp_path, (tmp_path,))

    assert request.permission_profile is not None
    assert request.permission_profile.filesystem is FileSystemAccess.READ_ONLY
    assert request.permission_profile.workspace_roots == (tmp_path.resolve(),)
    assert request.permission_profile.writable_roots == ()
    assert request.permission_profile.network is NetworkPolicy.NONE
    assert "HOME" not in request.permission_profile.environment_keys
    assert Path.home().resolve() / ".ssh" in request.permission_profile.unreadable_roots


def test_workspace_binding_resolves_exact_write_root(tmp_path: Path):
    requested = PermissionProfile(filesystem=FileSystemAccess.WORKSPACE_WRITE)
    resolved = requested.bind_workspace(tmp_path)

    assert resolved.workspace_roots == (tmp_path.resolve(),)
    assert resolved.writable_roots == (tmp_path.resolve(),)
    resolved.validate_resolved()


def test_read_only_binding_never_gains_write_root(tmp_path: Path):
    resolved = PermissionProfile().bind_workspace(tmp_path)

    assert resolved.workspace_roots == (tmp_path.resolve(),)
    assert resolved.writable_roots == ()
    resolved.validate_resolved()


def test_profile_rejects_unknown_schema_version():
    with pytest.raises(ValueError, match="schema version"):
        PermissionProfile(schema_version=2)


def test_profile_rejects_read_only_write_roots(tmp_path: Path):
    with pytest.raises(ValueError, match="read-only"):
        PermissionProfile(
            filesystem=FileSystemAccess.READ_ONLY,
            workspace_roots=(tmp_path,),
            writable_roots=(tmp_path,),
        )


def test_profile_digest_covers_security_relevant_fields(tmp_path: Path):
    base = PermissionProfile(
        filesystem=FileSystemAccess.WORKSPACE_WRITE,
        network=NetworkPolicy.NONE,
        environment_keys=frozenset({"PATH"}),
        resources=ResourceBudget(timeout_seconds=5),
    ).bind_workspace(tmp_path)
    changed = PermissionProfile(
        filesystem=FileSystemAccess.WORKSPACE_WRITE,
        network=NetworkPolicy.NONE,
        environment_keys=frozenset({"PATH", "LANG"}),
        resources=ResourceBudget(timeout_seconds=5),
    ).bind_workspace(tmp_path)

    assert base.digest() != changed.digest()
    assert base.digest() == base.digest()


def test_explicit_profile_is_the_request_authority(tmp_path: Path):
    profile = PermissionProfile(
        filesystem=FileSystemAccess.WORKSPACE_WRITE,
        network=NetworkPolicy.NONE,
        environment_keys=frozenset({"PATH"}),
        resources=ResourceBudget(timeout_seconds=9),
    ).bind_workspace(tmp_path)
    request = ExecutionRequest(
        ("true",),
        tmp_path,
        permission_profile=profile,
        # Conflicting legacy values must be overwritten, never become a
        # second execution authority.
        access_mode="read-only",
        network_policy=NetworkPolicy.LOOPBACK_ONLY,
        budget=ResourceBudget(timeout_seconds=1),
    )

    assert request.access_mode == "workspace-write"
    assert request.network_policy is NetworkPolicy.NONE
    assert request.writable_roots == (tmp_path.resolve(),)
    assert request.allowed_environment_keys == frozenset({"PATH"})
    assert request.budget.timeout_seconds == 9


def test_legacy_field_replace_cannot_downgrade_explicit_network_profile(
    tmp_path: Path,
):
    from dataclasses import replace

    profile = PermissionProfile(
        network=NetworkPolicy.UNRESTRICTED_WITH_APPROVAL
    ).bind_workspace(tmp_path)
    request = ExecutionRequest(("true",), tmp_path, permission_profile=profile)

    replaced = replace(request, network_policy=NetworkPolicy.NONE)

    assert replaced.network_policy is NetworkPolicy.UNRESTRICTED_WITH_APPROVAL
    assert replaced.permission_profile is profile


def test_profile_rejects_workspace_inside_protected_secret_root(tmp_path: Path):
    secret_root = tmp_path / "secrets"
    workspace = secret_root / "repo"
    workspace.mkdir(parents=True)
    profile = PermissionProfile(unreadable_roots=(secret_root,)).bind_workspace(
        workspace
    )

    with pytest.raises(PermissionError, match="protected unreadable"):
        profile.validate_resolved()


def test_explicit_profile_cannot_remove_mandatory_host_secret_roots():
    profile = PermissionProfile(unreadable_roots=())

    assert Path.home().resolve() / ".ssh" in profile.unreadable_roots
    assert Path.home().resolve() / ".aws" in profile.unreadable_roots
