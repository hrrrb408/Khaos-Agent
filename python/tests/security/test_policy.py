"""Tests for the YAML-driven sandbox policy loader."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from khaos.security.policy import SandboxPolicy, load_policy


def _write_policy(path: Path, content: str) -> Path:
    path.write_text(content, encoding="utf-8")
    return path


def test_load_from_file(tmp_path: Path) -> None:
    """A YAML file is parsed into a SandboxPolicy with the right fields."""
    policy_file = _write_policy(
        tmp_path / "khaos_policy.yaml",
        """
sandbox:
  mode: read-only
  network: true
  allowed_domains: [example.com]
  denied_paths: []
commands:
  require_approval: [rm]
secrets:
  scan_on_output: false
""",
    )
    policy = load_policy(policy_file)

    assert policy.mode == "read-only"
    assert policy.network_enabled is True
    assert policy.network_allowed_domains == ["example.com"]
    assert policy.commands_require_approval == ["rm"]
    assert policy.secrets_scan_on_output is False


def test_default_when_no_file(tmp_path: Path) -> None:
    """A non-existent path returns the safe default policy."""
    policy = load_policy(tmp_path / "does_not_exist.yaml")

    assert policy.mode == "workspace-write"
    assert policy.network_enabled is False
    # Defaults include the standard protected paths.
    assert "~/.ssh" in policy.denied_paths
    assert "git push" in policy.commands_require_approval


def test_explicit_path_takes_priority(tmp_path: Path) -> None:
    """An explicit path wins over the default search locations."""
    explicit = _write_policy(
        tmp_path / "explicit.yaml",
        "sandbox:\n  mode: yolo\n",
    )
    # Even though a khaos_policy.yaml may exist elsewhere, the explicit path wins.
    policy = load_policy(explicit)

    assert policy.mode == "yolo"


def test_mode_workspace_write(tmp_path: Path) -> None:
    """workspace-write is the default mode and loads correctly."""
    policy = load_policy(tmp_path / "none.yaml")

    assert policy.mode == "workspace-write"


def test_network_disabled_by_default(tmp_path: Path) -> None:
    """Network access is off by default for safety."""
    policy = load_policy(tmp_path / "none.yaml")

    assert policy.network_enabled is False
    assert policy.network_allowed_domains == []


def test_denied_paths_expansion(tmp_path: Path) -> None:
    """denied_paths from YAML replace the defaults when provided."""
    policy_file = _write_policy(
        tmp_path / "khaos_policy.yaml",
        """
sandbox:
  denied_paths:
    - "/custom/secret"
    - "~/vault"
""",
    )
    policy = load_policy(policy_file)

    assert "/custom/secret" in policy.denied_paths
    assert "~/vault" in policy.denied_paths
    # Explicit list replaces (does not merge with) the built-in defaults.
    assert "~/.ssh" not in policy.denied_paths


def test_commands_require_approval(tmp_path: Path) -> None:
    """require_approval list is loaded from the commands section."""
    policy_file = _write_policy(
        tmp_path / "khaos_policy.yaml",
        """
commands:
  require_approval:
    - rm
    - docker
""",
    )
    policy = load_policy(policy_file)

    assert policy.commands_require_approval == ["rm", "docker"]
    assert policy.commands_allowed == []
    assert policy.commands_blocked == []


def test_invalid_yaml_fails_closed(tmp_path: Path) -> None:
    """H3: malformed YAML raises rather than degrading to workspace-write.

    A user who breaks YAML while trying to lock down to read-only must see
    the failure at startup, not silently gain write/terminal access.
    """
    policy_file = _write_policy(
        tmp_path / "khaos_policy.yaml",
        "sandbox: [this is : not valid : yaml\n  - broken",
    )
    with pytest.raises(yaml.YAMLError):
        load_policy(policy_file)


def test_empty_yaml_file_uses_defaults(tmp_path: Path) -> None:
    """An empty (or null) YAML file yields the default policy."""
    policy_file = _write_policy(tmp_path / "khaos_policy.yaml", "")
    policy = load_policy(policy_file)

    assert policy.mode == "workspace-write"


def test_top_level_list_yaml_fails_closed(tmp_path: Path) -> None:
    """H1: a valid-but-non-mapping YAML (list at top level) must fail closed.

    Previously ``if not isinstance(data, dict): data = {}`` silently
    degraded to the default ``workspace-write`` policy, so a user who
    mistyped the structure while trying to lock down to read-only would
    silently gain write and terminal access.
    """
    from khaos.security.effective_policy import PolicyCompilationError

    policy_file = _write_policy(
        tmp_path / "khaos_policy.yaml",
        "- sandbox:\n    mode: read-only\n",
    )
    with pytest.raises(PolicyCompilationError, match="mapping"):
        load_policy(policy_file)


def test_top_level_scalar_yaml_fails_closed(tmp_path: Path) -> None:
    """H1: a bare scalar YAML (e.g. ``read-only``) must fail closed.

    A user might write just ``read-only`` intending it as the mode, but
    YAML parses this as a string, not a mapping.  Previously this silently
    degraded to ``workspace-write``.
    """
    from khaos.security.effective_policy import PolicyCompilationError

    policy_file = _write_policy(tmp_path / "khaos_policy.yaml", "read-only\n")
    with pytest.raises(PolicyCompilationError, match="mapping"):
        load_policy(policy_file)


def test_from_dict_rejects_unknown_keys() -> None:
    """H3: unknown top-level keys raise rather than being silently ignored."""
    with pytest.raises(ValueError, match="unknown"):
        SandboxPolicy.from_dict(
            {"unknown_section": {"foo": 1}, "sandbox": {"mode": "read-only"}}
        )


def test_from_dict_rejects_unknown_sandbox_key() -> None:
    """H3: a typo in a sandbox sub-key fails closed."""
    with pytest.raises(ValueError, match="unknown"):
        SandboxPolicy.from_dict({"sandbox": {"mode": "read-only", "colour": "red"}})


# ---- H5: strict scalar type validation through load_policy() ---- #


def test_load_policy_rejects_string_network_value(tmp_path: Path) -> None:
    """H5: ``network: "false"`` is a string and would be truthy in Python.

    Without strict bool validation this would silently enable network
    access.  ``load_policy`` must fail closed at startup.
    """
    from khaos.security.effective_policy import PolicyCompilationError

    policy_file = _write_policy(
        tmp_path / "khaos_policy.yaml",
        'sandbox:\n  mode: read-only\n  network: "false"\n',
    )
    with pytest.raises(PolicyCompilationError, match="sandbox.network must be a boolean"):
        load_policy(policy_file)


def test_load_policy_rejects_string_allowed_paths(tmp_path: Path) -> None:
    """H5: ``allowed_paths: "src"`` is a bare string, not a list of strings.

    Without strict type validation Python would iterate the string
    character-by-character.  ``load_policy`` must fail closed.
    """
    from khaos.security.effective_policy import PolicyCompilationError

    policy_file = _write_policy(
        tmp_path / "khaos_policy.yaml",
        'sandbox:\n  mode: read-only\n  allowed_paths: "src"\n',
    )
    with pytest.raises(PolicyCompilationError, match="must be a list of strings"):
        load_policy(policy_file)


def test_load_policy_rejects_int_audit_enabled(tmp_path: Path) -> None:
    """H5: ``audit.enabled: 1`` is an int, not a bool.

    YAML ``true``/``false`` parse to bool; ``1``/``0`` parse to int.  Reject
    ints so a careless hand-edit cannot silently flip audit state.
    """
    from khaos.security.effective_policy import PolicyCompilationError

    policy_file = _write_policy(
        tmp_path / "khaos_policy.yaml",
        "audit:\n  enabled: 1\n",
    )
    with pytest.raises(PolicyCompilationError, match="audit.enabled must be a boolean"):
        load_policy(policy_file)


def test_load_policy_rejects_string_secrets_flag(tmp_path: Path) -> None:
    """H5: ``secrets.scan_on_output: "true"`` is a string, not a bool."""
    from khaos.security.effective_policy import PolicyCompilationError

    policy_file = _write_policy(
        tmp_path / "khaos_policy.yaml",
        'secrets:\n  scan_on_output: "true"\n',
    )
    with pytest.raises(PolicyCompilationError, match="secrets.scan_on_output must be a boolean"):
        load_policy(policy_file)


def test_load_policy_accepts_well_formed_booleans(tmp_path: Path) -> None:
    """H5 regression guard: real YAML booleans are accepted unchanged."""
    policy_file = _write_policy(
        tmp_path / "khaos_policy.yaml",
        """
sandbox:
  mode: read-only
  network: false
secrets:
  scan_on_output: true
  block_env_dump: false
audit:
  enabled: true
""",
    )
    policy = load_policy(policy_file)
    assert policy.network_enabled is False
    assert policy.secrets_scan_on_output is True
    assert policy.secrets_block_env_dump is False
    assert policy.audit_enabled is True
