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
