"""Contracts for hash-pinned Docker outer-profile preflight."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest
from khaos.security import docker_profiles
from khaos.security.docker_profiles import (
    DockerProfileValidationError,
    validate_disposable_environment,
    validate_profile_manifest,
)


def _write_manifest(tmp_path: Path, *, option_overrides: dict[str, str] | None = None) -> tuple[Path, dict[str, str]]:
    seccomp = tmp_path / "seccomp.json"
    apparmor = tmp_path / "khaos-agent.apparmor"
    seccomp.write_text('{"defaultAction":"SCMP_ACT_ERRNO"}\n', encoding="utf-8")
    apparmor.write_text("profile khaos-agent {\n  # test fixture\n}\n", encoding="utf-8")
    os.chmod(seccomp, 0o600)
    os.chmod(apparmor, 0o600)
    options = {
        "seccomp": f"seccomp={seccomp}",
        "apparmor": "apparmor=khaos-agent",
        "systempaths": "systempaths=default",
    }
    if option_overrides:
        options.update(option_overrides)
    manifest = {
        "schema_version": 1,
        "profiles": {
            "seccomp": {
                "option": options["seccomp"],
                "sha256": hashlib.sha256(seccomp.read_bytes()).hexdigest(),
            },
            "apparmor": {
                "option": options["apparmor"],
                "source": str(apparmor),
                "sha256": hashlib.sha256(apparmor.read_bytes()).hexdigest(),
            },
            "systempaths": {"option": options["systempaths"]},
        },
    }
    manifest_path = tmp_path / "profiles.json"
    manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
    os.chmod(manifest_path, 0o600)
    environment = {
        "KHAOS_DOCKER_SECCOMP_OPT": options["seccomp"],
        "KHAOS_DOCKER_APPARMOR_OPT": options["apparmor"],
        "KHAOS_DOCKER_SYSTEMPATHS_OPT": options["systempaths"],
    }
    return manifest_path, environment


def test_profile_manifest_requires_exact_options_and_hashes(tmp_path: Path) -> None:
    manifest, environment = _write_manifest(tmp_path)

    digest = validate_profile_manifest(manifest, environment=environment)

    assert digest == hashlib.sha256(manifest.read_bytes()).hexdigest()


def test_profile_manifest_does_not_treat_windows_mode_bits_as_acl(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest, environment = _write_manifest(tmp_path)
    for path in (
        manifest,
        tmp_path / "seccomp.json",
        tmp_path / "khaos-agent.apparmor",
    ):
        os.chmod(path, 0o666)

    monkeypatch.setattr(docker_profiles, "_POSIX_MODE_BITS_AVAILABLE", False)

    assert validate_profile_manifest(manifest, environment=environment)


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits are unavailable")
def test_profile_manifest_rejects_group_world_writable_manifest(tmp_path: Path) -> None:
    manifest, environment = _write_manifest(tmp_path)
    os.chmod(manifest, 0o666)

    with pytest.raises(DockerProfileValidationError, match="group/world writable"):
        validate_profile_manifest(manifest, environment=environment)


def test_profile_manifest_rejects_source_digest_drift(tmp_path: Path) -> None:
    manifest, environment = _write_manifest(tmp_path)
    source = tmp_path / "seccomp.json"
    source.write_text('{"defaultAction":"SCMP_ACT_ALLOW"}\n', encoding="utf-8")

    with pytest.raises(DockerProfileValidationError, match="SHA-256"):
        validate_profile_manifest(manifest, environment=environment)


def test_profile_manifest_rejects_unconfined_in_production(tmp_path: Path) -> None:
    manifest, environment = _write_manifest(
        tmp_path,
        option_overrides={"systempaths": "systempaths=unconfined"},
    )

    with pytest.raises(DockerProfileValidationError, match="unconfined"):
        validate_profile_manifest(manifest, environment=environment)


def test_disposable_environment_is_explicit_and_scoped() -> None:
    validate_disposable_environment(
        environment={
            "KHAOS_DOCKER_SECCOMP_OPT": "seccomp=unconfined",
            "KHAOS_DOCKER_APPARMOR_OPT": "apparmor=unconfined",
            "KHAOS_DOCKER_SYSTEMPATHS_OPT": "systempaths=unconfined",
        }
    )
