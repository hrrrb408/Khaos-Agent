"""Fail-closed validation for Docker's host-controlled outer profiles.

Docker Compose cannot inspect whether a ``security_opt`` value was reviewed.
This module gives deployments a small, deterministic preflight contract:
the exact ``name=value`` options must match a manifest, and seccomp/AppArmor
source files must be regular, non-symlink files whose SHA-256 matches that
manifest.  The disposable composition probe may explicitly opt into
``unconfined`` values, but that mode is never accepted by the production
validator.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

PROFILE_ENVIRONMENT = {
    "seccomp": "KHAOS_DOCKER_SECCOMP_OPT",
    "apparmor": "KHAOS_DOCKER_APPARMOR_OPT",
    "systempaths": "KHAOS_DOCKER_SYSTEMPATHS_OPT",
}
MANIFEST_SCHEMA_VERSION = 1
_SHA256_LENGTH = 64
_POSIX_MODE_BITS_AVAILABLE = os.name != "nt"


class DockerProfileValidationError(ValueError):
    """Raised when a Docker outer-profile attestation is not trustworthy."""


@dataclass(frozen=True)
class DockerProfileSpec:
    """One exact Docker ``security_opt`` declaration from the manifest."""

    option: str
    source: Path | None
    sha256: str | None


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _secure_regular_file(path: Path, *, label: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise DockerProfileValidationError(
            f"{label} is not readable: {path}"
        ) from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise DockerProfileValidationError(
            f"{label} must be a regular non-symlink file: {path}"
        )
    # ``st_mode`` does not expose NTFS DACLs.  On Windows CPython reports
    # synthetic POSIX permission bits for ordinary files, so treating those
    # bits as an ACL oracle would reject every normal temporary/test file
    # before the manifest's semantic and digest checks run.  Docker's
    # production composition is a POSIX deployment boundary; Windows native
    # ACL claims are owned by the native sandbox/service package instead.
    if _POSIX_MODE_BITS_AVAILABLE and metadata.st_mode & 0o022:
        raise DockerProfileValidationError(
            f"{label} must not be group/world writable: {path}"
        )


def _load_json_manifest(path: Path) -> tuple[dict[str, object], str]:
    _secure_regular_file(path, label="profile manifest")
    try:
        raw = path.read_bytes()
        manifest = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DockerProfileValidationError(
            f"profile manifest is not valid UTF-8 JSON: {path}"
        ) from error
    if not isinstance(manifest, dict):
        raise DockerProfileValidationError("profile manifest must be a JSON object")
    return manifest, hashlib.sha256(raw).hexdigest()


def _required_text(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value or any(
        character.isspace() or ord(character) < 0x20 for character in value
    ):
        raise DockerProfileValidationError(f"{label} must be a non-empty token")
    return value


def _validate_sha256(value: object, *, label: str) -> str:
    digest = _required_text(value, label=label).lower()
    if len(digest) != _SHA256_LENGTH or any(
        character not in "0123456789abcdef" for character in digest
    ):
        raise DockerProfileValidationError(f"{label} must be a SHA-256 hex digest")
    return digest


def _parse_profile(
    kind: str,
    raw: object,
    *,
    allow_disposable: bool,
) -> DockerProfileSpec:
    if not isinstance(raw, dict):
        raise DockerProfileValidationError(f"{kind} profile must be an object")
    option = _required_text(raw.get("option"), label=f"{kind}.option")
    prefix = f"{kind}="
    if not option.startswith(prefix):
        raise DockerProfileValidationError(
            f"{kind}.option must use Docker name=value syntax"
        )
    value = option[len(prefix) :]
    if not value:
        raise DockerProfileValidationError(f"{kind}.option has an empty value")
    if value == "unconfined":
        if not allow_disposable:
            raise DockerProfileValidationError(
                f"{kind}=unconfined is permitted only by the disposable probe"
            )
        return DockerProfileSpec(option=option, source=None, sha256=None)

    source_value = raw.get("source")
    source = None
    if source_value is not None:
        source = Path(_required_text(source_value, label=f"{kind}.source"))
        if not source.is_absolute():
            raise DockerProfileValidationError(f"{kind}.source must be absolute")
        _secure_regular_file(source, label=f"{kind} source")

    sha256_value = raw.get("sha256")
    sha256 = None
    if sha256_value is not None:
        sha256 = _validate_sha256(sha256_value, label=f"{kind}.sha256")

    if kind in {"seccomp", "apparmor"}:
        if allow_disposable and source is None and sha256 is None:
            return DockerProfileSpec(option=option, source=None, sha256=None)
        # The option may carry a native absolute host path.  A POSIX-only
        # prefix check would make the production manifest unverifiable on
        # Windows, where the same digest-bearing option is written as a
        # drive-letter path or a UNC path.
        if source is None and Path(value).is_absolute():
            source = Path(value)
            _secure_regular_file(source, label=f"{kind} profile")
        if source is None or sha256 is None:
            raise DockerProfileValidationError(
                f"{kind} must include a hashed source file in production"
            )
        if kind == "seccomp" and value != str(source):
            raise DockerProfileValidationError(
                "seccomp option must point at its manifest source file"
            )
        if _sha256(source) != sha256:
            raise DockerProfileValidationError(
                f"{kind} source SHA-256 does not match the manifest"
            )
    elif kind == "systempaths":
        if value != "default":
            raise DockerProfileValidationError(
                "systempaths must be exactly systempaths=default in production"
            )
        if source is not None or sha256 is not None:
            raise DockerProfileValidationError(
                "systempaths does not accept a source file or digest"
            )
    else:
        raise DockerProfileValidationError(f"unsupported Docker profile kind: {kind}")

    return DockerProfileSpec(option=option, source=source, sha256=sha256)


def _environment_value(environment: Mapping[str, str], kind: str) -> str:
    variable = PROFILE_ENVIRONMENT[kind]
    value = environment.get(variable)
    return _required_text(value, label=variable)


def validate_profile_manifest(
    manifest_path: Path,
    *,
    environment: Mapping[str, str] | None = None,
    allow_disposable: bool = False,
) -> str:
    """Validate an attested production profile and return its file digest."""
    manifest, manifest_digest = _load_json_manifest(manifest_path)
    if manifest.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        raise DockerProfileValidationError(
            f"profile manifest schema_version must be {MANIFEST_SCHEMA_VERSION}"
        )
    raw_profiles = manifest.get("profiles")
    if not isinstance(raw_profiles, dict) or set(raw_profiles) != set(
        PROFILE_ENVIRONMENT
    ):
        raise DockerProfileValidationError(
            "profile manifest must contain exactly seccomp, apparmor, and systempaths"
        )
    values = os.environ if environment is None else environment
    for kind, environment_name in PROFILE_ENVIRONMENT.items():
        spec = _parse_profile(
            kind,
            raw_profiles[kind],
            allow_disposable=allow_disposable,
        )
        if _environment_value(values, kind) != spec.option:
            raise DockerProfileValidationError(
                f"{environment_name} does not match the profile manifest"
            )
    return manifest_digest


def validate_disposable_environment(
    *, environment: Mapping[str, str] | None = None
) -> None:
    """Validate explicit temporary CI options without blessing production use."""
    values = os.environ if environment is None else environment
    for kind, environment_name in PROFILE_ENVIRONMENT.items():
        option = _environment_value(values, kind)
        if not option.startswith(f"{kind}="):
            raise DockerProfileValidationError(
                f"{environment_name} must use Docker name=value syntax"
            )
        _parse_profile(
            kind,
            {"option": option},
            allow_disposable=True,
        )
