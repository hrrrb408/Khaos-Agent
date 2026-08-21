#!/usr/bin/env python3
"""Render the concrete launchd environment for the macOS authority backend.

The checked-in plist is a deployment template. launchd does not read the
frontend's protected configuration file for the backend, so copying that
template unchanged starts a Python daemon without its production identity,
policy, or WORM contract. This renderer is the single composition boundary:
it accepts only the bounded values needed by the backend and writes an
atomic, concrete plist for the authority-owned launchd job.
"""

from __future__ import annotations

import argparse
import os
import plistlib
import re
import tempfile
from pathlib import Path
from urllib.parse import urlsplit


_HEX_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_TEAM_ID = re.compile(r"[A-Za-z0-9]+\Z")
_UID = re.compile(r"[1-9][0-9]*\Z")


def _required_environment(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise SystemExit(f"{name} is required to render the backend plist")
    if any(character in value for character in ("\x00", "\r", "\n")):
        raise SystemExit(f"{name} contains a forbidden control character")
    return value


def _require_match(name: str, value: str, pattern: re.Pattern[str]) -> str:
    if pattern.fullmatch(value) is None:
        raise SystemExit(f"{name} has an invalid format")
    return value


def _require_https_endpoint(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.netloc:
        raise SystemExit("KHAOS_AUDIT_WORM_ENDPOINT must be an HTTPS URL")
    return value


def _require_ca_file(value: str) -> str:
    path = Path(value)
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise SystemExit("KHAOS_AUDIT_WORM_CA_FILE must be an absolute regular file")
    return str(path)


def _backend_environment() -> dict[str, str]:
    team_id = _require_match(
        "KHAOS_TEAM_ID", _required_environment("KHAOS_TEAM_ID"), _TEAM_ID
    )
    policy_digest = _require_match(
        "KHAOS_EFFECTIVE_POLICY_DIGEST",
        _required_environment("KHAOS_EFFECTIVE_POLICY_DIGEST"),
        _HEX_DIGEST,
    )
    authority_uid = _require_match(
        "KHAOS_AUTHORITYD_UID",
        _required_environment("KHAOS_AUTHORITYD_UID"),
        _UID,
    )
    agent_uid = _require_match(
        "KHAOS_AGENT_UID", _required_environment("KHAOS_AGENT_UID"), _UID
    )
    agent_signature = _required_environment("KHAOS_AGENT_CODE_SIGNATURE")
    endpoint = _require_https_endpoint(
        _required_environment("KHAOS_AUDIT_WORM_ENDPOINT")
    )
    ca_file = _require_ca_file(_required_environment("KHAOS_AUDIT_WORM_CA_FILE"))
    agent_requirement = (
        f'identifier "{agent_signature}" and anchor apple generic '
        f"and certificate leaf[subject.OU] = {team_id}"
    )
    service_requirement = (
        'identifier "khaos-authorityd-xpc" and anchor apple generic '
        f"and certificate leaf[subject.OU] = {team_id}"
    )
    return {
        "KHAOS_DEV_MODE": "0",
        "KHAOS_AUTHORITYD_SOCKET": "/var/run/khaos-authorityd/backend.sock",
        "KHAOS_AUTHORITYD_BACKEND_SOCKET": "/var/run/khaos-authorityd/backend.sock",
        "KHAOS_AUTHORITYD_KEY_PATH": "/var/db/khaos-authorityd/authorityd.pem",
        "KHAOS_AUTHORITYD_PUBLIC_KEY_PATH": "/var/run/khaos-authorityd/authorityd.pub",
        "KHAOS_TYPED_RESOURCE_CATALOG_PATH": "/etc/khaos/native-resource-catalog.json",
        "KHAOS_EFFECTIVE_POLICY_DIGEST": policy_digest,
        "KHAOS_AUDIT_WORM_ENDPOINT": endpoint,
        "KHAOS_AUDIT_WORM_CA_FILE": ca_file,
        "KHAOS_AUTHORITYD_UID": authority_uid,
        "KHAOS_AGENT_UID": agent_uid,
        "KHAOS_AUTHORITYD_LAUNCHD_SERVICE": "com.khaos.authorityd",
        "KHAOS_AUTHORITYD_XPC_SERVICE": "com.khaos.authorityd",
        "KHAOS_AUTHORITYD_AGENT_CODE_SIGNATURE": agent_signature,
        "KHAOS_AUTHORITYD_AGENT_CODE_REQUIREMENT": agent_requirement,
        "KHAOS_AUTHORITYD_SERVICE_CODE_SIGNATURE": "khaos-authorityd-xpc",
        "KHAOS_AUTHORITYD_SERVICE_CODE_REQUIREMENT": service_requirement,
        "KHAOS_AUTHORITYD_KEYCHAIN_GROUP": f"{team_id}.com.khaos.authority",
        "KHAOS_AUTHORITYD_PROTECTED_KEY_REF": "khaos-authority-signing-key",
        "KHAOS_AUTHORITYD_CONNECTION_TIMEOUT": "5",
        "KHAOS_AUTHORITYD_MAX_CONNECTIONS": "32",
    }


def render_backend_plist(template: Path, output: Path) -> None:
    """Render and atomically publish a concrete backend launchd plist."""
    try:
        with template.open("rb") as handle:
            document = plistlib.load(handle)
    except (OSError, plistlib.InvalidFileException) as exc:
        raise SystemExit(f"could not read backend plist template: {template}") from exc
    if document.get("Label") != "com.khaos.authorityd.backend":
        raise SystemExit("backend plist template has an unexpected launchd label")
    environment = document.get("EnvironmentVariables")
    if not isinstance(environment, dict):
        raise SystemExit(
            "backend plist template has no EnvironmentVariables dictionary"
        )
    environment.update(_backend_environment())
    if any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in environment.items()
    ):
        raise SystemExit("backend plist environment contains a non-string entry")
    document["EnvironmentVariables"] = environment

    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output.name}.", dir=str(output.parent)
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            plistlib.dump(document, handle, fmt=plistlib.FMT_XML, sort_keys=False)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary_name, 0o600)
        os.replace(temporary_name, output)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--template", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    render_backend_plist(args.template, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
