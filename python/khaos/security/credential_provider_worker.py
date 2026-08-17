# KHAOS-PRIVILEGED-SPAWN owner=CredentialProviderWorker threat-model=provider-helper-execution boundary=one-shot-worker-spec
"""One-shot worker for contained credential provider loaders.

The worker is spawned by :class:`khaos.security.credential_provider_host.
CredentialProviderHost` for exactly one provider materialization.  It reads
a single JSON request (``{"spec": ...}``) from stdin, executes the spec,
and writes a single JSON response line to stdout:

``{"ok": true, "environment": {...}}`` or ``{"ok": false, "error": "..."}``.

Provider *specs* are data, not code: the trusted server adapter registers
one of the built-in spec types below, so a hung or misbehaving provider is
a child process the host can SIGTERM/SIGKILL and reap — physical resource
reclamation never requires exiting the trusted runtime process.

Spec types:

* ``constant`` — return a fixed environment mapping.
* ``env`` — read selected variables from the worker environment (the host
  passes exactly the referenced variables through to the child).
* ``command`` — run a fixed helper argv and parse its stdout as a JSON
  environment object (the Keychain/askpass adapter shape), with its own
  command timeout.
* ``sleep`` — deterministic fault injection for killability/chaos tests.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from collections.abc import Mapping

PROVIDER_SPEC_TYPES = frozenset({"constant", "env", "command", "sleep"})

_MAX_SPEC_JSON_BYTES = 16 * 1024
_MAX_COMMAND_OUTPUT_BYTES = 256 * 1024
_MAX_REQUEST_BYTES = 1 * 1024 * 1024
_DEFAULT_COMMAND_TIMEOUT = 30.0


class ProviderSpecError(ValueError):
    """Raised when a provider spec is malformed or unsupported."""


def validate_provider_spec(spec: object) -> dict[str, object]:
    """Validate a host-executable provider spec and return it normalized.

    The broker calls this at registration time so an invalid spec fails
    before any lease can be issued against it.
    """
    if not isinstance(spec, Mapping):
        raise ProviderSpecError("credential provider spec must be a mapping")
    kind = spec.get("type")
    if kind not in PROVIDER_SPEC_TYPES:
        raise ProviderSpecError(
            "credential provider spec type is not supported"
        )
    try:
        encoded = json.dumps(dict(spec))
    except (TypeError, ValueError) as exc:
        raise ProviderSpecError("credential provider spec is not JSON data") from exc
    if len(encoded.encode("utf-8")) > _MAX_SPEC_JSON_BYTES:
        raise ProviderSpecError("credential provider spec exceeds its size bound")
    if kind == "constant":
        _validate_environment_shape(spec.get("environment"))
    elif kind == "env":
        variables = spec.get("variables")
        if not isinstance(variables, Mapping) or not variables:
            raise ProviderSpecError("env provider requires a variable mapping")
        for output_key, source_name in variables.items():
            if not _is_env_name(output_key) or not _is_env_name(source_name):
                raise ProviderSpecError("env provider variable names are invalid")
    elif kind == "command":
        argv = spec.get("argv")
        if not isinstance(argv, (list, tuple)) or not argv:
            raise ProviderSpecError("command provider requires an argv list")
        for part in argv:
            if not isinstance(part, str) or not part or "\x00" in part:
                raise ProviderSpecError("command provider argv is invalid")
        timeout = spec.get("timeout_seconds", _DEFAULT_COMMAND_TIMEOUT)
        if not isinstance(timeout, (int, float)) or not 0 < timeout <= 600:
            raise ProviderSpecError("command provider timeout is invalid")
    else:  # sleep
        seconds = spec.get("seconds")
        if not isinstance(seconds, (int, float)) or not 0 <= seconds <= 86400:
            raise ProviderSpecError("sleep provider duration is invalid")
    return dict(spec)


def environment_passthrough_names(spec: Mapping[str, object]) -> frozenset[str]:
    """Return worker-environment variable names an ``env`` spec reads."""
    if spec.get("type") != "env":
        return frozenset()
    variables = spec.get("variables")
    if not isinstance(variables, Mapping):
        return frozenset()
    return frozenset(str(name) for name in variables.values())


def run_provider_spec(spec: Mapping[str, object]) -> dict[str, str]:
    """Execute one validated spec and return its environment material."""
    kind = spec.get("type")
    if kind == "constant":
        return _validate_environment_shape(spec.get("environment"))
    if kind == "env":
        variables = spec.get("variables")
        if not isinstance(variables, Mapping):
            raise ProviderSpecError("env provider requires a variable mapping")
        material: dict[str, str] = {}
        for output_key, source_name in variables.items():
            value = _read_worker_environment(str(source_name))
            material[str(output_key)] = value
        return material
    if kind == "command":
        raw_argv = spec.get("argv")
        if not isinstance(raw_argv, (list, tuple)) or not raw_argv:
            raise ProviderSpecError("command provider requires an argv list")
        argv = [str(part) for part in raw_argv]
        raw_timeout = spec.get("timeout_seconds", _DEFAULT_COMMAND_TIMEOUT)
        if not isinstance(raw_timeout, (int, float)):
            raise ProviderSpecError("command provider timeout is invalid")
        timeout = float(raw_timeout)
        try:
            completed = subprocess.run(
                argv,
                capture_output=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise ProviderSpecError("provider command timed out") from exc
        except OSError as exc:
            raise ProviderSpecError(f"provider command failed: {exc}") from exc
        if completed.returncode != 0:
            raise ProviderSpecError(
                f"provider command exited with status {completed.returncode}"
            )
        if len(completed.stdout) > _MAX_COMMAND_OUTPUT_BYTES:
            raise ProviderSpecError("provider command output exceeds its bound")
        try:
            payload = json.loads(completed.stdout.decode("utf-8"))
        except (UnicodeError, ValueError) as exc:
            raise ProviderSpecError("provider command output is not JSON") from exc
        return _validate_environment_shape(payload)
    if kind == "sleep":
        raw_seconds = spec.get("seconds", 0)
        if not isinstance(raw_seconds, (int, float)):
            raise ProviderSpecError("sleep provider duration is invalid")
        seconds = float(raw_seconds)
        time.sleep(seconds)
        return {"PROVIDER_SLEPT": f"{seconds:g}"}
    raise ProviderSpecError("credential provider spec type is not supported")


def _read_worker_environment(name: str) -> str:
    import os

    value = os.environ.get(name)
    if value is None:
        raise ProviderSpecError(
            f"env provider variable {name!r} is missing from the worker environment"
        )
    return value


def _validate_environment_shape(environment: object) -> dict[str, str]:
    if not isinstance(environment, Mapping) or not environment:
        raise ProviderSpecError("provider material is empty or malformed")
    normalized: dict[str, str] = {}
    for key, value in environment.items():
        if not _is_env_name(str(key)) or not isinstance(value, str) or not value:
            raise ProviderSpecError("provider material has an invalid entry")
        if "\x00" in value:
            raise ProviderSpecError("provider material contains NUL bytes")
        normalized[str(key)] = value
    return normalized


def _is_env_name(name: object) -> bool:
    return isinstance(name, str) and name.isidentifier() and not name.startswith("_")


def main() -> int:
    request = sys.stdin.buffer.readline(_MAX_REQUEST_BYTES)
    try:
        payload = json.loads(request.decode("utf-8"))
        if not isinstance(payload, Mapping) or "spec" not in payload:
            raise ProviderSpecError("provider host request is malformed")
        environment = run_provider_spec(payload["spec"])
        response: object = {"ok": True, "environment": environment}
    except Exception as exc:  # noqa: BLE001 - the response line is the error channel
        response = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    sys.stdout.buffer.write(
        json.dumps(response, ensure_ascii=False).encode("utf-8") + b"\n"
    )
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
