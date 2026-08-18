# KHAOS-PRIVILEGED-SPAWN owner=CredentialProviderWorker threat-model=provider-helper-execution boundary=one-shot-worker-spec
"""One-shot worker for contained credential provider loaders.

The worker is spawned by :class:`khaos.security.credential_provider_host.
CredentialProviderHost` for exactly one provider materialization.  It reads
a single JSON request (``{"spec": ..., "untrusted_roots": [...]}``) from
stdin, executes the spec, and writes a single JSON response line to stdout:

``{"ok": true, "environment": {...}, "helper_identity": {...}}`` or
``{"ok": false, "error": "..."}``.

The worker depends on the Python standard library only, and the host
launches it with ``-I -S`` from an absolute canonical script path with a
trusted cwd and no inherited ``PYTHONPATH`` — a malicious repository cwd
cannot poison its imports (M5.6: No Untrusted Resolution Before Privileged
Spawn).

Provider *specs* are data, not code.  Helper commands must name an
absolute, canonical, executable file that does not resolve beneath any
untrusted root (model-writable workspaces); the resolved kernel object is
what gets executed.  Helper output is bounded *while it runs*: stdout,
stderr, and their combined total are capped by streaming counters, and a
breach terminates the helper immediately instead of accumulating unbounded
bytes until exit.

Spec types:

* ``constant`` — return a fixed environment mapping.
* ``env`` — read selected variables from the worker environment (the host
  passes exactly the referenced variables through to the child).
* ``command`` — run a fixed helper argv and parse its stdout as a JSON
  environment object (the Keychain/askpass adapter shape), with its own
  command timeout, streaming output budgets, and rlimits.
* ``sleep`` — deterministic fault injection for killability/chaos tests.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from collections.abc import Mapping
from pathlib import Path

PROVIDER_SPEC_TYPES = frozenset({"constant", "env", "command", "sleep"})

_MAX_SPEC_JSON_BYTES = 16 * 1024
_MAX_COMMAND_OUTPUT_BYTES = 256 * 1024
_MAX_COMMAND_COMBINED_BYTES = 512 * 1024
_MAX_REQUEST_BYTES = 1 * 1024 * 1024
_DEFAULT_COMMAND_TIMEOUT = 30.0
_HELPER_SIGTERM_GRACE = 1.0
_HELPER_SIGKILL_GRACE = 5.0
_HELPER_RLIMIT_AS_BYTES = 1024 * 1024 * 1024
_HELPER_READ_CHUNK_BYTES = 64 * 1024


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
        if not os.path.isabs(str(argv[0])):
            raise ProviderSpecError(
                "command provider argv[0] must be an absolute executable path"
            )
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


def resolve_helper_executable(
    argv0: str, untrusted_roots: list[str]
) -> tuple[str, dict[str, object]]:
    """Resolve argv[0] to a canonical trusted executable identity.

    Implements the spawn half of *No Untrusted Resolution Before Privileged
    Spawn*: no PATH lookup (absolute only), the canonical realpath must be
    an executable regular file, it must not resolve beneath any untrusted
    root, and the returned identity (dev/inode/mode) describes exactly the
    kernel object that will be executed.
    """
    raw = Path(argv0)
    if not raw.is_absolute():
        raise ProviderSpecError(
            "command provider executable must be an absolute path"
        )
    canonical = Path(os.path.realpath(str(raw)))
    try:
        info = canonical.stat()
    except OSError as exc:
        raise ProviderSpecError(
            f"command provider executable is unavailable: {exc}"
        ) from exc
    if not os.path.isfile(canonical) or not os.access(canonical, os.X_OK):
        raise ProviderSpecError(
            "command provider executable is not an executable regular file"
        )
    import stat as stat_module

    if not stat_module.S_ISREG(info.st_mode):
        raise ProviderSpecError(
            "command provider executable is not a regular file"
        )
    for root in untrusted_roots:
        if not isinstance(root, str) or not root:
            continue
        root_real = Path(os.path.realpath(root))
        if _is_within(canonical, root_real):
            raise ProviderSpecError(
                "command provider executable resolves beneath an untrusted root"
            )
    identity = {
        "path": str(canonical),
        "device": info.st_dev,
        "inode": info.st_ino,
        "mode": oct(stat_module.S_IMODE(info.st_mode)),
    }
    return str(canonical), identity


def _is_within(child: Path, ancestor: Path) -> bool:
    try:
        child.relative_to(ancestor)
    except ValueError:
        return False
    return True


def run_provider_spec(
    spec: Mapping[str, object], untrusted_roots: list[str] | None = None
) -> tuple[dict[str, str], dict[str, object] | None]:
    """Execute one validated spec; return material plus helper identity."""
    kind = spec.get("type")
    if kind == "constant":
        return _validate_environment_shape(spec.get("environment")), None
    if kind == "env":
        variables = spec.get("variables")
        if not isinstance(variables, Mapping):
            raise ProviderSpecError("env provider requires a variable mapping")
        material: dict[str, str] = {}
        for output_key, source_name in variables.items():
            material[str(output_key)] = _read_worker_environment(str(source_name))
        return material, None
    if kind == "command":
        raw_argv = spec.get("argv")
        if not isinstance(raw_argv, (list, tuple)) or not raw_argv:
            raise ProviderSpecError("command provider requires an argv list")
        raw_timeout = spec.get("timeout_seconds", _DEFAULT_COMMAND_TIMEOUT)
        if not isinstance(raw_timeout, (int, float)):
            raise ProviderSpecError("command provider timeout is invalid")
        executable, identity = resolve_helper_executable(
            str(raw_argv[0]), untrusted_roots or []
        )
        argv = [executable, *[str(part) for part in raw_argv[1:]]]
        stdout = _run_bounded_helper(argv, float(raw_timeout))
        try:
            payload = json.loads(stdout.decode("utf-8"))
        except (UnicodeError, ValueError) as exc:
            raise ProviderSpecError("provider command output is not JSON") from exc
        return _validate_environment_shape(payload), identity
    if kind == "sleep":
        raw_seconds = spec.get("seconds", 0)
        if not isinstance(raw_seconds, (int, float)):
            raise ProviderSpecError("sleep provider duration is invalid")
        seconds = float(raw_seconds)
        time.sleep(seconds)
        return {"PROVIDER_SLEPT": f"{seconds:g}"}, None
    raise ProviderSpecError("credential provider spec type is not supported")


def _run_bounded_helper(argv: list[str], timeout: float) -> bytes:
    """Run one helper with streaming output budgets and rlimits.

    Output is bounded *while the helper runs*: two reader threads count and
    retain at most the first budgeted bytes of each stream; any per-stream
    or combined breach terminates the helper immediately, so a flooding
    helper can never force unbounded worker memory.  A wall-clock timeout
    and POSIX rlimits bound CPU time and address space.
    """
    preexec = _helper_rlimit_preexec(timeout) if os.name == "posix" else None
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            preexec_fn=preexec,
        )
    except OSError as exc:
        raise ProviderSpecError(f"provider command failed: {exc}") from exc

    stdout_buffer = bytearray()
    stderr_buffer = bytearray()
    counters = {"total": 0}
    breached = threading.Event()

    def _drain(stream, buffer: bytearray) -> None:
        while True:
            chunk = stream.read(_HELPER_READ_CHUNK_BYTES)
            if not chunk:
                return
            counters["total"] += len(chunk)
            if len(buffer) < _MAX_COMMAND_OUTPUT_BYTES:
                buffer.extend(chunk[: _MAX_COMMAND_OUTPUT_BYTES - len(buffer)])
            if (
                counters["total"] > _MAX_COMMAND_COMBINED_BYTES
                or len(buffer) >= _MAX_COMMAND_OUTPUT_BYTES
            ):
                breached.set()
                return

    readers = [
        threading.Thread(target=_drain, args=(process.stdout, stdout_buffer), daemon=True),
        threading.Thread(target=_drain, args=(process.stderr, stderr_buffer), daemon=True),
    ]
    for reader in readers:
        reader.start()
    try:
        deadline = time.monotonic() + timeout
        while True:
            try:
                process.wait(timeout=0.05)
                break
            except subprocess.TimeoutExpired:
                pass
            if breached.is_set():
                _terminate_helper(process)
                raise ProviderSpecError(
                    "provider command exceeded its streaming output budget"
                )
            if time.monotonic() > deadline:
                _terminate_helper(process)
                raise ProviderSpecError("provider command timed out")
    finally:
        _terminate_helper(process)
        for reader in readers:
            reader.join(timeout=_HELPER_SIGKILL_GRACE)
    if process.returncode != 0:
        raise ProviderSpecError(
            f"provider command exited with status {process.returncode}"
        )
    return bytes(stdout_buffer)


def _terminate_helper(process: subprocess.Popen) -> None:
    """Best-effort TERM → KILL ladder for one helper process."""
    if process.poll() is not None:
        return
    try:
        process.terminate()
    except OSError:
        pass
    try:
        process.wait(timeout=_HELPER_SIGTERM_GRACE)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        process.kill()
    except OSError:
        pass
    try:
        process.wait(timeout=_HELPER_SIGKILL_GRACE)
    except subprocess.TimeoutExpired:
        pass


def _helper_rlimit_preexec(timeout: float):
    def _apply() -> None:
        import resource

        try:
            resource.setrlimit(
                resource.RLIMIT_AS, (_HELPER_RLIMIT_AS_BYTES, _HELPER_RLIMIT_AS_BYTES)
            )
        except (OSError, ValueError):
            pass
        cpu_seconds = max(1, int(timeout) + 10)
        try:
            resource.setrlimit(
                resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds + 5)
            )
        except (OSError, ValueError):
            pass

    return _apply


def _read_worker_environment(name: str) -> str:
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
        untrusted_roots_raw = payload.get("untrusted_roots", [])
        if not isinstance(untrusted_roots_raw, list) or any(
            not isinstance(item, str) for item in untrusted_roots_raw
        ):
            raise ProviderSpecError("provider host request roots are malformed")
        environment, helper_identity = run_provider_spec(
            payload["spec"], untrusted_roots_raw
        )
        response: object = {
            "ok": True,
            "environment": environment,
            "helper_identity": helper_identity,
        }
    except Exception as exc:  # noqa: BLE001 - the response line is the error channel
        response = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    sys.stdout.buffer.write(
        json.dumps(response, ensure_ascii=False).encode("utf-8") + b"\n"
    )
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
