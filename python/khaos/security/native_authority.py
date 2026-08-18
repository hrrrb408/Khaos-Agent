# KHAOS-PRIVILEGED-SPAWN owner=NativeAuthorityAdapter threat-model=native-authority boundary=platform-transport
"""Native authority transports for macOS and Windows production.

The Python process is deliberately only a typed client of these transports.
The native client executable must prove the platform-owned service identity,
the peer identity, the transport ACL, and the protected-key boundary before a
request is accepted.  There is no same-UID Python, Unix-socket, or local
broker fallback on either platform.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from khaos.security.identity_isolation import (
    AuthorityIdentityContract,
    IdentityIsolationError,
    read_contract_from_environment,
)

MAX_NATIVE_OUTPUT_BYTES = 64 * 1024
NATIVE_PROBE_TIMEOUT_SECONDS = 5.0
NATIVE_REQUEST_TIMEOUT_SECONDS = 30.0


class NativeAuthorityError(IdentityIsolationError):
    """The platform-native authority proof is unavailable or invalid."""


@dataclass(frozen=True, slots=True)
class NativeAuthorityProof:
    """Machine-produced proof returned by the native transport client."""

    platform: str
    transport: str
    service_id: str
    service_pid: int
    service_identity: str
    peer_identity: str
    protected_key_ref: str
    challenge_digest: str
    peer_verified: bool
    transport_verified: bool
    protected_key_verified: bool

    @classmethod
    def from_payload(
        cls,
        value: object,
        *,
        expected_platform: str,
        expected_transport: str,
        expected_service_id: str,
        expected_key_ref: str,
    ) -> NativeAuthorityProof:
        if not isinstance(value, dict):
            raise NativeAuthorityError("native authority proof is not an object")
        required = {
            "platform",
            "transport",
            "service_id",
            "service_pid",
            "service_identity",
            "peer_identity",
            "protected_key_ref",
            "challenge_digest",
            "peer_verified",
            "transport_verified",
            "protected_key_verified",
        }
        if set(value) != required:
            raise NativeAuthorityError("native authority proof fields are incomplete")
        try:
            proof = cls(
                platform=str(value["platform"]),
                transport=str(value["transport"]),
                service_id=str(value["service_id"]),
                service_pid=int(value["service_pid"]),
                service_identity=str(value["service_identity"]),
                peer_identity=str(value["peer_identity"]),
                protected_key_ref=str(value["protected_key_ref"]),
                challenge_digest=str(value["challenge_digest"]),
                peer_verified=value["peer_verified"] is True,
                transport_verified=value["transport_verified"] is True,
                protected_key_verified=value["protected_key_verified"] is True,
            )
        except (TypeError, ValueError) as exc:
            raise NativeAuthorityError("native authority proof values are malformed") from exc
        if (
            proof.platform != expected_platform
            or proof.transport != expected_transport
            or proof.service_id != expected_service_id
            or proof.protected_key_ref != expected_key_ref
            or proof.service_pid <= 0
            or not proof.service_identity
            or not proof.peer_identity
            or not proof.challenge_digest
            or not proof.peer_verified
            or not proof.transport_verified
            or not proof.protected_key_verified
        ):
            raise NativeAuthorityError("native authority proof does not match the deployment contract")
        return proof


class NativeAuthorityAdapter(Protocol):
    """Typed client contract implemented by a native platform transport."""

    proof: NativeAuthorityProof

    def request(self, payload: dict[str, object]) -> dict[str, object]:
        """Send one authority protocol request over the native transport."""


def _required_absolute_executable(path: Path) -> Path:
    if not path.is_absolute():
        raise NativeAuthorityError("native authority client path must be absolute")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise NativeAuthorityError("native authority client is unavailable") from exc
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise NativeAuthorityError("native authority client is not executable")
    return resolved


def _bounded_native_call(
    executable: Path,
    arguments: tuple[str, ...],
    *,
    input_bytes: bytes = b"",
    timeout_seconds: float,
    extra_environment: dict[str, str] | None = None,
) -> bytes:
    """Run a native probe with a bounded protocol and output budget."""
    environment = {
        "PATH": os.defpath,
        "LC_ALL": "C",
    }
    if extra_environment:
        environment.update(extra_environment)
    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen(
            (str(executable), *arguments),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=Path("/"),
            env=environment,
        )
        stdout, stderr = process.communicate(input=input_bytes, timeout=timeout_seconds)
    except (OSError, subprocess.TimeoutExpired) as exc:
        if process is not None:
            try:
                process.kill()
                process.wait(timeout=2)
            except (OSError, subprocess.TimeoutExpired):
                pass
        raise NativeAuthorityError("native authority client did not terminate") from exc
    if len(stdout) > MAX_NATIVE_OUTPUT_BYTES or len(stderr) > MAX_NATIVE_OUTPUT_BYTES:
        raise NativeAuthorityError("native authority client exceeded output budget")
    if process.returncode != 0:
        detail = stderr.decode("utf-8", errors="replace")[-512:]
        raise NativeAuthorityError(
            f"native authority client rejected request: rc={process.returncode} detail={detail}"
        )
    return stdout


def _decode_native_response(raw: bytes) -> dict[str, object]:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NativeAuthorityError("native authority response is malformed JSON") from exc
    if not isinstance(value, dict):
        raise NativeAuthorityError("native authority response is not an object")
    return value


class _SubprocessNativeAdapter:
    expected_platform: str
    expected_transport: str
    service_id: str
    protected_key_ref: str
    client: Path
    proof: NativeAuthorityProof

    def _native_environment(self) -> dict[str, str]:
        return {}

    def _probe(self) -> NativeAuthorityProof:
        payload = _decode_native_response(
            _bounded_native_call(
                self.client,
                ("--probe", "--service-id", self.service_id),
                timeout_seconds=NATIVE_PROBE_TIMEOUT_SECONDS,
                extra_environment=self._native_environment(),
            )
        )
        return NativeAuthorityProof.from_payload(
            payload,
            expected_platform=self.expected_platform,
            expected_transport=self.expected_transport,
            expected_service_id=self.service_id,
            expected_key_ref=self.protected_key_ref,
        )

    def request(self, payload: dict[str, object]) -> dict[str, object]:
        encoded = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        if len(encoded) > MAX_NATIVE_OUTPUT_BYTES:
            raise NativeAuthorityError("native authority request is too large")
        response = _decode_native_response(
            _bounded_native_call(
                self.client,
                ("--request", "--service-id", self.service_id),
                input_bytes=encoded,
                timeout_seconds=NATIVE_REQUEST_TIMEOUT_SECONDS,
                extra_environment=self._native_environment(),
            )
        )
        if response.get("native_transport") != self.expected_transport:
            raise NativeAuthorityError("native authority response transport is unbound")
        if response.get("proof_digest") != self.proof.challenge_digest:
            raise NativeAuthorityError("native authority response proof is stale")
        return response


@dataclass(frozen=True, slots=True)
class MacOSLaunchdXPCAdapter(_SubprocessNativeAdapter):
    """Production client for a launchd Mach-service/XPC authority."""

    expected_platform: str = "darwin"
    expected_transport: str = "xpc"
    service_id: str = "com.khaos.authorityd"
    protected_key_ref: str = ""
    client: Path = Path("/")

    @classmethod
    def from_contract(cls, contract: AuthorityIdentityContract) -> MacOSLaunchdXPCAdapter:
        if sys.platform != "darwin":
            raise NativeAuthorityError("macOS XPC authority used on a non-macOS platform")
        if not contract.launchd_service or not contract.protected_key_ref or not contract.code_signature:
            raise NativeAuthorityError("macOS XPC authority identity contract is incomplete")
        client_value = os.environ.get("KHAOS_MACOS_AUTHORITY_XPC_CLIENT")
        if not client_value:
            raise NativeAuthorityError("KHAOS_MACOS_AUTHORITY_XPC_CLIENT is missing")
        adapter = cls(
            service_id=contract.launchd_service,
            protected_key_ref=contract.protected_key_ref,
            client=_required_absolute_executable(Path(client_value)),
        )
        object.__setattr__(adapter, "proof", adapter._probe())
        return adapter


@dataclass(frozen=True, slots=True)
class WindowsServiceNamedPipeAdapter(_SubprocessNativeAdapter):
    """Production client for a Service-SID protected Named Pipe authority."""

    expected_platform: str = "win32"
    expected_transport: str = "named-pipe"
    service_id: str = "KhaosAuthorityD"
    protected_key_ref: str = ""
    client: Path = Path("/")
    named_pipe: str = ""
    agent_sid: str = ""

    def _native_environment(self) -> dict[str, str]:
        return {
            "KHAOS_AUTHORITYD_NAMED_PIPE": self.named_pipe,
            "KHAOS_AGENT_SID": self.agent_sid,
        }

    @classmethod
    def from_contract(cls, contract: AuthorityIdentityContract) -> WindowsServiceNamedPipeAdapter:
        if sys.platform != "win32":
            raise NativeAuthorityError("Windows Named Pipe authority used on a non-Windows platform")
        if not contract.service_sid or not contract.named_pipe or not contract.protected_key_ref:
            raise NativeAuthorityError("Windows Named Pipe authority identity contract is incomplete")
        client_value = os.environ.get("KHAOS_WINDOWS_AUTHORITY_PIPE_CLIENT")
        if not client_value:
            raise NativeAuthorityError("KHAOS_WINDOWS_AUTHORITY_PIPE_CLIENT is missing")
        adapter = cls(
            service_id=os.environ.get("KHAOS_AUTHORITYD_SERVICE_NAME", "KhaosAuthorityD"),
            protected_key_ref=contract.protected_key_ref,
            client=_required_absolute_executable(Path(client_value)),
            named_pipe=contract.named_pipe,
            agent_sid=contract.agent_sid or "",
        )
        object.__setattr__(adapter, "proof", adapter._probe())
        return adapter


def build_native_authority_adapter(
    *,
    production: bool,
    contract: AuthorityIdentityContract | None = None,
) -> NativeAuthorityAdapter:
    """Build and probe the only supported non-Linux authority transport."""
    if not production:
        raise NativeAuthorityError("development mode cannot create a production native authority")
    identity = contract or read_contract_from_environment()
    if sys.platform == "darwin":
        return MacOSLaunchdXPCAdapter.from_contract(identity)
    if sys.platform == "win32":
        return WindowsServiceNamedPipeAdapter.from_contract(identity)
    raise NativeAuthorityError("no native macOS/Windows authority transport applies")


__all__ = [
    "MacOSLaunchdXPCAdapter",
    "NativeAuthorityAdapter",
    "NativeAuthorityError",
    "NativeAuthorityProof",
    "WindowsServiceNamedPipeAdapter",
    "build_native_authority_adapter",
]
