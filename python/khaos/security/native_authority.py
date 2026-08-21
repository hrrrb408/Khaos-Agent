# KHAOS-PRIVILEGED-SPAWN owner=NativeAuthorityAdapter threat-model=native-authority boundary=platform-transport
"""Native authority transports for macOS and Windows production.

The Python process is deliberately only a typed client of these transports.
The native client executable must prove the platform-owned service identity,
the peer identity, the transport ACL, and the protected-key boundary before a
request is accepted.  There is no same-UID Python, Unix-socket, or local
broker fallback on either platform.

Every probe and request is a signed challenge-response (ADR-023): the
adapter generates a fresh 256-bit CSPRNG nonce, the authority backend signs
a canonical attestation covering the nonce and the exact request digest
with its protected Ed25519 key, and the adapter verifies the signature with
the public verification key it owns.  A replayed proof carries a stale
nonce and fails closed.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from khaos.security.authorityd_protocol import (
    AuthorityControlPlaneError,
    Ed25519KeyStore,
)
from khaos.security.identity_isolation import (
    AuthorityIdentityContract,
    IdentityIsolationError,
    read_contract_from_environment,
)
from khaos.security.protocol_boundary import canonical_json_bytes
from khaos.security.windows_native_ffi import (
    assign_process_to_job,
    close_handle,
    create_termination_job,
    terminate_job,
    wait_for_job_terminal,
)

MAX_NATIVE_OUTPUT_BYTES = 64 * 1024
# The native client wraps the raw request into a JSON envelope (escaping
# included) before the message-mode pipe transport; keep the raw request
# well below the pipe frame budget.
MAX_NATIVE_REQUEST_BYTES = 16 * 1024
NATIVE_PROBE_TIMEOUT_SECONDS = 5.0
NATIVE_REQUEST_TIMEOUT_SECONDS = 30.0
# An attestation is produced synchronously inside one request round trip;
# anything older than this window is stale, not fresh proof.
ATTESTATION_MAX_AGE_SECONDS = 120.0
# The fixed inner request the frontend sends for identity probes.
PROBE_INNER_REQUEST = '{"operation":"ping","protocol":1}'


class NativeAuthorityError(IdentityIsolationError):
    """The platform-native authority proof is unavailable or invalid."""


@dataclass
class _OwnedTerminationJob:
    """Idempotent owner for one Windows kill-on-close Job Object."""

    handle: object
    closed: bool = False

    def close(self) -> None:
        if self.closed:
            return
        # Closing a kill-on-close job requests termination but does not by
        # itself prove that every assigned descendant has exited.  Explicitly
        # terminate and wait while the handle is still valid, then release it.
        terminate_job(self.handle)
        if not wait_for_job_terminal(self.handle, 5000):
            raise NativeAuthorityError(
                "native authority Job Object did not reach a terminal state"
            )
        close_handle(self.handle)
        self.closed = True


@dataclass(frozen=True, slots=True)
class NativeAuthorityProof:
    """Machine-produced proof returned by the native transport client.

    The proof binds the full code identity the native transport enforced:
    the peer's designated requirement digest (Team-ID anchored on macOS,
    agent-SID anchored on Windows), the peer Team ID, the code-directory
    hash where the platform exposes it, and the service instance id.  A
    same-UID process with the right identifier but the wrong signing
    identity cannot produce a matching requirement digest.
    """

    platform: str
    transport: str
    service_id: str
    service_pid: int
    service_identity: str
    peer_identity: str
    peer_team_id: str
    peer_cdhash: str
    designated_requirement_digest: str
    service_instance_id: str
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
        expected_requirement_digest: str = "",
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
            "peer_team_id",
            "peer_cdhash",
            "designated_requirement_digest",
            "service_instance_id",
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
                peer_team_id=str(value["peer_team_id"]),
                peer_cdhash=str(value["peer_cdhash"]),
                designated_requirement_digest=str(value["designated_requirement_digest"]),
                service_instance_id=str(value["service_instance_id"]),
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
            or not proof.peer_team_id
            or not proof.designated_requirement_digest
            or not proof.service_instance_id
            or not proof.challenge_digest
            or not proof.peer_verified
            or not proof.transport_verified
            or not proof.protected_key_verified
        ):
            raise NativeAuthorityError("native authority proof does not match the deployment contract")
        if (
            expected_requirement_digest
            and proof.designated_requirement_digest != expected_requirement_digest
        ):
            raise NativeAuthorityError(
                "native authority peer requirement digest does not match the deployment contract"
            )
        return proof


class NativeAuthorityAdapter(Protocol):
    """Typed client contract implemented by a native platform transport."""

    proof: NativeAuthorityProof

    def request(self, payload: dict[str, object]) -> dict[str, object]:
        """Send one authority protocol request over the native transport."""
        ...


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
    """Run a native probe with a bounded protocol, budget, and process tree.

    M6.9 BATCH 7: the previous implementation buffered the entire child
    output via ``communicate()`` and only checked the budget afterwards, so
    an infinite-output or hung native client consumed unbounded memory and
    time.  This version enforces the stdout, stderr, and combined budgets
    *incrementally* (overflow terminates the child's whole process domain
    immediately), covers spawn + IO + wait with one deadline, and terminates
    the domain with SIGTERM -> grace -> SIGKILL (process group on POSIX, a
    kill-on-close Job Object on Windows).  A cleanup failure is an error,
    never a false success.
    """
    environment = {
        "PATH": os.defpath,
        "LC_ALL": "C",
    }
    if extra_environment:
        environment.update(extra_environment)
    job_handle: object | None = None
    process: subprocess.Popen[bytes] | None = None
    overflow = threading.Event()
    collected: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray()}
    try:
        if os.name == "nt":
            job_handle = _create_termination_job()
        process = subprocess.Popen(
            (str(executable), *arguments),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=Path("/"),
            env=environment,
            start_new_session=os.name == "posix",
        )
        if job_handle is not None:
            _assign_process_to_job(job_handle, process.pid)
        readers = {
            "stdout": _spawn_budget_reader(process.stdout, "stdout", collected, overflow),
            "stderr": _spawn_budget_reader(process.stderr, "stderr", collected, overflow),
        }
        writer = _spawn_input_writer(process.stdin, input_bytes)
        try:
            deadline = time.monotonic() + timeout_seconds
            while True:
                if overflow.is_set():
                    raise NativeAuthorityError(
                        "native authority client exceeded output budget"
                    )
                try:
                    process.wait(timeout=0.05)
                    break
                except subprocess.TimeoutExpired:
                    pass
                if time.monotonic() >= deadline:
                    raise NativeAuthorityError(
                        "native authority client exceeded its deadline"
                    )
            for reader in readers.values():
                reader.join(timeout=2.0)
            writer.join(timeout=2.0)
            if writer.is_alive():
                raise NativeAuthorityError(
                    "native authority client stdin writer did not terminate"
                )
            if overflow.is_set():
                raise NativeAuthorityError(
                    "native authority client exceeded output budget"
                )
        except NativeAuthorityError:
            # Budget/deadline violations (NativeAuthorityError is a
            # PermissionError subclass): terminate the domain FIRST so the
            # pipes reach EOF, then briefly drain the readers and re-raise.
            _terminate_process_domain(process, job_handle)
            for reader in readers.values():
                reader.join(timeout=0.5)
            writer.join(timeout=0.5)
            raise
        finally:
            for reader in readers.values():
                reader.join(timeout=0.5)
            writer.join(timeout=0.5)
    except NativeAuthorityError:
        # Re-raised domain violations; termination already happened in the
        # inner handler (or the process exited).
        if process is not None and process.returncode is None:
            _terminate_process_domain(process, job_handle)
        raise
    except (OSError, ValueError) as exc:
        _terminate_process_domain(process, job_handle)
        raise NativeAuthorityError(
            "native authority client could not be executed"
        ) from exc
    finally:
        if process is not None and process.returncode is None:
            # Any exit path that leaves the child alive is a termination
            # failure, never a success.
            _terminate_process_domain(process, job_handle)
        _close_job(job_handle)
    if overflow.is_set():
        raise NativeAuthorityError("native authority client exceeded output budget")
    stdout = bytes(collected["stdout"])
    stderr = bytes(collected["stderr"])
    if len(stdout) > MAX_NATIVE_OUTPUT_BYTES or len(stderr) > MAX_NATIVE_OUTPUT_BYTES:
        raise NativeAuthorityError("native authority client exceeded output budget")
    if process is None or process.returncode is None:
        raise NativeAuthorityError("native authority client termination is unproven")
    if process.returncode != 0:
        detail = stderr.decode("utf-8", errors="replace")[-512:]
        raise NativeAuthorityError(
            f"native authority client rejected request: rc={process.returncode} detail={detail}"
        )
    return stdout


def _spawn_budget_reader(
    stream: IO[bytes] | None,
    name: str,
    collected: dict[str, bytearray],
    overflow: threading.Event,
) -> threading.Thread:
    """Read one stream incrementally, tripping the overflow event on cap."""

    def _read() -> None:
        assert stream is not None
        try:
            while True:
                chunk = stream.read(4096)
                if not chunk:
                    break
                buffer = collected[name]
                buffer.extend(chunk)
                total = len(collected["stdout"]) + len(collected["stderr"])
                if (
                    len(buffer) > MAX_NATIVE_OUTPUT_BYTES
                    or total > MAX_NATIVE_OUTPUT_BYTES * 2
                ):
                    overflow.set()
                    return
        except (OSError, ValueError):
            # A closed pipe after termination is expected; the budget
            # decision is made from what was already read.
            return
        finally:
            try:
                stream.close()
            except OSError:
                pass

    thread = threading.Thread(target=_read, daemon=True, name=f"native-{name}")
    thread.start()
    return thread


def _spawn_input_writer(
    stream: IO[bytes] | None, input_bytes: bytes
) -> threading.Thread:
    """Write and close child stdin off the supervisor's deadline path."""

    def _write() -> None:
        if stream is None:
            return
        try:
            if input_bytes:
                stream.write(input_bytes)
                stream.flush()
        except (BrokenPipeError, OSError):
            # A probe client does not consume stdin and a request client may
            # exit before reading the full frame; both are bounded outcomes.
            pass
        finally:
            try:
                stream.close()
            except OSError:
                pass

    thread = threading.Thread(target=_write, daemon=True, name="native-stdin")
    thread.start()
    return thread


def _terminate_process_domain(
    process: subprocess.Popen[bytes] | None, job_handle: object | None
) -> None:
    """Terminate the child's whole execution domain, SIGTERM -> SIGKILL.

    On POSIX the child is a session leader, so ``os.killpg`` reaches every
    descendant.  On Windows the kill-on-close Job Object terminates the
    whole job when the handle closes; the direct terminate covers the
    window before job assignment.
    """
    if process is None:
        return
    if os.name == "posix":
        import signal as signal_module

        try:
            # ``start_new_session=True`` makes the child PID the process
            # group ID.  Use that stable ID even if the group leader already
            # exited while a descendant still owns one of the pipes.
            os.killpg(process.pid, signal_module.SIGTERM)
        except (OSError, PermissionError):
            if process.returncode is None:
                try:
                    process.terminate()
                except OSError:
                    pass
        if process.returncode is None:
            try:
                process.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                pass
        try:
            os.killpg(process.pid, signal_module.SIGKILL)
        except (OSError, PermissionError):
            pass
        if process.returncode is None:
            try:
                process.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                raise NativeAuthorityError(
                    "native authority client process domain did not terminate"
                )
    else:
        try:
            process.terminate()
            process.wait(timeout=2.0)
        except (OSError, subprocess.TimeoutExpired):
            pass
        if process.returncode is None:
            # Closing the job handle kills everything in the job.
            if job_handle is not None:
                _close_job(job_handle)
            try:
                process.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                raise NativeAuthorityError(
                    "native authority client process domain did not terminate"
                )


def _create_termination_job() -> _OwnedTerminationJob | None:
    """Create a kill-on-close Job Object; failure is never best effort."""
    if os.name != "nt":
        return None
    try:
        return _OwnedTerminationJob(create_termination_job())
    except OSError as exc:
        raise NativeAuthorityError(
            "native authority process domain cannot be owned by a Job Object"
        ) from exc


def _assign_process_to_job(job_handle: _OwnedTerminationJob, pid: int) -> None:
    """Assign a process to the termination job or fail closed."""
    try:
        assign_process_to_job(job_handle.handle, pid)
    except OSError as exc:
        raise NativeAuthorityError(
            "native authority process could not be assigned to its Job Object"
        ) from exc


def _close_job(job_handle: object | None) -> None:
    """Close the Job Object, terminating any remaining assigned processes."""
    if job_handle is None:
        return
    try:
        if not isinstance(job_handle, _OwnedTerminationJob):
            raise NativeAuthorityError("native authority Job Object owner is invalid")
        job_handle.close()
    except OSError as exc:
        raise NativeAuthorityError("native authority Job Object close failed") from exc


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
    expected_requirement_digest: str = ""
    public_key_path: Path = Path("/")
    proof: NativeAuthorityProof

    def _native_environment(self) -> dict[str, str]:
        return {}

    def _load_public_key(self) -> Ed25519PublicKey:
        try:
            return Ed25519KeyStore.load_public_key(self.public_key_path)
        except AuthorityControlPlaneError as exc:
            # "malformed" / "not a regular single-link file" / "unsafe
            # permissions" are deterministic integrity findings, not
            # transient unavailability — conflating them with "unavailable"
            # hid a Windows text-mode truncation bug behind load retries.
            raise NativeAuthorityError(str(exc)) from exc
        except OSError as exc:
            raise NativeAuthorityError(
                "authority public verification key is unavailable"
            ) from exc

    def _verify_attestation(
        self,
        response: dict[str, object],
        *,
        challenge_nonce: str,
        request_bytes: bytes,
        public_key: Ed25519PublicKey,
        expected_instance_id: str | None = None,
    ) -> dict[str, object]:
        """Verify the signed challenge-response for one native round trip."""
        if response.get("ok") is False:
            error_code = response.get("error_code", "native_authority_rejected")
            detail = response.get("error", "native authority rejected the request")
            if not isinstance(error_code, str) or not error_code:
                error_code = "native_authority_rejected"
            if not isinstance(detail, str) or not detail:
                detail = "native authority rejected the request"
            raise NativeAuthorityError(
                f"native authority request rejected: {error_code}: {detail}"
            )
        if response.get("native_transport") != self.expected_transport:
            raise NativeAuthorityError("native authority response transport is unbound")
        attestation = response.get("attestation")
        if not isinstance(attestation, dict):
            raise NativeAuthorityError("native authority attestation is missing")
        if attestation.get("challenge_nonce") != challenge_nonce:
            raise NativeAuthorityError(
                "native authority attestation nonce does not match the challenge"
            )
        expected_digest = hashlib.sha256(request_bytes).hexdigest()
        if attestation.get("request_digest") != expected_digest:
            raise NativeAuthorityError(
                "native authority attestation does not cover this request"
            )
        if attestation.get("platform") != self.expected_platform:
            raise NativeAuthorityError("native authority attestation platform mismatch")
        if attestation.get("transport") != self.expected_transport:
            raise NativeAuthorityError("native authority attestation transport mismatch")
        if attestation.get("service_id") != self.service_id:
            raise NativeAuthorityError("native authority attestation service mismatch")
        if attestation.get("protected_key_ref") != self.protected_key_ref:
            raise NativeAuthorityError(
                "native authority attestation protected key mismatch"
            )
        if (
            self.expected_requirement_digest
            and attestation.get("designated_requirement_digest")
            != self.expected_requirement_digest
        ):
            raise NativeAuthorityError(
                "native authority attestation requirement digest mismatch"
            )
        if expected_instance_id is not None and attestation.get(
            "service_instance_id"
        ) != expected_instance_id:
            raise NativeAuthorityError(
                "native authority attestation service instance changed mid-session"
            )
        issued_at = attestation.get("issued_at")
        if not isinstance(issued_at, int) or issued_at < 0:
            raise NativeAuthorityError("native authority attestation timestamp invalid")
        issued_seconds = issued_at / 1000.0
        if abs(time.time() - issued_seconds) > ATTESTATION_MAX_AGE_SECONDS:
            raise NativeAuthorityError("native authority attestation is stale")
        signature = attestation.get("signature")
        if not isinstance(signature, str) or not signature:
            raise NativeAuthorityError("native authority attestation is unsigned")
        unsigned = {key: value for key, value in attestation.items() if key != "signature"}
        try:
            public_key.verify(
                base64.b64decode(signature.encode("ascii"), validate=True),
                canonical_json_bytes(unsigned),
            )
        except (InvalidSignature, ValueError, UnicodeError) as exc:
            raise NativeAuthorityError(
                "native authority attestation signature is invalid"
            ) from exc
        return attestation

    def _probe(self) -> NativeAuthorityProof:
        challenge = secrets.token_hex(32)
        payload = _decode_native_response(
            _bounded_native_call(
                self.client,
                (
                    "--probe",
                    "--service-id",
                    self.service_id,
                    "--challenge",
                    challenge,
                ),
                timeout_seconds=NATIVE_PROBE_TIMEOUT_SECONDS,
                extra_environment=self._native_environment(),
            )
        )
        attestation = self._verify_attestation(
            payload,
            challenge_nonce=challenge,
            request_bytes=PROBE_INNER_REQUEST.encode("utf-8"),
            public_key=self._load_public_key(),
        )
        # The proof object carries the digest of the challenge nonce this
        # attestation answered; freshness itself is the verified signature.
        # The three *_verified booleans are the verdicts of the checks in
        # _verify_attestation above: the signed peer identity fields (the
        # backend attests the peer it admitted), the transport equality
        # check, and the protected-key-ref equality check.  from_payload()
        # requires all three; omitting them made every real probe fail
        # closed at construction ("fields incomplete").
        proof_payload = {
            "platform": attestation["platform"],
            "transport": attestation["transport"],
            "service_id": attestation["service_id"],
            "service_pid": attestation["service_pid"],
            "service_identity": attestation["service_identity"],
            "peer_identity": attestation["peer_identity"],
            "peer_team_id": attestation["peer_team_id"],
            "peer_cdhash": attestation["peer_cdhash"],
            "designated_requirement_digest": attestation[
                "designated_requirement_digest"
            ],
            "service_instance_id": attestation["service_instance_id"],
            "protected_key_ref": attestation["protected_key_ref"],
            "challenge_digest": hashlib.sha256(
                challenge.encode("ascii")
            ).hexdigest(),
            "peer_verified": True,
            "transport_verified": True,
            "protected_key_verified": True,
        }
        return NativeAuthorityProof.from_payload(
            proof_payload,
            expected_platform=self.expected_platform,
            expected_transport=self.expected_transport,
            expected_service_id=self.service_id,
            expected_key_ref=self.protected_key_ref,
            expected_requirement_digest=self.expected_requirement_digest,
        )

    def request(self, payload: dict[str, object]) -> dict[str, object]:
        encoded = canonical_json_bytes(payload)
        if len(encoded) > MAX_NATIVE_REQUEST_BYTES:
            raise NativeAuthorityError("native authority request is too large")
        challenge = secrets.token_hex(32)
        response = _decode_native_response(
            _bounded_native_call(
                self.client,
                (
                    "--request",
                    "--service-id",
                    self.service_id,
                    "--challenge",
                    challenge,
                ),
                input_bytes=encoded,
                timeout_seconds=NATIVE_REQUEST_TIMEOUT_SECONDS,
                extra_environment=self._native_environment(),
            )
        )
        self._verify_attestation(
            response,
            challenge_nonce=challenge,
            request_bytes=encoded,
            public_key=self._load_public_key(),
            expected_instance_id=self.proof.service_instance_id,
        )
        inner = response.get("response")
        if not isinstance(inner, dict):
            raise NativeAuthorityError("native authority response body is missing")
        return inner


@dataclass(frozen=True, slots=True)
class MacOSLaunchdXPCAdapter(_SubprocessNativeAdapter):
    """Production client for a launchd Mach-service/XPC authority."""

    expected_platform: str = "darwin"
    expected_transport: str = "xpc"
    service_id: str = "com.khaos.authorityd"
    protected_key_ref: str = ""
    client: Path = Path("/")
    expected_requirement_digest: str = ""
    public_key_path: Path = Path("/")

    @classmethod
    def from_contract(cls, contract: AuthorityIdentityContract) -> MacOSLaunchdXPCAdapter:
        if sys.platform != "darwin":
            raise NativeAuthorityError("macOS XPC authority used on a non-macOS platform")
        if not contract.launchd_service or not contract.protected_key_ref or not contract.code_signature:
            raise NativeAuthorityError("macOS XPC authority identity contract is incomplete")
        if not contract.agent_requirement_digest:
            raise NativeAuthorityError(
                "macOS XPC authority requires the designated agent code requirement"
            )
        client_value = os.environ.get("KHAOS_MACOS_AUTHORITY_XPC_CLIENT")
        if not client_value:
            raise NativeAuthorityError("KHAOS_MACOS_AUTHORITY_XPC_CLIENT is missing")
        public_key_value = os.environ.get("KHAOS_AUTHORITYD_PUBLIC_KEY_PATH")
        if not public_key_value:
            raise NativeAuthorityError(
                "KHAOS_AUTHORITYD_PUBLIC_KEY_PATH is required to verify attestations"
            )
        adapter = cls(
            service_id=contract.launchd_service,
            protected_key_ref=contract.protected_key_ref,
            client=_required_absolute_executable(Path(client_value)),
            expected_requirement_digest=contract.agent_requirement_digest,
            public_key_path=Path(public_key_value),
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
    expected_requirement_digest: str = ""
    public_key_path: Path = Path("/")

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
        if not contract.agent_requirement_digest:
            raise NativeAuthorityError(
                "Windows Named Pipe authority requires the agent SID requirement"
            )
        client_value = os.environ.get("KHAOS_WINDOWS_AUTHORITY_PIPE_CLIENT")
        if not client_value:
            raise NativeAuthorityError("KHAOS_WINDOWS_AUTHORITY_PIPE_CLIENT is missing")
        public_key_value = os.environ.get("KHAOS_AUTHORITYD_PUBLIC_KEY_PATH")
        if not public_key_value:
            raise NativeAuthorityError(
                "KHAOS_AUTHORITYD_PUBLIC_KEY_PATH is required to verify attestations"
            )
        adapter = cls(
            service_id=os.environ.get("KHAOS_AUTHORITYD_SERVICE_NAME", "KhaosAuthorityD"),
            protected_key_ref=contract.protected_key_ref,
            client=_required_absolute_executable(Path(client_value)),
            named_pipe=contract.named_pipe,
            agent_sid=contract.agent_sid or "",
            expected_requirement_digest=contract.agent_requirement_digest,
            public_key_path=Path(public_key_value),
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
