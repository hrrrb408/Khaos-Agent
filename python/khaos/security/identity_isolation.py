"""OS identity and transport contracts for the authority control plane.

The checks here are admission gates, not a claim that Python can emulate
launchd/XPC, Windows service SIDs, or a root-owned Linux service.  Production
startup must supply the platform-native identity proof; missing proof is a
refusal to execute.
"""

from __future__ import annotations

import os
import socket
import stat
import struct
from dataclasses import dataclass
from pathlib import Path


class IdentityIsolationError(PermissionError):
    """The authority transport does not have an independent OS identity."""


@dataclass(frozen=True, slots=True)
class AuthorityIdentityContract:
    """Deployment-provided identity handles for agent, authority, and jobs."""

    agent_uid: int | None
    authority_uid: int | None
    job_uid: int | None
    launchd_service: str | None = None
    code_signature: str | None = None
    keychain_access_group: str | None = None
    service_sid: str | None = None
    agent_sid: str | None = None
    named_pipe: str | None = None
    protected_key_ref: str | None = None
    agent_requirement_digest: str | None = None

    def validate(
        self,
        *,
        production: bool,
        transport: str | None = None,
        profile: str | None = None,
    ) -> None:
        """Validate the identity contract for a selected deployment.

        ``transport=None`` preserves the legacy platform-native validation
        used by callers that have not selected a profile.  The explicit
        ``unix`` + ``community`` combination is the supported same-user
        macOS/POSIX profile: it still requires a private socket and kernel
        peer credentials at the daemon boundary, but it deliberately does not
        pretend that an Apple code signature or a second OS identity exists.
        """
        if not production:
            return
        if transport not in {None, "unix", "native"}:
            raise IdentityIsolationError("authority transport is unknown")
        platform_name = sys_platform()
        is_windows = platform_name.startswith(("win", "cygwin", "msys"))
        if transport == "unix" and profile == "community":
            if is_windows:
                raise IdentityIsolationError(
                    "the community authority profile is not supported on Windows"
                )
            if self.job_uid == 0:
                raise IdentityIsolationError(
                    "community authority job UID 0 is forbidden"
                )
            return
        if is_windows:
            required = {
                "service_sid": self.service_sid,
                "agent_sid": self.agent_sid,
                "named_pipe": self.named_pipe,
                "protected_key_ref": self.protected_key_ref,
                "agent_requirement_digest": self.agent_requirement_digest,
            }
        elif platform_name == "darwin":
            required = {
                "launchd_service": self.launchd_service,
                "code_signature": self.code_signature,
                "keychain_access_group": self.keychain_access_group,
                "protected_key_ref": self.protected_key_ref,
                "agent_requirement_digest": self.agent_requirement_digest,
            }
        else:
            required = {}
            if self.agent_uid is None or self.authority_uid is None or self.job_uid is None:
                raise IdentityIsolationError(
                    "Linux production authority requires agent, authority, and job UIDs"
                )
            if len({self.agent_uid, self.authority_uid, self.job_uid}) != 3:
                raise IdentityIsolationError("agent, authority, and job UIDs must be distinct")
            if self.job_uid == 0:
                raise IdentityIsolationError(
                    "Linux production job UID must be a non-root unprivileged UID"
                )
        missing = [name for name, value in required.items() if not value]
        if missing:
            raise IdentityIsolationError(
                f"native authority identity proof is missing: {', '.join(missing)}"
            )


def sys_platform() -> str:
    """Small indirection for platform-matrix tests."""
    import sys

    return sys.platform


def read_contract_from_environment() -> AuthorityIdentityContract:
    """Read deployment identity handles without inventing defaults."""
    def integer(name: str) -> int | None:
        value = os.environ.get(name)
        if value is None or value == "":
            return None
        try:
            parsed = int(value, 10)
        except ValueError as exc:
            raise IdentityIsolationError(f"{name} is not a valid UID") from exc
        if parsed < 0:
            raise IdentityIsolationError(f"{name} is negative")
        return parsed

    def requirement_digest(*names: str) -> str | None:
        """Digest the designated peer requirement the native transport enforces.

        On macOS this is the full designated code requirement expression
        (identifier + anchor + Team ID); on Windows it is the expected agent
        SID binding (canonically prefixed, matching the Rust frontend's
        ``agent_requirement_digest``).  The digest is compared against the
        proof the native service returns, so a deployment cannot silently
        fall back to an identifier-only trust model.
        """
        import hashlib

        windows = os.name == "nt"
        for name in names:
            value = os.environ.get(name)
            if not value:
                continue
            canonical = (
                f"windows-agent-sid:{value}" if windows and name == "KHAOS_AGENT_SID" else value
            )
            return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        return None

    return AuthorityIdentityContract(
        agent_uid=integer("KHAOS_AGENT_UID"),
        authority_uid=integer("KHAOS_AUTHORITYD_UID"),
        job_uid=integer("KHAOS_JOB_UID"),
        launchd_service=os.environ.get("KHAOS_AUTHORITYD_LAUNCHD_SERVICE"),
        # macOS names this field after the authenticated peer: the native
        # service compares the XPC audit-token code signature against
        # KHAOS_AUTHORITYD_AGENT_CODE_SIGNATURE.  Do not silently accept a
        # service signature in its place.
        code_signature=os.environ.get("KHAOS_AUTHORITYD_AGENT_CODE_SIGNATURE"),
        keychain_access_group=os.environ.get("KHAOS_AUTHORITYD_KEYCHAIN_GROUP"),
        service_sid=os.environ.get("KHAOS_AUTHORITYD_SERVICE_SID"),
        agent_sid=os.environ.get("KHAOS_AGENT_SID"),
        named_pipe=os.environ.get("KHAOS_AUTHORITYD_NAMED_PIPE"),
        protected_key_ref=os.environ.get("KHAOS_AUTHORITYD_PROTECTED_KEY_REF"),
        agent_requirement_digest=requirement_digest(
            "KHAOS_AUTHORITYD_AGENT_CODE_REQUIREMENT",
            "KHAOS_AGENT_SID",
        ),
    )


def validate_private_unix_socket(path: Path, *, expected_uid: int | None) -> None:
    """Check the daemon socket's local ownership before connecting."""
    if os.name == "nt":
        raise IdentityIsolationError("Unix socket transport is not valid on Windows")
    try:
        info = path.lstat()
    except OSError as exc:
        raise IdentityIsolationError("authority socket is unavailable") from exc
    mode = stat.S_IMODE(info.st_mode)
    if not stat.S_ISSOCK(info.st_mode) or mode not in {0o600, 0o660}:
        raise IdentityIsolationError(
            "authority socket must be 0600 or 0660 with no other access"
        )
    if expected_uid is not None and info.st_uid != expected_uid:
        raise IdentityIsolationError("authority socket owner is not the authority UID")


def peer_uid(connection: socket.socket) -> int:
    """Return SO_PEERCRED UID on Linux; fail closed elsewhere."""
    if not hasattr(socket, "SO_PEERCRED"):
        raise IdentityIsolationError("SO_PEERCRED is unavailable")
    try:
        raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
    except OSError as exc:
        raise IdentityIsolationError("could not read authority peer credentials") from exc
    if len(raw) < 12:
        raise IdentityIsolationError("authority peer credential payload is malformed")
    # struct ucred { pid_t pid; uid_t uid; gid_t gid; } in native ABI layout:
    # bytes 4..8 are the UID and bytes 8..12 the GID.  This used to return
    # raw[8:12], i.e. the peer's GID, so the admission gate compared the
    # peer's effective GID against the configured agent UID.
    _pid, uid, _gid = struct.unpack("=3i", raw[:12])
    return uid


# darwin exposes peer credentials through the LOCAL_PEERCRED socket option
# (struct xucred).  The constant is not in the Python socket module.
_LOCAL_PEERCRED = 0x001
_XUCRED_SIZE = 4 + 4 + 2 + 2 + 16 * 4  # version, uid, padding, ngroups, groups[16]


def peer_uid_darwin(connection: socket.socket) -> int:
    """Return the LOCAL_PEERCRED UID on darwin; fail closed elsewhere.

    The kernel fills ``struct xucred`` for connected AF_UNIX sockets; a
    successful getsockopt is itself the kernel validation.  ``cr_version``
    is the structure-layout version (``XUCRED_VERSION`` is 0 on current
    macOS) and is *not* a validation flag.  A short or out-of-range payload
    fails closed rather than being interpreted optimistically.
    """
    if sys_platform() != "darwin":
        raise IdentityIsolationError("LOCAL_PEERCRED is only available on darwin")
    try:
        raw = connection.getsockopt(
            0, _LOCAL_PEERCRED, _XUCRED_SIZE
        )  # SOL_LOCAL == 0 on darwin
    except OSError as exc:
        raise IdentityIsolationError(
            "could not read authority peer credentials"
        ) from exc
    if len(raw) < 12:
        raise IdentityIsolationError("authority peer credential payload is malformed")
    uid = int.from_bytes(raw[4:8], byteorder="little", signed=True)
    if uid < 0:
        raise IdentityIsolationError("authority peer credential UID is invalid")
    return uid


def peer_uid_platform(connection: socket.socket) -> int:
    """Return the kernel-verified peer UID for the current platform."""
    if sys_platform() == "darwin":
        return peer_uid_darwin(connection)
    return peer_uid(connection)


def require_distinct_linux_identities(
    *, agent_uid: int, authority_uid: int, job_uid: int
) -> None:
    """Fail closed unless all local execution identities are distinct."""
    if len({agent_uid, authority_uid, job_uid}) != 3:
        raise IdentityIsolationError("Linux execution identities must be distinct")
    if os.geteuid() != agent_uid:
        raise IdentityIsolationError(
            "agent process is not running as the configured agent UID"
        )
    if os.geteuid() == authority_uid:
        raise IdentityIsolationError(
            "agent process must not run as the authority daemon UID"
        )


def linux_job_namespace_args() -> tuple[str, ...]:
    """Return the fail-closed bwrap identity mapping for coding jobs.

    The configured job UID is the UID visible inside the private user
    namespace.  Production additionally requires the deployment contract and
    distinct agent/authority/job identities; development uses the nobody-like
    65534 default only under the explicit dev flag.  A job UID of 0 is
    always rejected: the payload identity must never be root, and the
    zero-capability postcondition (``--cap-drop ALL`` plus the launcher's
    final capget assertion) must not depend on UID inference.
    """
    development = os.environ.get("KHAOS_DEV_MODE") == "1"
    contract = read_contract_from_environment()
    if development:
        job_uid = contract.job_uid if contract.job_uid is not None else 65534
    else:
        if (
            contract.agent_uid is None
            or contract.authority_uid is None
            or contract.job_uid is None
        ):
            raise IdentityIsolationError(
                "Linux production authority requires agent, authority, and job UIDs"
            )
        if len({contract.agent_uid, contract.authority_uid, contract.job_uid}) != 3:
            raise IdentityIsolationError(
                "Linux job UID must be distinct from agent and authority UIDs"
            )
        if os.geteuid() != contract.agent_uid:
            raise IdentityIsolationError(
                "Linux sandbox builder is not running as the configured agent UID"
            )
        job_uid = contract.job_uid
    if not 0 <= job_uid <= 2**32 - 1:
        raise IdentityIsolationError("Linux job UID is outside the namespace range")
    if job_uid == 0:
        raise IdentityIsolationError(
            "Linux job UID 0 is forbidden; payloads must run as an unprivileged UID"
        )
    # --cap-drop ALL is paired with the Rust final launcher's capget
    # zero-capability assertion: construction alone is not proof.
    return (
        "--unshare-user",
        "--uid",
        str(job_uid),
        "--gid",
        str(job_uid),
        "--cap-drop",
        "ALL",
    )


@dataclass(frozen=True)
class LinuxProcessIdentityEvidence:
    """Host-observable identity evidence for a sandboxed process."""

    pid: int
    uid: int
    euid: int
    gid: int
    egid: int
    uid_map: str
    gid_map: str


def read_linux_process_identity(pid: int) -> LinuxProcessIdentityEvidence:
    """Read /proc identity and namespace maps without trusting the child."""
    if pid <= 0 or not sys_platform().startswith("linux"):
        raise IdentityIsolationError("Linux process identity oracle is unavailable")
    root = Path(f"/proc/{pid}")
    try:
        status = (root / "status").read_text(encoding="utf-8")
        uid_map = (root / "uid_map").read_text(encoding="ascii")
        gid_map = (root / "gid_map").read_text(encoding="ascii")
    except (OSError, UnicodeError) as exc:
        raise IdentityIsolationError("Linux process identity evidence is unavailable") from exc
    values: dict[str, tuple[int, ...]] = {}
    for line in status.splitlines():
        key, separator, raw = line.partition(":")
        if separator and key in {"Uid", "Gid"}:
            try:
                values[key] = tuple(int(value) for value in raw.split())
            except ValueError as exc:
                raise IdentityIsolationError("Linux process identity evidence is malformed") from exc
    try:
        uid, euid = values["Uid"][:2]
        gid, egid = values["Gid"][:2]
    except (KeyError, ValueError) as exc:
        raise IdentityIsolationError("Linux process identity fields are incomplete") from exc
    if not uid_map.strip() or not gid_map.strip():
        raise IdentityIsolationError("Linux process namespace maps are empty")
    return LinuxProcessIdentityEvidence(
        pid=pid,
        uid=uid,
        euid=euid,
        gid=gid,
        egid=egid,
        uid_map=uid_map,
        gid_map=gid_map,
    )


__all__ = [
    "AuthorityIdentityContract",
    "IdentityIsolationError",
    "LinuxProcessIdentityEvidence",
    "linux_job_namespace_args",
    "peer_uid",
    "peer_uid_darwin",
    "peer_uid_platform",
    "read_contract_from_environment",
    "read_linux_process_identity",
    "require_distinct_linux_identities",
    "validate_private_unix_socket",
]
