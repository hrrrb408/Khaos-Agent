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
    named_pipe: str | None = None
    protected_key_ref: str | None = None

    def validate(self, *, production: bool) -> None:
        if not production:
            return
        if os.name == "nt":
            required = {
                "service_sid": self.service_sid,
                "named_pipe": self.named_pipe,
                "protected_key_ref": self.protected_key_ref,
            }
        elif sys_platform() == "darwin":
            required = {
                "launchd_service": self.launchd_service,
                "code_signature": self.code_signature,
                "keychain_access_group": self.keychain_access_group,
                "protected_key_ref": self.protected_key_ref,
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

    return AuthorityIdentityContract(
        agent_uid=integer("KHAOS_AGENT_UID"),
        authority_uid=integer("KHAOS_AUTHORITYD_UID"),
        job_uid=integer("KHAOS_JOB_UID"),
        launchd_service=os.environ.get("KHAOS_AUTHORITYD_LAUNCHD_SERVICE"),
        code_signature=os.environ.get("KHAOS_AUTHORITYD_CODE_SIGNATURE"),
        keychain_access_group=os.environ.get("KHAOS_AUTHORITYD_KEYCHAIN_GROUP"),
        service_sid=os.environ.get("KHAOS_AUTHORITYD_SERVICE_SID"),
        named_pipe=os.environ.get("KHAOS_AUTHORITYD_NAMED_PIPE"),
        protected_key_ref=os.environ.get("KHAOS_AUTHORITYD_PROTECTED_KEY_REF"),
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
    return int.from_bytes(raw[8:12], byteorder="little", signed=True)


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
    "read_contract_from_environment",
    "read_linux_process_identity",
    "require_distinct_linux_identities",
    "validate_private_unix_socket",
]
