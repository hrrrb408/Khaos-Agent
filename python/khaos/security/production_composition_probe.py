# KHAOS-PRIVILEGED-SPAWN owner=ProductionCompositionProbe threat-model=compose-job-identity boundary=production-compose-e2e

"""Real production authorityd + WORM + Linux job-namespace composition probe.

This module is intentionally an opt-in deployment probe.  It must run inside
the production compose agent with KHAOS_DEV_MODE=0 and an actual
authorityd socket; it never substitutes the in-process broker or a local
audit file.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import time
from pathlib import Path

from khaos.coding.execution.platform import LinuxBubblewrapBackend
from khaos.security.authority_broker import (
    AuthorityBrokerError,
    AuthorityDaemonBroker,
)
from khaos.security.authorityd_protocol import AuthorityDaemonClient
from khaos.security.identity_isolation import (
    IdentityIsolationError,
    LinuxProcessIdentityEvidence,
    read_linux_process_identity,
)

_BWRAP_INFO_MAX_BYTES = 8192
_BWRAP_ERROR_MAX_BYTES = 1024
_IDENTITY_ORACLE_TIMEOUT_SECONDS = 2.0
_IDENTITY_ORACLE_RETRY_SECONDS = 0.01


def _resource_digest(command: tuple[str, ...], workspace: Path) -> str:
    payload = json.dumps(
        {"command": command, "workspace": str(workspace)},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _mapping_contains_pair(mapping: str, namespace_id: int, host_id: int) -> bool:
    for line in mapping.splitlines():
        fields = line.split()
        if len(fields) != 3:
            continue
        try:
            namespace_start, host_start, count = (int(field, 10) for field in fields)
        except ValueError:
            continue
        if (
            count > 0
            and namespace_start <= namespace_id < namespace_start + count
            and host_start <= host_id < host_start + count
        ):
            return True
    return False


def _read_bwrap_child_pid(info_fd: int) -> int:
    try:
        with os.fdopen(info_fd, "r", encoding="ascii", newline="") as stream:
            raw_info = stream.read(_BWRAP_INFO_MAX_BYTES + 1)
    except (OSError, UnicodeError) as exc:
        raise SystemExit("bubblewrap child identity metadata is unavailable") from exc
    if not raw_info:
        raise SystemExit("bubblewrap child identity metadata is unavailable")
    if len(raw_info) > _BWRAP_INFO_MAX_BYTES:
        raise SystemExit("bubblewrap child identity metadata exceeds the size limit")

    decoder = json.JSONDecoder()
    offset = 0
    child_pid: int | None = None
    try:
        while offset < len(raw_info):
            while offset < len(raw_info) and raw_info[offset].isspace():
                offset += 1
            if offset == len(raw_info):
                break
            info, next_offset = decoder.raw_decode(raw_info, offset)
            offset = next_offset
            if not isinstance(info, dict) or "child-pid" not in info:
                continue
            candidate = info["child-pid"]
            if isinstance(candidate, bool) or not isinstance(candidate, int) or candidate <= 0:
                raise SystemExit(
                    "bubblewrap child identity metadata has no valid PID"
                )
            if child_pid is not None and child_pid != candidate:
                raise SystemExit("bubblewrap child identity metadata has conflicting PIDs")
            child_pid = candidate
    except json.JSONDecodeError as exc:
        preview = raw_info[:256].replace("\n", "\\n")
        raise SystemExit(
            f"bubblewrap child identity metadata is malformed: {preview!r}"
        ) from exc
    if child_pid is None:
        raise SystemExit("bubblewrap child identity metadata has no valid PID")
    return child_pid


def _spawn_probe_process(
    prefix: tuple[str, ...],
    command: tuple[str, ...],
    workspace: Path,
) -> tuple[subprocess.Popen, int]:
    info_read_fd, info_write_fd = os.pipe()
    try:
        process = subprocess.Popen(
            (*prefix, "--info-fd", str(info_write_fd), "--", *command),
            cwd=workspace,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=(info_write_fd,),
            text=True,
        )
    except BaseException:
        os.close(info_read_fd)
        raise
    finally:
        os.close(info_write_fd)
    return process, info_read_fd


def _terminate_probe_process(process: subprocess.Popen) -> str:
    """Terminate a failed probe and retain a bounded launcher diagnostic."""
    if process.poll() is None:
        try:
            process.kill()
        except ProcessLookupError:
            pass
    try:
        _stdout, stderr = process.communicate(timeout=15)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except ProcessLookupError:
            pass
        try:
            _stdout, stderr = process.communicate(timeout=1)
        except (OSError, subprocess.TimeoutExpired):
            return ""
    except OSError:
        return ""
    return stderr.strip()[:_BWRAP_ERROR_MAX_BYTES]


def _read_linux_process_identity_when_ready(
    pid: int,
) -> LinuxProcessIdentityEvidence:
    """Wait briefly for bwrap to publish its proc namespace mappings."""
    deadline = time.monotonic() + _IDENTITY_ORACLE_TIMEOUT_SECONDS
    while True:
        try:
            return read_linux_process_identity(pid)
        except IdentityIsolationError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(_IDENTITY_ORACLE_RETRY_SECONDS)


def main() -> int:
    if os.environ.get("KHAOS_DEV_MODE") == "1":
        raise SystemExit("production composition probe refuses KHAOS_DEV_MODE=1")
    socket_value = os.environ.get("KHAOS_AUTHORITYD_SOCKET")
    policy_digest = os.environ.get("KHAOS_EFFECTIVE_POLICY_DIGEST")
    job_uid = os.environ.get("KHAOS_JOB_UID")
    if not socket_value or not policy_digest or not job_uid:
        raise SystemExit(
            "production composition probe requires authority socket, policy digest, and job UID"
        )
    workspace = Path(tempfile.mkdtemp(prefix="khaos-composition-"))
    home = Path(tempfile.mkdtemp(prefix="khaos-composition-home-"))
    command = (
        "/bin/sh",
        "-c",
        "printf 'composition-probe\\n'; id -u; id -g; cat /proc/self/uid_map; cat /proc/self/gid_map; sleep 1",
    )
    broker = AuthorityDaemonBroker(
        AuthorityDaemonClient(
            Path(socket_value),
            expected_authority_uid=int(os.environ.get("KHAOS_AUTHORITYD_UID", "10003")),
        )
    )
    capability = broker.issue(
        broker.envelope(
            principal_id="agent",
            project_id="compose",
            runtime_id="compose-agent",
            task_id="authority-composition",
            workspace_id="authority-composition",
            workspace_generation=1,
            policy_digest=policy_digest,
            operation_class="exec.compose",
            resource_digest=_resource_digest(command, workspace),
        ),
        allowed_operation="exec.*",
    )
    claimed = False
    committed = False
    try:
        broker.claim(capability)
        claimed = True
        prefix = LinuxBubblewrapBackend().argv_prefix(
            workspace,
            cwd=workspace,
            synthetic_home=home,
            command=("/bin/sh",),
            environment={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
            include_network_authority=False,
        )
        process, info_fd = _spawn_probe_process(prefix, command, workspace)
        try:
            child_pid = _read_bwrap_child_pid(info_fd)
            expected_job_uid = int(job_uid)
            expected_agent_uid = os.getuid()
            expected_agent_gid = os.getgid()
            evidence = _read_linux_process_identity_when_ready(child_pid)
            if (
                evidence.uid != expected_agent_uid
                or evidence.euid != expected_agent_uid
                or evidence.gid != expected_agent_gid
                or evidence.egid != expected_agent_gid
                or not _mapping_contains_pair(
                    evidence.uid_map, expected_job_uid, expected_agent_uid
                )
                or not _mapping_contains_pair(
                    evidence.gid_map, expected_job_uid, expected_agent_gid
                )
            ):
                raise SystemExit(
                    "external /proc identity oracle did not observe the configured job UID/GID mapping"
                )
            stdout, stderr = process.communicate(timeout=15)
        except BaseException as exc:
            stderr = _terminate_probe_process(process)
            if stderr and isinstance(exc, SystemExit) and isinstance(exc.code, str):
                raise SystemExit(f"{exc.code}; bwrap stderr: {stderr}") from exc
            if stderr and isinstance(exc, IdentityIsolationError):
                raise IdentityIsolationError(f"{exc}; bwrap stderr: {stderr}") from exc
            raise
        completed = subprocess.CompletedProcess(
            process.args,
            process.returncode,
            stdout,
            stderr,
        )
        if completed.returncode != 0:
            broker.complete(
                capability,
                result="failed",
                result_digest=hashlib.sha256(completed.stderr.encode()).hexdigest(),
            )
            committed = True
            raise SystemExit(
                f"production job namespace command failed: {completed.stderr.strip()}"
            )
        lines = completed.stdout.splitlines()
        if len(lines) < 4 or lines[0] != "composition-probe":
            raise SystemExit("production composition probe output is malformed")
        if lines[1] != job_uid or lines[2] != job_uid or not lines[3].strip():
            raise SystemExit(
                "production composition probe did not observe the configured job UID"
            )
        broker.complete(
            capability,
            result="success",
            result_digest=hashlib.sha256(completed.stdout.encode()).hexdigest(),
        )
        committed = True
        try:
            broker.claim(capability)
        except AuthorityBrokerError:
            pass
        else:
            raise SystemExit("completed authority receipt was reusable")
        print("production authority composition: prepare claim bwrap result success")
        return 0
    except BaseException:
        if claimed and not committed:
            try:
                broker.complete(
                    capability,
                    result="unknown",
                    result_digest=hashlib.sha256(b"composition-unknown").hexdigest(),
                )
            except (AuthorityBrokerError, OSError):
                pass
        raise
    finally:
        for path in (workspace, home):
            try:
                path.rmdir()
            except OSError:
                pass
        broker.close()


if __name__ == "__main__":
    raise SystemExit(main())
