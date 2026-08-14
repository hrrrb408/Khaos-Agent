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
from pathlib import Path

from khaos.coding.execution.platform import LinuxBubblewrapBackend
from khaos.security.authority_broker import (
    AuthorityBrokerError,
    AuthorityDaemonBroker,
)
from khaos.security.authorityd_protocol import AuthorityDaemonClient
from khaos.security.identity_isolation import read_linux_process_identity


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
        with os.fdopen(info_fd, "r", encoding="ascii") as stream:
            raw_info = stream.read(8192)
    except (OSError, UnicodeError) as exc:
        raise SystemExit("bubblewrap child identity metadata is unavailable") from exc
    try:
        info = json.loads(raw_info)
    except json.JSONDecodeError as exc:
        raise SystemExit("bubblewrap child identity metadata is malformed") from exc
    child_pid = info.get("child-pid") if isinstance(info, dict) else None
    if isinstance(child_pid, bool) or not isinstance(child_pid, int) or child_pid <= 0:
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
        "printf 'composition-probe\\n'; id -u; id -g; cat /proc/self/uid_map; cat /proc/self/gid_map",
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
            evidence = read_linux_process_identity(child_pid)
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
        except BaseException:
            process.kill()
            process.communicate()
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
