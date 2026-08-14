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


def _spawn_probe_process(
    prefix: tuple[str, ...],
    command: tuple[str, ...],
    workspace: Path,
) -> subprocess.Popen:
    return subprocess.Popen(
        (*prefix, "--", *command),
        cwd=workspace,
        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


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
        "printf 'composition-probe\\n'; id -u; cat /proc/self/uid_map",
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
        process = _spawn_probe_process(prefix, command, workspace)
        try:
            evidence = read_linux_process_identity(process.pid)
            expected_job_uid = int(job_uid)
            if (
                evidence.uid != expected_job_uid
                or evidence.euid != expected_job_uid
                or evidence.gid != expected_job_uid
                or evidence.egid != expected_job_uid
            ):
                raise SystemExit(
                    "external /proc identity oracle did not observe the configured job UID"
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
        if len(lines) < 3 or lines[0] != "composition-probe":
            raise SystemExit("production composition probe output is malformed")
        if lines[1] != job_uid or not lines[2].strip():
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
