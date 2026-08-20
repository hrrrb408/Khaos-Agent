# KHAOS-PRIVILEGED-SPAWN owner=ProductionCompositionProbe threat-model=compose-job-identity boundary=production-compose-e2e

"""Real production authorityd + WORM + Linux job-namespace composition probe.

This module is intentionally an opt-in deployment probe.  It must run inside
the production compose agent with KHAOS_DEV_MODE=0 and an actual
authorityd socket; it never substitutes the in-process broker or a local
audit file.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import tempfile
import time
from pathlib import Path

from khaos.agent.approval import StepExecutionAuthority
from khaos.coding.execution import (
    ExecutionRequest,
    ExecutionResult,
    ExecutionService,
    FileSystemAccess,
    LinuxBubblewrapBackend,
    NetworkPolicy,
    PermissionProfile,
    ProcessSupervisor,
    ResourceBudget,
)
from khaos.coding.execution.authority import ExecutionAuthority
from khaos.coding.execution.identity import executable_identity
from khaos.coding.execution.models import ResolvedSpawnPlan
from khaos.security.identity_isolation import (
    IdentityIsolationError,
    LinuxProcessIdentityEvidence,
    read_linux_process_identity,
)
from khaos.security.principals import PrincipalKind, transport_root_delegation_digest

_IDENTITY_ORACLE_TIMEOUT_SECONDS = 15.0
_IDENTITY_ORACLE_RETRY_SECONDS = 0.01
_FAILURE_DETAIL_LIMIT = 512
_COMPOSE_PRINCIPAL_ID = "agent"
_COMPOSE_PRINCIPAL_KIND = PrincipalKind.AUTOMATION.value
_COMPOSE_PARENT_PRINCIPAL_ID = "automation:compose-security-e2e"
_COMPOSE_SESSION_ID = "compose-session"
_COMPOSE_RUNTIME_ID = "compose-agent"


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


def _digest_payload(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _supervisor_process_tree(supervisor: ProcessSupervisor, execution_id: str) -> tuple[int, ...]:
    """Return the supervisor-owned process and its observable descendants."""
    active = getattr(supervisor, "_active", {}).get(execution_id)
    if active is None or active.process.pid is None:
        return ()
    pending = [int(active.process.pid)]
    seen: set[int] = set()
    while pending:
        pid = pending.pop()
        if pid in seen or pid <= 0:
            continue
        seen.add(pid)
        try:
            children = Path(f"/proc/{pid}/task/{pid}/children").read_text(
                encoding="ascii"
            )
        except (OSError, UnicodeError):
            continue
        for raw_child in children.split():
            try:
                pending.append(int(raw_child, 10))
            except ValueError:
                continue
    return tuple(sorted(seen))


def _matches_job_identity(
    evidence: LinuxProcessIdentityEvidence,
    *,
    job_uid: int,
    agent_uid: int,
    agent_gid: int,
) -> bool:
    return (
        evidence.uid == agent_uid
        and evidence.euid == agent_uid
        and evidence.gid == agent_gid
        and evidence.egid == agent_gid
        and _mapping_contains_pair(evidence.uid_map, job_uid, agent_uid)
        and _mapping_contains_pair(evidence.gid_map, job_uid, agent_gid)
    )


def _bounded_detail(value: object) -> str:
    """Return compact diagnostic text without leaking an unbounded payload."""
    message = " ".join(str(value).split())
    if not message:
        return "<no detail>"
    if len(message) > _FAILURE_DETAIL_LIMIT:
        return message[: _FAILURE_DETAIL_LIMIT - 3] + "..."
    return message


def _failure_detail(error: BaseException) -> str:
    """Include the real exception type and bounded message in probe failures."""
    return f"{type(error).__name__}: {_bounded_detail(error)}"


async def _wait_for_supervisor_job_identity(
    supervisor: ProcessSupervisor,
    execution_id: str,
    *,
    job_uid: int,
    execution: asyncio.Task[ExecutionResult] | None = None,
) -> LinuxProcessIdentityEvidence:
    """Use the external proc oracle while the exact production effect runs."""
    deadline = time.monotonic() + _IDENTITY_ORACLE_TIMEOUT_SECONDS
    agent_uid = os.getuid()
    agent_gid = os.getgid()
    while True:
        for pid in _supervisor_process_tree(supervisor, execution_id):
            try:
                evidence = read_linux_process_identity(pid)
            except (IdentityIsolationError, OSError):
                continue
            if _matches_job_identity(
                evidence,
                job_uid=job_uid,
                agent_uid=agent_uid,
                agent_gid=agent_gid,
            ):
                return evidence
        if execution is not None and execution.done():
            try:
                result = execution.result()
            except asyncio.CancelledError as error:
                raise SystemExit(
                    "production exact-effect task was cancelled before the "
                    "external identity oracle observed it"
                ) from error
            except BaseException as error:
                raise SystemExit(
                    "production exact-effect task failed before the external "
                    f"identity oracle observed it ({_failure_detail(error)})"
                ) from error
            raise SystemExit(
                "production exact-effect task finished before the external "
                f"identity oracle observed it: {getattr(result, 'status', 'unknown')} "
                f"return_code={getattr(result, 'return_code', 'unknown')} "
                f"stderr={_bounded_detail(getattr(result, 'stderr', ''))}"
            )
        if time.monotonic() >= deadline:
            raise SystemExit(
                "external /proc identity oracle did not observe the configured "
                "job UID/GID mapping on the ProcessSupervisor-owned tree"
            )
        await asyncio.sleep(_IDENTITY_ORACLE_RETRY_SECONDS)


def _probe_request(
    *,
    command: tuple[str, ...],
    workspace: Path,
    policy_digest: str,
) -> ExecutionRequest:
    """Build the same immutable authority pair used by approved execution."""
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
    budget = ResourceBudget(timeout_seconds=15.0, output_bytes=32 * 1024)
    profile = PermissionProfile(
        filesystem=FileSystemAccess.READ_ONLY,
        workspace_roots=(workspace,),
        environment_keys=frozenset(environment),
        resources=budget,
    )
    root_info = workspace.stat()
    executable = executable_identity(command, environment)
    sandbox_digest = _digest_payload({"backend": "linux-bwrap", "network": "isolated"})
    # Must be byte-identical to what the daemon recomputes from the grant's
    # own fields: use the one canonical recipe, never a local copy.
    delegation_digest = transport_root_delegation_digest(
        principal_id=_COMPOSE_PRINCIPAL_ID,
        principal_kind=_COMPOSE_PRINCIPAL_KIND,
        parent_principal_id=_COMPOSE_PARENT_PRINCIPAL_ID,
        project_id="compose",
        session_id=_COMPOSE_SESSION_ID,
        runtime_id=_COMPOSE_RUNTIME_ID,
        source_transport="cron",
        policy_digest=policy_digest,
    )
    plan = ResolvedSpawnPlan(
        principal_id=_COMPOSE_PRINCIPAL_ID,
        project_id="compose",
        session_id=_COMPOSE_SESSION_ID,
        task_id="authority-composition",
        turn_id="compose-turn",
        step_id="compose-exact-effect",
        workspace_generation=1,
        workspace_root_device=int(root_info.st_dev),
        workspace_root_inode=int(root_info.st_ino),
        workspace_cwd_device=int(root_info.st_dev),
        workspace_cwd_inode=int(root_info.st_ino),
        permission_profile_digest=profile.digest(),
        sandbox_decision_digest=sandbox_digest,
        network_authority="network:none",
        environment=tuple(sorted(environment.items())),
        executable_identity=executable,
        argv=command,
        budget_digest=budget.digest(),
        principal_kind=_COMPOSE_PRINCIPAL_KIND,
        parent_principal_id=_COMPOSE_PARENT_PRINCIPAL_ID,
        delegation_digest=delegation_digest,
        source_transport="cron",
    )
    step = StepExecutionAuthority(
        principal_id=_COMPOSE_PRINCIPAL_ID,
        project_id="compose",
        session_id=_COMPOSE_SESSION_ID,
        task_id="authority-composition",
        turn_id="compose-turn",
        step_id="compose-exact-effect",
        tool_call_id="compose-exact-effect",
        tool_name="production_composition_probe",
        workspace_id="authority-composition",
        workspace_generation=1,
        cwd_identity=f"{root_info.st_dev}:{root_info.st_ino}",
        permission_profile_digest=profile.digest(),
        environment_keys=tuple(sorted(environment)),
        environment_digest=_digest_payload(environment),
        sandbox_backend="linux-bwrap",
        sandbox_decision_digest=sandbox_digest,
        executable_identity=executable,
        network_authority="network:none",
        target="production-composition",
        approval_target="production-composition",
        arguments_digest=_digest_payload({"argv": command}),
        authorization_resource_digest=_resource_digest(command, workspace),
        authorization_epoch=1,
        policy_digest=policy_digest,
        tool_schema_digest=_digest_payload("production-composition-probe-schema"),
        tool_security_digest=_digest_payload("production-composition-probe-security"),
        spawn_plan_digest=plan.digest(),
        approval_receipt_digest=_digest_payload("production-composition-probe-approval"),
        principal_kind=_COMPOSE_PRINCIPAL_KIND,
        parent_principal_id=_COMPOSE_PARENT_PRINCIPAL_ID,
        delegation_digest=delegation_digest,
        source_transport="cron",
    )
    authority = ExecutionAuthority(step_authority=step, spawn_plan=plan)
    return ExecutionRequest(
        argv=command,
        cwd=workspace,
        environment=environment,
        allowed_environment_keys=frozenset(environment),
        network_policy=NetworkPolicy.NONE,
        budget=budget,
        permission_profile=profile,
        correlation_id="authority-composition-exact",
        workspace_root_identity=(int(root_info.st_dev), int(root_info.st_ino)),
        workspace_cwd_identity=(int(root_info.st_dev), int(root_info.st_ino)),
        executable_identity=executable,
        execution_authority=authority,
    )


async def _run_exact_effect(
    *,
    request: ExecutionRequest,
    job_uid: int,
) -> tuple[LinuxProcessIdentityEvidence, ExecutionResult]:
    """Run through ExecutionService -> backend -> supervisor -> native launcher."""
    supervisor = ProcessSupervisor()
    backend = LinuxBubblewrapBackend(supervisor)
    service = ExecutionService(
        backend=backend,
        process_supervisor=supervisor,
        principal_id=_COMPOSE_PRINCIPAL_ID,
        project_id="compose",
        runtime_id=_COMPOSE_RUNTIME_ID,
    )
    execution_id = request.correlation_id
    if execution_id is None:
        raise SystemExit("production exact-effect request has no correlation id")
    execution = asyncio.create_task(service.execute(request))
    try:
        evidence = await _wait_for_supervisor_job_identity(
            supervisor,
            execution_id,
            job_uid=job_uid,
            execution=execution,
        )
        result = await execution
        if getattr(result, "status", None) != "passed":
            raise SystemExit(
                "production exact-effect execution did not pass: "
                f"{getattr(result, 'status', 'unknown')} {getattr(result, 'stderr', '')}"
            )
        return evidence, result
    finally:
        if not execution.done():
            execution.cancel()
        await asyncio.gather(execution, return_exceptions=True)
        await service.close()


def main() -> int:
    if os.environ.get("KHAOS_DEV_MODE") == "1":
        raise SystemExit("production composition probe refuses KHAOS_DEV_MODE=1")
    policy_digest = os.environ.get("KHAOS_EFFECTIVE_POLICY_DIGEST")
    job_uid = os.environ.get("KHAOS_JOB_UID")
    if (
        not os.environ.get("KHAOS_AUTHORITYD_SOCKET")
        or not os.environ.get("KHAOS_AUTHORITYD_PUBLIC_KEY_PATH")
        or not policy_digest
        or not job_uid
    ):
        raise SystemExit(
            "production composition probe requires authority socket, public key, "
            "policy digest, and job UID"
        )
    # The cgroup-v2 io.max contract needs a real block-backed device. The
    # production Compose profile mounts /app/data as a named volume; using
    # /tmp here would make the probe depend on the container overlay device
    # and could fail after all other isolation checks had already passed.
    workspace_parent = Path("/app/data")
    if not workspace_parent.is_dir():
        raise SystemExit(
            "production composition probe requires the mounted /app/data "
            "workspace volume for cgroup io.max evidence"
        )
    workspace = Path(
        tempfile.mkdtemp(prefix="khaos-composition-", dir=workspace_parent)
    )
    command = (
        "/bin/sh",
        "-c",
        "printf 'composition-probe\\n'; id -u; id -g; cat /proc/self/uid_map; cat /proc/self/gid_map; sleep 5",
    )
    try:
        request = _probe_request(
            command=command,
            workspace=workspace,
            policy_digest=policy_digest,
        )
        evidence, result = asyncio.run(
            _run_exact_effect(request=request, job_uid=int(job_uid))
        )
        lines = result.stdout.splitlines()
        if len(lines) < 4 or lines[0] != "composition-probe":
            raise SystemExit("production composition probe output is malformed")
        if lines[1] != job_uid or lines[2] != job_uid or not lines[3].strip():
            raise SystemExit(
                "production composition probe did not observe the configured job UID"
            )
        print(
            "production exact-effect composition: "
            "ExecutionService -> ProcessSupervisor -> exec.host receipt -> "
            "native launcher -> bwrap -> child -> WORM success; "
            f"observed job UID {evidence.uid_map.splitlines()[-1]}"
        )
        return 0
    finally:
        for path in (workspace,):
            try:
                path.rmdir()
            except OSError:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
