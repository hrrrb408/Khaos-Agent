# KHAOS-PRIVILEGED-SPAWN owner=ProductionCompositionProbe threat-model=compose-job-identity boundary=production-compose-e2e

"""Real production authorityd + WORM + Linux job-namespace composition probe.

This module is intentionally an opt-in deployment probe.  It must run inside
the production compose agent with KHAOS_DEV_MODE=0 and an actual
authorityd socket; it never substitutes the in-process broker or a local
audit file.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import stat
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
from khaos.security.local_closure import LocalEvidenceError, canonical_digest
from khaos.security.producer_evidence import (
    PRODUCTION_COMPOSITION_PROOF,
    build_runtime_producer_proof,
    sha256_file,
    write_producer_proof,
)

_IDENTITY_ORACLE_TIMEOUT_SECONDS = 15.0
_IDENTITY_ORACLE_RETRY_SECONDS = 0.01
_FAILURE_DETAIL_LIMIT = 512
_COMPOSE_PRINCIPAL_ID = "agent"
_COMPOSE_PRINCIPAL_KIND = PrincipalKind.AUTOMATION.value
_COMPOSE_PARENT_PRINCIPAL_ID = "automation:compose-security-e2e"
_COMPOSE_SESSION_ID = "compose-session"
_COMPOSE_RUNTIME_ID = "compose-agent"
_PRODUCTION_EXECUTION_CHAIN = (
    "khaos.runtime.factory.RuntimeResult",
    "khaos.coding.execution.service.ExecutionService",
    "khaos.coding.execution.platform.LinuxBubblewrapBackend",
    "khaos.coding.execution.supervisor.ProcessSupervisor",
    "khaos.coding.execution.native_launcher",
    "linux-kernel-pid-and-user-namespace",
)


def _runtime_composition_digest(runtime_manifest: dict[str, object]) -> str:
    """Return the one canonical digest for the production execution chain."""
    return canonical_digest(
        {
            "manifest": runtime_manifest,
            "execution_chain": list(_PRODUCTION_EXECUTION_CHAIN),
        }
    )


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
    timeout_seconds: float = 15.0,
) -> ExecutionRequest:
    """Build the same immutable authority pair used by approved execution."""
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
    budget = ResourceBudget(timeout_seconds=timeout_seconds, output_bytes=32 * 1024)
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
        tool_name="production_composition_probe",
        authorization_resource_digest=_resource_digest(command, workspace),
        principal_kind=_COMPOSE_PRINCIPAL_KIND,
        parent_principal_id=_COMPOSE_PARENT_PRINCIPAL_ID,
        delegation_digest=delegation_digest,
        source_transport="cron",
        runtime_id=_COMPOSE_RUNTIME_ID,
        authorization_epoch=1,
        workspace_id="authority-composition",
        policy_digest=policy_digest,
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
        runtime_id=_COMPOSE_RUNTIME_ID,
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


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("/tmp/production-composition-proof.json"),
    )
    return parser.parse_args()


def _require_production_socket(path: Path, authority_uid: int) -> dict[str, object]:
    """Return identity facts for the real authorityd endpoint."""
    try:
        info = path.lstat()
    except OSError as exc:
        raise SystemExit(f"production authority socket is unavailable: {exc}") from exc
    if not stat.S_ISSOCK(info.st_mode) or path.is_symlink():
        raise SystemExit("production authority endpoint is not a non-symlink Unix socket")
    if info.st_uid != authority_uid or info.st_mode & 0o007:
        raise SystemExit("production authority socket ownership or mode is unsafe")
    public_key_path = Path(os.environ["KHAOS_AUTHORITYD_PUBLIC_KEY_PATH"])
    try:
        key_info = public_key_path.lstat()
    except OSError as exc:
        raise SystemExit(f"production authority public key is unavailable: {exc}") from exc
    if (
        not stat.S_ISREG(key_info.st_mode)
        or public_key_path.is_symlink()
        or key_info.st_uid != authority_uid
        or key_info.st_nlink != 1
        or key_info.st_mode & 0o022
    ):
        raise SystemExit("production authority public key ownership or mode is unsafe")
    return {
        "socket_path": str(path),
        "socket_owner_uid": int(info.st_uid),
        "public_key_digest": sha256_file(public_key_path),
        "authority_profile": os.environ.get("KHAOS_AUTHORITY_PROFILE", ""),
    }


async def _build_runtime_manifest() -> dict[str, object]:
    """Build and verify the same structural production Runtime factory uses."""
    if not Path("/app/khaos_policy.yaml").is_file():
        raise SystemExit(
            "production composition probe requires the mounted project policy"
        )
    from khaos.db.database import Database
    from khaos.runtime import ProductionRuntimeConfig, build_production_runtime
    from khaos.security.production_composition_manifest import verify_runtime_composition

    with tempfile.TemporaryDirectory(prefix="khaos-runtime-composition-") as temporary:
        database = Database(Path(temporary) / "composition.db")
        await database.connect()
        await database.run_migrations()
        runtime = None
        try:
            runtime = await build_production_runtime(
                ProductionRuntimeConfig(
                    project_root=Path("/app"),
                    config_path=Path("/app/config.yaml"),
                    db=database,
                    principal_id=_COMPOSE_PRINCIPAL_ID,
                    principal_kind=_COMPOSE_PRINCIPAL_KIND,
                    parent_principal_id=_COMPOSE_PARENT_PRINCIPAL_ID,
                    source_transport="cron",
                    project_id="compose",
                    runtime_id=_COMPOSE_RUNTIME_ID,
                )
            )
            manifest = verify_runtime_composition(runtime)
            payload = manifest.to_payload()
            if not manifest.valid or manifest.forbidden_detected:
                raise SystemExit(
                    "production runtime composition is invalid: "
                    + "; ".join(manifest.errors)
                )
            return payload
        finally:
            if runtime is not None:
                await runtime.aclose()
            await database.close()


def _runtime_diagnostics(
    *,
    proof_name: str,
    output_dir: Path,
    result: ExecutionResult,
    oracle_detail: str,
) -> dict[str, object]:
    """Persist bounded producer diagnostics for the exact-effect oracle."""
    import xml.etree.ElementTree as element_tree

    passed = result.status == "passed" and not oracle_detail
    junit = output_dir / f"{proof_name}.junit.xml"
    suite = element_tree.Element(
        "testsuite",
        {
            "name": proof_name,
            "tests": "1",
            "failures": "0" if passed else "1",
            "errors": "0",
        },
    )
    case = element_tree.SubElement(suite, "testcase", {"name": proof_name})
    if not passed:
        element_tree.SubElement(
            case,
            "failure",
            {"message": (oracle_detail or result.stderr or result.status)[:512]},
        )
    element_tree.ElementTree(suite).write(
        junit, encoding="utf-8", xml_declaration=True
    )
    stdout = output_dir / f"{proof_name}.stdout.log"
    stderr = output_dir / f"{proof_name}.stderr.log"
    stdout.write_text(result.stdout[-16_000:], encoding="utf-8")
    stderr.write_text(
        (result.stderr or oracle_detail)[-16_000:], encoding="utf-8"
    )
    from khaos.security.producer_evidence import diagnostics_from_junit

    return diagnostics_from_junit(
        proof_name=proof_name,
        junit=junit,
        returncode=0 if passed else (result.return_code or 1),
        stdout=stdout,
        stderr=stderr,
    )


def _write_composition_proof(
    *,
    output: Path,
    policy_digest: str,
    authority_identity: dict[str, object],
    runtime_manifest: dict[str, object],
    launcher_digest: str,
    result: ExecutionResult,
    output_dir: Path,
) -> None:
    manifest_digest = canonical_digest(runtime_manifest)
    diagnostics = _runtime_diagnostics(
        proof_name=PRODUCTION_COMPOSITION_PROOF,
        output_dir=output_dir,
        result=result,
        oracle_detail="",
    )
    workflow = {
        "repository": os.environ.get("GITHUB_REPOSITORY", ""),
        "workflow": os.environ.get("GITHUB_WORKFLOW", ""),
        "run_id": os.environ.get("GITHUB_RUN_ID", ""),
        "run_attempt": int(os.environ.get("GITHUB_RUN_ATTEMPT", "0")),
        "event": os.environ.get("GITHUB_EVENT_NAME", ""),
        "ref": os.environ.get("GITHUB_REF", ""),
        "head_sha": os.environ.get("GITHUB_SHA", ""),
        "runner_os": os.environ.get("RUNNER_OS", ""),
        "job": os.environ.get("GITHUB_JOB", ""),
    }
    identity = {
        "runtime_composition_digest": _runtime_composition_digest(runtime_manifest),
        "production_composition_manifest_digest": manifest_digest,
        "launcher_digest": launcher_digest,
        "authority_proof_identity": authority_identity,
        "authority_proof_digest": canonical_digest(authority_identity),
        "host_backend_absent": True,
        "dev_fallback_absent": os.environ.get("KHAOS_DEV_MODE") == "0",
        "production_mode": os.environ.get("KHAOS_DEV_MODE") == "0",
        "authority_profile": os.environ.get("KHAOS_AUTHORITY_PROFILE", ""),
    }
    proof = build_runtime_producer_proof(
        proof_type=PRODUCTION_COMPOSITION_PROOF,
        commit=os.environ.get("GITHUB_SHA", ""),
        policy_digest=policy_digest,
        workflow=workflow,
        diagnostics=diagnostics,
        production_identity=identity,
    )
    write_producer_proof(output, proof)


def main() -> int:
    args = _parse_args()
    if os.environ.get("KHAOS_DEV_MODE") != "0":
        raise SystemExit("production composition probe requires KHAOS_DEV_MODE=0")
    if os.environ.get("KHAOS_AUTHORITY_PROFILE") != "native-production":
        raise SystemExit("production composition probe requires native-production authority")
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
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    authority_identity = _require_production_socket(
        Path(os.environ["KHAOS_AUTHORITYD_SOCKET"]),
        int(os.environ.get("KHAOS_AUTHORITYD_UID", "0")),
    )
    if os.getuid() != int(os.environ.get("KHAOS_AGENT_UID", str(os.getuid()))):
        raise SystemExit("production composition probe is running as the wrong Agent UID")
    runtime_manifest = asyncio.run(_build_runtime_manifest())
    from khaos.coding.execution.platform import _linux_sandbox_launcher

    sandbox_launcher = _linux_sandbox_launcher()
    exec_launcher = Path(os.environ.get("KHAOS_EXEC_LAUNCHER", ""))
    if sandbox_launcher is None or not exec_launcher.is_file() or exec_launcher.is_symlink():
        raise SystemExit("production native launcher identity is unavailable")
    launcher_digest = canonical_digest(
        {
            "sandbox_launcher": sha256_file(sandbox_launcher),
            "exec_launcher": sha256_file(exec_launcher),
        }
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
        _write_composition_proof(
            output=output,
            policy_digest=policy_digest,
            authority_identity=authority_identity,
            runtime_manifest=runtime_manifest,
            launcher_digest=launcher_digest,
            result=result,
            output_dir=output.parent,
        )
        print(
            "production exact-effect composition: "
            "ProductionRuntime -> ExecutionService -> ProcessSupervisor -> "
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
