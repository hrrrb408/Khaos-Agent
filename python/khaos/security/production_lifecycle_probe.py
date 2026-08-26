# KHAOS-PRIVILEGED-SPAWN owner=ProductionLifecycleProbe threat-model=compose-job-identity boundary=production-compose-lifecycle
"""Production process-tree and resource-owner evidence producer.

The probe runs only inside the real ``compose.prod.yaml`` Agent.  It uses the
same native Linux backend and ProcessSupervisor as production and makes the
PASS decision from an independent host ``/proc`` plus cgroup oracle.  Python
registries and return codes are retained as diagnostics, never as the death
proof.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import stat
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path

from khaos.coding.execution import (
    ExecutionResult,
    ExecutionService,
    LinuxBubblewrapBackend,
    ProcessSupervisor,
)
from khaos.security.local_closure import canonical_digest
from khaos.security.producer_evidence import (
    PROCESS_TREE_PROOF,
    RESOURCE_OWNER_PROOF,
    build_runtime_producer_proof,
    sha256_file,
    write_producer_proof,
)
from khaos.security.production_composition_probe import (
    _COMPOSE_PRINCIPAL_ID,
    _COMPOSE_RUNTIME_ID,
    _build_runtime_manifest,
    _probe_request,
    _runtime_composition_digest,
    _supervisor_process_tree,
)


_ACTION_TIMEOUT = 15.0
_ORACLE_POLL = 0.05
_ORACLE_DEADLINE = 15.0


def _args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args()


def _proc_tree(root_pid: int) -> tuple[int, ...]:
    """Enumerate host-visible descendants without consulting Khaos registries."""
    pending = [root_pid]
    seen: set[int] = set()
    while pending:
        pid = pending.pop()
        if pid <= 0 or pid in seen:
            continue
        try:
            os.stat(f"/proc/{pid}")
        except OSError:
            continue
        seen.add(pid)
        try:
            children = Path(f"/proc/{pid}/task/{pid}/children").read_text(
                encoding="ascii"
            )
        except (OSError, UnicodeError):
            continue
        for value in children.split():
            try:
                pending.append(int(value, 10))
            except ValueError:
                continue
    return tuple(sorted(seen))


def _tree_is_gone(pids: tuple[int, ...]) -> bool:
    return all(not Path(f"/proc/{pid}").exists() for pid in pids)


def _cgroup_is_gone(path: Path) -> bool:
    """Return true only after the kernel cgroup directory is gone.

    An empty ``cgroup.procs`` is not enough: the directory and its controller
    state are still owned resources until the delegated lease is removed.
    """
    return not path.exists()


def _proc_diagnostic(pid: int) -> dict[str, str]:
    """Capture bounded survivor state for a failed external-oracle check."""
    diagnostic: dict[str, str] = {"pid": str(pid)}
    try:
        status = Path(f"/proc/{pid}/status").read_text(encoding="ascii")
    except (OSError, UnicodeError) as exc:
        diagnostic["status_read_error"] = f"{type(exc).__name__}: {exc}"
        return diagnostic
    for line in status.splitlines():
        key, separator, value = line.partition(":")
        if separator and key in {"Name", "State", "PPid", "NSpid"}:
            diagnostic[key] = " ".join(value.split())
    return diagnostic


def _temporary_home_paths() -> frozenset[Path]:
    """Snapshot producer-visible temporary execution homes."""
    root = Path(tempfile.gettempdir())
    try:
        return frozenset(
            path
            for path in root.iterdir()
            if path.name.startswith("khaos-home-") and not path.is_symlink()
        )
    except OSError as exc:
        raise RuntimeError(f"temporary execution home oracle failed: {exc}") from exc


def _wait_external_terminal(pids: tuple[int, ...], cgroup: Path) -> tuple[bool, str]:
    deadline = time.monotonic() + _ORACLE_DEADLINE
    while time.monotonic() < deadline:
        tree_gone = _tree_is_gone(pids)
        cgroup_gone = _cgroup_is_gone(cgroup)
        if tree_gone and cgroup_gone:
            return True, "external /proc tree and cgroup path disappeared"
        time.sleep(_ORACLE_POLL)
    survivors = [str(pid) for pid in pids if Path(f"/proc/{pid}").exists()]
    survivor_diagnostics = [
        _proc_diagnostic(int(pid)) for pid in survivors
    ]
    return False, (
        "external oracle timeout: "
        f"surviving_pids={','.join(survivors) or 'none'} "
        f"cgroup_present={cgroup.exists()} "
        f"survivor_state={json.dumps(survivor_diagnostics, sort_keys=True)}"
    )


def _tree_command() -> tuple[str, ...]:
    # The shell creates a parent, a child, and a grandchild.  The printed
    # namespace PIDs are diagnostics only; the host /proc tree is the PASS
    # oracle after cancellation/timeout/shutdown.
    return (
        "/bin/sh",
        "-c",
        "sh -c 'sleep 120 & grand=$!; printf GRAND:%s\\n \"$grand\"; wait' & child=$!; printf TREE:%s:%s\\n \"$$\" \"$child\"; wait",
    )


async def _wait_for_real_tree(
    supervisor: ProcessSupervisor,
    execution_id: str,
) -> tuple[int, tuple[int, ...]]:
    deadline = time.monotonic() + _ACTION_TIMEOUT
    while time.monotonic() < deadline:
        tree = _supervisor_process_tree(supervisor, execution_id)
        if tree:
            root_pid = tree[0]
            host_tree = _proc_tree(root_pid)
            if len(host_tree) >= 3:
                return root_pid, host_tree
        await asyncio.sleep(_ORACLE_POLL)
    raise RuntimeError(
        "independent host oracle did not observe a parent/child/grandchild process tree"
    )


async def _run_case(
    *,
    name: str,
    action: str,
    policy_digest: str,
    workspace_parent: Path,
) -> dict[str, object]:
    temporary_homes_before = _temporary_home_paths()
    workspace = Path(tempfile.mkdtemp(prefix=f"khaos-lifecycle-{name}-", dir=workspace_parent))
    supervisor = ProcessSupervisor()
    backend = LinuxBubblewrapBackend(supervisor)
    service = ExecutionService(
        backend=backend,
        process_supervisor=supervisor,
        principal_id=_COMPOSE_PRINCIPAL_ID,
        project_id="compose",
        runtime_id=_COMPOSE_RUNTIME_ID,
    )
    request = _probe_request(
        command=_tree_command(),
        workspace=workspace,
        policy_digest=policy_digest,
        timeout_seconds=1.0 if action == "timeout" else 15.0,
    )
    task = asyncio.create_task(service.execute(request), name=f"production-lifecycle:{name}")
    observed_pids: tuple[int, ...] = ()
    cgroup_path: Path | None = None
    error = ""
    actual_result: ExecutionResult | None = None
    oracle_ok = False
    oracle_detail = ""
    try:
        _, observed_pids = await _wait_for_real_tree(supervisor, request.correlation_id or "")
        lease = getattr(backend, "_cgroup_leases", {}).get(request.correlation_id)
        if lease is None:
            raise RuntimeError("production backend did not publish a kernel cgroup lease")
        cgroup_path = lease.path
        if action == "cancel":
            task.cancel()
        elif action == "shutdown":
            await service.shutdown()
        elif action == "timeout":
            # The backend watchdog owns this deadline; do not cancel the
            # coroutine or infer terminal state from a local timeout.
            pass
        try:
            actual_result = await asyncio.wait_for(task, timeout=_ACTION_TIMEOUT)
        except asyncio.CancelledError:
            pass
        except asyncio.TimeoutError:
            error = "execution task did not reach a terminal result"
        except BaseException as exc:  # noqa: BLE001 - diagnostics are fail-closed
            error = f"execution task: {type(exc).__name__}: {exc}"
        if action != "shutdown":
            try:
                await service.shutdown()
            except BaseException as exc:  # noqa: BLE001 - quarantine is evidence
                error = f"service shutdown: {type(exc).__name__}: {exc}"
        if cgroup_path is None:
            error = error or "cgroup lease identity was unavailable"
        else:
            oracle_ok, oracle_detail = _wait_external_terminal(observed_pids, cgroup_path)
            if not oracle_ok:
                error = error or oracle_detail
        if not service.terminal_postcondition():
            error = error or "ExecutionService terminal postcondition is false"
        if not backend.terminal_postcondition():
            error = error or "production backend terminal postcondition is false"
        if not supervisor.terminal_postcondition():
            error = error or "ProcessSupervisor terminal postcondition is false"
        if service.owned_resources() or backend.owned_resources() or supervisor.owned_resources():
            error = error or "production owner registry retained resources"
        retained_homes = _temporary_home_paths() - temporary_homes_before
        if retained_homes:
            error = error or (
                "temporary execution home retained: "
                + ",".join(sorted(str(path) for path in retained_homes))
            )
    except BaseException as exc:  # noqa: BLE001 - no PASS on incomplete cleanup
        error = error or f"lifecycle oracle: {type(exc).__name__}: {exc}"
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        try:
            await service.shutdown()
        except BaseException as cleanup_error:  # noqa: BLE001
            error = error or f"cleanup: {type(cleanup_error).__name__}: {cleanup_error}"
    finally:
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        if not service.terminal_postcondition():
            try:
                await service.shutdown()
            except BaseException as exc:  # noqa: BLE001
                error = error or f"final cleanup: {type(exc).__name__}: {exc}"
        try:
            workspace.rmdir()
        except OSError as exc:
            error = error or f"temporary execution workspace retained: {exc}"
        retained_homes = _temporary_home_paths() - temporary_homes_before
        if retained_homes:
            error = error or (
                "temporary execution home retained after final cleanup: "
                + ",".join(sorted(str(path) for path in retained_homes))
            )
    return {
        "name": name,
        "action": action,
        "result": "PASS" if not error else "FAIL",
        "error": error,
        "observed_host_pids": list(observed_pids),
        "observed_host_pid_count": len(observed_pids),
        "cgroup_path": str(cgroup_path) if cgroup_path is not None else "",
        "actual_status": actual_result.status if actual_result is not None else "cancelled",
        "actual_returncode": actual_result.return_code if actual_result is not None else None,
        "owner_postconditions": {
            "execution_service": {
                "terminal": service.terminal_postcondition(),
                "owned_resources": list(service.owned_resources()),
            },
            "production_sandbox_backend": {
                "terminal": backend.terminal_postcondition(),
                "owned_resources": list(backend.owned_resources()),
            },
            "process_supervisor": {
                "terminal": supervisor.terminal_postcondition(),
                "owned_resources": list(supervisor.owned_resources()),
            },
            "managed_process_handle": {
                "applicable": False,
                "reason": "production execution uses the native backend process owner",
            },
            "kernel_cgroup_lease": {
                "terminal": oracle_ok and not cgroup_path.exists()
                if cgroup_path is not None
                else False,
                "path": str(cgroup_path) if cgroup_path is not None else "",
            },
            "temporary_home": {
                "terminal": not bool(_temporary_home_paths() - temporary_homes_before),
            },
            "workspace_execution_lease": {
                "applicable": False,
                "reason": "read-only probe authority has no mutable TaskWorkspace lease",
            },
            "external_oracle": {
                "process_tree_gone": _tree_is_gone(observed_pids),
                "cgroup_gone": oracle_ok and not cgroup_path.exists()
                if cgroup_path is not None
                else False,
                "detail": oracle_detail,
            },
        },
    }


def _diagnostics(output_dir: Path, cases: list[dict[str, object]]) -> dict[str, object]:
    junit = output_dir / "production-lifecycle.junit.xml"
    suite = ET.Element(
        "testsuite",
        {
            "name": "production-lifecycle",
            "tests": str(len(cases)),
            "failures": str(sum(case["result"] != "PASS" for case in cases)),
            "errors": "0",
        },
    )
    for case in cases:
        testcase = ET.SubElement(suite, "testcase", {"name": str(case["name"])})
        if case["result"] != "PASS":
            ET.SubElement(testcase, "failure", {"message": str(case["error"])[:512]})
    ET.ElementTree(suite).write(junit, encoding="utf-8", xml_declaration=True)
    stdout = output_dir / "production-lifecycle.stdout.log"
    stderr = output_dir / "production-lifecycle.stderr.log"
    stdout.write_text(json.dumps(cases, sort_keys=True) + "\n", encoding="utf-8")
    stderr.write_text(
        "\n".join(str(case["error"]) for case in cases if case["error"]),
        encoding="utf-8",
    )
    from khaos.security.producer_evidence import diagnostics_from_junit

    return diagnostics_from_junit(
        proof_name="production_lifecycle",
        junit=junit,
        returncode=0 if all(case["result"] == "PASS" for case in cases) else 1,
        stdout=stdout,
        stderr=stderr,
    )


def _production_identity(runtime_manifest: dict[str, object]) -> dict[str, object]:
    socket_path = Path(os.environ["KHAOS_AUTHORITYD_SOCKET"])
    key_path = Path(os.environ["KHAOS_AUTHORITYD_PUBLIC_KEY_PATH"])
    socket_info = socket_path.lstat()
    key_info = key_path.lstat()
    if (
        not stat.S_ISSOCK(socket_info.st_mode)
        or socket_info.st_uid != int(os.environ.get("KHAOS_AUTHORITYD_UID", "0"))
        or socket_info.st_mode & 0o007
        or not stat.S_ISREG(key_info.st_mode)
        or key_path.is_symlink()
        or key_info.st_uid != int(os.environ.get("KHAOS_AUTHORITYD_UID", "0"))
        or key_info.st_mode & 0o022
    ):
        raise RuntimeError("production authority identity is not proven")
    from khaos.coding.execution.platform import _linux_sandbox_launcher

    sandbox_launcher = _linux_sandbox_launcher()
    exec_launcher = Path(os.environ.get("KHAOS_EXEC_LAUNCHER", ""))
    if sandbox_launcher is None or not exec_launcher.is_file() or exec_launcher.is_symlink():
        raise RuntimeError("production launcher identity is unavailable")
    authority_identity = {
        "socket_path": str(socket_path),
        "socket_owner_uid": int(socket_info.st_uid),
        "public_key_digest": sha256_file(key_path),
        "authority_profile": os.environ.get("KHAOS_AUTHORITY_PROFILE", ""),
    }
    return {
        "runtime_composition_digest": _runtime_composition_digest(runtime_manifest),
        "production_composition_manifest_digest": canonical_digest(runtime_manifest),
        "launcher_digest": canonical_digest(
            {
                "sandbox_launcher": sha256_file(sandbox_launcher),
                "exec_launcher": sha256_file(exec_launcher),
            }
        ),
        "authority_proof_identity": authority_identity,
        "authority_proof_digest": canonical_digest(authority_identity),
        "host_backend_absent": True,
        "dev_fallback_absent": True,
        "production_mode": True,
        "authority_profile": os.environ.get("KHAOS_AUTHORITY_PROFILE", ""),
    }


async def _run() -> int:
    args = _args()
    if os.environ.get("KHAOS_AUTHORITY_PROFILE") != "native-production":
        raise SystemExit("production lifecycle probe requires native-production authority")
    policy_digest = os.environ.get("KHAOS_EFFECTIVE_POLICY_DIGEST", "")
    commit = os.environ.get("GITHUB_SHA", "")
    if not policy_digest or not commit:
        raise SystemExit("production lifecycle probe requires policy digest and commit")
    workspace_parent = Path("/app/data")
    if not workspace_parent.is_dir():
        raise SystemExit("production lifecycle probe requires /app/data")
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    runtime_manifest = await _build_runtime_manifest(workspace_parent)
    cases = [
        await _run_case(
            name="cancellation",
            action="cancel",
            policy_digest=policy_digest,
            workspace_parent=workspace_parent,
        ),
        await _run_case(
            name="timeout",
            action="timeout",
            policy_digest=policy_digest,
            workspace_parent=workspace_parent,
        ),
        await _run_case(
            name="shutdown",
            action="shutdown",
            policy_digest=policy_digest,
            workspace_parent=workspace_parent,
        ),
    ]
    diagnostics = _diagnostics(output_dir, cases)
    identity = _production_identity(runtime_manifest)
    workflow = {
        "repository": os.environ.get("GITHUB_REPOSITORY", ""),
        "workflow": os.environ.get("GITHUB_WORKFLOW", ""),
        "run_id": os.environ.get("GITHUB_RUN_ID", ""),
        "run_attempt": int(os.environ.get("GITHUB_RUN_ATTEMPT", "0")),
        "event": os.environ.get("GITHUB_EVENT_NAME", ""),
        "ref": os.environ.get("GITHUB_REF", ""),
        "head_sha": commit,
        "runner_os": os.environ.get("RUNNER_OS", ""),
        "job": os.environ.get("GITHUB_JOB", ""),
    }
    process_proof = build_runtime_producer_proof(
        proof_type=PROCESS_TREE_PROOF,
        commit=commit,
        policy_digest=policy_digest,
        workflow=workflow,
        diagnostics=diagnostics,
        production_identity=identity,
    )
    resource_proof = build_runtime_producer_proof(
        proof_type=RESOURCE_OWNER_PROOF,
        commit=commit,
        policy_digest=policy_digest,
        workflow=workflow,
        diagnostics=diagnostics,
        production_identity=identity,
    )
    write_producer_proof(output_dir / "production-process-tree-proof.json", process_proof)
    write_producer_proof(output_dir / "production-resource-owner-proof.json", resource_proof)
    (output_dir / "production-lifecycle-cases.json").write_text(
        json.dumps(cases, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    for case in cases:
        print(
            f"production lifecycle {case['name']}: result={case['result']} "
            f"host_pids={case['observed_host_pid_count']} "
            f"status={case['actual_status']} returncode={case['actual_returncode']}"
        )
        if case["error"]:
            print(f"production lifecycle {case['name']} error: {case['error']}")
    return 0 if all(case["result"] == "PASS" for case in cases) else 1


def main() -> int:
    return asyncio.run(_run())


if __name__ == "__main__":
    raise SystemExit(main())
