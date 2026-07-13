"""M4 Batch 3.1 trusted verification contracts and isolation matrix."""
from __future__ import annotations

import asyncio
import hashlib
import os
import sqlite3
import stat
import time
from dataclasses import replace
from pathlib import Path

import pytest

from _m4_batch2_helpers import verification
from test_m4_batch3_0_workspace_mutation import (
    _apply, _authorize, _bundle, _hash, _plan, _workspace,
)
from test_m4_batch2_8_boot_scope_closure import _real_runtime
from khaos.coding.planning.approval import PlanApprovalStore
from khaos.coding.planning.approval.repository import PersistedPlanRepository
from khaos.coding.planning.contracts import (
    PlanEvidence, VerificationCatalogEntry, VerificationRequirement,
)
from khaos.coding.planning.execution_models import (
    ExecutionRunStatus, PlanExecutionRun, PlannedEditOperation, PlannedFileEdit,
)
from khaos.coding.planning.trusted_verification import (
    SandboxProfile, TrustedCommandFactory, TrustedToolchain,
    VerificationWorkspaceFactory,
)
from khaos.coding.planning.verification_execution_models import (
    TrustedVerificationCommand, VerificationExecutionRun, VerificationRunStatus,
    VerificationStepRun, VerificationStepStatus, verification_plan_digest,
)
from khaos.coding.planning.verification_sandbox import (
    DockerVerificationSandboxBackend, SandboxStepResult,
)
from khaos.coding.planning.verification_sandbox_instance import (
    SandboxInstanceState, VerificationSandboxInstance,
)
from khaos.coding.planning.verification_store import VerificationExecutionStore


IMAGE = "sha256:eb43ff125d8d58d7449dcba7d336c23bcac412f526d861db493b9994d8010280"


def _profile(*, network=False, read_only=True):
    return SandboxProfile(
        "python-offline-v1", IMAGE, network_enabled=network,
        read_only_root=read_only, run_as_user=f"{os.getuid()}:{os.getgid()}",
    )


def _entry(argv=("python", "-m", "pytest", "-q"), *, language="python", kind="unit-test"):
    return VerificationCatalogEntry(
        language, kind, argv, "repository", "pyproject.toml",
        "pyproject.toml", "a" * 64, "high",
    )


def _requirement(argv=("python", "-m", "pytest", "-q"), *, scope="python", required=True):
    return VerificationRequirement(
        argv, "unit-test", scope, "exit 0", required, "low", (),
    )


def _factory(profile=None):
    profile = profile or _profile()
    return TrustedCommandFactory((
        TrustedToolchain("python", "python", "/usr/local/bin/python3", "3.13", IMAGE),
        TrustedToolchain("npm", "javascript", "/usr/local/bin/npm", "11", IMAGE),
        TrustedToolchain("npm", "typescript", "/usr/local/bin/npm", "11", IMAGE),
        TrustedToolchain("go", "go", "/usr/local/go/bin/go", "1.25", IMAGE),
        TrustedToolchain("cargo", "rust", "/usr/local/bin/cargo", "1.90", IMAGE),
    ), (profile,))


@pytest.mark.parametrize("argv", [
    (), ("sh", "-c", "pytest"), ("bash", "-c", "pytest"),
    ("cmd", "/c", "pytest"), ("powershell", "-Command", "pytest"),
    ("env", "python"), ("xargs", "python"), ("python\x00",),
    ("python", "a;id"), ("python", "a&&id"), ("python", "$(id)"),
    ("./python", "-m", "pytest"), ("/usr/bin/python", "-m", "pytest"),
    ("npm", "install"), ("npm", "exec", "jest"),
])
def test_command_factory_rejects_untrusted_argv(argv):
    entry = _entry(argv=argv)
    requirement = _requirement(argv=argv)
    with pytest.raises(PermissionError):
        _factory().build((requirement,), (entry,), profile_id="python-offline-v1")


@pytest.mark.parametrize("mutation", [
    "absent-entry", "scope", "kind", "argv", "network", "writable-root",
    "wrong-image", "missing-tool", "required-manual",
])
def test_command_binding_fails_closed(mutation):
    profile = _profile(network=mutation == "network", read_only=mutation != "writable-root")
    factory = _factory(profile)
    entry = _entry()
    requirement = _requirement()
    entries = (entry,)
    if mutation == "absent-entry":
        entries = ()
    elif mutation == "scope":
        requirement = replace(requirement, scope="go")
    elif mutation == "kind":
        requirement = replace(requirement, verification_type="lint")
    elif mutation == "argv":
        requirement = replace(requirement, command=("python", "-m", "unittest"))
    elif mutation == "wrong-image":
        profile = replace(profile, image_digest="sha256:" + "b" * 64)
        factory = _factory(profile)
    elif mutation == "missing-tool":
        entry = replace(entry, language="ruby")
        requirement = replace(requirement, scope="ruby")
        entries = (entry,)
    elif mutation == "required-manual":
        requirement = replace(requirement, command=None)
    with pytest.raises((PermissionError, ValueError)):
        factory.build((requirement,), entries, profile_id=profile.profile_id)


def test_command_digest_is_canonical_and_caller_fields_are_absent():
    first = _factory().build((_requirement(),), (_entry(),), profile_id="python-offline-v1")[0]
    second = _factory().build((_requirement(),), (_entry(),), profile_id="python-offline-v1")[0]
    assert first == second
    assert first.argv[0] == "/usr/local/bin/python3"
    assert not hasattr(first, "env")
    assert not hasattr(first, "image")
    assert verification_plan_digest(
        (first,), catalog_fingerprint="catalog", sandbox_profile_digest=_profile().digest,
    ) == verification_plan_digest(
        (second,), catalog_fingerprint="catalog", sandbox_profile_digest=_profile().digest,
    )


@pytest.mark.parametrize("field,value", [
    ("argv", ("/usr/local/bin/python3", "-c", "print('tampered')")),
    ("cwd", "subdir"), ("timeout_ms", 999999),
    ("output_limit_bytes", 999999), ("expected_exit_codes", (0, 7)),
    ("config_hash", "tampered"), ("toolchain_version", "tampered"),
    ("sandbox_profile_id", "tampered"), ("executable_id", "tampered"),
    ("executes_project_code", False),
])
def test_caller_command_field_tampering_is_rejected_before_process(tmp_path, field, value):
    command = _factory().build(
        (_requirement(),), (_entry(),), profile_id="python-offline-v1",
    )[0]
    tampered = replace(command, **{field: value})
    workspace_root = tmp_path / "copy"
    workspace_root.mkdir()
    workspace = type("Workspace", (), {"root": workspace_root})()
    backend = DockerVerificationSandboxBackend(profile=_profile())
    with pytest.raises(PermissionError):
        asyncio.run(backend.execute(tampered, workspace))


@pytest.mark.parametrize("language,executable,absolute,argv", [
    ("python", "python", "/usr/local/bin/python3", ("python", "-m", "pytest", "-q")),
    ("javascript", "npm", "/usr/local/bin/npm", ("npm", "run", "test")),
    ("typescript", "npm", "/usr/local/bin/npm", ("npm", "run", "typecheck")),
    ("go", "go", "/usr/local/go/bin/go", ("go", "test", "./...")),
    ("rust", "cargo", "/usr/local/bin/cargo", ("cargo", "test")),
])
def test_language_catalog_commands_resolve_only_to_manifest_toolchain(
    language, executable, absolute, argv,
):
    entry = _entry(argv=argv, language=language)
    requirement = replace(_requirement(argv=argv), scope=language)
    command = _factory().build(
        (requirement,), (entry,), profile_id="python-offline-v1",
    )[0]
    assert command.executable_id == executable
    assert command.argv[0] == absolute


@pytest.mark.parametrize("cwd", ["/tmp", "../outside", "a/../b", "a//b", "C:\\temp"])
def test_unsafe_verification_cwd_rejected_before_process(tmp_path, cwd):
    command = replace(_docker_command("-c", "print(1)"), cwd=cwd)
    command = command.normalized()
    workspace_root = tmp_path / "copy"
    workspace_root.mkdir()
    workspace = type("Workspace", (), {"root": workspace_root})()
    backend = DockerVerificationSandboxBackend(profile=_profile())
    with pytest.raises(PermissionError):
        asyncio.run(backend.execute(command, workspace))


@pytest.mark.parametrize("unsafe", ["symlink", "git", "overlap", "fifo"])
def test_verification_workspace_copy_boundaries(tmp_path, unsafe):
    source = tmp_path / "canonical"
    source.mkdir()
    (source / "a.py").write_text("print('ok')\n")
    (source / ".git").write_text("gitdir: elsewhere\n")
    if unsafe == "symlink":
        (source / "escape").symlink_to(tmp_path / "outside")
    elif unsafe == "fifo":
        os.mkfifo(source / "pipe")
    root = source / "copies" if unsafe == "overlap" else tmp_path / "copies"
    factory = VerificationWorkspaceFactory(root)
    if unsafe in {"symlink", "overlap", "fifo"}:
        with pytest.raises(PermissionError):
            factory.create(source, forbidden_roots=(source,))
    else:
        copied = factory.create(source, forbidden_roots=(source,))
        assert not (copied.root / ".git").exists()
        assert (copied.root / "a.py").read_bytes() == (source / "a.py").read_bytes()
        assert (copied.root / "a.py").stat().st_ino != (source / "a.py").stat().st_ino
        factory.destroy(copied)


def _execution_run(run_id="run1"):
    now = time.time()
    return PlanExecutionRun(
        run_id, "plan", "p-hash", "approval", "authorization", "context", "lease",
        "task", "workspace", "repository", "abc", 1, "binding", "bundle",
        ExecutionRunStatus.CREATED, now, now,
    )


def _mutated_store(tmp_path):
    approval = PlanApprovalStore(sqlite3.connect(tmp_path / "state.sqlite"))
    run = _execution_run()
    approval.create_execution_run(run)
    approval.transition_execution_run(run.execution_run_id, expected=("created",), target="validating")
    approval.transition_execution_run(run.execution_run_id, expected=("validating",), target="mutating")
    approval.transition_execution_run(run.execution_run_id, expected=("mutating",), target="sealing")
    approval.transition_execution_run(run.execution_run_id, expected=("sealing",), target="mutated")
    return approval, VerificationExecutionStore(approval)


def _verification_run(status=VerificationRunStatus.CREATED):
    now = time.time()
    return VerificationExecutionRun(
        "verify1", "run1", "plan", "p-hash", "approval", "vctx", "task",
        "workspace", "repository", "bundle", "attestation", "verify-digest",
        "catalog", "profile", status, now, now,
    )


@pytest.mark.parametrize("target", [
    VerificationRunStatus.VALIDATING, VerificationRunStatus.PREPARING_SANDBOX,
    VerificationRunStatus.RUNNING, VerificationRunStatus.PASSED,
    VerificationRunStatus.FAILED, VerificationRunStatus.ERRORED,
    VerificationRunStatus.TIMED_OUT, VerificationRunStatus.CANCELLED,
])
def test_verification_store_cas_and_atomic_execution_status(tmp_path, target):
    approval, store = _mutated_store(tmp_path)
    run, duplicate = store.create_run(_verification_run())
    assert not duplicate
    if target == VerificationRunStatus.VALIDATING:
        store.transition_run("verify1", expected=(VerificationRunStatus.CREATED,), target=target)
        return
    store.transition_run("verify1", expected=(VerificationRunStatus.CREATED,), target=VerificationRunStatus.VALIDATING)
    if target == VerificationRunStatus.PREPARING_SANDBOX:
        store.transition_run("verify1", expected=(VerificationRunStatus.VALIDATING,), target=target)
        return
    store.transition_run("verify1", expected=(VerificationRunStatus.VALIDATING,), target=VerificationRunStatus.PREPARING_SANDBOX)
    store.transition_run("verify1", expected=(VerificationRunStatus.PREPARING_SANDBOX,), target=VerificationRunStatus.RUNNING)
    if target == VerificationRunStatus.RUNNING:
        assert approval.get_execution_run("run1").status == ExecutionRunStatus.VERIFYING
        return
    store.transition_run("verify1", expected=(VerificationRunStatus.RUNNING,), target=target)
    expected = {
        VerificationRunStatus.PASSED: ExecutionRunStatus.VERIFIED,
        VerificationRunStatus.FAILED: ExecutionRunStatus.VERIFICATION_FAILED,
        VerificationRunStatus.ERRORED: ExecutionRunStatus.VERIFICATION_ERROR,
        VerificationRunStatus.TIMED_OUT: ExecutionRunStatus.VERIFICATION_ERROR,
        VerificationRunStatus.CANCELLED: ExecutionRunStatus.CANCELLED,
    }[target]
    assert approval.get_execution_run("run1").status == expected


def test_verification_store_idempotency_digest_conflict_and_crash_recovery(tmp_path):
    approval, store = _mutated_store(tmp_path)
    original, duplicate = store.create_run(_verification_run())
    assert not duplicate
    same, duplicate = store.create_run(_verification_run())
    assert duplicate and same == original
    with pytest.raises(RuntimeError, match="digest"):
        store.create_run(replace(_verification_run(), verification_plan_digest="different"))
    store.transition_run("verify1", expected=(VerificationRunStatus.CREATED,), target=VerificationRunStatus.VALIDATING)
    store.transition_run("verify1", expected=(VerificationRunStatus.VALIDATING,), target=VerificationRunStatus.PREPARING_SANDBOX)
    store.transition_run("verify1", expected=(VerificationRunStatus.PREPARING_SANDBOX,), target=VerificationRunStatus.RUNNING)
    assert store.recover_interrupted() == 1
    assert store.get_run_by_execution("run1").status == VerificationRunStatus.ERRORED
    assert approval.get_execution_run("run1").status == ExecutionRunStatus.VERIFICATION_ERROR


@pytest.mark.parametrize("bad", ["jump", "backward", "wrong-cas", "double-terminal"])
def test_verification_store_rejects_invalid_transition(tmp_path, bad):
    _, store = _mutated_store(tmp_path)
    store.create_run(_verification_run())
    with pytest.raises(RuntimeError):
        if bad == "jump":
            store.transition_run("verify1", expected=(VerificationRunStatus.CREATED,), target=VerificationRunStatus.RUNNING)
        elif bad == "backward":
            store.transition_run("verify1", expected=(VerificationRunStatus.CREATED,), target=VerificationRunStatus.PREPARING_SANDBOX)
        elif bad == "wrong-cas":
            store.transition_run("verify1", expected=(VerificationRunStatus.VALIDATING,), target=VerificationRunStatus.PREPARING_SANDBOX)
        else:
            store.transition_run("verify1", expected=(VerificationRunStatus.CREATED,), target=VerificationRunStatus.CANCELLED)
            store.transition_run("verify1", expected=(VerificationRunStatus.CREATED,), target=VerificationRunStatus.CANCELLED)


class UnsafeTestSandboxBackend:
    """Does not create host processes; records server-owned command only."""
    BACKEND_ID = "unsafe-test-v1"

    def __init__(self, profile):
        self.profile = profile
        self.calls = []

    async def probe(self):
        return self.profile.image_digest

    async def execute(self, command, workspace, *, cancellation=None, **kwargs):
        self.calls.append((command, workspace))
        data = b"trusted fake output"
        return SandboxStepResult(
            "fake-sandbox", self.profile.image_digest, 0, None, 1, data, b"",
            hashlib.sha256(data).hexdigest(), hashlib.sha256(b"").hexdigest(), False,
        )


def _verification_plan(plan, workspace):
    (workspace.worktree_path / "pyproject.toml").write_text("[tool.pytest.ini_options]\n")
    catalog = __import__(
        "khaos.coding.planning.verification_catalog", fromlist=["VerificationCatalog"]
    ).VerificationCatalog(workspace.worktree_path, repository_id=plan.repository_id)
    entry = catalog.entries[0]
    requirement = VerificationRequirement(
        entry.argv, entry.verification_type, entry.language, "exit 0", True, "low",
        (PlanEvidence(
            "verification-config", plan.repository_id,
            path=entry.config_path, query=entry.provenance, confidence=1.0,
            metadata={"config_hash": entry.config_hash},
        ),),
    )
    steps = tuple(replace(step, verification_requirements=(requirement,)) for step in plan.steps)
    candidate = replace(plan, steps=steps, verification_requirements=(requirement,))
    return replace(candidate, content_hash=PersistedPlanRepository._recompute_plan_content_hash(candidate))


def test_runtime_phase_context_runner_is_idempotent_and_canonical_workspace_unchanged(tmp_path):
    edit = PlannedFileEdit(
        "e1", "s1", PlannedEditOperation.CREATE, "fixture.py",
        expected_exists=False, new_content="print('fixture')\n",
    )
    runtime, _, workspaces, _ = _real_runtime(tmp_path)
    workspace = _workspace(tmp_path, workspaces)
    plan = _plan((edit,))
    plan = _verification_plan(plan, workspace)
    plan, authorization = _authorize(runtime, plan)
    result = _apply(runtime, plan, authorization, _bundle(plan, (edit,)))
    canonical_before = {
        path.relative_to(workspace.worktree_path).as_posix(): path.read_bytes()
        for path in workspace.worktree_path.rglob("*") if path.is_file()
    }
    profile = _profile()
    backend = UnsafeTestSandboxBackend(profile)
    runtime.configure_trusted_verification(
        backend=backend, command_factory=_factory(profile),
        workspace_factory=VerificationWorkspaceFactory(tmp_path / "verification-copies"),
        artifact_root=tmp_path / "verification-artifacts", profile=profile,
    )

    async def scenario():
        async with runtime.acquire_verification_context(
            execution_run_id=result.execution_run_id, owner_execution_id="verifier",
        ) as context:
            forged = replace(context)
            with pytest.raises(PermissionError, match="issued by runtime"):
                await runtime.run_trusted_verification(context=forged)
            first = await runtime.run_trusted_verification(context=context)
            second = await runtime.run_trusted_verification(context=context)
            return first, second

    first, second = runtime._test_sync._loop.run_until_complete(scenario())
    assert first.status == VerificationRunStatus.PASSED
    assert second.idempotent
    assert len(backend.calls) == 1
    assert runtime._store.get_execution_run(result.execution_run_id).status == ExecutionRunStatus.VERIFIED
    canonical_after = {
        path.relative_to(workspace.worktree_path).as_posix(): path.read_bytes()
        for path in workspace.worktree_path.rglob("*") if path.is_file()
    }
    assert canonical_after == canonical_before
    database_text = "\n".join(runtime._store._conn.iterdump())
    assert "print('fixture')" not in database_text
    assert "trusted fake output" not in database_text
    assert str(tmp_path) not in database_text
    artifact = runtime._store._conn.execute(
        "SELECT relative_name FROM plan_verification_artifacts"
    ).fetchone()[0]
    assert not Path(artifact).is_absolute()
    assert stat.S_IMODE((tmp_path / "verification-artifacts" / artifact).stat().st_mode) == 0o600
    assert not tuple((tmp_path / "verification-copies").iterdir())


def _docker_command(*argv, timeout=10_000, limit=64 * 1024):
    return TrustedVerificationCommand(
        "docker-e2e", "requirement-1", "unit-test", "python", "python",
        ("/usr/local/bin/python3", *argv), ".", "server-rule", "server-hash",
        "python:python", "3.13", "python-offline-v1", timeout, limit, (0,), True,
    ).normalized()


@pytest.mark.production_sandbox_real
def test_real_docker_sandbox_python_network_secret_workspace_and_timeout(tmp_path, monkeypatch):
    if os.environ.get("KHAOS_RUN_PRODUCTION_SANDBOX") != "1":
        pytest.skip("set KHAOS_RUN_PRODUCTION_SANDBOX=1 for the production backend E2E")
    source = tmp_path / "canonical"
    source.mkdir()
    secret = "KHAOS_HOST_SECRET_7dff8c"
    (source / "fixture.py").write_text(
        "import os,socket\n"
        "assert os.getenv('KHAOS_E2E_SECRET') is None\n"
        "try:\n socket.create_connection(('1.1.1.1',53),0.2)\n"
        "except OSError:\n pass\n"
        "else:\n raise AssertionError('network available')\n"
        "open('sandbox-output.txt','w').write('sandbox only')\n"
        "print('trusted-python-pass')\n"
    )
    monkeypatch.setenv("KHAOS_E2E_SECRET", secret)
    factory = VerificationWorkspaceFactory(tmp_path / "copies")
    disposable = factory.create(source, forbidden_roots=(source,))
    backend = DockerVerificationSandboxBackend(
        profile=_profile(), secret_values=(secret,), host_paths=(tmp_path,),
    )

    async def scenario():
        await backend.probe()
        passed = await backend.execute(_docker_command("fixture.py"), disposable)
        bounded = await backend.execute(
            _docker_command(
                "-c",
                f"import os; os.write(1,b'{secret}\\xff'+b'x'*100000)",
                limit=1024,
            ), disposable,
        )
        timeout = await backend.execute(
            _docker_command(
                "-c",
                "import subprocess,sys,time; "
                "subprocess.Popen([sys.executable,'-c',\"import time;time.sleep(5);"
                "open('/workspace/escaped','w').write('bad')\"]); time.sleep(30)",
                timeout=300,
            ), disposable,
        )
        await asyncio.sleep(5.2)
        return passed, bounded, timeout

    passed, bounded, timeout = asyncio.run(scenario())
    assert passed.exit_code == 0 and b"trusted-python-pass" in passed.stdout, passed.stderr
    assert timeout.timed_out
    assert bounded.output_truncated
    assert b"<redacted-secret>" in bounded.stdout
    assert secret.encode() not in bounded.stdout
    assert b"\xef\xbf\xbd" in bounded.stdout
    assert not (disposable.root / "escaped").exists()
    assert not (source / "sandbox-output.txt").exists()
    assert (disposable.root / "sandbox-output.txt").read_text() == "sandbox only"
    assert secret.encode() not in passed.stdout + passed.stderr
    factory.destroy(disposable)


def test_static_planned_verification_has_no_agent_tool_or_shell_route():
    import inspect
    from khaos.coding.planning import trusted_verification_runner, verification_sandbox
    source = inspect.getsource(trusted_verification_runner) + inspect.getsource(verification_sandbox)
    assert "ToolScheduler" not in source
    assert "terminal_tools" not in source
    assert "planned_tool_invocation" not in source
    assert "test_tools" not in source
    assert "shell=True" not in source
    assert "ChangeSet" not in source
    assert "git commit" not in source
    assert "git push" not in source


# ----------------------------------------------------------------------
# Batch 3.1.1 §2/§3/§5: crash reconciliation, atomic termination,
# artifact RESERVED→SEALED protocol, sandbox instance lifecycle.
# ----------------------------------------------------------------------

def _sandbox_instance(
    *, sandbox_instance_id="vsi-1", verification_run_id="verify1",
    step_run_id="step-1", state=SandboxInstanceState.PREPARED,
    boot_id="boot-1",
):
    return VerificationSandboxInstance(
        sandbox_instance_id=sandbox_instance_id,
        verification_run_id=verification_run_id,
        step_run_id=step_run_id,
        backend_id="docker-verification-v1",
        backend_instance_name="khaos-verify-test",
        runtime_epoch=1,
        boot_id=boot_id,
        image_reference=IMAGE,
        expected_image_digest=IMAGE,
        actual_image_digest=IMAGE,
        workspace_manifest_digest="manifest-hash",
        container_id="container-abc",
        state=state,
    )


def _step_run(
    *, step_run_id="step-1", verification_run_id="verify1",
    status=VerificationStepStatus.RUNNING, ordinal=0,
):
    return VerificationStepRun(
        step_run_id=step_run_id, verification_run_id=verification_run_id,
        requirement_id="requirement-1", command_id="verify-1",
        command_digest="digest", ordinal=ordinal, status=status,
        started_at=time.time(), timeout_ms=10_000,
    )


def _running_store(tmp_path):
    """Create a store with a run in RUNNING state and one RUNNING step."""
    approval, store = _mutated_store(tmp_path)
    store.create_run(_verification_run())
    store.transition_run(
        "verify1", expected=(VerificationRunStatus.CREATED,),
        target=VerificationRunStatus.VALIDATING,
    )
    store.transition_run(
        "verify1", expected=(VerificationRunStatus.VALIDATING,),
        target=VerificationRunStatus.PREPARING_SANDBOX,
    )
    store.transition_run(
        "verify1", expected=(VerificationRunStatus.PREPARING_SANDBOX,),
        target=VerificationRunStatus.RUNNING,
    )
    store.create_steps((_step_run(),))
    return approval, store


@pytest.mark.parametrize("active_state", [
    SandboxInstanceState.PREPARED, SandboxInstanceState.STARTING,
    SandboxInstanceState.RUNNING, SandboxInstanceState.TERMINATING,
])
def test_reconcile_sandbox_instances_marks_active_orphaned(tmp_path, active_state):
    """Batch 3.1.1 §2: active sandbox instances are ORPHANED on restart."""
    _, store = _running_store(tmp_path)
    store.create_sandbox_instance(_sandbox_instance(state=active_state))
    count = store.reconcile_sandbox_instances()
    assert count == 1
    instance = store.get_sandbox_instance("vsi-1")
    assert instance.state == SandboxInstanceState.ORPHANED
    assert instance.failure_code == "runtime-restart-orphaned"


def test_reconcile_sandbox_instances_skips_terminal(tmp_path):
    """Batch 3.1.1 §2: terminal sandbox instances are NOT re-orphaned."""
    _, store = _running_store(tmp_path)
    store.create_sandbox_instance(_sandbox_instance(state=SandboxInstanceState.TERMINATED))
    count = store.reconcile_sandbox_instances()
    assert count == 0
    instance = store.get_sandbox_instance("vsi-1")
    assert instance.state == SandboxInstanceState.TERMINATED


def test_finish_step_and_run_is_atomic(tmp_path):
    """Batch 3.1.1 §3: finish_step_and_run transitions step+run+execution."""
    approval, store = _running_store(tmp_path)
    step = store.list_steps("verify1")[0]
    finished = replace(step, status=VerificationStepStatus.PASSED, exit_code=0)
    store.finish_step_and_run(finished)
    assert store.list_steps("verify1")[0].status == VerificationStepStatus.PASSED
    assert store.get_run_by_execution("run1").status == VerificationRunStatus.PASSED
    assert approval.get_execution_run("run1").status == ExecutionRunStatus.VERIFIED
    assert store.assert_no_running_steps_in_terminal_run() == 0


def test_fail_step_and_run_is_atomic(tmp_path):
    """Batch 3.1.1 §3: fail_step_and_run transitions step+run+execution."""
    approval, store = _running_store(tmp_path)
    step = store.list_steps("verify1")[0]
    failed = replace(step, status=VerificationStepStatus.FAILED, exit_code=1)
    store.fail_step_and_run(failed)
    assert store.list_steps("verify1")[0].status == VerificationStepStatus.FAILED
    assert store.get_run_by_execution("run1").status == VerificationRunStatus.FAILED
    assert approval.get_execution_run("run1").status == ExecutionRunStatus.VERIFICATION_FAILED


def test_timeout_step_and_run_is_atomic(tmp_path):
    """Batch 3.1.1 §3: timeout_step_and_run transitions step+run+execution."""
    approval, store = _running_store(tmp_path)
    step = store.list_steps("verify1")[0]
    timed = replace(step, status=VerificationStepStatus.TIMED_OUT)
    store.timeout_step_and_run(timed)
    assert store.list_steps("verify1")[0].status == VerificationStepStatus.TIMED_OUT
    assert store.get_run_by_execution("run1").status == VerificationRunStatus.TIMED_OUT
    assert approval.get_execution_run("run1").status == ExecutionRunStatus.VERIFICATION_ERROR


def test_abort_step_and_run_is_atomic(tmp_path):
    """Batch 3.1.1 §3: abort_step_and_run transitions step+run+execution."""
    approval, store = _running_store(tmp_path)
    store.abort_step_and_run("step-1", verification_run_id="verify1", failure_code="backend-crash")
    assert store.list_steps("verify1")[0].status == VerificationStepStatus.ABORTED
    assert store.get_run_by_execution("run1").status == VerificationRunStatus.ERRORED
    assert approval.get_execution_run("run1").status == ExecutionRunStatus.VERIFICATION_ERROR
    assert store.assert_no_running_steps_in_terminal_run() == 0


def test_assert_no_running_steps_in_terminal_run_detects_violation(tmp_path):
    """Batch 3.1.1 §3 invariant: terminal run with RUNNING step is detected."""
    approval, store = _running_store(tmp_path)
    # Force the run to PASSED without transitioning the step.
    approval._conn.execute(
        "UPDATE plan_verification_runs SET status='passed' WHERE verification_run_id='verify1'"
    )
    approval._conn.commit()
    # Step is still RUNNING, run is PASSED — invariant violated.
    assert store.assert_no_running_steps_in_terminal_run() == 1


def test_artifact_reserved_to_sealed_protocol(tmp_path):
    """Batch 3.1.1 §5: artifact transitions RESERVED → SEALED atomically."""
    _, store = _running_store(tmp_path)
    store.reserve_artifact(
        artifact_id="art-1", verification_run_id="verify1",
        relative_name="verify1/output.txt", expires_at=time.time() + 3600,
    )
    # Artifact is RESERVED, not yet SEALED.
    unsealed = store.list_unsealed_artifacts()
    assert len(unsealed) == 1
    assert unsealed[0]["artifact_id"] == "art-1"
    # Seal it.
    store.seal_artifact(artifact_id="art-1", content_digest="sha256:abc", byte_length=42)
    assert len(store.list_unsealed_artifacts()) == 0
    # Sealing again fails (CAS).
    with pytest.raises(RuntimeError, match="CAS failed"):
        store.seal_artifact(artifact_id="art-1", content_digest="sha256:abc", byte_length=42)


def test_artifact_quarantine(tmp_path):
    """Batch 3.1.1 §5: quarantine marks artifact as quarantined."""
    _, store = _running_store(tmp_path)
    store.reserve_artifact(
        artifact_id="art-2", verification_run_id="verify1",
        relative_name="verify1/bad.txt", expires_at=time.time() + 3600,
    )
    store.quarantine_artifact("art-2", reason="suspected-tamper")
    row = store._conn.execute(
        "SELECT quarantined, status FROM plan_verification_artifacts WHERE artifact_id='art-2'"
    ).fetchone()
    assert row[0] == 1
    assert row[1] == "quarantined"


def test_artifact_seal_cas_rejects_unreserved(tmp_path):
    """Batch 3.1.1 §5: sealing a non-RESERVED artifact fails."""
    _, store = _running_store(tmp_path)
    with pytest.raises(RuntimeError, match="CAS failed"):
        store.seal_artifact(artifact_id="nonexistent", content_digest="sha256:x", byte_length=1)


def test_list_artifacts_without_files(tmp_path):
    """Batch 3.1.1 §5: SEALED artifacts missing files are detected."""
    _, store = _running_store(tmp_path)
    store.reserve_artifact(
        artifact_id="art-3", verification_run_id="verify1",
        relative_name="missing/output.txt", expires_at=time.time() + 3600,
    )
    store.seal_artifact(artifact_id="art-3", content_digest="sha256:abc", byte_length=10)
    missing = store.list_artifacts_without_files(tmp_path / "artifacts")
    assert len(missing) == 1
    assert missing[0]["artifact_id"] == "art-3"
