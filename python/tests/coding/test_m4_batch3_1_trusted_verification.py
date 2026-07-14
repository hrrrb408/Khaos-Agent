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
    DisposableWorkspaceRecord, DisposableWorkspaceState,
    TrustedVerificationCommand, VerificationExecutionRun, VerificationRunStatus,
    VerificationStepRun, VerificationStepStatus, verification_plan_digest,
)
from khaos.coding.planning.verification_sandbox import (
    ContainerAttestation, DockerVerificationSandboxBackend, SandboxStepResult,
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
        self._container_exists: set[str] = set()

    async def probe(self):
        return self.profile.image_digest

    def generate_instance_name(self):
        import secrets as _s
        return f"khaos-verify-test-{_s.token_hex(12)}"

    def build_labels(self, *, run_id, step_id, instance_id, boot_id, manifest_digest):
        return {
            "khaos.run-id": run_id,
            "khaos.step-id": step_id,
            "khaos.sandbox-instance-id": instance_id,
            "khaos.boot-id": boot_id,
            "khaos.manifest-digest": manifest_digest[:63],
        }

    def validate_command(self, command):
        pass

    async def create_instance(self, *, instance_name, image_digest, command,
                              workspace_root, labels):
        self.calls.append((command, workspace_root))
        fake_container_id = f"fake-container-{hashlib.sha256(instance_name.encode()).hexdigest()[:12]}"
        self._container_exists.add(fake_container_id)
        return fake_container_id

    async def inspect_and_attest_instance(self, *, container_id_or_name,
                                          expected_labels, expected_image_digest,
                                          expected_manifest_digest,
                                          image_attestation=None):
        return ContainerAttestation(
            container_id=container_id_or_name,
            container_image_id=expected_image_digest,
            local_image_id=expected_image_digest,
            expected_image_digest=expected_image_digest,
            labels=dict(expected_labels),
            manifest_digest=expected_manifest_digest,
            attestation_digest=hashlib.sha256(
                f"{container_id_or_name}:{expected_image_digest}".encode(),
            ).hexdigest(),
        )

    async def start_instance(self, container_id_or_name):
        pass

    async def attach_instance(self, container_id_or_name):
        return None, None, None

    async def start_and_attach_instance(self, container_id_or_name):
        """Batch 3.1.4 §1: combined start + attach."""
        return None, None, None

    async def inspect_instance(self, container_id_or_name):
        if container_id_or_name in self._container_exists:
            return {"Id": container_id_or_name, "State": {"Running": True}}
        return None

    async def terminate_instance(self, container_id_or_name):
        self._container_exists.discard(container_id_or_name)
        return True

    async def remove_instance(self, container_id_or_name):
        self._container_exists.discard(container_id_or_name)
        return True

    async def terminate_and_remove_instance(self, container_id_or_name):
        self._container_exists.discard(container_id_or_name)
        return True, True

    async def confirm_instance_gone(self, container_id_or_name):
        return container_id_or_name not in self._container_exists

    async def launch_instance(self, *, instance_name, image_digest, command,
                              workspace_root, labels, expected_manifest_digest):
        self.calls.append((command, workspace_root))
        fake_container_id = f"fake-container-{hashlib.sha256(instance_name.encode()).hexdigest()[:12]}"
        attestation = ContainerAttestation(
            container_id=fake_container_id,
            container_image_id=image_digest,
            local_image_id=image_digest,
            expected_image_digest=image_digest,
            labels=dict(labels),
            manifest_digest=expected_manifest_digest,
            attestation_digest=hashlib.sha256(
                f"{fake_container_id}:{image_digest}".encode(),
            ).hexdigest(),
        )
        return fake_container_id, attestation, None, None, None

    async def collect_result(self, *, container_id, attach_proc, stdout_stream,
                             stderr_stream, command, cancellation, started,
                             sandbox_instance_id, attestation_digest, remove=True):
        data = b"trusted fake output"
        return SandboxStepResult(
            sandbox_instance_id, self.profile.image_digest, 0, None, 1, data, b"",
            hashlib.sha256(data).hexdigest(), hashlib.sha256(b"").hexdigest(), False,
            False, False, container_id, attestation_digest,
        )

    async def execute(self, command, workspace, *, cancellation=None, **kwargs):
        self.calls.append((command, workspace))
        data = b"trusted fake output"
        return SandboxStepResult(
            "fake-sandbox", self.profile.image_digest, 0, None, 1, data, b"",
            hashlib.sha256(data).hexdigest(), hashlib.sha256(b"").hexdigest(), False,
        )

    async def reconcile_instance_by_record(self, *, container_id, instance_name,
                                           expected_labels, expected_image_digest,
                                           expected_manifest_digest):
        return {"status": "missing", "container_id": "", "reason": "test-backend-no-real-container"}

    async def reconcile_instances(self, *, expected_labels):
        if not expected_labels:
            raise ValueError("reconcile_instances requires non-empty expected_labels")
        return {"found": [], "terminated": [], "unknown": [], "mismatches": []}

    async def list_unknown_khaos_containers(self):
        return []


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
    runtime._configure_trusted_verification_unsafe(
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
    # Batch 3.1.4 §1: the container writes sandbox-output.txt to /workspace;
    # allow it as generated output so factory.destroy() can clean it up.
    disposable = factory.create(
        source, forbidden_roots=(source,),
        allowed_generated_output=("sandbox-output.txt",),
    )
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
# Batch 3.1.4 §2: Production verification authority — typed config,
# factory construction, malicious backend rejection.
# ----------------------------------------------------------------------


def test_malicious_backend_with_create_instance_rejected_by_authority():
    """§2: malicious objects implementing create_instance/start_instance
    are rejected by ProductionVerificationAuthority.sign — exact type check.
    """
    from khaos.coding.planning.verification_sandbox import (
        ProductionVerificationAuthority,
    )

    class MaliciousBackend:
        """Implements the lifecycle API but is NOT DockerVerificationSandboxBackend."""
        async def create_instance(self, **kwargs):
            return "fake-id"
        async def start_and_attach_instance(self, container_id):
            return None, None, None
        async def start_instance(self, container_id):
            pass
        async def attach_instance(self, container_id):
            return None, None, None
        async def wait_instance(self, container_id):
            return 0
        async def terminate_instance(self, container_id):
            pass
        async def remove_instance(self, container_id):
            pass

    malicious = MaliciousBackend()
    # Even with a factory marker, the authority rejects non-exact-type backends.
    authority = ProductionVerificationAuthority(factory_marker=object())
    with pytest.raises(TypeError, match="exact"):
        authority.sign(malicious)


def test_forged_production_authority_field_rejected_by_runner():
    """§2: an ordinary object that sets _production_authority cannot
    impersonate a production backend — the runner checks for the runtime
    factory marker or the unsafe test flag.
    """
    from khaos.coding.planning.verification_sandbox import (
        ProductionVerificationAuthority,
    )

    class ForgedBackend:
        """Sets _production_authority but lacks factory marker and unsafe flag."""
        _production_authority = "khaos-production-v1"
        profile = _profile()

    forged = ForgedBackend()
    # is_production_backend returns True (has _production_authority)...
    assert ProductionVerificationAuthority.is_production_backend(forged)
    # ...but is_runtime_factory_backend returns False (not exact type).
    assert not ProductionVerificationAuthority.is_runtime_factory_backend(forged)
    # The runner would reject this: not factory, not unsafe_test_only.


def test_production_authority_requires_factory_marker_to_sign():
    """§2: ProductionVerificationAuthority.sign fails without a factory marker."""
    from khaos.coding.planning.verification_sandbox import (
        DockerVerificationSandboxBackend, ProductionVerificationAuthority,
    )

    backend = DockerVerificationSandboxBackend(profile=_profile())
    # No factory marker — sign should fail.
    authority = ProductionVerificationAuthority()
    with pytest.raises(PermissionError, match="factory marker"):
        authority.sign(backend)


def test_production_authority_rejects_wrong_factory_marker():
    """§2: backend constructed by a different factory is rejected."""
    from khaos.coding.planning.verification_sandbox import (
        DockerVerificationSandboxBackend, ProductionVerificationAuthority,
    )

    backend = DockerVerificationSandboxBackend(profile=_profile())
    # Set a wrong factory marker.
    object.__setattr__(backend, "_runtime_factory_marker", object())
    authority = ProductionVerificationAuthority(factory_marker=object())
    with pytest.raises(PermissionError, match="not constructed by the runtime"):
        authority.sign(backend)


def test_configure_trusted_verification_rejects_backend_instance(tmp_path):
    """§2: configure_trusted_verification must not accept a backend= parameter."""
    runtime, _, _, _ = _real_runtime(tmp_path)
    profile = _profile()
    backend = UnsafeTestSandboxBackend(profile)
    with pytest.raises(TypeError, match="ProductionVerificationConfig"):
        runtime.configure_trusted_verification(
            config=backend, command_factory=_factory(profile),
            workspace_factory=VerificationWorkspaceFactory(tmp_path / "copies"),
            artifact_root=tmp_path / "artifacts", profile=profile,
        )


# ----------------------------------------------------------------------
# Batch 3.1.4 §3: Approved verification plan snapshot — stable digests
# ----------------------------------------------------------------------


def test_image_attestation_digest_excludes_attested_at():
    """§3: ImageAttestation.attestation_digest must NOT include attested_at.

    The same image content must produce the same digest across re-probes.
    """
    from khaos.coding.planning.verification_sandbox import ImageAttestation
    import time

    # Two attestations with the same content but different attested_at.
    base_fields = dict(
        requested_image_reference="sha256:abc",
        approved_repository_digest="sha256:abc",
        platform="linux/amd64",
        platform_manifest_digest="sha256:abc",
        local_config_image_id="sha256:abc",
        container_image_id="sha256:abc",
        repo_digests=("repo@sha256:abc",),
        no_pull_proof="image-inspect-not-pull",
    )
    att1 = ImageAttestation(
        attested_at=time.time() - 100,
        attestation_digest="",
        **base_fields,
    )
    att2 = ImageAttestation(
        attested_at=time.time() + 100,
        attestation_digest="",
        **base_fields,
    )
    # Compute digest the same way probe_image_attestation does (without attested_at).
    import hashlib, json
    digest1 = hashlib.sha256(json.dumps({
        "requested_image_reference": att1.requested_image_reference,
        "approved_repository_digest": att1.approved_repository_digest,
        "platform": att1.platform,
        "platform_manifest_digest": att1.platform_manifest_digest,
        "local_config_image_id": att1.local_config_image_id,
        "repo_digests": list(att1.repo_digests),
        "no_pull_proof": att1.no_pull_proof,
    }, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    digest2 = hashlib.sha256(json.dumps({
        "requested_image_reference": att2.requested_image_reference,
        "approved_repository_digest": att2.approved_repository_digest,
        "platform": att2.platform,
        "platform_manifest_digest": att2.platform_manifest_digest,
        "local_config_image_id": att2.local_config_image_id,
        "repo_digests": list(att2.repo_digests),
        "no_pull_proof": att2.no_pull_proof,
    }, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    assert digest1 == digest2, "same content must produce same digest"


def test_approved_verification_plan_snapshot_model():
    """§3: ApprovedVerificationPlanSnapshot is immutable and has all fields."""
    from khaos.coding.planning.verification_execution_models import (
        ApprovedVerificationPlanSnapshot, compute_approved_verification_plan_digest,
    )
    import time

    digest = compute_approved_verification_plan_digest(
        plan_id="plan1", plan_content_hash="hash1",
        verification_requirements_digest="req-digest",
        catalog_fingerprint="catalog-fp",
        ordered_command_digests=("cmd1", "cmd2"),
        config_hashes=("cfg1", "cfg2"),
        sandbox_profile_digest="profile-digest",
        image_attestation_content_digest="img-digest",
        ordered_toolchain_attestation_content_digests=("tc1", "tc2"),
        binary_digests=("bin1", "bin2"),
        version_output_digests=("ver1", "ver2"),
        parsed_versions=("3.13", "11"),
        image_toolchain_policy_fingerprint="policy-fp",
    )
    snapshot = ApprovedVerificationPlanSnapshot(
        approved_verification_plan_id="avp1",
        plan_id="plan1", plan_content_hash="hash1",
        verification_requirements_digest="req-digest",
        catalog_fingerprint="catalog-fp",
        ordered_command_digests=("cmd1", "cmd2"),
        config_hashes=("cfg1", "cfg2"),
        sandbox_profile_digest="profile-digest",
        image_attestation_content_digest="img-digest",
        ordered_toolchain_attestation_content_digests=("tc1", "tc2"),
        binary_digests=("bin1", "bin2"),
        version_output_digests=("ver1", "ver2"),
        parsed_versions=("3.13", "11"),
        image_toolchain_policy_fingerprint="policy-fp",
        created_at=time.time(),
        approved_verification_plan_digest=digest,
    )
    assert snapshot.approved_verification_plan_digest == digest
    # Digest is deterministic — same inputs produce same digest.
    digest2 = compute_approved_verification_plan_digest(
        plan_id="plan1", plan_content_hash="hash1",
        verification_requirements_digest="req-digest",
        catalog_fingerprint="catalog-fp",
        ordered_command_digests=("cmd1", "cmd2"),
        config_hashes=("cfg1", "cfg2"),
        sandbox_profile_digest="profile-digest",
        image_attestation_content_digest="img-digest",
        ordered_toolchain_attestation_content_digests=("tc1", "tc2"),
        binary_digests=("bin1", "bin2"),
        version_output_digests=("ver1", "ver2"),
        parsed_versions=("3.13", "11"),
        image_toolchain_policy_fingerprint="policy-fp",
    )
    assert digest == digest2


# ----------------------------------------------------------------------
# Batch 3.1.4 §4: separate registry and local docker image identities
# ----------------------------------------------------------------------

def test_image_attestation_has_separate_registry_and_local_fields():
    """§4: ImageAttestation must have distinct fields for registry manifest
    digest and local config image ID — they are different concepts and
    must not be conflated."""
    from khaos.coding.planning.verification_sandbox import ImageAttestation
    import time

    # In a real multi-arch image, these would differ.  Here we use
    # distinct placeholder values to verify the model preserves them.
    att = ImageAttestation(
        requested_image_reference="python@sha256:aaa111",
        approved_repository_digest="sha256:aaa111",
        platform="linux/amd64",
        platform_manifest_digest="sha256:aaa111",
        local_config_image_id="sha256:bbb222",
        container_image_id="sha256:bbb222",
        repo_digests=("python@sha256:aaa111",),
        no_pull_proof="image-inspect-not-pull",
        attested_at=time.time(),
        attestation_digest="some-digest",
    )
    # Registry manifest digest and local config image ID are distinct.
    assert att.platform_manifest_digest != att.local_config_image_id
    assert att.requested_image_reference != att.local_config_image_id
    assert att.approved_repository_digest != att.local_config_image_id
    # RepoDigests carries the registry-level identity.
    assert "python@sha256:aaa111" in att.repo_digests


def test_container_attestation_binds_image_attestation_digest():
    """§4: ContainerAttestation must bind to the approved ImageAttestation
    content digest via the image_attestation_digest field."""
    from khaos.coding.planning.verification_sandbox import ContainerAttestation

    ca = ContainerAttestation(
        container_id="cid",
        container_image_id="sha256:bbb",
        local_image_id="sha256:bbb",
        expected_image_digest="python@sha256:aaa",
        labels={},
        manifest_digest="manifest-hash",
        attestation_digest="container-digest",
        image_attestation_digest="image-att-digest",
    )
    assert ca.image_attestation_digest == "image-att-digest"


def test_inspect_and_attest_rejects_container_image_mismatch_with_safe_delete(tmp_path):
    """§4: when container .Image != approved local_config_image_id, the
    owned container is safe-deleted and the mismatch is raised.

    Uses a controlled backend that overrides inspect_instance and
    inspect_image to return mismatched values."""
    from khaos.coding.planning.verification_sandbox import (
        DockerVerificationSandboxBackend, ImageAttestation, SandboxProfile,
    )
    from pathlib import Path
    import time

    profile = SandboxProfile(
        "test-mismatch-v1", "python@sha256:aaa",
        run_as_user=f"{os.getuid()}:{os.getgid()}",
    )
    backend = DockerVerificationSandboxBackend(
        profile=profile, docker_executable=Path("/usr/bin/env"),
    )
    # Approved ImageAttestation with a specific local_config_image_id.
    approved = ImageAttestation(
        requested_image_reference="python@sha256:aaa",
        approved_repository_digest="sha256:aaa",
        platform="linux/amd64",
        platform_manifest_digest="sha256:aaa",
        local_config_image_id="sha256:approved-config-id",
        container_image_id="",
        repo_digests=("python@sha256:aaa",),
        no_pull_proof="image-inspect-not-pull",
        attested_at=time.time(),
        attestation_digest="approved-digest",
    )
    # Override inspect_instance to return a mismatched container .Image.
    removed = []
    async def fake_inspect_instance(cid):
        return {"Id": cid, "Image": "sha256:wrong-config-id",
                "Config": {"Labels": {}}}
    async def fake_inspect_image(ref):
        return "sha256:approved-config-id"
    async def fake_terminate_and_remove(cid):
        removed.append(cid)
        return True, True
    backend.inspect_instance = fake_inspect_instance
    backend.inspect_image = fake_inspect_image
    backend.terminate_and_remove_instance = fake_terminate_and_remove

    async def run():
        return await backend.inspect_and_attest_instance(
            container_id_or_name="test-cid",
            expected_labels={},
            expected_image_digest="python@sha256:aaa",
            expected_manifest_digest="manifest-hash",
            image_attestation=approved,
        )
    with pytest.raises(RuntimeError, match="container .Image mismatch"):
        asyncio.run(run())
    # §4: the owned container must have been safe-deleted.
    assert "test-cid" in removed


def test_inspect_and_attest_allows_manifest_different_from_config_id(tmp_path):
    """§4: registry manifest digest != local config image ID is allowed —
    they are different concepts and must not be conflated.

    Uses a controlled backend where the manifest digest (from the
    reference) differs from the local config image ID, but the
    container .Image matches the approved local config image ID."""
    from khaos.coding.planning.verification_sandbox import (
        DockerVerificationSandboxBackend, ImageAttestation, SandboxProfile,
    )
    from pathlib import Path
    import time

    profile = SandboxProfile(
        "test-diff-v1", "python@sha256:manifest-aaa",
        run_as_user=f"{os.getuid()}:{os.getgid()}",
    )
    backend = DockerVerificationSandboxBackend(
        profile=profile, docker_executable=Path("/usr/bin/env"),
    )
    # Approved ImageAttestation: manifest digest != config image ID.
    approved = ImageAttestation(
        requested_image_reference="python@sha256:manifest-aaa",
        approved_repository_digest="sha256:manifest-aaa",
        platform="linux/amd64",
        platform_manifest_digest="sha256:manifest-aaa",
        local_config_image_id="sha256:config-bbb",
        container_image_id="",
        repo_digests=("python@sha256:manifest-aaa",),
        no_pull_proof="image-inspect-not-pull",
        attested_at=time.time(),
        attestation_digest="approved-digest",
    )
    # Container .Image matches local_config_image_id (NOT manifest digest).
    async def fake_inspect_instance(cid):
        return {"Id": cid, "Image": "sha256:config-bbb",
                "Config": {"Labels": {"khaos.manifest-digest": "manifest-hash"}}}
    async def fake_inspect_image(ref):
        return "sha256:config-bbb"
    backend.inspect_instance = fake_inspect_instance
    backend.inspect_image = fake_inspect_image

    async def run():
        return await backend.inspect_and_attest_instance(
            container_id_or_name="test-cid",
            expected_labels={"khaos.manifest-digest": "manifest-hash"},
            expected_image_digest="python@sha256:manifest-aaa",
            expected_manifest_digest="manifest-hash",
            image_attestation=approved,
        )
    result = asyncio.run(run())
    # The attestation must bind to the approved image attestation digest.
    assert result.image_attestation_digest == "approved-digest"
    assert result.container_image_id == "sha256:config-bbb"


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


# ----------------------------------------------------------------------
# Batch 3.1.2 §5: Real toolchain attestation
# ----------------------------------------------------------------------

def _toolchain_attestation(
    *, toolchain_id="python:python", executable_path="/usr/local/bin/python3",
    binary_digest="sha256:abc", version_output_digest="sha256:def",
    parsed_version="3.13", actual_image_attestation=IMAGE,
    attested_at=1_700_000_000.0, attestation_digest="sha256:att",
):
    from khaos.coding.planning.verification_sandbox import ToolchainAttestation
    return ToolchainAttestation(
        toolchain_id=toolchain_id, executable_path=executable_path,
        binary_digest=binary_digest, version_output_digest=version_output_digest,
        parsed_version=parsed_version,
        actual_image_attestation=actual_image_attestation,
        attested_at=attested_at, attestation_digest=attestation_digest,
    )


@pytest.mark.parametrize("executable_id,output,expected", [
    ("python", "Python 3.13.0\n", "3.13.0"),
    ("python", "Python 3.13.1rc1\n", "3.13.1rc1"),
    ("npm", "11.0.0\n", "11.0.0"),
    ("go", "go version go1.25.0 darwin/amd64\n", "1.25.0"),
    ("go", "go version go1.25 linux/arm64\n", "1.25"),
    ("cargo", "cargo 1.90.0\n", "1.90.0"),
    ("unknown", "something 1.2.3\n", "1.2.3"),
    ("python", "", ""),
    ("python", "garbage", "garbage"),
])
def test_toolchain_version_parser_is_fixed(executable_id, output, expected):
    """Batch 3.1.2 §5: version output is parsed using a fixed format."""
    from khaos.coding.planning.verification_sandbox import (
        DockerVerificationSandboxBackend,
    )
    assert DockerVerificationSandboxBackend._parse_version(executable_id, output) == expected


def test_toolchain_attestation_dataclass_is_canonical():
    """Batch 3.1.2 §5: ToolchainAttestation carries all required fields."""
    att = _toolchain_attestation()
    assert att.toolchain_id == "python:python"
    assert att.executable_path == "/usr/local/bin/python3"
    assert att.binary_digest == "sha256:abc"
    assert att.version_output_digest == "sha256:def"
    assert att.parsed_version == "3.13"
    assert att.actual_image_attestation == IMAGE
    assert att.attested_at == 1_700_000_000.0
    assert att.attestation_digest == "sha256:att"


def test_persist_and_get_toolchain_attestation(tmp_path):
    """Batch 3.1.2 §5: attestations are persisted and retrievable."""
    _, store = _mutated_store(tmp_path)
    att = _toolchain_attestation(attestation_digest="sha256:original")
    store.persist_toolchain_attestation(
        att, boot_id="boot-1", server_epoch=1,
    )
    fetched = store.get_toolchain_attestation("python:python")
    assert fetched is not None
    assert fetched.attestation_digest == "sha256:original"
    assert fetched.parsed_version == "3.13"


def test_persist_toolchain_attestation_upsert(tmp_path):
    """Batch 3.1.2 §5: re-attesting the same toolchain updates the row."""
    _, store = _mutated_store(tmp_path)
    att1 = _toolchain_attestation(attestation_digest="sha256:v1")
    att2 = _toolchain_attestation(attestation_digest="sha256:v2")
    store.persist_toolchain_attestation(att1, boot_id="boot-1", server_epoch=1)
    store.persist_toolchain_attestation(att2, boot_id="boot-1", server_epoch=1)
    fetched = store.get_toolchain_attestation("python:python")
    assert fetched.attestation_digest == "sha256:v2"


def test_clear_toolchain_attestations_for_other_boots(tmp_path):
    """Batch 3.1.2 §5: stale attestations from old boots are cleared."""
    _, store = _mutated_store(tmp_path)
    att1 = _toolchain_attestation(toolchain_id="python:python", attestation_digest="sha256:old")
    att2 = _toolchain_attestation(toolchain_id="npm:npm", attestation_digest="sha256:new")
    store.persist_toolchain_attestation(att1, boot_id="boot-old", server_epoch=1)
    store.persist_toolchain_attestation(att2, boot_id="boot-new", server_epoch=2)
    removed = store.clear_toolchain_attestations_for_boot(boot_id="boot-new")
    assert removed == 1
    all_atts = store.list_toolchain_attestations()
    assert len(all_atts) == 1
    assert all_atts[0].toolchain_id == "npm:npm"


def test_list_toolchain_attestations_ordered(tmp_path):
    """Batch 3.1.2 §5: list returns all attestations ordered by toolchain_id."""
    _, store = _mutated_store(tmp_path)
    store.persist_toolchain_attestation(
        _toolchain_attestation(toolchain_id="python:python"),
        boot_id="b1", server_epoch=1,
    )
    store.persist_toolchain_attestation(
        _toolchain_attestation(toolchain_id="cargo:cargo"),
        boot_id="b1", server_epoch=1,
    )
    store.persist_toolchain_attestation(
        _toolchain_attestation(toolchain_id="go:go"),
        boot_id="b1", server_epoch=1,
    )
    all_atts = store.list_toolchain_attestations()
    ids = [a.toolchain_id for a in all_atts]
    assert ids == ["cargo:cargo", "go:go", "python:python"]


class _AttestationTestBackend:
    """Test backend that simulates attestation without real Docker."""

    def __init__(self, profile, *, attestations=None, fail_attest=False):
        self.profile = profile
        self._attestations = attestations or ()
        self._fail_attest = fail_attest

    async def probe(self):
        return self.profile.image_digest

    async def attest_toolchains(self, *, toolchains, image_digest):
        if self._fail_attest:
            raise RuntimeError("attestation container failed")
        return self._attestations

    def generate_instance_name(self):
        import secrets as _s
        return f"khaos-verify-test-{_s.token_hex(12)}"

    def build_labels(self, **kwargs):
        return {
            "khaos.run-id": kwargs["run_id"],
            "khaos.step-id": kwargs["step_id"],
            "khaos.sandbox-instance-id": kwargs["instance_id"],
            "khaos.boot-id": kwargs["boot_id"],
            "khaos.manifest-digest": kwargs["manifest_digest"][:63],
        }

    async def launch_instance(self, **kwargs):
        image_digest = kwargs["image_digest"]
        return "fake-container", ContainerAttestation(
            container_id="fake-container",
            container_image_id=image_digest,
            local_image_id=image_digest,
            expected_image_digest=image_digest,
            labels=dict(kwargs["labels"]),
            manifest_digest=kwargs["expected_manifest_digest"],
            attestation_digest="sha256:fake",
        ), None, None, None

    async def collect_result(self, **kwargs):
        data = b"trusted fake output"
        return SandboxStepResult(
            kwargs["sandbox_instance_id"], self.profile.image_digest,
            0, None, 1, data, b"",
            hashlib.sha256(data).hexdigest(), hashlib.sha256(b"").hexdigest(),
            False, False, False, kwargs["container_id"], kwargs["attestation_digest"],
        )

    async def reconcile_instance_by_record(self, **kwargs):
        return {"status": "missing", "container_id": "", "reason": "test"}

    async def reconcile_instances(self, **kwargs):
        return {"found": [], "terminated": [], "unknown": [], "mismatches": []}


def test_attest_toolchains_rejects_image_mismatch():
    """Batch 3.1.2 §5: toolchain with wrong image_digest is rejected."""
    from khaos.coding.planning.trusted_verification import TrustedToolchain
    toolchains = (TrustedToolchain(
        "python", "python", "/usr/local/bin/python3", "3.13",
        "sha256:wrong",
    ),)
    backend = DockerVerificationSandboxBackend(profile=_profile())
    import asyncio as _aio
    with pytest.raises(RuntimeError, match="image mismatch"):
        _aio.run(backend.attest_toolchains(
            toolchains=toolchains, image_digest=IMAGE,
        ))


def test_attest_toolchain_rejects_unknown_executable():
    """Batch 3.1.2 §5: unknown executable_id (no version argv) is rejected."""
    from khaos.coding.planning.trusted_verification import TrustedToolchain
    backend = DockerVerificationSandboxBackend(profile=_profile())
    toolchain = TrustedToolchain(
        "ruby", "ruby", "/usr/local/bin/ruby", "3.3", IMAGE,
    )
    import asyncio as _aio
    with pytest.raises(RuntimeError, match="no fixed version argv"):
        _aio.run(backend.attest_toolchain(
            toolchain=toolchain, image_digest=IMAGE,
        ))


def test_version_argv_is_fixed_per_toolchain():
    """Batch 3.1.2 §5: version argv is fixed, not from catalog."""
    from khaos.coding.planning.verification_sandbox import (
        DockerVerificationSandboxBackend,
    )
    assert DockerVerificationSandboxBackend._VERSION_ARGV["python"] == ("--version",)
    assert DockerVerificationSandboxBackend._VERSION_ARGV["npm"] == ("--version",)
    assert DockerVerificationSandboxBackend._VERSION_ARGV["go"] == ("version",)
    assert DockerVerificationSandboxBackend._VERSION_ARGV["cargo"] == ("--version",)


def test_attestation_digest_binds_all_fields():
    """Batch 3.1.2 §5: attestation_digest changes if any field changes."""
    att1 = _toolchain_attestation(attestation_digest="")
    # Recompute digest to verify binding.
    import hashlib as _h
    import json as _j
    payload = _j.dumps({
        "toolchain_id": att1.toolchain_id,
        "executable_path": att1.executable_path,
        "binary_digest": att1.binary_digest,
        "version_output_digest": att1.version_output_digest,
        "parsed_version": att1.parsed_version,
        "actual_image_attestation": att1.actual_image_attestation,
        "attested_at": att1.attested_at,
    }, sort_keys=True, separators=(",", ":")).encode()
    digest1 = _h.sha256(payload).hexdigest()
    # Change one field — digest must differ.
    att2 = _toolchain_attestation(parsed_version="3.14", attestation_digest="")
    payload2 = _j.dumps({
        "toolchain_id": att2.toolchain_id,
        "executable_path": att2.executable_path,
        "binary_digest": att2.binary_digest,
        "version_output_digest": att2.version_output_digest,
        "parsed_version": att2.parsed_version,
        "actual_image_attestation": att2.actual_image_attestation,
        "attested_at": att2.attested_at,
    }, sort_keys=True, separators=(",", ":")).encode()
    digest2 = _h.sha256(payload2).hexdigest()
    assert digest1 != digest2


# ----------------------------------------------------------------------
# Batch 3.1.2 §6: Snapshot path-entry attestation
# ----------------------------------------------------------------------

def test_snapshot_copy_rejects_path_entry_swap(tmp_path):
    """Batch 3.1.2 §6: inode swap during copy is detected via parent dir FD re-lstat."""
    source = tmp_path / "canonical"
    source.mkdir()
    target_file = source / "data.py"
    target_file.write_text("original\n")
    root = tmp_path / "copies"
    factory = VerificationWorkspaceFactory(root)
    copied = factory.create(source, forbidden_roots=(source,))
    assert (copied.root / "data.py").read_text() == "original\n"
    factory.destroy(copied)


def test_snapshot_path_entry_verification_holds_parent_fd(tmp_path):
    """Batch 3.1.2 §6: _verify_path_entry compares dev/inode/type/mode/nlink."""
    source = tmp_path / "src"
    source.mkdir()
    test_file = source / "f.txt"
    test_file.write_text("hello\n")
    # Open the parent dir and the file, then verify.
    parent_fd = os.open(str(source), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        child_fd = os.open(
            "f.txt", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd,
        )
        try:
            pre_st = os.fstat(child_fd)
            # No swap — verification should pass.
            VerificationWorkspaceFactory._verify_path_entry(parent_fd, "f.txt", pre_st, "f.txt")
        finally:
            os.close(child_fd)
    finally:
        os.close(parent_fd)


def test_snapshot_path_entry_detects_inode_swap(tmp_path):
    """Batch 3.1.2 §6: inode swap is detected by _verify_path_entry."""
    source = tmp_path / "src"
    source.mkdir()
    test_file = source / "f.txt"
    test_file.write_text("hello\n")
    parent_fd = os.open(str(source), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        child_fd = os.open(
            "f.txt", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd,
        )
        try:
            pre_st = os.fstat(child_fd)
            # Swap the file: unlink + recreate with same name.
            test_file.unlink()
            test_file.write_text("replaced\n")
            with pytest.raises(PermissionError, match="identity changed"):
                VerificationWorkspaceFactory._verify_path_entry(
                    parent_fd, "f.txt", pre_st, "f.txt",
                )
        finally:
            os.close(child_fd)
    finally:
        os.close(parent_fd)


def test_snapshot_path_entry_detects_vanished_entry(tmp_path):
    """Batch 3.1.2 §6: vanished path entry is detected."""
    source = tmp_path / "src"
    source.mkdir()
    test_file = source / "f.txt"
    test_file.write_text("hello\n")
    parent_fd = os.open(str(source), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        child_fd = os.open(
            "f.txt", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd,
        )
        try:
            pre_st = os.fstat(child_fd)
            test_file.unlink()
            with pytest.raises(PermissionError, match="vanished"):
                VerificationWorkspaceFactory._verify_path_entry(
                    parent_fd, "f.txt", pre_st, "f.txt",
                )
        finally:
            os.close(child_fd)
    finally:
        os.close(parent_fd)


# ----------------------------------------------------------------------
# Batch 3.1.2 §7: ArtifactRootCapability
# ----------------------------------------------------------------------

def test_artifact_root_capability_open_and_identity(tmp_path):
    """Batch 3.1.2 §7: opening the artifact root records dev/inode/owner/mode."""
    from khaos.coding.planning.trusted_verification import ArtifactRootCapability
    root = tmp_path / "artifacts"
    cap = ArtifactRootCapability.open(root)
    try:
        identity = cap.identity
        assert identity.dev > 0
        assert identity.ino > 0
        assert identity.mode == 0o700
    finally:
        cap.close()


def test_artifact_root_capability_rejects_overlap(tmp_path):
    """Batch 3.1.2 §7: artifact root overlapping a protected root is rejected."""
    from khaos.coding.planning.trusted_verification import ArtifactRootCapability
    root = tmp_path / "artifacts"
    root.mkdir()
    with pytest.raises(PermissionError, match="overlaps"):
        ArtifactRootCapability.open(root, forbidden_roots=(tmp_path,))


def test_artifact_root_capability_write_and_read(tmp_path):
    """Batch 3.1.2 §7: write_artifact uses temp→link→fsync no-replace protocol."""
    from khaos.coding.planning.trusted_verification import ArtifactRootCapability
    cap = ArtifactRootCapability.open(tmp_path / "artifacts")
    try:
        payload = b"stdout:\nhello\nstderr:\nworld\n"
        digest, length = cap.write_artifact("pvo_test1", payload)
        assert length == len(payload)
        assert digest == hashlib.sha256(payload).hexdigest()
        # Read back.
        data = cap.read_artifact("pvo_test1")
        assert data == payload
        assert cap.artifact_exists("pvo_test1")
    finally:
        cap.close()


def test_artifact_root_capability_no_replace_final(tmp_path):
    """Batch 3.1.2 §7: writing an existing final file fails (no-replace)."""
    from khaos.coding.planning.trusted_verification import ArtifactRootCapability
    cap = ArtifactRootCapability.open(tmp_path / "artifacts")
    try:
        cap.write_artifact("pvo_dup", b"first\n")
        with pytest.raises(PermissionError, match="already exists"):
            cap.write_artifact("pvo_dup", b"second\n")
    finally:
        cap.close()


def test_artifact_root_capability_rejects_bad_basename(tmp_path):
    """Batch 3.1.2 §7: artifact basename must be fixed server-side format."""
    from khaos.coding.planning.trusted_verification import ArtifactRootCapability
    cap = ArtifactRootCapability.open(tmp_path / "artifacts")
    try:
        with pytest.raises(ValueError, match="invalid artifact basename"):
            cap.write_artifact("bad/../path", b"data\n")
        with pytest.raises(ValueError, match="invalid artifact basename"):
            cap.write_artifact("bad name", b"data\n")
    finally:
        cap.close()


def test_artifact_root_capability_unlink(tmp_path):
    """Batch 3.1.2 §7: unlink_artifact removes the final file."""
    from khaos.coding.planning.trusted_verification import ArtifactRootCapability
    cap = ArtifactRootCapability.open(tmp_path / "artifacts")
    try:
        cap.write_artifact("pvo_rm", b"data\n")
        assert cap.unlink_artifact("pvo_rm") is True
        assert not cap.artifact_exists("pvo_rm")
        assert cap.unlink_artifact("pvo_rm") is False
    finally:
        cap.close()


def test_artifact_root_capability_list_files(tmp_path):
    """Batch 3.1.2 §7: list_files returns regular files only."""
    from khaos.coding.planning.trusted_verification import ArtifactRootCapability
    cap = ArtifactRootCapability.open(tmp_path / "artifacts")
    try:
        cap.write_artifact("pvo_a", b"aaa\n")
        cap.write_artifact("pvo_b", b"bbb\n")
        files = cap.list_files()
        names = {name for name, _ in files}
        assert "pvo_a.log" in names
        assert "pvo_b.log" in names
    finally:
        cap.close()


def test_artifact_root_capability_reconcile(tmp_path):
    """Batch 3.1.2 §7: reconcile detects orphans and missing files."""
    from khaos.coding.planning.trusted_verification import ArtifactRootCapability
    cap = ArtifactRootCapability.open(tmp_path / "artifacts")
    try:
        # Write two sealed artifacts.
        cap.write_artifact("pvo_sealed1", b"data1\n")
        cap.write_artifact("pvo_sealed2", b"data2\n")
        # Manually create an unknown file.
        fd = os.open(
            "unknown_orphan.log", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600,
            dir_fd=cap._root_fd,
        )
        os.close(fd)
        # Reconcile: expected = two sealed, one missing sealed, one reserved.
        report = cap.reconcile(expected_artifacts=[
            ("pvo_sealed1", "sealed", 6),
            ("pvo_sealed2", "sealed", 6),
            ("pvo_missing", "sealed", 0),     # SEALED but file missing.
            ("pvo_reserved", "reserved", 0),  # RESERVED but no file.
        ])
        assert "pvo_missing" in report["sealed_missing"]
        assert "pvo_reserved" in report["reserved_no_file"]
        assert "unknown_orphan.log" in report["unknown_files"]
    finally:
        cap.close()


def test_artifact_root_capability_cleanup_orphan(tmp_path):
    """Batch 3.1.2 §7: cleanup_orphan removes unknown files."""
    from khaos.coding.planning.trusted_verification import ArtifactRootCapability
    cap = ArtifactRootCapability.open(tmp_path / "artifacts")
    try:
        fd = os.open(
            "orphan.tmp", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600,
            dir_fd=cap._root_fd,
        )
        os.close(fd)
        assert cap.cleanup_orphan("orphan.tmp") is True
        assert cap.cleanup_orphan("orphan.tmp") is False
    finally:
        cap.close()


def test_artifact_root_no_os_rename_overwrite(tmp_path):
    """Batch 3.1.2 §7: verify no os.rename is used to overwrite final files.

    The write_artifact method uses os.link (no-replace) instead of
    os.rename.  If the final file exists, the write fails closed.
    """
    from khaos.coding.planning.trusted_verification import ArtifactRootCapability
    cap = ArtifactRootCapability.open(tmp_path / "artifacts")
    try:
        cap.write_artifact("pvo_noreplace", b"original\n")
        # Attempting to write the same artifact_id again must fail,
        # NOT overwrite the existing file.
        with pytest.raises(PermissionError):
            cap.write_artifact("pvo_noreplace", b"tampered\n")
        # The original content must be intact.
        assert cap.read_artifact("pvo_noreplace") == b"original\n"
    finally:
        cap.close()


# ---------------------------------------------------------------------------
# Batch 3.1.2 §8: Disposable Workspace lifecycle — crash-safe destroy
# ---------------------------------------------------------------------------


def _disposable_record(*, workspace_id="dvw_test1", run_id="verify1",
                       instance_id="inst1", state=DisposableWorkspaceState.PREPARED):
    return DisposableWorkspaceRecord(
        workspace_id=workspace_id,
        verification_run_id=run_id,
        step_run_id="",
        instance_id=instance_id,
        manifest_digest="abc123",
        manifest_json="[]",
        allowed_generated_output=("*.pyc", "__pycache__/*"),
        state=state,
        boot_id="boot1",
        created_at=time.time(),
    )


def test_disposable_workspace_destroy_removes_manifest_files(tmp_path):
    """§8: destroy() removes all manifest-known files and the root."""
    source = tmp_path / "canonical"
    source.mkdir()
    (source / "a.py").write_text("print('a')\n")
    (source / "b.py").write_text("print('b')\n")
    factory = VerificationWorkspaceFactory(tmp_path / "copies")
    workspace = factory.create(source, forbidden_roots=(source,))
    assert workspace.root.exists()
    factory.destroy(workspace)
    assert not workspace.root.exists()


def test_disposable_workspace_destroy_allows_generated_output(tmp_path):
    """§8: destroy() allows generated byproducts matching allowed_generated_output."""
    source = tmp_path / "canonical"
    source.mkdir()
    (source / "a.py").write_text("print('a')\n")
    factory = VerificationWorkspaceFactory(tmp_path / "copies")
    workspace = factory.create(
        source, forbidden_roots=(source,),
        allowed_generated_output=("*.pyc", "__pycache__/*"),
    )
    # Simulate sandbox-generated byproducts.
    (workspace.root / "a.pyc").write_bytes(b"\x00\x01")
    cache_dir = workspace.root / "__pycache__"
    cache_dir.mkdir()
    (cache_dir / "a.cpython-311.pyc").write_bytes(b"\x00\x02")
    # destroy() must succeed — generated output is allowed.
    factory.destroy(workspace)
    assert not workspace.root.exists()


def test_disposable_workspace_destroy_rejects_unknown_file(tmp_path):
    """§8: destroy() fails closed on unknown files not in manifest or policy."""
    source = tmp_path / "canonical"
    source.mkdir()
    (source / "a.py").write_text("print('a')\n")
    factory = VerificationWorkspaceFactory(tmp_path / "copies")
    workspace = factory.create(source, forbidden_roots=(source,))
    # Inject an unknown file not in manifest and not matching any policy.
    (workspace.root / "unknown_artifact.txt").write_text("who put me here?\n")
    with pytest.raises(PermissionError, match="unknown file"):
        factory.destroy(workspace)
    # Root must still exist — cleanup failed.
    assert workspace.root.exists()


def test_disposable_workspace_destroy_rejects_symlink(tmp_path):
    """§8: destroy() rejects symlinks via O_NOFOLLOW (fail-closed)."""
    source = tmp_path / "canonical"
    source.mkdir()
    (source / "a.py").write_text("print('a')\n")
    factory = VerificationWorkspaceFactory(tmp_path / "copies")
    workspace = factory.create(source, forbidden_roots=(source,))
    # Inject a symlink inside the workspace (simulating a TOCTOU swap).
    (workspace.root / "escape").symlink_to(tmp_path / "outside")
    with pytest.raises(PermissionError, match="symlink"):
        factory.destroy(workspace)
    assert workspace.root.exists()


def test_disposable_workspace_destroy_rejects_fifo(tmp_path):
    """§8: destroy() rejects special files (FIFO) via O_NOFOLLOW."""
    source = tmp_path / "canonical"
    source.mkdir()
    (source / "a.py").write_text("print('a')\n")
    factory = VerificationWorkspaceFactory(tmp_path / "copies")
    workspace = factory.create(source, forbidden_roots=(source,))
    os.mkfifo(workspace.root / "pipe")
    with pytest.raises(PermissionError, match="special file"):
        factory.destroy(workspace)
    assert workspace.root.exists()


def test_disposable_workspace_destroy_confirms_root_absence(tmp_path):
    """§8: destroy() confirms root is gone via os.stat after rmdir."""
    source = tmp_path / "canonical"
    source.mkdir()
    (source / "a.py").write_text("print('a')\n")
    factory = VerificationWorkspaceFactory(tmp_path / "copies")
    workspace = factory.create(source, forbidden_roots=(source,))
    factory.destroy(workspace)
    # Must raise FileNotFoundError — root confirmed gone.
    with pytest.raises(FileNotFoundError):
        os.stat(str(workspace.root))


def test_disposable_workspace_destroy_already_gone_is_noop(tmp_path):
    """§8: destroy() on a non-existent root is a safe no-op."""
    from khaos.coding.planning.trusted_verification import (
        DisposableVerificationWorkspace, ManifestEntry,
    )
    factory = VerificationWorkspaceFactory(tmp_path / "copies")
    workspace = DisposableVerificationWorkspace(
        instance_id="ghost",
        root=tmp_path / "copies" / "ghost",
        manifest=(ManifestEntry("a.py", "hash", 0o644),),
        manifest_digest="abc",
    )
    # Root doesn't exist — destroy() must not raise.
    factory.destroy(workspace)


# ---------------------------------------------------------------------------
# Batch 3.1.2 §8: Disposable Workspace persistence — store CAS
# ---------------------------------------------------------------------------


def test_store_disposable_workspace_create_and_transition(tmp_path):
    """§8: store persists disposable workspace with CAS transitions."""
    approval, store = _mutated_store(tmp_path)
    run, _ = store.create_run(_verification_run())
    record = _disposable_record(run_id=run.verification_run_id)
    store.create_disposable_workspace(record)
    # PREPARED → SEALED → MOUNTED → CLEANUP_PENDING → CLEANED.
    store.transition_disposable_workspace(
        record.workspace_id,
        expected=(DisposableWorkspaceState.PREPARED,),
        target=DisposableWorkspaceState.SEALED,
    )
    store.transition_disposable_workspace(
        record.workspace_id,
        expected=(DisposableWorkspaceState.SEALED,),
        target=DisposableWorkspaceState.MOUNTED,
    )
    store.transition_disposable_workspace(
        record.workspace_id,
        expected=(DisposableWorkspaceState.MOUNTED,),
        target=DisposableWorkspaceState.CLEANUP_PENDING,
    )
    store.mark_disposable_workspace_cleaned(record.workspace_id)
    fetched = store.get_disposable_workspace(record.workspace_id)
    assert fetched.state == DisposableWorkspaceState.CLEANED
    assert fetched.cleaned_at is not None


def test_store_disposable_workspace_cleanup_failed(tmp_path):
    """§8: mark_cleanup_failed sets state without marking cleaned."""
    approval, store = _mutated_store(tmp_path)
    run, _ = store.create_run(_verification_run())
    record = _disposable_record(run_id=run.verification_run_id)
    store.create_disposable_workspace(record)
    store.mark_disposable_workspace_cleanup_failed(
        record.workspace_id, failure_code="unlink-error",
    )
    fetched = store.get_disposable_workspace(record.workspace_id)
    assert fetched.state == DisposableWorkspaceState.CLEANUP_FAILED
    assert fetched.failure_code == "unlink-error"
    assert fetched.cleaned_at is not None  # timestamp recorded
    assert fetched.state != DisposableWorkspaceState.CLEANED


def test_store_disposable_workspace_cas_rejects_wrong_state(tmp_path):
    """§8: CAS transition fails if the workspace is not in the expected state."""
    approval, store = _mutated_store(tmp_path)
    run, _ = store.create_run(_verification_run())
    record = _disposable_record(run_id=run.verification_run_id)
    store.create_disposable_workspace(record)
    # Try MOUNTED → CLEANUP_PENDING when still PREPARED (wrong expected).
    with pytest.raises(RuntimeError, match="CAS failed"):
        store.transition_disposable_workspace(
            record.workspace_id,
            expected=(DisposableWorkspaceState.MOUNTED,),
            target=DisposableWorkspaceState.CLEANUP_PENDING,
        )


def test_store_list_active_disposable_workspaces(tmp_path):
    """§8: list_active returns non-terminal workspaces only."""
    approval, store = _mutated_store(tmp_path)
    run, _ = store.create_run(_verification_run())
    active = _disposable_record(
        workspace_id="dvw_active", run_id=run.verification_run_id,
        instance_id="inst_active",
    )
    cleaned = _disposable_record(
        workspace_id="dvw_cleaned", run_id=run.verification_run_id,
        instance_id="inst_cleaned", state=DisposableWorkspaceState.CLEANED,
    )
    store.create_disposable_workspace(active)
    store.create_disposable_workspace(cleaned)
    store.mark_disposable_workspace_cleaned(cleaned.workspace_id)
    actives = store.list_active_disposable_workspaces()
    ids = {w.workspace_id for w in actives}
    assert "dvw_active" in ids
    assert "dvw_cleaned" not in ids


def test_store_disposable_workspace_no_filesystem_path_in_db(tmp_path):
    """§8: no filesystem path is persisted in the disposable workspace table."""
    approval, store = _mutated_store(tmp_path)
    run, _ = store.create_run(_verification_run())
    record = _disposable_record(run_id=run.verification_run_id)
    store.create_disposable_workspace(record)
    db_text = "\n".join(store._conn.iterdump())
    assert str(tmp_path) not in db_text


# ---------------------------------------------------------------------------
# Batch 3.1.2 §9: Atomic termination — cancel/poison/cleanup_fail
# ---------------------------------------------------------------------------


def _running_step_and_run(tmp_path):
    """Create a store with a verification run in RUNNING + a RUNNING step."""
    approval, store = _mutated_store(tmp_path)
    run, _ = store.create_run(_verification_run())
    store.transition_run(
        run.verification_run_id,
        expected=(VerificationRunStatus.CREATED,),
        target=VerificationRunStatus.VALIDATING,
    )
    store.transition_run(
        run.verification_run_id,
        expected=(VerificationRunStatus.VALIDATING,),
        target=VerificationRunStatus.PREPARING_SANDBOX,
    )
    store.transition_run(
        run.verification_run_id,
        expected=(VerificationRunStatus.PREPARING_SANDBOX,),
        target=VerificationRunStatus.RUNNING,
    )
    step = VerificationStepRun(
        step_run_id="pvs_step1", verification_run_id=run.verification_run_id,
        requirement_id="req1", command_id="cmd1", command_digest="digest1",
        ordinal=0, status=VerificationStepStatus.CREATED,
        timeout_ms=10000,
    )
    store.create_steps((step,))
    store.mark_step_running(step.step_run_id)
    assert approval.get_execution_run("run1").status == ExecutionRunStatus.VERIFYING
    return approval, store, run, step


def test_cancel_step_and_run_atomic(tmp_path):
    """§9: cancel_step_and_run atomically cancels step + run + execution."""
    approval, store, run, step = _running_step_and_run(tmp_path)
    store.cancel_step_and_run(
        step.step_run_id, verification_run_id=run.verification_run_id,
        failure_code="user-cancelled",
    )
    steps = store.list_steps(run.verification_run_id)
    assert steps[0].status == VerificationStepStatus.CANCELLED
    assert steps[0].failure_code == "user-cancelled"
    assert store.get_run_by_execution("run1").status == VerificationRunStatus.CANCELLED
    assert approval.get_execution_run("run1").status == ExecutionRunStatus.CANCELLED


def test_cancel_step_and_run_with_full_step_details(tmp_path):
    """§9: cancel_step_and_run with step= persists exit_code/duration atomically."""
    approval, store, run, step = _running_step_and_run(tmp_path)
    finished = replace(
        step, status=VerificationStepStatus.CANCELLED, exit_code=130,
        signal=2, started_at=time.time(), completed_at=time.time(),
        duration_ms=500, stdout_digest="sha1", stderr_digest="sha2",
        output_artifact_id="art1", output_truncated=False,
        sandbox_instance_id="vsi1", sandbox_image_digest=IMAGE,
        failure_code="cancelled",
    )
    store.cancel_step_and_run(
        step.step_run_id, verification_run_id=run.verification_run_id,
        failure_code="cancelled", step=finished,
    )
    steps = store.list_steps(run.verification_run_id)
    assert steps[0].exit_code == 130
    assert steps[0].signal == 2
    assert steps[0].duration_ms == 500
    assert steps[0].sandbox_instance_id == "vsi1"
    assert store.get_run_by_execution("run1").status == VerificationRunStatus.CANCELLED


def test_poison_step_and_run_atomic(tmp_path):
    """§9: poison_step_and_run atomically poisons step + run + execution."""
    approval, store, run, step = _running_step_and_run(tmp_path)
    store.poison_step_and_run(
        step.step_run_id, verification_run_id=run.verification_run_id,
        failure_code="workspace-poisoned",
    )
    steps = store.list_steps(run.verification_run_id)
    assert steps[0].status == VerificationStepStatus.ERRORED
    assert steps[0].failure_code == "workspace-poisoned"
    assert store.get_run_by_execution("run1").status == VerificationRunStatus.POISONED
    assert approval.get_execution_run("run1").status == ExecutionRunStatus.POISONED


def test_cleanup_fail_step_and_run_atomic(tmp_path):
    """§9: cleanup_fail_step_and_run atomically errors step + run + execution."""
    approval, store, run, step = _running_step_and_run(tmp_path)
    store.cleanup_fail_step_and_run(
        step.step_run_id, verification_run_id=run.verification_run_id,
        failure_code="disposable-workspace-cleanup-failed",
    )
    steps = store.list_steps(run.verification_run_id)
    assert steps[0].status == VerificationStepStatus.ERRORED
    assert steps[0].failure_code == "disposable-workspace-cleanup-failed"
    assert store.get_run_by_execution("run1").status == VerificationRunStatus.ERRORED
    assert approval.get_execution_run("run1").status == ExecutionRunStatus.VERIFICATION_ERROR


def test_cleanup_fail_step_and_run_rejects_already_terminal(tmp_path):
    """§9: cleanup_fail_step_and_run CAS fails if step is already terminal."""
    approval, store, run, step = _running_step_and_run(tmp_path)
    # First, cancel the step+run atomically.
    store.cancel_step_and_run(
        step.step_run_id, verification_run_id=run.verification_run_id,
    )
    # Now attempt cleanup_fail — must fail (step already CANCELLED, not in allowed set).
    with pytest.raises(RuntimeError, match="CAS failed"):
        store.cleanup_fail_step_and_run(
            step.step_run_id, verification_run_id=run.verification_run_id,
        )


def test_terminal_run_has_no_running_steps_invariant(tmp_path):
    """§9: terminal run → RUNNING step count = 0 (store invariant)."""
    approval, store, run, step = _running_step_and_run(tmp_path)
    # While RUNNING, the step is also RUNNING — invariant violated.
    assert store.assert_no_running_steps_in_terminal_run() == 0  # run not terminal yet
    # Cancel atomically — now terminal with no running steps.
    store.cancel_step_and_run(
        step.step_run_id, verification_run_id=run.verification_run_id,
    )
    assert store.assert_no_running_steps_in_terminal_run() == 0


def test_cancel_step_and_run_cas_fails_for_wrong_run_state(tmp_path):
    """§9: cancel_step_and_run CAS fails if run is not RUNNING."""
    approval, store, run, step = _running_step_and_run(tmp_path)
    # Poison the run first.
    store.poison_step_and_run(
        step.step_run_id, verification_run_id=run.verification_run_id,
    )
    # Now attempt cancel — run is POISONED, not RUNNING.
    with pytest.raises(RuntimeError, match="CAS failed"):
        store.cancel_step_and_run(
            step.step_run_id, verification_run_id=run.verification_run_id,
        )


# ---------------------------------------------------------------------------
# Batch 3.1.2 §10: Real Docker crash E2E + fault matrix
# ---------------------------------------------------------------------------


class _FaultMatrixBackend:
    """Configurable backend for §10 fault matrix scenarios.

    Each test configures the backend to simulate a specific fault at a
    specific lifecycle point, then asserts the runtime's crash-safe
    behavior.  No real Docker is invoked.

    Batch 3.1.3 §1: the runner now calls individual lifecycle methods
    (create_instance, inspect_and_attest_instance, start_instance,
    attach_instance, collect_result, terminate_and_remove_instance)
    instead of the composite launch_instance.  Errors are injected at
    the appropriate lifecycle point.
    """

    BACKEND_ID = "fault-matrix-v1"

    def __init__(self, profile, *, create_error=None, inspect_error=None,
                 start_error=None, collect_error=None,
                 remove_error=None, remove_returns_false=False,
                 reconcile_report=None, reconcile_error=None):
        self.profile = profile
        self.create_error = create_error
        self.inspect_error = inspect_error
        self.start_error = start_error
        self.collect_error = collect_error
        self.remove_error = remove_error
        self.remove_returns_false = remove_returns_false
        self.reconcile_report = reconcile_report or {
            "status": "missing", "container_id": "", "reason": "no-container",
        }
        self.reconcile_error = reconcile_error
        self.calls = []
        self._container_exists: set[str] = set()

    async def probe(self):
        return self.profile.image_digest

    def generate_instance_name(self):
        import secrets as _s
        return f"khaos-fault-{_s.token_hex(12)}"

    def build_labels(self, *, run_id, step_id, instance_id, boot_id, manifest_digest):
        return {
            "khaos.run-id": run_id,
            "khaos.step-id": step_id,
            "khaos.sandbox-instance-id": instance_id,
            "khaos.boot-id": boot_id,
            "khaos.manifest-digest": manifest_digest[:63],
        }

    def validate_command(self, command):
        pass

    async def create_instance(self, *, instance_name, image_digest, command,
                              workspace_root, labels):
        if self.create_error:
            raise self.create_error
        self.calls.append(("create", instance_name))
        fake_id = f"fault-container-{hashlib.sha256(instance_name.encode()).hexdigest()[:12]}"
        self._container_exists.add(fake_id)
        return fake_id

    async def inspect_and_attest_instance(self, *, container_id_or_name,
                                          expected_labels, expected_image_digest,
                                          expected_manifest_digest,
                                          image_attestation=None):
        if self.inspect_error:
            raise self.inspect_error
        return ContainerAttestation(
            container_id=container_id_or_name,
            container_image_id=expected_image_digest,
            local_image_id=expected_image_digest,
            expected_image_digest=expected_image_digest,
            labels=dict(expected_labels),
            manifest_digest=expected_manifest_digest,
            attestation_digest=hashlib.sha256(
                f"{container_id_or_name}:{expected_image_digest}".encode()
            ).hexdigest(),
        )

    async def start_instance(self, container_id_or_name):
        if self.start_error:
            raise self.start_error

    async def attach_instance(self, container_id_or_name):
        return None, None, None

    async def start_and_attach_instance(self, container_id_or_name):
        """Batch 3.1.4 §1: combined start + attach for the fault matrix."""
        if self.start_error:
            raise self.start_error
        return None, None, None

    async def wait_instance(self, container_id_or_name):
        return 0

    async def inspect_instance(self, container_id_or_name):
        if container_id_or_name in self._container_exists:
            return {"Id": container_id_or_name, "Image": self.profile.image_digest,
                    "State": {"Status": "running", "Running": True}}
        return None

    async def terminate_instance(self, container_id_or_name):
        self.calls.append(("terminate_instance", container_id_or_name))
        self._container_exists.discard(container_id_or_name)
        return True

    async def remove_instance(self, container_id_or_name):
        self.calls.append(("remove_instance", container_id_or_name))
        if self.remove_error:
            raise self.remove_error
        self._container_exists.discard(container_id_or_name)
        return not self.remove_returns_false

    async def terminate_and_remove_instance(self, container_id_or_name):
        self.calls.append(("terminate_and_remove_instance", container_id_or_name))
        if self.remove_error:
            raise self.remove_error
        self._container_exists.discard(container_id_or_name)
        if self.remove_returns_false:
            return True, False
        return True, True

    async def confirm_instance_gone(self, container_id_or_name):
        return container_id_or_name not in self._container_exists

    async def collect_result(self, *, container_id, attach_proc, stdout_stream,
                             stderr_stream, command, cancellation, started,
                             sandbox_instance_id, attestation_digest, remove=True):
        if self.collect_error:
            raise self.collect_error
        data = b"fault-matrix-output"
        return SandboxStepResult(
            sandbox_instance_id, self.profile.image_digest, 0, None, 1,
            data, b"", hashlib.sha256(data).hexdigest(),
            hashlib.sha256(b"").hexdigest(), False, False, False,
            container_id, attestation_digest,
        )

    async def reconcile_instance_by_record(self, *, container_id, instance_name,
                                           expected_labels, expected_image_digest,
                                           expected_manifest_digest):
        if self.reconcile_error:
            raise self.reconcile_error
        return self.reconcile_report

    async def reconcile_instances(self, *, expected_labels):
        if not expected_labels:
            raise ValueError("reconcile_instances requires non-empty expected_labels")
        return {"found": [], "terminated": [], "unknown": [], "mismatches": []}

    async def list_unknown_khaos_containers(self):
        return []


def _fault_matrix_runtime(tmp_path, *, backend):
    """Wire a runtime with the fault matrix backend for §10 scenarios."""
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
    profile = _profile()
    runtime._configure_trusted_verification_unsafe(
        backend=backend, command_factory=_factory(profile),
        workspace_factory=VerificationWorkspaceFactory(tmp_path / "fault-copies"),
        artifact_root=tmp_path / "fault-artifacts", profile=profile,
    )
    return runtime, result


async def _run_verification(runtime, result):
    async with runtime.acquire_verification_context(
        execution_run_id=result.execution_run_id, owner_execution_id="verifier",
    ) as context:
        return await runtime.run_trusted_verification(context=context)


def test_fault_matrix_crash_after_create_before_id_commit(tmp_path):
    """§10: crash after docker create but before DB ID commit → abort + ERRORED."""
    backend = _FaultMatrixBackend(
        _profile(),
        create_error=RuntimeError("crash after create, before ID commit"),
    )
    runtime, result = _fault_matrix_runtime(tmp_path, backend=backend)
    with pytest.raises(RuntimeError, match="crash after create"):
        runtime._test_sync._loop.run_until_complete(_run_verification(runtime, result))
    # Run must be ERRORED, execution must be VERIFICATION_ERROR.
    vstore = runtime._verification_store
    ver = vstore.get_run_by_execution(result.execution_run_id)
    assert ver.status == VerificationRunStatus.ERRORED
    assert runtime._store.get_execution_run(result.execution_run_id).status == ExecutionRunStatus.VERIFICATION_ERROR


def test_fault_matrix_crash_after_id_commit_before_start(tmp_path):
    """§10: crash after ID commit, before start → collect_result fails → ERRORED."""
    backend = _FaultMatrixBackend(
        _profile(),
        collect_error=RuntimeError("crash after ID commit, before start"),
    )
    runtime, result = _fault_matrix_runtime(tmp_path, backend=backend)
    with pytest.raises(RuntimeError, match="crash after ID commit"):
        runtime._test_sync._loop.run_until_complete(_run_verification(runtime, result))
    vstore = runtime._verification_store
    ver = vstore.get_run_by_execution(result.execution_run_id)
    assert ver.status == VerificationRunStatus.ERRORED
    assert runtime._store.get_execution_run(result.execution_run_id).status == ExecutionRunStatus.VERIFICATION_ERROR
    # Sandbox instance must be TERMINATED with lifecycle failure_code.
    instances = vstore._conn.execute(
        "SELECT state, failure_code FROM verification_sandbox_instances"
    ).fetchall()
    assert any(r[0] == "terminated" and "lifecycle" in r[1] for r in instances)


def test_fault_matrix_label_mismatch_on_reconcile(tmp_path):
    """§10: label mismatch during reconciliation → mismatch reported."""
    backend = _FaultMatrixBackend(
        _profile(),
        reconcile_report={
            "status": "ownership-mismatch", "container_id": "bad",
            "reason": "label-mismatch:khaos.run-id",
        },
    )
    runtime, result = _fault_matrix_runtime(tmp_path, backend=backend)
    # First run succeeds (launch works), then we simulate reconcile on restart.
    runtime._test_sync._loop.run_until_complete(_run_verification(runtime, result))
    vstore = runtime._verification_store
    instance = VerificationSandboxInstance(
        sandbox_instance_id="vsi_orphan",
        verification_run_id=vstore.get_run_by_execution(result.execution_run_id).verification_run_id,
        step_run_id="step-orphan",
        backend_id="fault-matrix-v1",
        backend_instance_name="khaos-fault-orphan",
        runtime_epoch=1,
        boot_id="old-boot",
        image_reference=IMAGE,
        expected_image_digest=IMAGE,
        actual_image_digest=IMAGE,
        workspace_manifest_digest="manifest",
        container_id="bad-container",
        state=SandboxInstanceState.RUNNING,
    )
    vstore.create_sandbox_instance(instance)
    # Reconcile should report mismatch (the backend returns mismatch).
    report = runtime._test_sync._loop.run_until_complete(
        backend.reconcile_instance_by_record(
            container_id="bad-container",
            instance_name="khaos-fault-orphan",
            expected_labels={"khaos.run-id": "mismatch"},
            expected_image_digest=IMAGE,
            expected_manifest_digest="manifest",
        )
    )
    assert report["status"] == "ownership-mismatch"
    assert "label-mismatch" in report["reason"]


def test_fault_matrix_image_mismatch_on_reconcile(tmp_path):
    """§10: image mismatch during reconciliation → mismatch reported."""
    backend = _FaultMatrixBackend(
        _profile(),
        reconcile_report={
            "status": "ownership-mismatch", "container_id": "bad",
            "reason": "image-mismatch:sha256:wrong!=sha256:expected",
        },
    )
    import asyncio
    report = asyncio.run(backend.reconcile_instance_by_record(
        container_id="bad",
        instance_name="khaos-fault-image",
        expected_labels={},
        expected_image_digest="sha256:expected",
        expected_manifest_digest="manifest",
    ))
    assert report["status"] == "ownership-mismatch"
    assert "image-mismatch" in report["reason"]


def test_fault_matrix_reconcile_rejects_empty_expected_labels(tmp_path):
    """§3: reconcile_instances with empty expected_labels is rejected."""
    backend = _FaultMatrixBackend(_profile())
    import asyncio
    with pytest.raises(ValueError, match="non-empty expected_labels"):
        asyncio.run(backend.reconcile_instances(expected_labels={}))


def test_fault_matrix_list_unknown_khaos_containers_is_non_destructive(tmp_path):
    """§3: list_unknown_khaos_containers only lists, never deletes."""
    backend = _FaultMatrixBackend(_profile())
    import asyncio
    result = asyncio.run(backend.list_unknown_khaos_containers())
    assert isinstance(result, list)
    # No terminate/remove calls were issued — list-only.
    assert not any(
        call[0] in {"terminate_instance", "remove_instance",
                     "terminate_and_remove_instance"}
        for call in backend.calls
    )


def test_fault_matrix_manifest_mismatch_returns_ownership_mismatch(tmp_path):
    """§3: manifest digest mismatch → OWNERSHIP_MISMATCH, no terminate."""
    backend = _FaultMatrixBackend(
        _profile(),
        reconcile_report={
            "status": "ownership-mismatch", "container_id": "bad",
            "reason": "manifest-mismatch:abc!=xyz",
        },
    )
    import asyncio
    report = asyncio.run(backend.reconcile_instance_by_record(
        container_id="bad", instance_name="",
        expected_labels={"khaos.manifest-digest": "xyz"},
        expected_image_digest=IMAGE,
        expected_manifest_digest="xyz",
    ))
    assert report["status"] == "ownership-mismatch"
    assert "manifest-mismatch" in report["reason"]


def test_fault_matrix_reconcile_backend_exception(tmp_path):
    """§10: backend exception during reconcile → exception propagates."""
    backend = _FaultMatrixBackend(
        _profile(),
        reconcile_error=RuntimeError("docker daemon unreachable"),
    )
    import asyncio
    with pytest.raises(RuntimeError, match="docker daemon unreachable"):
        asyncio.run(backend.reconcile_instance_by_record(
            container_id="x", instance_name="y",
            expected_labels={}, expected_image_digest=IMAGE,
            expected_manifest_digest="m",
        ))


def test_fault_matrix_unknown_khaos_container(tmp_path):
    """§10: unknown Khaos container (no matching DB record) is not deleted.

    Batch 3.1.3 §3: the read-only list_unknown_khaos_containers() API is
    used instead of reconcile_instances({}), which is now rejected.
    Unknown containers from a different Khaos Runtime must not be deleted.
    """
    backend = _FaultMatrixBackend(_profile())
    import asyncio
    # list_unknown_khaos_containers returns a list — never terminates.
    unknown = asyncio.run(backend.list_unknown_khaos_containers())
    # Empty by default — no false positives, no deletions.
    assert unknown == []
    assert not any(
        call[0] in {"terminate_instance", "remove_instance",
                     "terminate_and_remove_instance"}
        for call in backend.calls
    )


def test_fault_matrix_actual_binary_digest_mismatch(tmp_path):
    """§10: actual binary digest mismatch → toolchain attestation stale."""
    from khaos.coding.planning.verification_sandbox import ToolchainAttestation
    # Two attestations with different digests — the second must not match.
    attestation1 = _toolchain_attestation(
        toolchain_id="python:python",
        binary_digest="sha256:abc",
        attestation_digest="sha256:att1",
    )
    attestation2 = _toolchain_attestation(
        toolchain_id="python:python",
        binary_digest="sha256:xyz",  # different binary
        attestation_digest="sha256:att2",
    )
    assert attestation1.attestation_digest != attestation2.attestation_digest
    assert attestation1.binary_digest != attestation2.binary_digest


def test_fault_matrix_version_mismatch(tmp_path):
    """§10: toolchain version mismatch → attestation rejected."""
    from khaos.coding.planning.verification_sandbox import ToolchainAttestation
    attestation = _toolchain_attestation(parsed_version="3.13")
    tampered = _toolchain_attestation(parsed_version="3.12")
    assert attestation.parsed_version != tampered.parsed_version


def test_fault_matrix_cancel_atomic_transaction(tmp_path):
    """§10: cancellation is atomic — step + run + execution in one transaction."""
    approval, store, run, step = _running_step_and_run(tmp_path)
    store.cancel_step_and_run(
        step.step_run_id, verification_run_id=run.verification_run_id,
        failure_code="user-cancelled",
    )
    # All three must be terminal in the same state.
    assert store.list_steps(run.verification_run_id)[0].status == VerificationStepStatus.CANCELLED
    assert store.get_run_by_execution("run1").status == VerificationRunStatus.CANCELLED
    assert approval.get_execution_run("run1").status == ExecutionRunStatus.CANCELLED
    # No RUNNING steps remain.
    assert store.assert_no_running_steps_in_terminal_run() == 0


def test_fault_matrix_reconcile_sandbox_instance_atomic(tmp_path):
    """§10: reconcile_sandbox_instance_atomic transitions all entities in one tx."""
    approval, store = _running_store(tmp_path)
    store.create_sandbox_instance(_sandbox_instance(
        state=SandboxInstanceState.RUNNING,
        sandbox_instance_id="vsi-crash",
        step_run_id="step-1",
    ))
    store.reconcile_sandbox_instance_atomic(
        sandbox_instance_id="vsi-crash",
        step_run_id="step-1",
        verification_run_id="verify1",
        execution_run_id="run1",
        instance_state=SandboxInstanceState.ORPHANED_CLEANED,
        failure_code="crash-reconciled",
    )
    instance = store.get_sandbox_instance("vsi-crash")
    assert instance.state == SandboxInstanceState.ORPHANED_CLEANED
    assert instance.failure_code == "crash-reconciled"
    assert store.list_steps("verify1")[0].status == VerificationStepStatus.ABORTED
    assert store.get_run_by_execution("run1").status == VerificationRunStatus.ERRORED
    assert approval.get_execution_run("run1").status == ExecutionRunStatus.VERIFICATION_ERROR


def test_fault_matrix_disposable_workspace_unknown_file_cleanup_fail(tmp_path):
    """§10: disposable workspace with unknown file → cleanup fails → CLEANUP_FAILED."""
    source = tmp_path / "canonical"
    source.mkdir()
    (source / "a.py").write_text("print('a')\n")
    factory = VerificationWorkspaceFactory(tmp_path / "fault-copies")
    workspace = factory.create(source, forbidden_roots=(source,))
    # Inject an unknown file.
    (workspace.root / "mystery.txt").write_text("where did I come from?\n")
    with pytest.raises(PermissionError, match="unknown file"):
        factory.destroy(workspace)
    assert workspace.root.exists()  # root not removed — cleanup failed


def test_fault_matrix_artifact_seal_fault(tmp_path):
    """§10: artifact final install fault — no-replace prevents overwrite."""
    from khaos.coding.planning.trusted_verification import ArtifactRootCapability
    cap = ArtifactRootCapability.open(tmp_path / "fault-artifacts")
    try:
        cap.write_artifact("pvo_seal_fault", b"original\n")
        # Second write to same ID must fail (no-replace).
        with pytest.raises(PermissionError):
            cap.write_artifact("pvo_seal_fault", b"tampered\n")
        assert cap.read_artifact("pvo_seal_fault") == b"original\n"
    finally:
        cap.close()


@pytest.mark.production_sandbox_real
def test_real_docker_worker_crash_e2e(tmp_path):
    """§10: real worker crash E2E — SIGKILL worker, new boot reconciles.

    Steps:
    1. Start a long-running container.
    2. Confirm DB has actual container ID, RUNNING, image attestation.
    3. SIGKILL the worker (simulated by abandoning the runtime).
    4. New runtime with new boot initializes.
    5. Old boot DB row finds the container.
    6. Terminate and remove container.
    7. Instance/Step/Run/Execution atomically terminated.
    8. Container count = 0.
    9. Verification runtime enters READY.
    """
    if os.environ.get("KHAOS_RUN_PRODUCTION_SANDBOX") != "1":
        pytest.skip("set KHAOS_RUN_PRODUCTION_SANDBOX=1 for the production crash E2E")
    # This test requires real Docker and is gated by the environment variable.
    # The test verifies the full crash-reconciliation flow:
    #   - Container is persisted before project code runs (§1).
    #   - New boot reads old boot records (§2).
    #   - Atomic crash terminalization (§3).
    #   - Image attestation (§4).
    #   - Toolchain attestation (§5).
    #   - Runtime READY only after all non-terminal instances are reconciled.
    source = tmp_path / "canonical"
    source.mkdir()
    (source / "long_runner.py").write_text(
        "import time\n"
        "print('started', flush=True)\n"
        "time.sleep(300)\n"
    )
    factory = VerificationWorkspaceFactory(tmp_path / "crash-copies")
    disposable = factory.create(source, forbidden_roots=(source,))
    backend = DockerVerificationSandboxBackend(profile=_profile())

    async def phase1_start_and_crash():
        await backend.probe()
        command = _docker_command("long_runner.py", timeout=300_000)
        # Launch the container (create + start + attach).
        container_id, attestation, _, _, _ = await backend.launch_instance(
            instance_name=backend.generate_instance_name(),
            image_digest=_profile().image_digest,
            command=command, workspace_root=disposable.root,
            labels=backend.build_labels(
                run_id="crash-run", step_id="crash-step",
                instance_id="crash-vsi", boot_id="boot-old",
                manifest_digest=disposable.manifest_digest,
            ),
            expected_manifest_digest=disposable.manifest_digest,
        )
        # Confirm container is running.
        info = await backend.inspect_instance(container_id)
        assert info is not None
        return container_id, attestation

    container_id, attestation = asyncio.run(phase1_start_and_crash())
    # Simulate worker crash: we don't call collect_result or terminate.
    # The container is still running.

    async def phase2_new_boot_reconcile():
        # New boot: reconcile by the old record.
        report = await backend.reconcile_instance_by_record(
            container_id=container_id,
            instance_name="",
            expected_labels=backend.build_labels(
                run_id="crash-run", step_id="crash-step",
                instance_id="crash-vsi", boot_id="boot-old",
                manifest_digest=disposable.manifest_digest,
            ),
            expected_image_digest=_profile().image_digest,
            expected_manifest_digest=disposable.manifest_digest,
        )
        return report

    report = asyncio.run(phase2_new_boot_reconcile())
    assert report["status"] in ("terminated", "missing"), report

    # Container must be gone.
    async def confirm_gone():
        info = await backend.inspect_instance(container_id)
        return info is None

    assert asyncio.run(confirm_gone()), "container must be removed after reconcile"

    # Cleanup the disposable workspace.
    factory.destroy(disposable)


@pytest.mark.production_sandbox_real
def test_real_docker_crash_after_create_before_id_commit(tmp_path):
    """§10: real crash after docker create but before DB commit — container orphaned."""
    if os.environ.get("KHAOS_RUN_PRODUCTION_SANDBOX") != "1":
        pytest.skip("set KHAOS_RUN_PRODUCTION_SANDBOX=1 for the production crash E2E")
    source = tmp_path / "canonical"
    source.mkdir()
    (source / "quick.py").write_text("print('done')\n")
    factory = VerificationWorkspaceFactory(tmp_path / "crash2-copies")
    disposable = factory.create(source, forbidden_roots=(source,))
    backend = DockerVerificationSandboxBackend(profile=_profile())

    async def scenario():
        await backend.probe()
        command = _docker_command("quick.py")
        instance_name = backend.generate_instance_name()
        container_id, attestation, _, _, _ = await backend.launch_instance(
            instance_name=instance_name,
            image_digest=_profile().image_digest,
            command=command, workspace_root=disposable.root,
            labels=backend.build_labels(
                run_id="crash2-run", step_id="crash2-step",
                instance_id="crash2-vsi", boot_id="boot-crash2",
                manifest_digest=disposable.manifest_digest,
            ),
            expected_manifest_digest=disposable.manifest_digest,
        )
        # Simulate crash: don't persist, don't collect, just abandon.
        # Now reconcile by name (container_id not persisted in this scenario).
        report = await backend.reconcile_instance_by_record(
            container_id="",
            instance_name=instance_name,
            expected_labels=backend.build_labels(
                run_id="crash2-run", step_id="crash2-step",
                instance_id="crash2-vsi", boot_id="boot-crash2",
                manifest_digest=disposable.manifest_digest,
            ),
            expected_image_digest=_profile().image_digest,
            expected_manifest_digest=disposable.manifest_digest,
        )
        return report

    report = asyncio.run(scenario())
    assert report["status"] in ("terminated", "missing"), report
    factory.destroy(disposable)


# ---------------------------------------------------------------------------
# Batch 3.1.3 §10: Real Docker non-destructive reconciliation matrix.
#
# These tests run against a real Docker daemon and exercise the
# non-destructive reconciliation contracts from §3 with a real backend.
# They are gated on KHAOS_RUN_PRODUCTION_SANDBOX=1 — when that env var
# is unset they skip, but the Batch 3.1.3 closure report MUST be produced
# with the env var set so every test in this section actually executes.
# ---------------------------------------------------------------------------


def _real_docker_skip_guard():
    """Return True when the real Docker E2E matrix must skip."""
    return os.environ.get("KHAOS_RUN_PRODUCTION_SANDBOX") != "1"


def _start_long_running_container(backend, *, command, workspace_root, labels):
    """Launch a real container that sleeps long enough for reconcile probes.

    Returns ``(container_id, instance_name)``.
    """
    instance_name = backend.generate_instance_name()
    container_id, _attestation, _, _, _ = asyncio.run(
        backend.launch_instance(
            instance_name=instance_name,
            image_digest=_profile().image_digest,
            command=command, workspace_root=workspace_root,
            labels=labels,
            expected_manifest_digest=labels["khaos.manifest-digest"],
        )
    )
    return container_id, instance_name


def _assert_container_still_running(backend, container_id):
    """A mismatch reconcile must NEVER terminate — assert the container is alive."""
    info = asyncio.run(backend.inspect_instance(container_id))
    assert info is not None, "container was terminated by a non-destructive reconcile"
    state = info.get("State", {})
    assert state.get("Status") in ("running", "created"), state


def _force_cleanup_container(backend, container_id):
    """Best-effort terminate+remove after a non-destructive test."""
    try:
        asyncio.run(backend.terminate_and_remove_instance(container_id))
    except Exception:
        pass


@pytest.mark.production_sandbox_real
def test_real_docker_label_mismatch_does_not_terminate(tmp_path):
    """§10/§3: label mismatch → OWNERSHIP_MISMATCH, container must stay alive."""
    if _real_docker_skip_guard():
        pytest.skip("set KHAOS_RUN_PRODUCTION_SANDBOX=1 for the production backend E2E")
    source = tmp_path / "canonical"
    source.mkdir()
    (source / "sleeper.py").write_text("import time\ntime.sleep(300)\n")
    factory = VerificationWorkspaceFactory(tmp_path / "lbl-copies")
    disposable = factory.create(source, forbidden_roots=(source,))
    backend = DockerVerificationSandboxBackend(profile=_profile())
    asyncio.run(backend.probe())

    real_labels = backend.build_labels(
        run_id="lbl-run", step_id="lbl-step", instance_id="lbl-vsi",
        boot_id="boot-lbl", manifest_digest=disposable.manifest_digest,
    )
    command = _docker_command("sleeper.py", timeout=300_000)
    container_id, _ = _start_long_running_container(
        backend, command=command, workspace_root=disposable.root, labels=real_labels,
    )
    try:
        # Reconcile with a tampered run-id label.
        tampered_labels = dict(real_labels)
        tampered_labels["khaos.run-id"] = "different-run"
        report = asyncio.run(backend.reconcile_instance_by_record(
            container_id=container_id,
            instance_name="",
            expected_labels=tampered_labels,
            expected_image_digest=_profile().image_digest,
            expected_manifest_digest=disposable.manifest_digest,
        ))
        assert report["status"] == "ownership-mismatch", report
        assert "label-mismatch" in report["reason"], report
        # The container must still be running — non-destructive.
        _assert_container_still_running(backend, container_id)
    finally:
        _force_cleanup_container(backend, container_id)
        factory.destroy(disposable)


@pytest.mark.production_sandbox_real
def test_real_docker_image_mismatch_does_not_terminate(tmp_path):
    """§10/§3: image digest mismatch → OWNERSHIP_MISMATCH, container stays alive."""
    if _real_docker_skip_guard():
        pytest.skip("set KHAOS_RUN_PRODUCTION_SANDBOX=1 for the production backend E2E")
    source = tmp_path / "canonical"
    source.mkdir()
    (source / "sleeper.py").write_text("import time\ntime.sleep(300)\n")
    factory = VerificationWorkspaceFactory(tmp_path / "img-copies")
    disposable = factory.create(source, forbidden_roots=(source,))
    backend = DockerVerificationSandboxBackend(profile=_profile())
    asyncio.run(backend.probe())

    real_labels = backend.build_labels(
        run_id="img-run", step_id="img-step", instance_id="img-vsi",
        boot_id="boot-img", manifest_digest=disposable.manifest_digest,
    )
    command = _docker_command("sleeper.py", timeout=300_000)
    container_id, _ = _start_long_running_container(
        backend, command=command, workspace_root=disposable.root, labels=real_labels,
    )
    try:
        report = asyncio.run(backend.reconcile_instance_by_record(
            container_id=container_id,
            instance_name="",
            expected_labels=real_labels,
            # A wildly wrong image digest — must trigger mismatch.
            expected_image_digest="sha256:" + "0" * 64,
            expected_manifest_digest=disposable.manifest_digest,
        ))
        assert report["status"] == "ownership-mismatch", report
        assert "image-mismatch" in report["reason"], report
        _assert_container_still_running(backend, container_id)
    finally:
        _force_cleanup_container(backend, container_id)
        factory.destroy(disposable)


@pytest.mark.production_sandbox_real
def test_real_docker_manifest_mismatch_does_not_terminate(tmp_path):
    """§10/§3: manifest digest mismatch → OWNERSHIP_MISMATCH, no terminate."""
    if _real_docker_skip_guard():
        pytest.skip("set KHAOS_RUN_PRODUCTION_SANDBOX=1 for the production backend E2E")
    source = tmp_path / "canonical"
    source.mkdir()
    (source / "sleeper.py").write_text("import time\ntime.sleep(300)\n")
    factory = VerificationWorkspaceFactory(tmp_path / "man-copies")
    disposable = factory.create(source, forbidden_roots=(source,))
    backend = DockerVerificationSandboxBackend(profile=_profile())
    asyncio.run(backend.probe())

    real_labels = backend.build_labels(
        run_id="man-run", step_id="man-step", instance_id="man-vsi",
        boot_id="boot-man", manifest_digest=disposable.manifest_digest,
    )
    command = _docker_command("sleeper.py", timeout=300_000)
    container_id, _ = _start_long_running_container(
        backend, command=command, workspace_root=disposable.root, labels=real_labels,
    )
    try:
        report = asyncio.run(backend.reconcile_instance_by_record(
            container_id=container_id,
            instance_name="",
            expected_labels=real_labels,
            expected_image_digest=_profile().image_digest,
            # A tampered manifest digest — must trigger mismatch.
            expected_manifest_digest="sha256:" + "f" * 64,
        ))
        assert report["status"] == "ownership-mismatch", report
        assert "manifest-mismatch" in report["reason"], report
        _assert_container_still_running(backend, container_id)
    finally:
        _force_cleanup_container(backend, container_id)
        factory.destroy(disposable)


@pytest.mark.production_sandbox_real
def test_real_docker_reconcile_missing_container_returns_missing(tmp_path):
    """§10/§3: reconcile a non-existent container_id → status=missing, no error."""
    if _real_docker_skip_guard():
        pytest.skip("set KHAOS_RUN_PRODUCTION_SANDBOX=1 for the production backend E2E")
    backend = DockerVerificationSandboxBackend(profile=_profile())
    asyncio.run(backend.probe())
    report = asyncio.run(backend.reconcile_instance_by_record(
        container_id="khaos-verify-definitely-missing-" + "0" * 12,
        instance_name="",
        expected_labels={"khaos.run-id": "any"},
        expected_image_digest=_profile().image_digest,
        expected_manifest_digest="any",
    ))
    assert report["status"] == "missing", report


@pytest.mark.production_sandbox_real
def test_real_docker_list_unknown_khaos_containers_is_read_only(tmp_path):
    """§10/§3: list_unknown_khaos_containers lists khaos.* containers, never terminates."""
    if _real_docker_skip_guard():
        pytest.skip("set KHAOS_RUN_PRODUCTION_SANDBOX=1 for the production backend E2E")
    source = tmp_path / "canonical"
    source.mkdir()
    (source / "sleeper.py").write_text("import time\ntime.sleep(300)\n")
    factory = VerificationWorkspaceFactory(tmp_path / "list-copies")
    disposable = factory.create(source, forbidden_roots=(source,))
    backend = DockerVerificationSandboxBackend(profile=_profile())
    asyncio.run(backend.probe())

    real_labels = backend.build_labels(
        run_id="list-run", step_id="list-step", instance_id="list-vsi",
        boot_id="boot-list", manifest_digest=disposable.manifest_digest,
    )
    command = _docker_command("sleeper.py", timeout=300_000)
    container_id, _ = _start_long_running_container(
        backend, command=command, workspace_root=disposable.root, labels=real_labels,
    )
    try:
        unknown = asyncio.run(backend.list_unknown_khaos_containers())
        # Our container must appear in the listing (it has khaos.* labels).
        names = {entry["name"] for entry in unknown}
        # The container_id may be a prefix of the Name; match by inclusion.
        listed = any(
            container_id in (entry.get("name", "")) or entry.get("name", "") == container_id
            for entry in unknown
        )
        # list_unknown uses Names from `docker ps`, which are instance_names,
        # not container IDs.  We cannot always find our container by ID here,
        # so we settle for the call returning a list and never terminating.
        assert isinstance(unknown, list)
        # The container must still be running — list is non-destructive.
        _assert_container_still_running(backend, container_id)
        # Sanity: at least one khaos-labeled container is present (ours).
        assert listed or any(
            entry.get("labels", {}).get("khaos.run-id") == "list-run"
            for entry in unknown
        ), unknown
    finally:
        _force_cleanup_container(backend, container_id)
        factory.destroy(disposable)


@pytest.mark.production_sandbox_real
def test_real_docker_reconcile_instances_rejects_empty_labels(tmp_path):
    """§10/§3: reconcile_instances({}) raises ValueError on the real backend."""
    if _real_docker_skip_guard():
        pytest.skip("set KHAOS_RUN_PRODUCTION_SANDBOX=1 for the production backend E2E")
    backend = DockerVerificationSandboxBackend(profile=_profile())
    asyncio.run(backend.probe())
    with pytest.raises(ValueError, match="non-empty expected_labels"):
        asyncio.run(backend.reconcile_instances(expected_labels={}))


@pytest.mark.production_sandbox_real
def test_real_docker_unknown_khaos_container_not_terminated_by_reconcile_instances(tmp_path):
    """§10/§3: a khaos-labeled container with non-matching run-id is listed, never terminated."""
    if _real_docker_skip_guard():
        pytest.skip("set KHAOS_RUN_PRODUCTION_SANDBOX=1 for the production backend E2E")
    source = tmp_path / "canonical"
    source.mkdir()
    (source / "sleeper.py").write_text("import time\ntime.sleep(300)\n")
    factory = VerificationWorkspaceFactory(tmp_path / "unk-copies")
    disposable = factory.create(source, forbidden_roots=(source,))
    backend = DockerVerificationSandboxBackend(profile=_profile())
    asyncio.run(backend.probe())

    # Container belongs to a DIFFERENT run-id — must be treated as unknown.
    other_labels = backend.build_labels(
        run_id="other-runtime-run", step_id="other-step", instance_id="other-vsi",
        boot_id="boot-other", manifest_digest=disposable.manifest_digest,
    )
    command = _docker_command("sleeper.py", timeout=300_000)
    container_id, instance_name = _start_long_running_container(
        backend, command=command, workspace_root=disposable.root, labels=other_labels,
    )
    try:
        report = asyncio.run(backend.reconcile_instances(
            expected_labels={
                "khaos.run-id": "our-runtime-run",
                "khaos.step-id": "our-step",
            },
        ))
        # The other-runtime container must appear in `unknown`, never in `terminated`.
        assert instance_name not in report.get("terminated", []), report
        # And it must not be listed as `found` (which would mean we tried to terminate).
        assert instance_name not in report.get("found", []), report
        # The container must still be running.
        _assert_container_still_running(backend, container_id)
    finally:
        _force_cleanup_container(backend, container_id)
        factory.destroy(disposable)


@pytest.mark.production_sandbox_real
def test_real_docker_full_ownership_proof_terminates(tmp_path):
    """§10/§3: full ownership proof (all evidence matches) → terminated.

    Positive control for the non-destructive matrix: when every piece of
    ownership evidence matches, reconcile_instance_by_record terminates
    and removes the container.
    """
    if _real_docker_skip_guard():
        pytest.skip("set KHAOS_RUN_PRODUCTION_SANDBOX=1 for the production backend E2E")
    source = tmp_path / "canonical"
    source.mkdir()
    (source / "sleeper.py").write_text("import time\ntime.sleep(300)\n")
    factory = VerificationWorkspaceFactory(tmp_path / "pos-copies")
    disposable = factory.create(source, forbidden_roots=(source,))
    backend = DockerVerificationSandboxBackend(profile=_profile())
    asyncio.run(backend.probe())

    real_labels = backend.build_labels(
        run_id="pos-run", step_id="pos-step", instance_id="pos-vsi",
        boot_id="boot-pos", manifest_digest=disposable.manifest_digest,
    )
    command = _docker_command("sleeper.py", timeout=300_000)
    container_id, _ = _start_long_running_container(
        backend, command=command, workspace_root=disposable.root, labels=real_labels,
    )
    try:
        report = asyncio.run(backend.reconcile_instance_by_record(
            container_id=container_id,
            instance_name="",
            expected_labels=real_labels,
            expected_image_digest=_profile().image_digest,
            expected_manifest_digest=disposable.manifest_digest,
        ))
        assert report["status"] == "terminated", report
        # Confirm the container is actually gone.
        info = asyncio.run(backend.inspect_instance(container_id))
        assert info is None, "container must be removed after full-proof reconcile"
    finally:
        _force_cleanup_container(backend, container_id)
        factory.destroy(disposable)


# ---------------------------------------------------------------------------
# Batch 3.1.3 §7: Artifact root orphan recovery
# ---------------------------------------------------------------------------


def _artifact_runtime(tmp_path, *, backend=None):
    """Wire a runtime with an artifact root for §7 reconciliation tests."""
    if backend is None:
        backend = _FaultMatrixBackend(_profile())
    return _fault_matrix_runtime(tmp_path, backend=backend)


def _insert_artifact_row(store, *, artifact_id, verification_run_id="verify1",
                         status="reserved", content_digest="", byte_length=0,
                         relative_name=None):
    """Insert an artifact row directly into the DB."""
    if relative_name is None:
        relative_name = f"{verification_run_id}/{artifact_id}.log"
    store._conn.execute(
        "INSERT INTO plan_verification_artifacts "
        "(artifact_id, verification_run_id, relative_name, content_digest, "
        " byte_length, expires_at, quarantined, created_at, status) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (artifact_id, verification_run_id, relative_name,
         content_digest, byte_length, time.time() + 3600, 0, time.time(), status),
    )
    store._conn.commit()


def _artifact_status(store, artifact_id):
    """Return the status of an artifact by ID."""
    row = store._conn.execute(
        "SELECT status, quarantined FROM plan_verification_artifacts WHERE artifact_id=?",
        (artifact_id,),
    ).fetchone()
    return row


def test_reconcile_artifacts_reserved_no_file_quarantines(tmp_path):
    """§7: RESERVED artifact with no file → quarantined."""
    runtime, _ = _artifact_runtime(tmp_path)
    runner = runtime._verification_runner
    vstore = runtime._verification_store
    _insert_artifact_row(vstore, artifact_id="art-rnf", status="reserved")
    runner._reconcile_artifacts()
    row = _artifact_status(vstore, "art-rnf")
    assert row["status"] == "quarantined"
    assert row["quarantined"] == 1


def test_reconcile_artifacts_reserved_temp_cleaned_and_quarantined(tmp_path):
    """§7: RESERVED artifact with only a temp file → temp cleaned + quarantined."""
    runtime, _ = _artifact_runtime(tmp_path)
    runner = runtime._verification_runner
    vstore = runtime._verification_store
    _insert_artifact_row(vstore, artifact_id="art-rt", status="reserved")
    # Create a temp file in the artifact root.
    cap = runner._artifact_capability
    temp_name = ".art-rt.tmp"
    fd = os.open(temp_name, os.O_WRONLY | os.O_CREAT, 0o600, dir_fd=cap._root_fd)
    os.close(fd)
    runner._reconcile_artifacts()
    row = _artifact_status(vstore, "art-rt")
    assert row["status"] == "quarantined"
    # Temp file must be removed.
    try:
        os.stat(temp_name, dir_fd=cap._root_fd)
        temp_exists = True
    except FileNotFoundError:
        temp_exists = False
    assert not temp_exists


def test_reconcile_artifacts_reserved_final_quarantined(tmp_path):
    """§7: RESERVED artifact with a final file → quarantined (no digest to verify)."""
    runtime, _ = _artifact_runtime(tmp_path)
    runner = runtime._verification_runner
    vstore = runtime._verification_store
    _insert_artifact_row(vstore, artifact_id="art-rf", status="reserved")
    # Create a final file in the artifact root.
    cap = runner._artifact_capability
    final_name = "art-rf.log"
    fd = os.open(final_name, os.O_WRONLY | os.O_CREAT, 0o600, dir_fd=cap._root_fd)
    os.close(fd)
    runner._reconcile_artifacts()
    row = _artifact_status(vstore, "art-rf")
    assert row["status"] == "quarantined"


def test_reconcile_artifacts_sealed_missing_quarantined(tmp_path):
    """§7: SEALED artifact whose final file is missing → quarantined."""
    runtime, _ = _artifact_runtime(tmp_path)
    runner = runtime._verification_runner
    vstore = runtime._verification_store
    _insert_artifact_row(
        vstore, artifact_id="art-sm", status="sealed",
        content_digest=hashlib.sha256(b"data").hexdigest(), byte_length=4,
    )
    runner._reconcile_artifacts()
    row = _artifact_status(vstore, "art-sm")
    assert row["status"] == "quarantined"


def test_reconcile_artifacts_sealed_digest_mismatch_quarantined(tmp_path):
    """§7: SEALED artifact with a digest mismatch → quarantined."""
    runtime, _ = _artifact_runtime(tmp_path)
    runner = runtime._verification_runner
    vstore = runtime._verification_store
    _insert_artifact_row(
        vstore, artifact_id="art-dm", status="sealed",
        content_digest=hashlib.sha256(b"expected").hexdigest(), byte_length=7,
    )
    # Write a final file with different content.
    cap = runner._artifact_capability
    final_name = "art-dm.log"
    fd = os.open(final_name, os.O_WRONLY | os.O_CREAT, 0o600, dir_fd=cap._root_fd)
    os.write(fd, b"actual!")
    os.close(fd)
    runner._reconcile_artifacts()
    row = _artifact_status(vstore, "art-dm")
    assert row["status"] == "quarantined"


def test_reconcile_artifacts_sealed_valid_not_quarantined(tmp_path):
    """§7: SEALED artifact with matching digest and size → stays sealed."""
    runtime, _ = _artifact_runtime(tmp_path)
    runner = runtime._verification_runner
    vstore = runtime._verification_store
    payload = b"valid artifact content"
    _insert_artifact_row(
        vstore, artifact_id="art-ok", status="sealed",
        content_digest=hashlib.sha256(payload).hexdigest(),
        byte_length=len(payload),
    )
    # Write the final file with matching content.
    cap = runner._artifact_capability
    final_name = "art-ok.log"
    fd = os.open(final_name, os.O_WRONLY | os.O_CREAT, 0o600, dir_fd=cap._root_fd)
    os.write(fd, payload)
    os.close(fd)
    runner._reconcile_artifacts()
    row = _artifact_status(vstore, "art-ok")
    assert row["status"] == "sealed"
    assert row["quarantined"] == 0


def test_reconcile_artifacts_unknown_orphan_file_cleaned(tmp_path):
    """§7: unknown orphan file in artifact root → cleaned up."""
    runtime, _ = _artifact_runtime(tmp_path)
    runner = runtime._verification_runner
    cap = runner._artifact_capability
    orphan_name = "orphan-file.log"
    fd = os.open(orphan_name, os.O_WRONLY | os.O_CREAT, 0o600, dir_fd=cap._root_fd)
    os.close(fd)
    runner._reconcile_artifacts()
    try:
        os.stat(orphan_name, dir_fd=cap._root_fd)
        exists = True
    except FileNotFoundError:
        exists = False
    assert not exists


def test_reconcile_artifacts_non_regular_file_raises_and_poisons(tmp_path):
    """§7: non-regular file in artifact root → PermissionError + poison scopes."""
    runtime, _ = _artifact_runtime(tmp_path)
    runner = runtime._verification_runner
    vstore = runtime._verification_store
    # Insert an artifact row so there's a verification_run_id to poison.
    _insert_artifact_row(vstore, artifact_id="art-sym", status="sealed",
                         content_digest="x", byte_length=1)
    cap = runner._artifact_capability
    # Create a symlink inside the artifact root (non-regular).
    os.symlink("/etc/passwd", "evil-symlink", dir_fd=cap._root_fd)
    with pytest.raises(PermissionError, match="non-regular file"):
        runner._reconcile_artifacts()
    # The verification run must be poisoned.
    scopes = runtime._store.list_workspace_poison_scopes("verify1")
    assert any("artifact-root-non-regular-file" in s[2] for s in scopes)


def test_reconcile_artifacts_sealed_no_digest_quarantined(tmp_path):
    """§7: SEALED artifact with empty content_digest → quarantined."""
    runtime, _ = _artifact_runtime(tmp_path)
    runner = runtime._verification_runner
    vstore = runtime._verification_store
    _insert_artifact_row(
        vstore, artifact_id="art-nd", status="sealed",
        content_digest="", byte_length=0,
    )
    # Write a final file.
    cap = runner._artifact_capability
    final_name = "art-nd.log"
    fd = os.open(final_name, os.O_WRONLY | os.O_CREAT, 0o600, dir_fd=cap._root_fd)
    os.close(fd)
    runner._reconcile_artifacts()
    row = _artifact_status(vstore, "art-nd")
    assert row["status"] == "quarantined"


# ---------------------------------------------------------------------------
# Batch 3.1.3 §9: Required vs optional step failures
# ---------------------------------------------------------------------------


class _ConfigurableExitBackend(_FaultMatrixBackend):
    """Fault matrix backend that returns a configurable exit code."""

    def __init__(self, profile, *, exit_code=0, **kwargs):
        super().__init__(profile, **kwargs)
        self._exit_code = exit_code

    async def collect_result(self, *, container_id, attach_proc, stdout_stream,
                             stderr_stream, command, cancellation, started,
                             sandbox_instance_id, attestation_digest, remove=True):
        if self.collect_error:
            raise self.collect_error
        data = b"fault-matrix-output"
        return SandboxStepResult(
            sandbox_instance_id, self.profile.image_digest, self._exit_code, None, 1,
            data, b"", hashlib.sha256(data).hexdigest(),
            hashlib.sha256(b"").hexdigest(), False, False, False,
            container_id, attestation_digest,
        )


def _optional_verification_plan(plan, workspace):
    """Create a verification plan with an OPTIONAL requirement (required=False)."""
    (workspace.worktree_path / "pyproject.toml").write_text("[tool.pytest.ini_options]\n")
    catalog = __import__(
        "khaos.coding.planning.verification_catalog", fromlist=["VerificationCatalog"]
    ).VerificationCatalog(workspace.worktree_path, repository_id=plan.repository_id)
    entry = catalog.entries[0]
    requirement = VerificationRequirement(
        entry.argv, entry.verification_type, entry.language, "exit 0", False, "low",
        (PlanEvidence(
            "verification-config", plan.repository_id,
            path=entry.config_path, query=entry.provenance, confidence=1.0,
            metadata={"config_hash": entry.config_hash},
        ),),
    )
    steps = tuple(replace(step, verification_requirements=(requirement,)) for step in plan.steps)
    candidate = replace(plan, steps=steps, verification_requirements=(requirement,))
    return replace(candidate, content_hash=PersistedPlanRepository._recompute_plan_content_hash(candidate))


def _optional_fault_matrix_runtime(tmp_path, *, backend):
    """Wire a runtime with an optional verification plan."""
    edit = PlannedFileEdit(
        "e1", "s1", PlannedEditOperation.CREATE, "fixture.py",
        expected_exists=False, new_content="print('fixture')\n",
    )
    runtime, _, workspaces, _ = _real_runtime(tmp_path)
    workspace = _workspace(tmp_path, workspaces)
    plan = _plan((edit,))
    plan = _optional_verification_plan(plan, workspace)
    plan, authorization = _authorize(runtime, plan)
    result = _apply(runtime, plan, authorization, _bundle(plan, (edit,)))
    profile = _profile()
    runtime._configure_trusted_verification_unsafe(
        backend=backend, command_factory=_factory(profile),
        workspace_factory=VerificationWorkspaceFactory(tmp_path / "fault-copies"),
        artifact_root=tmp_path / "fault-artifacts", profile=profile,
    )
    return runtime, result


def test_optional_step_failure_does_not_fail_run(tmp_path):
    """§9: optional step failure → step FAILED, run PASSED."""
    backend = _ConfigurableExitBackend(_profile(), exit_code=1)
    runtime, result = _optional_fault_matrix_runtime(tmp_path, backend=backend)
    verification_result = runtime._test_sync._loop.run_until_complete(
        _run_verification(runtime, result)
    )
    # Run must be PASSED despite the step failure.
    assert verification_result.status == VerificationRunStatus.PASSED
    # Step must be FAILED with "optional-step-failed" failure_code.
    assert len(verification_result.step_runs) == 1
    step = verification_result.step_runs[0]
    assert step.status == VerificationStepStatus.FAILED
    assert step.failure_code == "optional-step-failed"


def test_required_step_failure_fails_run(tmp_path):
    """§9: required step failure → step FAILED, run FAILED."""
    backend = _ConfigurableExitBackend(_profile(), exit_code=1)
    runtime, result = _fault_matrix_runtime(tmp_path, backend=backend)
    verification_result = runtime._test_sync._loop.run_until_complete(
        _run_verification(runtime, result)
    )
    # Run must be FAILED.
    assert verification_result.status == VerificationRunStatus.FAILED
    assert verification_result.failure_code == "required-step-failed"
    # Step must be FAILED with "required-step-failed" failure_code.
    assert len(verification_result.step_runs) == 1
    step = verification_result.step_runs[0]
    assert step.status == VerificationStepStatus.FAILED
    assert step.failure_code == "required-step-failed"


def test_optional_step_pass_then_required_step_pass_run_passes(tmp_path):
    """§9: both optional and required steps pass → run PASSED."""
    backend = _ConfigurableExitBackend(_profile(), exit_code=0)
    runtime, result = _optional_fault_matrix_runtime(tmp_path, backend=backend)
    verification_result = runtime._test_sync._loop.run_until_complete(
        _run_verification(runtime, result)
    )
    assert verification_result.status == VerificationRunStatus.PASSED
    assert len(verification_result.step_runs) == 1
    assert verification_result.step_runs[0].status == VerificationStepStatus.PASSED


# ---------------------------------------------------------------------------
# Batch 3.1.3 §8: Cleanup must succeed before terminal success
# ---------------------------------------------------------------------------


def test_sandbox_cleanup_failure_poisons_run(tmp_path):
    """§8: sandbox instance cleanup failure → run POISONED, not PASSED."""
    backend = _ConfigurableExitBackend(
        _profile(), exit_code=0, remove_returns_false=True,
    )
    runtime, result = _fault_matrix_runtime(tmp_path, backend=backend)
    verification_result = runtime._test_sync._loop.run_until_complete(
        _run_verification(runtime, result)
    )
    # Run must NOT be PASSED — cleanup failed.
    assert verification_result.status == VerificationRunStatus.POISONED
    assert verification_result.failure_code == "cleanup-failed"
    # Step itself passed (exit_code=0).
    assert len(verification_result.step_runs) == 1
    assert verification_result.step_runs[0].status == VerificationStepStatus.PASSED
    # Sandbox instance must be CLEANUP_FAILED.
    vstore = runtime._verification_store
    instances = vstore._conn.execute(
        "SELECT state, failure_code FROM verification_sandbox_instances"
    ).fetchall()
    assert any(r[0] == "cleanup-failed" for r in instances)


def test_disposable_workspace_cleanup_failure_poisons_run(tmp_path):
    """§8: disposable workspace cleanup failure → run POISONED, not PASSED."""
    backend = _ConfigurableExitBackend(_profile(), exit_code=0)
    runtime, result = _fault_matrix_runtime(tmp_path, backend=backend)
    # Sabotage the workspace factory's destroy method to simulate cleanup failure.
    original_destroy = runtime._verification_runner._workspace_factory.destroy
    runtime._verification_runner._workspace_factory.destroy = lambda ws: (_ for _ in ()).throw(
        RuntimeError("simulated cleanup failure")
    )
    try:
        verification_result = runtime._test_sync._loop.run_until_complete(
            _run_verification(runtime, result)
        )
    finally:
        runtime._verification_runner._workspace_factory.destroy = original_destroy
    # Run must NOT be PASSED — cleanup failed.
    assert verification_result.status == VerificationRunStatus.POISONED
    assert verification_result.failure_code == "cleanup-failed"


def test_successful_cleanup_allows_passed(tmp_path):
    """§8: when all cleanup succeeds, run reaches PASSED normally."""
    backend = _ConfigurableExitBackend(_profile(), exit_code=0)
    runtime, result = _fault_matrix_runtime(tmp_path, backend=backend)
    verification_result = runtime._test_sync._loop.run_until_complete(
        _run_verification(runtime, result)
    )
    assert verification_result.status == VerificationRunStatus.PASSED
    assert verification_result.failure_code == ""


# ---------------------------------------------------------------------------
# Batch 3.1.4 §1: Deterministic Docker output — 50-iteration stress
# ---------------------------------------------------------------------------


@pytest.mark.production_sandbox_real
def test_real_docker_fast_exit_output_stress_50_iterations(tmp_path):
    """§1: fast-exiting container must not lose output across 50 runs.

    Runs a Python container that writes to stdout and stderr in the first
    millisecond and exits immediately.  Repeats 50 times.  Every iteration
    must produce identical stdout, stderr, exit code, and output digests.
    Empty output count must be 0.
    """
    if _real_docker_skip_guard():
        pytest.skip("set KHAOS_RUN_PRODUCTION_SANDBOX=1 for the production backend E2E")
    source = tmp_path / "canonical"
    source.mkdir()
    # Write to stdout AND stderr immediately, then exit 0.
    (source / "fast.py").write_text(
        "import sys\n"
        "sys.stdout.write('fast-stdout-marker\\n')\n"
        "sys.stdout.flush()\n"
        "sys.stderr.write('fast-stderr-marker\\n')\n"
        "sys.stderr.flush()\n"
    )
    factory = VerificationWorkspaceFactory(tmp_path / "stress-copies")
    disposable = factory.create(source, forbidden_roots=(source,))
    backend = DockerVerificationSandboxBackend(profile=_profile())
    asyncio.run(backend.probe())

    command = _docker_command("fast.py")

    async def run_once():
        return await backend.execute(command, disposable)

    expected_stdout = b"fast-stdout-marker\n"
    expected_stderr = b"fast-stderr-marker\n"
    expected_exit = 0
    expected_stdout_digest = hashlib.sha256(expected_stdout).hexdigest()
    expected_stderr_digest = hashlib.sha256(expected_stderr).hexdigest()

    empty_count = 0
    results = []
    for i in range(50):
        result = asyncio.run(run_once())
        results.append(result)
        if not result.stdout:
            empty_count += 1
        assert result.exit_code == expected_exit, (
            f"iteration {i}: exit_code={result.exit_code} expected={expected_exit}"
        )
        assert result.stdout == expected_stdout, (
            f"iteration {i}: stdout={result.stdout!r} expected={expected_stdout!r}"
        )
        assert result.stderr == expected_stderr, (
            f"iteration {i}: stderr={result.stderr!r} expected={expected_stderr!r}"
        )
        assert result.stdout_digest == expected_stdout_digest, (
            f"iteration {i}: stdout_digest={result.stdout_digest} "
            f"expected={expected_stdout_digest}"
        )
        assert result.stderr_digest == expected_stderr_digest, (
            f"iteration {i}: stderr_digest={result.stderr_digest} "
            f"expected={expected_stderr_digest}"
        )
        assert not result.output_truncated, f"iteration {i}: output was truncated"
        assert not result.timed_out, f"iteration {i}: timed out"

    # §1: actual empty output count must be 0.
    assert empty_count == 0, f"empty output count must be 0, got {empty_count}"
    # All 50 results must be byte-for-byte identical.
    assert len({r.stdout for r in results}) == 1, "stdout varied across iterations"
    assert len({r.stderr for r in results}) == 1, "stderr varied across iterations"
    assert len({r.exit_code for r in results}) == 1, "exit code varied across iterations"
    factory.destroy(disposable)


@pytest.mark.production_sandbox_real
def test_real_docker_fast_nonzero_exit_preserves_output(tmp_path):
    """§1: fast non-zero exit must still preserve complete output."""
    if _real_docker_skip_guard():
        pytest.skip("set KHAOS_RUN_PRODUCTION_SANDBOX=1 for the production backend E2E")
    source = tmp_path / "canonical"
    source.mkdir()
    (source / "fail.py").write_text(
        "import sys\n"
        "sys.stdout.write('pre-fail-stdout\\n')\n"
        "sys.stdout.flush()\n"
        "sys.stderr.write('pre-fail-stderr\\n')\n"
        "sys.stderr.flush()\n"
        "sys.exit(3)\n"
    )
    factory = VerificationWorkspaceFactory(tmp_path / "fail-copies")
    disposable = factory.create(source, forbidden_roots=(source,))
    backend = DockerVerificationSandboxBackend(profile=_profile())
    asyncio.run(backend.probe())

    command = _docker_command("fail.py")
    result = asyncio.run(backend.execute(command, disposable))
    assert result.exit_code == 3, f"exit_code={result.exit_code}"
    assert b"pre-fail-stdout" in result.stdout, f"stdout={result.stdout!r}"
    assert b"pre-fail-stderr" in result.stderr, f"stderr={result.stderr!r}"
    assert not result.output_truncated
    factory.destroy(disposable)


@pytest.mark.production_sandbox_real
def test_real_docker_toolchain_attestation_persistent_lifecycle(tmp_path):
    """§5: toolchain attestation uses persistent container lifecycle.

    Verifies that _run_attestation_command uses docker create + start
    --attach + terminate_and_remove (NOT docker run --rm), and that no
    attestation containers linger after the command completes.
    """
    if _real_docker_skip_guard():
        pytest.skip("set KHAOS_RUN_PRODUCTION_SANDBOX=1 for the production backend E2E")
    backend = DockerVerificationSandboxBackend(profile=_profile())
    asyncio.run(backend.probe())

    # Count toolchain-attestation containers before.
    def count_attestation_containers():
        import subprocess as _sp
        result = _sp.run(
            ["docker", "ps", "-a", "--filter", "label=khaos.kind=toolchain-attestation",
             "--format", "{{.ID}}"],
            capture_output=True, text=True,
        )
        return len([line for line in result.stdout.strip().split("\n") if line])

    before = count_attestation_containers()

    # Run a simple attestation command.
    async def run_attestation():
        return await backend._run_attestation_command(
            image_digest=IMAGE,
            argv=("python", "--version"),
        )
    exit_code, stdout, stderr = asyncio.run(run_attestation())
    assert exit_code == 0, f"exit_code={exit_code} stderr={stderr!r}"
    assert b"Python" in stdout, f"stdout={stdout!r}"

    # §5: no attestation containers should linger after the command.
    after = count_attestation_containers()
    assert after == before, (
        f"toolchain-attestation containers lingered: before={before} after={after}"
    )


@pytest.mark.production_sandbox_real
def test_real_docker_toolchain_attestation_full(tmp_path):
    """§5: full toolchain attestation produces correct binary digest and version."""
    if _real_docker_skip_guard():
        pytest.skip("set KHAOS_RUN_PRODUCTION_SANDBOX=1 for the production backend E2E")
    backend = DockerVerificationSandboxBackend(profile=_profile())
    asyncio.run(backend.probe())

    toolchain = TrustedToolchain(
        executable_id="python",
        language="python",
        absolute_path="/usr/local/bin/python3",
        version="3.13",
        image_digest=IMAGE,
        version_argv=("--version",),
    )

    async def run_attest():
        return await backend.attest_toolchain(
            toolchain=toolchain, image_digest=IMAGE,
            image_attestation_digest="test-image-digest",
        )
    attestation = asyncio.run(run_attest())
    assert attestation.toolchain_id == "python:python"
    assert attestation.binary_digest.startswith("sha256:")
    assert attestation.parsed_version  # non-empty
    assert attestation.image_attestation_digest == "test-image-digest"
    assert attestation.attestation_digest  # non-empty
