"""M5.5 Batch B — contained credential providers are physically killable.

A provider classified as blocking/untrusted executes as validated data in
a dedicated child process.  These tests prove the closure conditions:

* a hung provider is reclaimed by TERM → grace → KILL → wait within a
  bounded wall clock, without exiting the trusted process;
* broker ``close()`` actively terminates hung hosts instead of waiting
  out their materialization deadline;
* ``terminal_closed`` / ``owned_resources`` never lie about a live host;
* worker material still passes the parent-side environment schema;
* caller cancellation discards the result and settles bounded.
"""

from __future__ import annotations

import asyncio
import json
import sys
import time

import pytest

from khaos.security.credential_broker import (
    CredentialBroker,
    CredentialBrokerError,
)
from khaos.security.credential_provider_host import (
    CredentialProviderHost,
    CredentialProviderHostError,
)
from khaos.security.credential_provider_worker import (
    ProviderSpecError,
    validate_provider_spec,
)
from khaos.security.resource_scope import CredentialScope

pytestmark = pytest.mark.posix_host


def _scope(name: str = "ssh-agent") -> CredentialScope:
    return CredentialScope(
        provider="git",
        names=frozenset({name}),
        operations=frozenset({"git_push"}),
    )


async def _await_terminal(broker: CredentialBroker, timeout: float = 10.0) -> bool:
    """Poll until every owned transaction and host has provably settled."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if broker.terminal_postcondition() and broker.owned_resources() == ():
            return True
        await asyncio.sleep(0.05)
    return False


# ─── Spec validation ──────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "spec",
    [
        {"type": "unknown"},
        {"type": "constant"},
        {"type": "constant", "environment": {}},
        {"type": "constant", "environment": {"NOT A KEY": "v"}},
        {"type": "env", "variables": {}},
        {"type": "env", "variables": {"OUT": "bad name"}},
        {"type": "command", "argv": []},
        {"type": "command", "argv": ["sh", "-c", "x"], "timeout_seconds": 0},
        {"type": "sleep", "seconds": -1},
        {"no-type": True},
    ],
)
def test_invalid_specs_are_rejected_at_registration(spec):
    with pytest.raises(ProviderSpecError):
        validate_provider_spec(spec)
    broker = CredentialBroker()
    with pytest.raises(CredentialBrokerError, match="spec is invalid"):
        broker.register_hosted(_scope(), spec)


def test_non_json_spec_is_rejected():
    with pytest.raises(ProviderSpecError):
        validate_provider_spec({"type": "constant", "environment": {"A": object()}})


# ─── Host: happy paths ────────────────────────────────────────────────────


async def test_host_materializes_constant_spec():
    host = CredentialProviderHost()
    environment = await host.materialize(
        {"type": "constant", "environment": {"SSH_AUTH_SOCK": "/tmp/agent.sock"}},
        deadline=15.0,
    )
    assert environment == {"SSH_AUTH_SOCK": "/tmp/agent.sock"}
    assert not host.alive


async def test_host_materializes_env_spec_with_passthrough(monkeypatch):
    monkeypatch.setenv("KHAOS_TEST_AGENT_SOCK", "/tmp/passthrough.sock")
    host = CredentialProviderHost()
    environment = await host.materialize(
        {"type": "env", "variables": {"SSH_AUTH_SOCK": "KHAOS_TEST_AGENT_SOCK"}},
        deadline=15.0,
    )
    assert environment == {"SSH_AUTH_SOCK": "/tmp/passthrough.sock"}


async def test_host_env_spec_missing_variable_fails_closed():
    host = CredentialProviderHost()
    with pytest.raises(CredentialProviderHostError, match="missing"):
        await host.materialize(
            {"type": "env", "variables": {"SSH_AUTH_SOCK": "KHAOS_ABSENT_VAR"}},
            deadline=15.0,
        )
    assert not host.alive


async def test_host_materializes_command_spec():
    helper = (
        "import json; print(json.dumps({'GIT_ASKPASS': '/bin/true'}))"
    )
    host = CredentialProviderHost()
    environment = await host.materialize(
        {"type": "command", "argv": [sys.executable, "-c", helper]},
        deadline=20.0,
    )
    assert environment == {"GIT_ASKPASS": "/bin/true"}


async def test_host_command_failure_fails_closed():
    host = CredentialProviderHost()
    with pytest.raises(CredentialProviderHostError, match="status"):
        await host.materialize(
            {"type": "command", "argv": [sys.executable, "-c", "import sys; sys.exit(3)"]},
            deadline=20.0,
        )
    assert not host.alive


# ─── Host: killability ────────────────────────────────────────────────────


async def test_hung_provider_deadline_terminates_child_bounded():
    host = CredentialProviderHost(termination_grace=0.5, kill_grace=2.0)
    started = time.monotonic()
    with pytest.raises(CredentialProviderHostError, match="deadline"):
        await host.materialize({"type": "sleep", "seconds": 3600}, deadline=0.5)
    elapsed = time.monotonic() - started

    assert not host.alive
    # TERM (or KILL) plus wait must stay far below the provider's hang time.
    assert elapsed < 10.0


async def test_host_signals_do_not_kill_wrong_process_after_settlement():
    host = CredentialProviderHost()
    await host.materialize(
        {"type": "constant", "environment": {"SSH_AUTH_SOCK": "/x"}}, deadline=15.0
    )
    # Repeated late termination requests against a reaped host are no-ops.
    host.request_termination()
    host.request_termination()
    assert not host.alive


# ─── Broker integration ───────────────────────────────────────────────────


async def test_broker_materializes_hosted_provider_and_settles():
    broker = CredentialBroker()
    broker.register_hosted(
        _scope(),
        {"type": "constant", "environment": {"SSH_AUTH_SOCK": "/tmp/agent.sock"}},
        deadline_seconds=15.0,
    )
    lease = broker.issue(
        _scope(), binding={"remote_url": "git@host:repo"}, operation="git_push"
    )
    environment = await broker.materialize_async(
        lease, binding={"remote_url": "git@host:repo"}, operation="git_push"
    )
    assert environment == {"SSH_AUTH_SOCK": "/tmp/agent.sock"}
    assert broker.owned_resources() == ()
    broker.close()
    assert broker.terminal_closed


async def test_broker_hung_hosted_provider_is_killed_and_close_is_terminal():
    broker = CredentialBroker()
    broker.register_hosted(
        _scope(),
        {"type": "sleep", "seconds": 3600},
        deadline_seconds=0.5,
    )
    lease = broker.issue(
        _scope(), binding={"remote_url": "git@host:repo"}, operation="git_push"
    )
    started = time.monotonic()
    with pytest.raises(CredentialBrokerError, match="deadline"):
        await broker.materialize_async(
            lease, binding={"remote_url": "git@host:repo"}, operation="git_push"
        )
    assert time.monotonic() - started < 10.0

    broker.close()
    assert await _await_terminal(broker)
    assert broker.owned_resources() == ()


async def test_broker_close_terminates_hung_host_without_waiting_deadline():
    broker = CredentialBroker()
    broker.register_hosted(
        _scope(),
        {"type": "sleep", "seconds": 3600},
        deadline_seconds=120.0,
    )
    lease = broker.issue(
        _scope(), binding={"remote_url": "git@host:repo"}, operation="git_push"
    )
    materialization = asyncio.ensure_future(
        broker.materialize_async(
            lease, binding={"remote_url": "git@host:repo"}, operation="git_push"
        )
    )
    # Let the hosted child start, then close: SIGTERM must reclaim it long
    # before the 120 s materialization deadline would have elapsed.
    await asyncio.sleep(0.3)
    assert any(
        resource.startswith("credential-provider-host:")
        for resource in broker.owned_resources()
    )
    started = time.monotonic()
    broker.close()
    done, _pending = await asyncio.wait(
        [materialization], timeout=15.0, return_when=asyncio.FIRST_EXCEPTION
    )
    assert done, "hosted materialization did not settle after close"
    assert time.monotonic() - started < 15.0
    assert await _await_terminal(broker)


async def test_broker_hung_host_cancellation_discards_result_bounded():
    broker = CredentialBroker()
    broker.register_hosted(
        _scope(),
        {"type": "sleep", "seconds": 3600},
        deadline_seconds=0.5,
    )
    lease = broker.issue(
        _scope(), binding={"remote_url": "git@host:repo"}, operation="git_push"
    )
    task = asyncio.ensure_future(
        broker.materialize_async(
            lease, binding={"remote_url": "git@host:repo"}, operation="git_push"
        )
    )
    await asyncio.sleep(0.1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    # Cancellation never destroys ownership: the transaction stays owned
    # until the (killed) provider settles, then the broker reaches a true
    # terminal state without process exit.
    assert await _await_terminal(broker)
    with pytest.raises(CredentialBrokerError):
        # The one-shot lease was consumed by the canceled transaction.
        await broker.materialize_async(
            lease, binding={"remote_url": "git@host:repo"}, operation="git_push"
        )


async def test_broker_enforces_schema_on_hosted_material():
    broker = CredentialBroker()
    broker.register_hosted(
        _scope(),
        # ssh-agent schema allows only SSH_AUTH_SOCK.
        {"type": "constant", "environment": {"GIT_ASKPASS": "/evil/helper"}},
        deadline_seconds=15.0,
    )
    lease = broker.issue(
        _scope(), binding={"remote_url": "git@host:repo"}, operation="git_push"
    )
    with pytest.raises(CredentialBrokerError, match="outside its schema"):
        await broker.materialize_async(
            lease, binding={"remote_url": "git@host:repo"}, operation="git_push"
        )
    assert broker.owned_resources() == ()


async def test_hosted_provider_requires_async_materialization():
    broker = CredentialBroker()
    broker.register_hosted(
        _scope(),
        {"type": "constant", "environment": {"SSH_AUTH_SOCK": "/x"}},
        deadline_seconds=15.0,
    )
    lease = broker.issue(
        _scope(), binding={"remote_url": "git@host:repo"}, operation="git_push"
    )
    with pytest.raises(CredentialBrokerError, match="materialize_async"):
        broker.materialize(
            lease, binding={"remote_url": "git@host:repo"}, operation="git_push"
        )


async def test_hosted_provider_admission_is_bounded():
    broker = CredentialBroker(max_provider_workers=1, max_pending_providers=0)
    broker.register_hosted(
        _scope(),
        {"type": "sleep", "seconds": 2},
        allowed_environment_keys={"PROVIDER_SLEPT"},
        deadline_seconds=10.0,
    )
    lease = broker.issue(
        _scope(), binding={"remote_url": "git@host:repo"}, operation="git_push"
    )
    first = asyncio.ensure_future(
        broker.materialize_async(
            lease, binding={"remote_url": "git@host:repo"}, operation="git_push"
        )
    )
    await asyncio.sleep(0.3)
    second_lease = broker.issue(
        _scope(), binding={"remote_url": "git@other:repo"}, operation="git_push"
    )
    with pytest.raises(CredentialBrokerError, match="admission is full"):
        await broker.materialize_async(
            second_lease,
            binding={"remote_url": "git@other:repo"},
            operation="git_push",
        )
    await asyncio.wait_for(first, timeout=20.0)


# ─── M5.6-A: spawn identity / import poisoning ────────────────────────────


async def test_malicious_cwd_cannot_poison_worker_imports(tmp_path, monkeypatch):
    """A hostile repository cwd must not reach privileged worker code.

    The cwd contains a fake ``khaos`` package, ``json.py``, ``subprocess.py``,
    and ``sitecustomize.py`` that each drop a marker file when imported; the
    caller also exports the repository on PYTHONPATH.  The worker must be
    launched from its absolute canonical identity in isolated mode with a
    trusted cwd — none of the poisoned modules may load.
    """
    repo = tmp_path / "untrusted-repo"
    marker = tmp_path / "poisoned"
    (repo / "khaos" / "security").mkdir(parents=True)
    (repo / "khaos" / "__init__.py").write_text("", encoding="utf-8")
    (repo / "khaos" / "security" / "__init__.py").write_text("", encoding="utf-8")
    poison = (
        "import pathlib; "
        f"pathlib.Path({str(marker)!r}).write_text({str(marker.stem)!r})\n"
    )
    (repo / "khaos" / "security" / "credential_provider_worker.py").write_text(
        poison, encoding="utf-8"
    )
    for name in ("json.py", "subprocess.py", "sitecustomize.py"):
        (repo / name).write_text(poison, encoding="utf-8")
    monkeypatch.chdir(repo)
    monkeypatch.setenv("PYTHONPATH", str(repo))

    host = CredentialProviderHost()
    environment = await host.materialize(
        {"type": "constant", "environment": {"SSH_AUTH_SOCK": "/trusted"}},
        deadline=15.0,
    )

    assert environment == {"SSH_AUTH_SOCK": "/trusted"}
    assert not marker.exists()
    assert host.worker_identity is not None
    assert host.worker_identity["path"].endswith(
        "credential_provider_worker.py"
    )


def test_relative_helper_argv0_is_rejected_at_registration():
    broker = CredentialBroker()
    with pytest.raises(CredentialBrokerError, match="absolute"):
        broker.register_hosted(
            _scope(),
            {"type": "command", "argv": ["credential-helper", "--flag"]},
            deadline_seconds=15.0,
        )


def test_path_resolved_helper_argv0_is_rejected_at_registration():
    broker = CredentialBroker()
    with pytest.raises(CredentialBrokerError, match="absolute"):
        broker.register_hosted(
            _scope(),
            {"type": "command", "argv": ["./bin/credential-helper"]},
            deadline_seconds=15.0,
        )


async def test_helper_under_untrusted_root_fails_closed(tmp_path):
    """A model-writable root may never host a provider helper executable."""
    untrusted = tmp_path / "workspace"
    untrusted.mkdir()
    helper = untrusted / "credential-helper"
    helper.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    helper.chmod(0o755)

    broker = CredentialBroker(untrusted_helper_roots=(untrusted,))
    broker.register_hosted(
        _scope(),
        {"type": "command", "argv": [str(helper)]},
        deadline_seconds=15.0,
    )
    lease = broker.issue(
        _scope(), binding={"remote_url": "git@host:repo"}, operation="git_push"
    )
    with pytest.raises(CredentialBrokerError, match="untrusted root"):
        await broker.materialize_async(
            lease, binding={"remote_url": "git@host:repo"}, operation="git_push"
        )
    assert broker.owned_resources() == ()


async def test_symlinked_helper_resolving_into_untrusted_root_fails_closed(tmp_path):
    untrusted = tmp_path / "workspace"
    untrusted.mkdir()
    real = untrusted / "real-helper"
    real.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    real.chmod(0o755)
    link_dir = tmp_path / "trusted-bin"
    link_dir.mkdir()
    link = link_dir / "helper"
    link.symlink_to(real)

    broker = CredentialBroker(untrusted_helper_roots=(untrusted,))
    broker.register_hosted(
        _scope(),
        {"type": "command", "argv": [str(link)]},
        deadline_seconds=15.0,
    )
    lease = broker.issue(
        _scope(), binding={"remote_url": "git@host:repo"}, operation="git_push"
    )
    with pytest.raises(CredentialBrokerError, match="untrusted root"):
        await broker.materialize_async(
            lease, binding={"remote_url": "git@host:repo"}, operation="git_push"
        )


async def test_trusted_absolute_helper_executes_canonical_identity(tmp_path):
    helper = tmp_path / "trusted-helper"
    helper.write_text(
        "#!/bin/sh\necho '{\"SSH_AUTH_SOCK\": \"/tmp/canonical.sock\"}'\n",
        encoding="utf-8",
    )
    helper.chmod(0o755)

    host = CredentialProviderHost()
    environment = await host.materialize(
        {"type": "command", "argv": [str(helper)]}, deadline=15.0
    )
    assert environment == {"SSH_AUTH_SOCK": "/tmp/canonical.sock"}
    assert not host.alive


# ─── M5.6-B: provider process-tree closure ────────────────────────────────


async def _wait_for_file(path, timeout: float = 10.0) -> None:
    import asyncio as _asyncio

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        await _asyncio.sleep(0.02)
    raise AssertionError(f"sentinel {path} never appeared")


def _pid_is_gone(pid: int, timeout: float = 10.0) -> bool:
    import os as os_module

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            os_module.kill(pid, 0)
        except OSError:
            return True
        time.sleep(0.05)
    return False


async def test_timeout_reclaims_worker_helper_and_grandchild(tmp_path):
    """Provider terminal means process-TREE terminal.

    The helper forks a grandchild that hangs forever; the deadline breach
    must reclaim the worker, the helper, AND the grandchild, with the
    grandchild pid proven dead via the sentinel it wrote (deterministic
    readiness — no timing sleeps for the race itself).
    """
    sentinel = tmp_path / "grandchild.pid"
    helper = tmp_path / "forker.py"
    helper.write_text(
        "import os, sys, time\n"
        "pid = os.fork()\n"
        "if pid == 0:\n"
        f"    open({str(sentinel)!r}, 'w').write(str(os.getpid()))\n"
        "    time.sleep(3600)\n"
        "time.sleep(3600)\n",
        encoding="utf-8",
    )

    host = CredentialProviderHost(termination_grace=0.5, kill_grace=3.0)
    materialization = asyncio.ensure_future(
        host.materialize(
            {
                "type": "command",
                "argv": [sys.executable, str(helper)],
                "timeout_seconds": 3600,
            },
            deadline=1.5,
        )
    )
    await _wait_for_file(sentinel)
    grandchild_pid = int(sentinel.read_text(encoding="utf-8").strip())
    assert not _pid_is_gone(grandchild_pid, timeout=0.0)

    with pytest.raises(CredentialProviderHostError, match="deadline"):
        await materialization

    assert _pid_is_gone(grandchild_pid)
    assert not host.alive


async def test_setsid_daemonizing_grandchild_is_still_reclaimed(tmp_path):
    """A grandchild that escapes the process group via setsid must not
    survive the domain-wide descendant sweep."""
    sentinel = tmp_path / "daemon.pid"
    helper = tmp_path / "daemonizer.py"
    helper.write_text(
        "import os, sys, time\n"
        "pid = os.fork()\n"
        "if pid == 0:\n"
        "    os.setsid()\n"
        f"    open({str(sentinel)!r}, 'w').write(str(os.getpid()))\n"
        "    time.sleep(3600)\n"
        "time.sleep(3600)\n",
        encoding="utf-8",
    )

    host = CredentialProviderHost(termination_grace=0.5, kill_grace=5.0)
    materialization = asyncio.ensure_future(
        host.materialize(
            {
                "type": "command",
                "argv": [sys.executable, str(helper)],
                "timeout_seconds": 3600,
            },
            deadline=1.5,
        )
    )
    await _wait_for_file(sentinel)
    daemon_pid = int(sentinel.read_text(encoding="utf-8").strip())

    with pytest.raises(CredentialProviderHostError, match="deadline"):
        await materialization

    assert _pid_is_gone(daemon_pid)
    assert not host.alive


async def test_sigterm_resistant_helper_is_killed_by_escalation(tmp_path):
    helper = tmp_path / "stubborn.py"
    helper.write_text(
        "import signal, time\n"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "time.sleep(3600)\n",
        encoding="utf-8",
    )

    host = CredentialProviderHost(termination_grace=0.4, kill_grace=3.0)
    started = time.monotonic()
    with pytest.raises(CredentialProviderHostError, match="deadline"):
        await host.materialize(
            {"type": "command", "argv": [sys.executable, str(helper)]},
            deadline=0.6,
        )
    assert time.monotonic() - started < 10.0
    assert not host.alive


# ─── M5.6-C: streaming output budgets ─────────────────────────────────────


async def test_stdout_flooding_helper_hits_streaming_budget(tmp_path):
    flood = "import sys\nwhile True: sys.stdout.write('x' * 65536)\n"

    host = CredentialProviderHost()
    with pytest.raises(CredentialProviderHostError, match="output budget"):
        await host.materialize(
            {"type": "command", "argv": [sys.executable, "-c", flood]},
            deadline=30.0,
        )
    assert not host.alive


async def test_stderr_flooding_helper_hits_streaming_budget(tmp_path):
    flood = "import sys\nwhile True: sys.stderr.write('x' * 65536)\n"

    host = CredentialProviderHost()
    with pytest.raises(CredentialProviderHostError, match="output budget"):
        await host.materialize(
            {"type": "command", "argv": [sys.executable, "-c", flood]},
            deadline=30.0,
        )
    assert not host.alive


async def test_helper_under_output_budget_still_succeeds(tmp_path):
    helper = (
        "import json, sys\n"
        "print(json.dumps({'GIT_ASKPASS': '/bin/true', 'PAD': 'x' * 1024}))\n"
    )

    host = CredentialProviderHost()
    environment = await host.materialize(
        {"type": "command", "argv": [sys.executable, "-c", helper]},
        deadline=20.0,
    )
    assert environment["GIT_ASKPASS"] == "/bin/true"
    assert environment["PAD"] == "x" * 1024
    assert not host.alive
