"""Integration tests: policy → sandbox → network → middleware full chain.

These verify that a ``khaos_policy.yaml`` actually flows all the way through
to the enforcement behaviour the user configured, across every layer.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from khaos.audit import AuditLogger
from khaos.db import Database
from khaos.security.middleware import SecurityMiddleware
from khaos.security.network_guard import NetworkGuard
from khaos.security.policy import SandboxPolicy, load_policy
from khaos.security.sandbox import Sandbox, SandboxMode


async def _db(tmp_path: Path) -> Database:
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    return db


def _write_policy(root: Path, content: str) -> Path:
    path = root / "khaos_policy.yaml"
    path.write_text(content, encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Policy → component mapping
# ---------------------------------------------------------------------------


def test_policy_to_sandbox_chain(tmp_path: Path) -> None:
    """A policy's mode string maps to the right SandboxMode."""
    policy = SandboxPolicy(mode="read-only")
    sandbox = Sandbox.from_policy_mode(policy.mode, workspace_root=tmp_path)

    assert sandbox.mode == SandboxMode.READ_ONLY

    policy_yolo = SandboxPolicy(mode="yolo")
    sandbox_yolo = Sandbox.from_policy_mode(policy_yolo.mode)
    assert sandbox_yolo.mode == SandboxMode.YOLO


def test_policy_to_network_guard_chain(tmp_path: Path) -> None:
    """A policy's network config maps to the right NetworkGuard state.

    H1: ``network_enabled`` is a TOTAL SWITCH — when off, ALL network
    access is blocked regardless of the allowlist.  The allowlist can
    only TIGHTEN an enabled network, not RELAX a disabled one.  To test
    the allowlist we therefore enable network and verify deny-by-default.
    """
    # network off → ALL curl blocked (even allowlisted domains).
    policy_off = SandboxPolicy(
        network_enabled=False,
        network_allowed_domains=["pypi.org"],
    )
    guard_off = NetworkGuard(
        network_enabled=policy_off.network_enabled,
        allowed_domains=policy_off.network_allowed_domains,
    )
    assert guard_off.check_tool("terminal", {"command": "curl https://example.com"}).allowed is False
    assert guard_off.check_tool("terminal", {"command": "curl https://pypi.org"}).allowed is False

    # network on + allowlist → only allowlisted domains pass.
    policy_on = SandboxPolicy(
        network_enabled=True,
        network_allowed_domains=["pypi.org"],
    )
    guard_on = NetworkGuard(
        network_enabled=policy_on.network_enabled,
        allowed_domains=policy_on.network_allowed_domains,
    )
    assert guard_on.check_tool("terminal", {"command": "curl https://example.com"}).allowed is False
    assert guard_on.check_tool("terminal", {"command": "curl https://pypi.org"}).allowed is True


def test_policy_to_middleware_chain(tmp_path: Path) -> None:
    """A full policy flows through into a configured SecurityMiddleware."""
    policy_file = _write_policy(
        tmp_path,
        """
sandbox:
  mode: read-only
  network: false
""",
    )
    policy = load_policy(policy_file)
    sandbox = Sandbox.from_policy_mode(policy.mode, workspace_root=tmp_path)
    network_guard = NetworkGuard(
        network_enabled=policy.network_enabled,
        allowed_domains=policy.network_allowed_domains,
    )
    middleware = SecurityMiddleware(policy=policy, sandbox=sandbox, network_guard=network_guard)

    assert middleware.policy.mode == "read-only"
    assert middleware.sandbox.mode == SandboxMode.READ_ONLY
    assert middleware.network_guard is not None


# ---------------------------------------------------------------------------
# Full-flow: workspace-write mode
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_workspace_write_mode_full_flow(tmp_path: Path) -> None:
    """workspace-write: inside writes pass, outside/external are blocked."""
    db = await _db(tmp_path)
    audit = AuditLogger(db)
    workspace = tmp_path / "proj"
    workspace.mkdir()
    policy = load_policy(_write_policy(tmp_path, "sandbox:\n  mode: workspace-write\n"))
    middleware = SecurityMiddleware(
        policy=policy,
        sandbox=Sandbox.from_policy_mode(policy.mode, workspace_root=workspace),
        network_guard=NetworkGuard(),
        audit_logger=audit,
    )

    # write inside workspace → allowed
    inside = await middleware.pre_check(
        "write_file", {"path": str(workspace / "src" / "main.py")}
    )
    assert inside.allowed is True

    # curl → blocked by network guard
    curl = await middleware.pre_check("terminal", {"command": "curl https://x.com"})
    assert curl.allowed is False
    assert curl.check_type == "network"

    # env → blocked by M1 env_dump guard (runs before the command guard
    # because environment-dump commands are the most common source of
    # API key / token leakage).  The check_type is ``env_dump``, not
    # ``command``.
    env = await middleware.pre_check("terminal", {"command": "env"})
    assert env.allowed is False
    assert env.check_type == "env_dump"

    # Blocks were recorded as security events.
    events = await audit.query()
    blocked = [e for e in events if e.result == "denied"]
    assert len(blocked) >= 2
    await db.close()


# ---------------------------------------------------------------------------
# Full-flow: read-only mode
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_read_only_mode_full_flow(tmp_path: Path) -> None:
    """read-only: writes blocked, reads allowed, terminal blocked."""
    db = await _db(tmp_path)
    workspace = tmp_path / "proj"
    workspace.mkdir()
    policy = load_policy(_write_policy(tmp_path, "sandbox:\n  mode: read-only\n"))
    middleware = SecurityMiddleware(
        policy=policy,
        sandbox=Sandbox.from_policy_mode(policy.mode, workspace_root=workspace),
    )

    write = await middleware.pre_check("write_file", {"path": str(workspace / "a.py")})
    assert write.allowed is False
    assert write.check_type == "sandbox"

    read = await middleware.pre_check("read_file", {"path": str(workspace / "a.py")})
    assert read.allowed is True

    term = await middleware.pre_check("terminal", {"command": "ls"})
    assert term.allowed is False  # terminal not in read-only capability set
    assert term.check_type == "sandbox"
    await db.close()


# ---------------------------------------------------------------------------
# Full-flow: yolo mode
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_yolo_mode_full_flow(tmp_path: Path) -> None:
    """yolo: everything passes, even sudo/dangerous commands."""
    db = await _db(tmp_path)
    workspace = tmp_path / "proj"
    workspace.mkdir()
    policy = load_policy(_write_policy(tmp_path, "sandbox:\n  mode: yolo\n"))
    middleware = SecurityMiddleware(
        policy=policy,
        sandbox=Sandbox.from_policy_mode(policy.mode, workspace_root=workspace),
        network_guard=NetworkGuard(network_enabled=True),
    )

    # sandbox allows everything
    assert (await middleware.pre_check("write_file", {"path": str(workspace / "a.py")})).allowed is True
    # terminal passes sandbox...
    term = await middleware.pre_check("terminal", {"command": "echo hi"})
    # ...but command_guard still runs after sandbox. yolo does NOT bypass
    # command_guard (only sandbox + network). echo is safe though.
    assert term.allowed is True
    await db.close()
