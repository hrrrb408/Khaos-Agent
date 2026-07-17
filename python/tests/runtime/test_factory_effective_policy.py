"""Factory integration: the effective policy is compiled and wired (H3).

Verifies build_runtime compiles the effective policy and threads
commands_require_approval into the PermissionEngine, and the office authority
is registered on the scheduler.

B1 / CI gap: also pins that ``RuntimeResult`` is constructed with the right
component in the right field (the positional-arg misalignment previously
bound ``ExecutionService`` into ``_closed``, making ``aclose()`` a no-op).
"""

import sys
from pathlib import Path

import pytest

from khaos.coding.execution import ExecutionService
from khaos.coding.workspace.office_authority import OfficeMutationAuthority
from khaos.db import Database
from khaos.runtime import RuntimeConfig, build_runtime


pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason="runtime factory wires POSIX-only workspace authority",
)


async def _build(tmp_path: Path, policy_yaml: str):
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    await db.create_session("s1")
    (tmp_path / "khaos_policy.yaml").write_text(policy_yaml, encoding="utf-8")
    cfg = RuntimeConfig(project_root=tmp_path, db=db)
    result = await build_runtime(cfg)
    return result, db


async def test_factory_compiles_effective_policy_and_threads_approval(tmp_path):
    policy = (
        "sandbox:\n"
        "  mode: workspace-write\n"
        "commands:\n"
        "  require_approval:\n"
        "    - rm\n"
        "    - git push\n"
    )
    result, db = await _build(tmp_path, policy)
    try:
        engine = result.tool_scheduler.permission_engine
        assert engine._commands_require_approval >= {"rm", "git push"}
        # Office authority is wired on the scheduler (H1).
        assert result.tool_scheduler.office_authority is not None
        # B1 / CI gap: ``RuntimeResult`` fields must be wired to the right
        # component, not shifted by a positional-arg misalignment.
        assert result._closed is False
        assert isinstance(result.execution_service, ExecutionService)
        assert isinstance(result.office_authority, OfficeMutationAuthority)
        # Identity: the scheduler, the file_tools module and the runtime
        # result must all share the *same* authority instance — otherwise
        # the shutdown fence would not cover in-flight mutations started
        # from a different reference.
        assert result.office_authority is result.tool_scheduler.office_authority
    finally:
        await db.close()


async def test_factory_default_policy_still_builds(tmp_path):
    # No commands.require_approval override → engine gets the default list.
    policy = "sandbox:\n  mode: read-only\n"
    result, db = await _build(tmp_path, policy)
    try:
        engine = result.tool_scheduler.permission_engine
        # Defaults include rm / git push (from SandboxPolicy defaults).
        assert "rm" in engine._commands_require_approval
        # B1: even in read-only mode the lifecycle fields must be wired.
        assert result._closed is False
        assert isinstance(result.execution_service, ExecutionService)
        assert isinstance(result.office_authority, OfficeMutationAuthority)
    finally:
        await db.close()


async def test_factory_aclose_actually_shuts_down_components(tmp_path):
    """B1 / CI gap: ``await result.aclose()`` must really close components.

    Previously the positional-arg misalignment bound ``ExecutionService``
    into ``_closed``, so ``if self._closed: return`` exited immediately
    and *none* of the shutdown bodies ran.  This test pins the contract
    that ``aclose()`` flips ``_closed`` and reaches every component.
    """
    policy = "sandbox:\n  mode: workspace-write\n"
    result, db = await _build(tmp_path, policy)
    office_authority = result.office_authority
    execution_service = result.execution_service
    memory_manager = result.memory_manager
    try:
        assert result._closed is False
        # Office authority is writable before close.
        # ``aclose()`` must mark every workspace read-only via shutdown().
        await result.aclose()
        assert result._closed is True
        # After shutdown the authority's _closing flag is set, so any new
        # mutation fails closed — proving ``shutdown()`` actually ran.
        assert office_authority._closing is True
        # ExecutionService must have been shut down too.  We can't easily
        # introspect its private state across all backends, but we can
        # confirm ``aclose()`` did not raise and ``_closed`` flipped.
    finally:
        # B1: the office authority is now owned by the RuntimeResult and
        # closed via ``aclose()``; there is no module global to clear.
        # ``db.close()`` is the caller's job per the factory contract.
        await db.close()


async def test_factory_aclose_is_idempotent(tmp_path):
    """B1: second ``aclose()`` must short-circuit without re-entering shutdown."""
    policy = "sandbox:\n  mode: workspace-write\n"
    result, db = await _build(tmp_path, policy)
    try:
        await result.aclose()
        assert result._closed is True
        # Second call must not raise and must remain closed.
        await result.aclose()
        assert result._closed is True
    finally:
        await db.close()
