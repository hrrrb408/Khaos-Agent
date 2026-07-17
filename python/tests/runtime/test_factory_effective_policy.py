"""Factory integration: the effective policy is compiled and wired (H3).

Verifies build_runtime compiles the effective policy and threads
commands_require_approval into the PermissionEngine, and the office authority
is registered on the scheduler.
"""

import sys
from pathlib import Path

import pytest

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
    finally:
        await db.close()
