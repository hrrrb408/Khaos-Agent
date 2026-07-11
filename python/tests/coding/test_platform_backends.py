import os
import shutil
import sys
from pathlib import Path

import pytest

from khaos.coding.execution import ExecutionRequest, NetworkPolicy, ResourceBudget
from khaos.coding.execution.platform import LinuxBubblewrapBackend, MacOSSandboxBackend, UnsupportedBackend


@pytest.mark.asyncio
async def test_unsupported_backend_refuses_writable_execution():
    with pytest.raises(PermissionError):
        await UnsupportedBackend().execute(object())


def test_platform_profiles_are_network_denying(tmp_path: Path):
    assert "deny network" in MacOSSandboxBackend().profile(tmp_path)
    assert "--unshare-net" in LinuxBubblewrapBackend().argv_prefix(tmp_path)


def _require_or_skip(binary: str) -> None:
    if shutil.which(binary):
        return
    if os.environ.get("KHAOS_REQUIRE_PLATFORM_SANDBOX") == "1":
        pytest.fail(f"required platform sandbox binary is unavailable: {binary}")
    pytest.skip(f"platform sandbox binary is unavailable: {binary}")


@pytest.mark.asyncio
@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux bubblewrap evidence")
async def test_real_bwrap_isolates_network_root_and_workspace(tmp_path: Path):
    """Run bwrap rather than merely asserting its argv construction."""
    _require_or_skip("bwrap")
    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside.txt"
    workspace.mkdir()
    command = (
        "from pathlib import Path; import socket; "
        "Path('inside.txt').write_text('ok'); "
        "assert Path('/tmp').is_dir(); "
        f"\ntry: Path({str(outside)!r}).write_text('no')\nexcept OSError: pass\nelse: raise SystemExit('outside write allowed'); "
        "\ntry: socket.create_connection(('1.1.1.1', 53), timeout=1)\nexcept OSError: pass\nelse: raise SystemExit('network allowed')"
    )
    result = await LinuxBubblewrapBackend().execute(
        ExecutionRequest(
            (sys.executable, "-c", command), workspace, (workspace,),
            network_policy=NetworkPolicy.NONE,
            budget=ResourceBudget(timeout_seconds=15),
        )
    )
    assert result.status == "passed", result.stderr
    assert (workspace / "inside.txt").read_text(encoding="utf-8") == "ok"
    assert not outside.exists()


@pytest.mark.asyncio
@pytest.mark.skipif(sys.platform != "darwin", reason="macOS sandbox-exec evidence")
async def test_real_macos_sandbox_blocks_network_and_external_writes(tmp_path: Path):
    """Run sandbox-exec against an actual process, with no host fallback."""
    _require_or_skip("sandbox-exec")
    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside.txt"
    workspace.mkdir()
    command = (
        "from pathlib import Path; import socket; "
        "Path('inside.txt').write_text('ok'); "
        f"\ntry: Path({str(outside)!r}).write_text('no')\nexcept OSError: pass\nelse: raise SystemExit('outside write allowed'); "
        "\ntry: socket.create_connection(('1.1.1.1', 53), timeout=1)\nexcept OSError: pass\nelse: raise SystemExit('network allowed')"
    )
    result = await MacOSSandboxBackend().execute(
        ExecutionRequest(
            (sys.executable, "-c", command), workspace, (workspace,),
            network_policy=NetworkPolicy.NONE,
            budget=ResourceBudget(timeout_seconds=15),
        )
    )
    if result.status != "passed" and "Operation not permitted" in result.stderr and os.environ.get("KHAOS_REQUIRE_PLATFORM_SANDBOX") != "1":
        pytest.skip("current execution sandbox cannot invoke host sandbox-exec")
    assert result.status == "passed", result.stderr
    assert (workspace / "inside.txt").read_text(encoding="utf-8") == "ok"
    assert not outside.exists()
