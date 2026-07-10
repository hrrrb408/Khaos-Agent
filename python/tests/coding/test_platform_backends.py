import sys
from pathlib import Path

import pytest

from khaos.coding.execution.platform import LinuxBubblewrapBackend, MacOSSandboxBackend, UnsupportedBackend


@pytest.mark.asyncio
async def test_unsupported_backend_refuses_writable_execution():
    with pytest.raises(PermissionError):
        await UnsupportedBackend().execute(object())


def test_platform_profiles_are_network_denying(tmp_path: Path):
    assert "deny network" in MacOSSandboxBackend().profile(tmp_path)
    assert "--unshare-net" in LinuxBubblewrapBackend().argv_prefix(tmp_path)
