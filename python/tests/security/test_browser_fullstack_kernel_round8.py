"""Round 8 privileged BrowserManager full-stack proof.

This test intentionally crosses every production layer: BrowserManager,
Playwright, Chromium, Rust launcher, netns/cgroup/nft, authenticated proxy,
and the route guard.  It is skipped unless the privileged CI gate opts in.
"""

from __future__ import annotations

import asyncio
import os
import socket
import subprocess
import sys
from urllib.parse import urlparse

import pytest

from khaos.security.host_network import ValidatedTarget
from khaos.security.network_guard import NetworkCheckResult
from khaos.tools.browser_tools import BrowserManager


pytestmark = [pytest.mark.browser_real, pytest.mark.kernel_real]


def _require_fullstack() -> None:
    if not sys.platform.startswith("linux"):
        pytest.skip("Linux kernel browser sandbox required")
    if os.environ.get("KHAOS_RUN_BROWSER_E2E") != "1":
        pytest.skip("set KHAOS_RUN_BROWSER_E2E=1")
    if os.environ.get("KHAOS_RUN_KERNEL_BROWSER_E2E") != "1":
        pytest.skip("set KHAOS_RUN_KERNEL_BROWSER_E2E=1")
    if os.geteuid() != 0:
        pytest.skip("privileged kernel test requires root")


class _PinnedLocalGuard:
    def __init__(self, address: str) -> None:
        self.address = address

    async def authorize_url(self, url: str, **_: object) -> ValidatedTarget:
        parsed = urlparse(url)
        return ValidatedTarget(
            url=url,
            parsed=parsed,
            hostname=parsed.hostname or "khaos.test",
            addresses=(self.address,),
        )

    async def check_resolved_url(self, url: str) -> NetworkCheckResult:
        return NetworkCheckResult(
            allowed=True,
            reason="round8 controlled local fixture",
            domain=urlparse(url).hostname or "",
        )


async def _http_handler(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
) -> None:
    await reader.readuntil(b"\r\n\r\n")
    body = b"khaos-fullstack-ok"
    writer.write(
        b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/plain\r\n"
        + f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
        + body
    )
    await writer.drain()
    writer.close()
    await writer.wait_closed()


@pytest.mark.asyncio
async def test_browser_manager_real_chromium_kernel_stack() -> None:
    _require_fullstack()
    manager = BrowserManager()
    sandbox = None
    server = None
    try:
        launch = await manager.launch()
        assert launch["ok"], launch
        sandbox = manager._browser_sandbox
        assert sandbox is not None and sandbox.is_active
        assert sandbox.enforcement_status.ok
        assert sandbox._netns_name and sandbox._cgroup_path and sandbox._nft_table

        server = await asyncio.start_server(_http_handler, sandbox._host_ip, 0)
        port = int(server.sockets[0].getsockname()[1])
        page = await manager.ensure_page(
            "round8-principal",
            session_id="round8-session",
            runtime_id="round8-runtime",
            network_guard=_PinnedLocalGuard(sandbox._host_ip),
        )
        assert page is not None, manager._last_ensure_error
        response = await page.goto(f"http://khaos.test:{port}/proof")
        assert response is not None and response.ok
        assert await page.text_content("body") == "khaos-fullstack-ok"

        pids = [
            int(value)
            for value in (sandbox._cgroup_path / "cgroup.procs").read_text().split()
        ]
        assert pids, "Chromium process tree did not join browser cgroup"
        expected_netns = os.stat(f"/var/run/netns/{sandbox._netns_name}").st_ino
        assert any(os.stat(f"/proc/{pid}/ns/net").st_ino == expected_netns for pid in pids)

        # A different host listener receives no authority from the nft port set.
        secret = socket.socket()
        secret.bind((sandbox._host_ip, 0))
        secret.listen(1)
        secret_port = int(secret.getsockname()[1])
        try:
            probe = subprocess.run(
                [
                    "ip", "netns", "exec", sandbox._netns_name,
                    "python3", "-c",
                    (
                        "import socket; s=socket.socket(); s.settimeout(2); "
                        f"raise SystemExit(0 if s.connect_ex(('{sandbox._host_ip}',"
                        f"{secret_port})) != 0 else 1)"
                    ),
                ],
                check=False,
                timeout=5,
            )
            assert probe.returncode == 0, "non-pinned host port was reachable"
        finally:
            secret.close()

        public_probe = subprocess.run(
            [
                "ip", "netns", "exec", sandbox._netns_name,
                "python3", "-c",
                (
                    "import socket; s=socket.socket(); s.settimeout(2); "
                    "raise SystemExit(0 if s.connect_ex(('1.1.1.1', 53)) "
                    "!= 0 else 1)"
                ),
            ],
            check=False,
            timeout=5,
        )
        assert public_probe.returncode == 0, "direct public egress was reachable"
        netns = sandbox._netns_name
        cgroup = sandbox._cgroup_path
        registry = sandbox._registry_file
    finally:
        if server is not None:
            server.close()
            await server.wait_closed()
        closed = await manager.close()
    assert closed["ok"], closed
    assert not cgroup.exists()
    assert registry is None or not registry.exists()
    assert subprocess.run(
        ["ip", "netns", "list"], capture_output=True, text=True, check=True,
    ).stdout.find(netns) == -1
