"""Round 8 privileged BrowserManager full-stack proof.

This test intentionally crosses every production layer: BrowserManager,
Playwright, Chromium, Rust launcher, netns/cgroup/nft, authenticated proxy,
and the route guard.  It is skipped unless the privileged CI gate opts in.
"""

from __future__ import annotations

import asyncio
import os
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
    if os.geteuid() == 0:
        pytest.fail("production Python browser runtime must be non-root")
    cap_eff = int(
        next(
            line.split()[1]
            for line in open("/proc/self/status", encoding="ascii")
            if line.startswith("CapEff:")
        ),
        16,
    )
    assert cap_eff == 0, "production Python browser runtime has capabilities"


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
        launch = await manager.launch(
            project_id="round8-project", runtime_id="round8-runtime"
        )
        assert launch["ok"], launch
        sandbox = manager._browser_sandbox
        assert sandbox is not None and sandbox.is_active
        assert sandbox.enforcement_status.ok
        evidence = await asyncio.to_thread(sandbox._kernel_authority.status)
        assert evidence.helper_authenticated
        assert evidence.network_namespace
        assert evidence.nft_default_deny
        assert evidence.cgroup_attached
        assert evidence.process_isolated
        assert evidence.resource_registry_verified

        server = await asyncio.start_server(_http_handler, sandbox._host_ip, 0)
        port = int(server.sockets[0].getsockname()[1])
        page = await manager.ensure_page(
            "round8-principal",
            session_id="round8-session",
            runtime_id="round8-runtime",
            network_guard=_PinnedLocalGuard(sandbox._host_ip),
        )
        assert page is not None, manager._last_ensure_error
        target_url = f"http://khaos.test:{port}/proof"
        response = await page.goto(target_url)
        assert response is not None and response.ok
        assert await page.text_content("body") == "khaos-fullstack-ok"

        final_evidence = await asyncio.to_thread(
            sandbox._kernel_authority.status
        )
        assert final_evidence.process_isolated
        assert not final_evidence.quarantined
    finally:
        if server is not None:
            server.close()
            await server.wait_closed()
        closed = await manager.close()
    assert closed["ok"], closed
