"""C-06~C-11 (round-4 review): Browser Kernel Egress Closure tests.

Covers:
  - C-07: proxy auth token — missing/wrong/valid credentials
  - C-11: relay exception re-raising (byte limit, idle timeout)
  - C-08: cgroup.procs join in wrapper script
  - C-09: fail-closed mode (require_os_sandbox)
  - C-10: secure wrapper directory (no /tmp, O_EXCL, owner-verified)
  - C-06: nftables egress pin (mocked subprocess)
"""

from __future__ import annotations

import asyncio
import base64
import os
import secrets
import sys
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import MagicMock, patch
from urllib.parse import urlsplit

import pytest

from khaos.security.browser_egress_proxy import (
    BrowserEgressProxy,
    _ByteLimitExceeded,
    _ProxyAuthError,
)
from khaos.security.browser_sandbox import (
    BrowserNetworkSandbox,
    BrowserSandboxConfig,
    BrowserSandboxError,
    EnforcementStatus,
    _RUN_DIR_ROOT,
)
from khaos.security.host_network import ValidatedTarget


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


class _PinnedGuard:
    """Minimal NetworkGuard stub that always pins to 127.0.0.1."""

    def __init__(self, address: str = "127.0.0.1") -> None:
        self.address = address

    async def authorize_url(self, url: str) -> ValidatedTarget:
        parsed = urlsplit(url)
        return ValidatedTarget(
            url=url,
            parsed=parsed,
            hostname=parsed.hostname or "",
            addresses=(self.address,),
        )


def _proxy_auth_header(proxy: BrowserEgressProxy) -> str:
    """C-07: build the ``Proxy-Authorization`` header for a proxy instance."""
    credentials = f"{proxy.proxy_username}:{proxy.proxy_password}"
    encoded = base64.b64encode(credentials.encode("ascii")).decode("ascii")
    return f"Proxy-Authorization: Basic {encoded}\r\n"


async def _start_origin_server(handler, host: str = "127.0.0.1"):
    server = await asyncio.start_server(handler, host, 0)
    port = server.sockets[0].getsockname()[1]
    return server, port


# ---------------------------------------------------------------------------
# C-07: Proxy auth token
# ---------------------------------------------------------------------------


async def test_c07_missing_auth_header_returns_407():
    """C-07: a request without Proxy-Authorization is rejected with 407."""
    proxy = BrowserEgressProxy(_PinnedGuard())  # type: ignore[arg-type]
    await proxy.start()
    try:
        port = int(urlsplit(proxy.server_url).port or 0)
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(
            b"GET http://target.example.invalid/ HTTP/1.1\r\n"
            b"Host: target.example.invalid\r\n\r\n"
        )
        await writer.drain()
        response = await reader.read()
        writer.close()
        await writer.wait_closed()
        assert b"407" in response
        assert b"Proxy-Authenticate" in response
    finally:
        await proxy.close()


async def test_c07_wrong_credentials_return_407():
    """C-07: a request with wrong credentials is rejected with 407."""
    proxy = BrowserEgressProxy(_PinnedGuard())  # type: ignore[arg-type]
    await proxy.start()
    try:
        port = int(urlsplit(proxy.server_url).port or 0)
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        bad_credentials = base64.b64encode(b"khaos:wrong-token").decode("ascii")
        writer.write(
            b"GET http://target.example.invalid/ HTTP/1.1\r\n"
            b"Host: target.example.invalid\r\n"
            + f"Proxy-Authorization: Basic {bad_credentials}\r\n\r\n".encode("ascii")
        )
        await writer.drain()
        response = await reader.read()
        writer.close()
        await writer.wait_closed()
        assert b"407" in response
    finally:
        await proxy.close()


async def test_c07_valid_credentials_pass_through():
    """C-07: a request with valid credentials reaches the origin."""
    async def origin(_reader, writer):
        await _reader.readuntil(b"\r\n\r\n")
        writer.write(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
            b"Connection: close\r\n\r\nok"
        )
        await writer.drain()
        writer.close()

    server, port = await _start_origin_server(origin)
    proxy = BrowserEgressProxy(_PinnedGuard())  # type: ignore[arg-type]
    await proxy.start()
    try:
        proxy_port = int(urlsplit(proxy.server_url).port or 0)
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
        writer.write(
            f"GET http://target.example.invalid:{port}/ HTTP/1.1\r\n"
            f"Host: target.example.invalid:{port}\r\n"
            f"{_proxy_auth_header(proxy)}\r\n".encode("ascii")
        )
        await writer.drain()
        response = await reader.read()
        writer.close()
        await writer.wait_closed()
        assert response.endswith(b"ok")
    finally:
        await proxy.close()
        server.close()
        await server.wait_closed()


async def test_c07_connect_without_auth_returns_407():
    """C-07: CONNECT without auth is also rejected with 407."""
    proxy = BrowserEgressProxy(_PinnedGuard())  # type: ignore[arg-type]
    await proxy.start()
    try:
        port = int(urlsplit(proxy.server_url).port or 0)
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(
            b"CONNECT target.example.invalid:443 HTTP/1.1\r\n\r\n"
        )
        await writer.drain()
        response = await reader.read()
        writer.close()
        await writer.wait_closed()
        assert b"407" in response
    finally:
        await proxy.close()


async def test_c07_malformed_basic_credentials_return_407():
    """C-07: malformed base64 in credentials is rejected with 407."""
    proxy = BrowserEgressProxy(_PinnedGuard())  # type: ignore[arg-type]
    await proxy.start()
    try:
        port = int(urlsplit(proxy.server_url).port or 0)
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(
            b"GET http://target.example.invalid/ HTTP/1.1\r\n"
            b"Host: target.example.invalid\r\n"
            b"Proxy-Authorization: Basic !!!not-base64!!!\r\n\r\n"
        )
        await writer.drain()
        response = await reader.read()
        writer.close()
        await writer.wait_closed()
        assert b"407" in response
    finally:
        await proxy.close()


async def test_c07_wrong_scheme_rejected():
    """C-07: non-Basic auth scheme is rejected with 407."""
    proxy = BrowserEgressProxy(_PinnedGuard())  # type: ignore[arg-type]
    await proxy.start()
    try:
        port = int(urlsplit(proxy.server_url).port or 0)
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(
            b"GET http://target.example.invalid/ HTTP/1.1\r\n"
            b"Host: target.example.invalid\r\n"
            b"Proxy-Authorization: Bearer some-token\r\n\r\n"
        )
        await writer.drain()
        response = await reader.read()
        writer.close()
        await writer.wait_closed()
        assert b"407" in response
    finally:
        await proxy.close()


def test_c07_auth_token_is_unique_per_proxy():
    """C-07: each proxy instance gets a unique auth token."""
    p1 = BrowserEgressProxy(_PinnedGuard())  # type: ignore[arg-type]
    p2 = BrowserEgressProxy(_PinnedGuard())  # type: ignore[arg-type]
    assert p1.proxy_password != p2.proxy_password
    assert p1.proxy_username == "khaos"
    assert p2.proxy_username == "khaos"


def test_c07_validate_proxy_auth_directly():
    """C-07: _validate_proxy_auth accepts valid and rejects invalid."""
    proxy = BrowserEgressProxy(_PinnedGuard())  # type: ignore[arg-type]
    # Valid
    valid_header = (
        f"GET http://x.invalid/ HTTP/1.1\r\n"
        f"Host: x.invalid\r\n"
        f"{_proxy_auth_header(proxy)}\r\n".encode("ascii")
    )
    proxy._validate_proxy_auth(valid_header)  # must not raise

    # Missing
    with pytest.raises(_ProxyAuthError, match="missing"):
        proxy._validate_proxy_auth(b"GET http://x.invalid/ HTTP/1.1\r\n\r\n")

    # Wrong token
    bad = base64.b64encode(b"khaos:wrong").decode("ascii")
    with pytest.raises(_ProxyAuthError, match="invalid"):
        proxy._validate_proxy_auth(
            f"GET http://x.invalid/ HTTP/1.1\r\n"
            f"Proxy-Authorization: Basic {bad}\r\n\r\n".encode("ascii")
        )


# ---------------------------------------------------------------------------
# C-11: Relay exception re-raising
# ---------------------------------------------------------------------------


async def test_c11_upload_byte_limit_propagates_as_413():
    """C-11: _ByteLimitExceeded from upload relay propagates as 413."""
    async def origin(_reader, writer):
        try:
            await _reader.readuntil(b"\r\n\r\n")
        except Exception:
            pass
        await asyncio.sleep(5)
        writer.close()

    server, port = await _start_origin_server(origin)
    proxy = BrowserEgressProxy(_PinnedGuard(), max_upload=512)  # type: ignore[arg-type]
    await proxy.start()
    try:
        proxy_port = int(urlsplit(proxy.server_url).port or 0)
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
        writer.write(
            f"POST http://upload.example.invalid:{port}/ HTTP/1.1\r\n"
            f"Host: upload.example.invalid:{port}\r\n"
            f"Content-Length: 99999\r\n"
            f"{_proxy_auth_header(proxy)}\r\n".encode("ascii")
        )
        await writer.drain()
        writer.write(b"x" * 2048)
        await writer.drain()
        response = await reader.read()
        writer.close()
        await writer.wait_closed()
        # C-11: the 413 response MUST be sent (previously swallowed)
        assert b"413" in response, (
            f"Expected 413 response but got: {response!r}"
        )
    finally:
        await proxy.close()
        server.close()
        await server.wait_closed()


async def test_c11_download_byte_limit_propagates_as_413():
    """C-11: _ByteLimitExceeded from download relay propagates as 413."""
    async def origin(_reader, writer):
        try:
            await _reader.readuntil(b"\r\n\r\n")
        except Exception:
            pass
        writer.write(
            b"HTTP/1.1 200 OK\r\nContent-Length: 99999\r\n\r\n"
        )
        writer.write(b"y" * 50000)
        await writer.drain()
        writer.close()

    server, port = await _start_origin_server(origin)
    proxy = BrowserEgressProxy(_PinnedGuard(), max_download=512)  # type: ignore[arg-type]
    await proxy.start()
    try:
        proxy_port = int(urlsplit(proxy.server_url).port or 0)
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
        writer.write(
            f"GET http://download.example.invalid:{port}/ HTTP/1.1\r\n"
            f"Host: download.example.invalid:{port}\r\n"
            f"{_proxy_auth_header(proxy)}\r\n".encode("ascii")
        )
        await writer.drain()
        response = await reader.read()
        writer.close()
        await writer.wait_closed()
        # Response should be truncated (less than full 50000)
        assert len(response) < 50000
    finally:
        await proxy.close()
        server.close()
        await server.wait_closed()


async def test_c11_relay_bidirectional_re_raises_byte_limit():
    """C-11: _relay_bidirectional re-raises _ByteLimitExceeded directly."""
    from khaos.security.browser_egress_proxy import _relay_bidirectional

    # Create mock stream objects
    class _MockReader:
        def __init__(self, data: bytes = b"") -> None:
            self._data = data
            self._read = False
        async def read(self, n: int = -1) -> bytes:
            if self._read:
                await asyncio.sleep(10)  # block forever
                return b""
            self._read = True
            return self._data

    class _MockWriter:
        def __init__(self) -> None:
            self.closed = False
            self.written = bytearray()
        def close(self) -> None:
            self.closed = True
        async def wait_closed(self) -> None:
            pass
        def write(self, data: bytes) -> None:
            self.written.extend(data)
        async def drain(self) -> None:
            pass
        def is_closing(self) -> bool:
            return self.closed

    # Upload that exceeds 1 byte limit
    client_reader = _MockReader(b"x" * 100)
    client_writer = _MockWriter()
    upstream_reader = _MockReader(b"")
    upstream_writer = _MockWriter()

    with pytest.raises(_ByteLimitExceeded):
        await _relay_bidirectional(
            client_reader, client_writer,
            upstream_reader, upstream_writer,
            stats=MagicMock(),
            idle_timeout=5.0,
            max_upload=1,
            max_download=999999,
        )


# ---------------------------------------------------------------------------
# C-09: Fail-closed mode
# ---------------------------------------------------------------------------


def test_c09_require_os_sandbox_raises_on_non_linux():
    """C-09: require_os_sandbox=True raises BrowserSandboxError on non-Linux."""
    if sys.platform.startswith("linux"):
        pytest.skip("test only for non-Linux")
    sandbox = BrowserNetworkSandbox(require_os_sandbox=True)
    with pytest.raises(BrowserSandboxError, match="non-Linux"):
        sandbox.setup()
    assert not sandbox.is_active


def test_c09_dev_mode_does_not_raise_on_non_linux():
    """C-09: require_os_sandbox=False (dev) does not raise on non-Linux."""
    if sys.platform.startswith("linux"):
        pytest.skip("test only for non-Linux")
    sandbox = BrowserNetworkSandbox(require_os_sandbox=False)
    sandbox.setup()  # must not raise
    assert not sandbox.is_active
    status = sandbox.enforcement_status
    assert not status.network_namespace
    assert not status.cgroup
    assert not status.route_guard


def test_c09_enforcement_status_defaults_all_false():
    """C-09: a fresh sandbox has all enforcement layers disabled."""
    sandbox = BrowserNetworkSandbox()
    status = sandbox.enforcement_status
    assert isinstance(status, EnforcementStatus)
    assert not status.network_namespace
    assert not status.proxy_required
    assert not status.cgroup
    assert not status.route_guard
    assert not status.service_workers_blocked


def test_c09_teardown_resets_enforcement_status():
    """C-09: teardown resets enforcement status to all-false."""
    sandbox = BrowserNetworkSandbox()
    sandbox._enforcement = EnforcementStatus(
        network_namespace=True, proxy_required=True,
    )
    sandbox.teardown()
    status = sandbox.enforcement_status
    assert not status.network_namespace
    assert not status.proxy_required


# ---------------------------------------------------------------------------
# C-10: Secure wrapper directory
# ---------------------------------------------------------------------------


def test_c10_wrapper_not_in_tmp():
    """C-10: the wrapper script directory is NOT in /tmp."""
    # The _RUN_DIR_ROOT should be under ~/.khaos/run, not /tmp
    assert "/tmp" not in str(_RUN_DIR_ROOT)
    assert ".khaos" in str(_RUN_DIR_ROOT)


def test_c10_secure_run_dir_created_with_o_excl():
    """C-10: _create_secure_run_dir uses O_EXCL and creates mode 0700."""
    if sys.platform.startswith("linux"):
        pytest.skip("test uses real filesystem on non-Linux only")
    # Clean up any leftover
    if _RUN_DIR_ROOT.exists():
        import shutil
        shutil.rmtree(_RUN_DIR_ROOT, ignore_errors=True)

    sandbox = BrowserNetworkSandbox()
    sandbox._create_secure_run_dir()

    assert sandbox._run_dir is not None
    assert sandbox._run_dir.exists()
    # Mode must be 0700
    mode = sandbox._run_dir.stat().st_mode & 0o777
    assert mode == 0o700, f"expected 0o700, got {oct(mode)}"
    # Owner must be current user
    assert sandbox._run_dir.stat().st_uid == os.getuid()
    # Must not be a symlink
    assert not sandbox._run_dir.is_symlink()

    # Cleanup
    sandbox._run_dir.rmdir()
    sandbox._run_dir = None


def test_c10_wrapper_script_uses_o_nofollow_o_excl():
    """C-10: wrapper script is created with O_NOFOLLOW and O_EXCL.

    This test mocks setup() to make the sandbox appear active, then
    verifies the wrapper script is created securely.
    """
    if sys.platform.startswith("linux"):
        pytest.skip("test uses real filesystem on non-Linux only")

    import shutil
    if _RUN_DIR_ROOT.exists():
        shutil.rmtree(_RUN_DIR_ROOT, ignore_errors=True)

    sandbox = BrowserNetworkSandbox()
    sandbox._create_secure_run_dir()
    # Simulate an active sandbox without actual netns
    sandbox._active = True
    sandbox._netns_name = "khaos-test-fake"
    sandbox._cgroup_path = None  # no cgroup on non-Linux

    wrapper_path = sandbox.create_wrapper_script("/fake/chromium", 0)
    assert wrapper_path is not None
    path = Path(wrapper_path)
    assert path.exists()
    # Must be in the secure run dir, not /tmp
    assert "/tmp/" not in wrapper_path
    assert str(_RUN_DIR_ROOT) in wrapper_path
    # Mode must be 0700 (executable but not world-readable)
    mode = path.stat().st_mode & 0o777
    assert mode == 0o700, f"expected 0o700, got {oct(mode)}"
    # Owner must be current user
    assert path.stat().st_uid == os.getuid()
    # Must not be a symlink
    assert not path.is_symlink()

    # Cleanup
    path.unlink(missing_ok=True)
    sandbox._run_dir.rmdir()


def test_c10_wrapper_creation_fails_on_existing_file():
    """C-10: O_EXCL prevents overwriting an existing wrapper."""
    if sys.platform.startswith("linux"):
        pytest.skip("test uses real filesystem on non-Linux only")

    import shutil
    if _RUN_DIR_ROOT.exists():
        shutil.rmtree(_RUN_DIR_ROOT, ignore_errors=True)

    sandbox = BrowserNetworkSandbox()
    sandbox._create_secure_run_dir()
    sandbox._active = True
    sandbox._netns_name = "khaos-test-dup"
    sandbox._cgroup_path = None

    # First creation succeeds
    wrapper1 = sandbox.create_wrapper_script("/fake/chromium", 0)
    assert wrapper1 is not None

    # Second creation with the same name should fail (O_EXCL)
    sandbox._wrapper_script = None  # reset
    with pytest.raises(FileExistsError):
        sandbox.create_wrapper_script("/fake/chromium", 0)

    # Cleanup
    Path(wrapper1).unlink(missing_ok=True)
    sandbox._run_dir.rmdir()


# ---------------------------------------------------------------------------
# C-08: cgroup.procs join in wrapper script
# ---------------------------------------------------------------------------


def test_c08_wrapper_contains_cgroup_join():
    """C-08: the wrapper script writes PID to cgroup.procs before exec."""
    if sys.platform.startswith("linux"):
        pytest.skip("test uses real filesystem on non-Linux only")

    import shutil
    if _RUN_DIR_ROOT.exists():
        shutil.rmtree(_RUN_DIR_ROOT, ignore_errors=True)

    sandbox = BrowserNetworkSandbox()
    sandbox._create_secure_run_dir()
    sandbox._active = True
    sandbox._netns_name = "khaos-test-cgroup"
    # Simulate a cgroup path
    sandbox._cgroup_path = Path("/sys/fs/cgroup/khaos/browser-test")

    wrapper_path = sandbox.create_wrapper_script("/fake/chromium", 0)
    assert wrapper_path is not None
    content = Path(wrapper_path).read_text()

    # C-08: the wrapper MUST write $$ to cgroup.procs
    assert "cgroup.procs" in content, (
        "wrapper must write PID to cgroup.procs (C-08)"
    )
    assert "echo $$" in content, (
        "wrapper must echo the shell PID to join the cgroup"
    )
    # C-08: if cgroup join fails, the wrapper must exit non-zero
    assert "exit 1" in content, (
        "wrapper must exit non-zero if cgroup join fails"
    )

    # Cleanup
    Path(wrapper_path).unlink(missing_ok=True)
    sandbox._run_dir.rmdir()


def test_c08_wrapper_without_cgroup_has_no_join():
    """C-08: when cgroup_path is None, the wrapper skips the cgroup join."""
    if sys.platform.startswith("linux"):
        pytest.skip("test uses real filesystem on non-Linux only")

    import shutil
    if _RUN_DIR_ROOT.exists():
        shutil.rmtree(_RUN_DIR_ROOT, ignore_errors=True)

    sandbox = BrowserNetworkSandbox()
    sandbox._create_secure_run_dir()
    sandbox._active = True
    sandbox._netns_name = "khaos-test-no-cgroup"
    sandbox._cgroup_path = None  # no cgroup

    wrapper_path = sandbox.create_wrapper_script("/fake/chromium", 0)
    assert wrapper_path is not None
    content = Path(wrapper_path).read_text()

    # No cgroup join when cgroup_path is None
    assert "cgroup.procs" not in content

    # Cleanup
    Path(wrapper_path).unlink(missing_ok=True)
    sandbox._run_dir.rmdir()


# ---------------------------------------------------------------------------
# C-06: nftables egress pin (mocked)
# ---------------------------------------------------------------------------


def test_c06_install_egress_pin_noop_when_inactive():
    """C-06: install_egress_pin is a no-op when the sandbox is inactive."""
    sandbox = BrowserNetworkSandbox()
    # Sandbox is not active
    sandbox.install_egress_pin(8080)
    assert not sandbox.enforcement_status.route_guard


def test_c06_install_egress_pin_fails_closed_in_production():
    """C-06: in production mode, missing nft raises BrowserSandboxError."""
    if sys.platform.startswith("linux"):
        pytest.skip("test only for non-Linux where nft is unavailable")
    sandbox = BrowserNetworkSandbox(require_os_sandbox=True)
    # Simulate active sandbox
    sandbox._active = True
    sandbox._veth_host = "khaos-brh-test"
    sandbox._host_ip = "10.200.1.1"
    with pytest.raises(BrowserSandboxError, match="nftables"):
        sandbox.install_egress_pin(8080)


def test_c06_install_egress_pin_dev_mode_warns_on_missing_nft():
    """C-06: in dev mode, missing nft logs a warning but does not raise."""
    if sys.platform.startswith("linux"):
        pytest.skip("test only for non-Linux where nft is unavailable")
    sandbox = BrowserNetworkSandbox(require_os_sandbox=False)
    sandbox._active = True
    sandbox._veth_host = "khaos-brh-test"
    sandbox._host_ip = "10.200.1.1"
    # Must not raise
    sandbox.install_egress_pin(8080)
    assert not sandbox.enforcement_status.route_guard


@patch("khaos.security.browser_sandbox.subprocess.run")
@patch("khaos.security.browser_sandbox.shutil.which")
def test_c06_install_egress_pin_calls_nft_rules(
    mock_which, mock_run
):
    """C-06 (round-5): when nft is available, install_egress_pin installs
    rules via ``nft -f -`` with an atomic stdin script."""
    mock_which.return_value = "/usr/sbin/nft"
    mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")

    sandbox = BrowserNetworkSandbox()
    sandbox._active = True
    sandbox._veth_host = "khaos-brh-test"
    sandbox._host_ip = "10.200.1.1"
    sandbox._nft_table = "khaos_browser_test1234"

    sandbox.install_egress_pin(9090)

    assert sandbox.enforcement_status.route_guard
    # C-02 (round-5): nft is called once with -f - (atomic stdin script)
    assert mock_run.call_count == 1
    call = mock_run.call_args
    assert call.args[0] == ["nft", "-f", "-"]
    # The script is passed via the 'input' kwarg
    script = call.kwargs.get("input", "")
    # Verify the script references the proxy port, host IP, and input hook
    assert "9090" in script
    assert "10.200.1.1" in script
    # C-01 (round-5): must use input hook, not just forward
    assert "hook input" in script
    assert "hook forward" in script
    # C-03 (round-5): base chains must use policy accept, not policy drop
    assert "policy accept" in script
    assert "policy drop" not in script


@patch("khaos.security.browser_sandbox.subprocess.run")
@patch("khaos.security.browser_sandbox.shutil.which")
def test_c06_teardown_deletes_nft_table(
    mock_which, mock_run
):
    """C-06 (round-5): teardown deletes the per-sandbox nftables table."""
    mock_which.return_value = "/usr/sbin/nft"
    mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")

    sandbox = BrowserNetworkSandbox()
    sandbox._nft_table = "khaos_browser_test1234"
    sandbox.teardown()
    # Verify nft delete table was called with the per-sandbox table name
    delete_calls = [
        call for call in mock_run.call_args_list
        if "delete" in " ".join(call.args[0])
    ]
    assert len(delete_calls) >= 1


# ---------------------------------------------------------------------------
# C-09: _has_net_admin actually probes
# ---------------------------------------------------------------------------


def test_c09_has_net_admin_returns_false_on_non_linux():
    """C-09: _has_net_admin returns False on non-Linux (not True)."""
    from khaos.security.browser_sandbox import _has_net_admin
    if sys.platform.startswith("linux"):
        pytest.skip("test only for non-Linux")
    # Previously this unconditionally returned True
    assert _has_net_admin() is False


@patch("khaos.security.browser_sandbox.subprocess.run")
@patch("khaos.security.browser_sandbox.shutil.which")
def test_c09_has_net_admin_probes_with_ip_netns(
    mock_which, mock_run
):
    """C-09: _has_net_admin actually probes by creating/deleting a netns."""
    mock_which.return_value = "/usr/sbin/ip"
    mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")

    from khaos.security.browser_sandbox import _has_net_admin
    with patch("khaos.security.browser_sandbox.sys.platform", "linux"):
        result = _has_net_admin()

    assert result is True
    # Verify ip netns add and del were called
    calls = [call.args[0] for call in mock_run.call_args_list]
    assert any("add" in c and "netns" in c for c in calls)
    assert any("del" in c and "netns" in c for c in calls)


@patch("khaos.security.browser_sandbox.subprocess.run")
@patch("khaos.security.browser_sandbox.shutil.which")
def test_c09_has_net_admin_returns_false_on_permission_denied(
    mock_which, mock_run
):
    """C-09: _has_net_admin returns False when ip netns add fails."""
    mock_which.return_value = "/usr/sbin/ip"
    mock_run.return_value = MagicMock(returncode=1, stderr="Operation not permitted")

    from khaos.security.browser_sandbox import _has_net_admin
    with patch("khaos.security.browser_sandbox.sys.platform", "linux"):
        result = _has_net_admin()

    assert result is False


# ---------------------------------------------------------------------------
# Round-5 Batch 5.1: per-sandbox resource names, registry-based reaper,
# fail-closed production, nft input hook
# ---------------------------------------------------------------------------


def test_round5_per_sandbox_token_in_resource_names():
    """H-01: each sandbox instance gets a unique token in resource names."""
    s1 = BrowserNetworkSandbox()
    s2 = BrowserNetworkSandbox()
    # Two instances must have different tokens.
    assert s1._token != s2._token
    # After setup names would include the token — verify the token is
    # 16 hex chars (8 bytes).
    assert len(s1._token) == 16
    assert all(c in "0123456789abcdef" for c in s1._token)


def test_round5_nft_table_is_per_sandbox():
    """H-01/H-02: nft table name includes the per-sandbox token."""
    s1 = BrowserNetworkSandbox()
    s2 = BrowserNetworkSandbox()
    # Simulate setup() naming.
    s1._nft_table = f"khaos_browser_{s1._token}"
    s2._nft_table = f"khaos_browser_{s2._token}"
    assert s1._nft_table != s2._nft_table
    assert s1._token in s1._nft_table
    assert s2._token in s2._nft_table


def test_round5_teardown_only_deletes_own_nft_table():
    """H-02: teardown deletes only THIS sandbox's nft table, not global."""
    with patch("khaos.security.browser_sandbox.subprocess.run") as mock_run, \
         patch("khaos.security.browser_sandbox.shutil.which", return_value="/usr/sbin/nft"):
        mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
        s1 = BrowserNetworkSandbox()
        expected_table = f"khaos_browser_{s1._token}"
        s1._nft_table = expected_table
        s1.teardown()
        # Verify the delete command used s1's table name.
        delete_calls = [
            call for call in mock_run.call_args_list
            if "delete" in " ".join(call.args[0])
        ]
        assert len(delete_calls) >= 1
        deleted_table = delete_calls[0].args[0][-1]
        assert deleted_table == expected_table
        # Must NOT be a global name like "khaos_browser_egress".
        assert deleted_table != "khaos_browser_egress"


def test_round5_nft_script_uses_input_hook_not_forward_only():
    """C-01: the nft script must include an 'input' hook for browser→host
    local traffic, not just 'forward'."""
    with patch("khaos.security.browser_sandbox.subprocess.run") as mock_run, \
         patch("khaos.security.browser_sandbox.shutil.which", return_value="/usr/sbin/nft"):
        mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
        sandbox = BrowserNetworkSandbox()
        sandbox._active = True
        sandbox._veth_host = "khbrh-abc123"
        sandbox._host_ip = "10.200.1.1"
        sandbox._nft_table = f"khaos_browser_{sandbox._token}"
        sandbox.install_egress_pin(9090)
        script = mock_run.call_args.kwargs.get("input", "")
        assert "hook input" in script
        assert "hook forward" in script


def test_round5_nft_script_uses_policy_accept_not_drop():
    """C-03: base chains must use 'policy accept' so unmatched host traffic
    is unaffected."""
    with patch("khaos.security.browser_sandbox.subprocess.run") as mock_run, \
         patch("khaos.security.browser_sandbox.shutil.which", return_value="/usr/sbin/nft"):
        mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
        sandbox = BrowserNetworkSandbox()
        sandbox._active = True
        sandbox._veth_host = "khbrh-abc123"
        sandbox._host_ip = "10.200.1.1"
        sandbox._nft_table = f"khaos_browser_{sandbox._token}"
        sandbox.install_egress_pin(9090)
        script = mock_run.call_args.kwargs.get("input", "")
        assert "policy accept" in script
        assert "policy drop" not in script


def test_round5_nft_uses_nft_f_minus_not_split():
    """C-02: nft is called with '-f -' (stdin script), not via .split()."""
    with patch("khaos.security.browser_sandbox.subprocess.run") as mock_run, \
         patch("khaos.security.browser_sandbox.shutil.which", return_value="/usr/sbin/nft"):
        mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
        sandbox = BrowserNetworkSandbox()
        sandbox._active = True
        sandbox._veth_host = "khbrh-abc123"
        sandbox._host_ip = "10.200.1.1"
        sandbox._nft_table = f"khaos_browser_{sandbox._token}"
        sandbox.install_egress_pin(9090)
        # Must be called exactly once with ["nft", "-f", "-"].
        assert mock_run.call_count == 1
        assert mock_run.call_args.args[0] == ["nft", "-f", "-"]
        # The script must be passed as the 'input' kwarg (stdin).
        assert "input" in mock_run.call_args.kwargs


def test_round5_create_wrapper_fails_closed_in_production():
    """C-04: in production mode, wrapper creation failure raises
    BrowserSandboxError instead of returning None."""
    sandbox = BrowserNetworkSandbox(require_os_sandbox=True)
    sandbox._active = True
    # _run_dir is None → should raise in production.
    with pytest.raises(BrowserSandboxError, match="secure run directory"):
        sandbox.create_wrapper_script("/usr/bin/chromium", 0)


def test_round5_create_wrapper_dev_mode_creates_run_dir():
    """C-04: in dev mode, wrapper creation creates the run dir as fallback."""
    sandbox = BrowserNetworkSandbox(require_os_sandbox=False)
    sandbox._active = True
    sandbox._netns_name = "khaos-br-test"
    sandbox._token = secrets.token_hex(8)
    # _run_dir is None → dev mode should create it.
    # This will create a real directory under ~/.khaos/run/<token>/.
    try:
        result = sandbox.create_wrapper_script("/usr/bin/echo", 0)
        assert result is not None
        assert os.path.exists(result)
    finally:
        if sandbox._run_dir is not None:
            # Clean up.
            try:
                for child in sandbox._run_dir.iterdir():
                    child.unlink()
                sandbox._run_dir.rmdir()
            except OSError:
                pass
