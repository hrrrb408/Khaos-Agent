import asyncio
import inspect
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from khaos.coding.execution.host import HostExecutionBackend
from khaos.coding.execution.managed import ManagedProcessHandle
from khaos.coding.execution.service import ExecutionService
from khaos.coding.intelligence.lsp.client import LspClient, _read_message
from khaos.coding.workspace.models import WorkspaceState


FAKE_SERVER = r'''import json,sys,time
def read():
 h={}
 while True:
  line=sys.stdin.buffer.readline()
  if not line: raise EOFError()
  if line in (b'\r\n',b'\n'): break
  k,v=line.decode().split(':',1); h[k.lower()]=v.strip()
 return json.loads(sys.stdin.buffer.read(int(h['content-length'])))
def write(x):
 b=json.dumps(x,separators=(',',':')).encode(); sys.stdout.buffer.write(('Content-Length: %d\r\n\r\n'%len(b)).encode()+b); sys.stdout.buffer.flush()
while True:
 try: m=read()
 except EOFError: break
 method=m.get('method')
 if method=='initialize': write({'jsonrpc':'2.0','id':m['id'],'result':{'capabilities':{'definitionProvider':True}}})
 elif method=='echo': write({'jsonrpc':'2.0','id':m['id'],'result':m.get('params',{})})
 elif method=='sleep': time.sleep(2); write({'jsonrpc':'2.0','id':m['id'],'result':{}})
 elif method=='stderr': sys.stderr.write('x'*70000); sys.stderr.flush(); write({'jsonrpc':'2.0','id':m['id'],'result':{}})
 elif method=='shutdown': write({'jsonrpc':'2.0','id':m['id'],'result':{}})
 elif method=='exit': break
'''


async def _spawn(context, temporary_home):
    process = await asyncio.create_subprocess_exec(
        *context.argv, cwd=str(context.cwd), env=context.environment,
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    return ManagedProcessHandle(
        context.correlation_id, process, temporary_home=temporary_home,
        stderr_limit=context.budget.output_bytes,
    )


def _runtime(tmp_path: Path, *, state=WorkspaceState.RUNNING):
    worktree = tmp_path / "worktree"
    worktree.mkdir(parents=True)
    (worktree / ".git").write_text("gitdir: ../repo/.git/worktrees/task\n", encoding="utf-8")
    repository = tmp_path / "repo"
    repository.mkdir(parents=True)
    workspace = SimpleNamespace(
        task_id="task", worktree_path=worktree, repository_root=repository, state=state,
    )
    manager = SimpleNamespace(get=lambda workspace_id: workspace if workspace_id == "workspace" else None)
    captured = []

    async def spawn(context, temporary_home):
        captured.append(context)
        return await _spawn(context, temporary_home)

    service = ExecutionService(HostExecutionBackend(), manager, managed_process_factory=spawn)
    service.managed_contexts = captured
    return service, workspace


def _client(service, workspace, server: Path, *, timeout=1):
    return LspClient(
        (sys.executable, str(server)), execution_service=service,
        task_id="task", workspace_id="workspace", trusted_argv=(sys.executable, str(server)), timeout=timeout,
    )


async def test_lsp_managed_lifecycle_request_notification_and_close(tmp_path: Path):
    service, workspace = _runtime(tmp_path)
    server = tmp_path / "server.py"
    server.write_text(FAKE_SERVER, encoding="utf-8")
    client = _client(service, workspace, server)

    result = await client.start(workspace.worktree_path.as_uri())
    assert result["ok"] is True
    assert result["capabilities"]["definitionProvider"] is True
    assert await client.request("echo", {"value": 1}) == {"value": 1}
    await client.notify("didOpen", {})
    assert service._active
    temporary_home = client._process._temporary_home
    await client.close()
    await client.close()
    assert not service._active
    assert not temporary_home.exists()
    with pytest.raises(RuntimeError, match="closed"):
        await client.request("echo", {})


@pytest.mark.parametrize("state", [WorkspaceState.CANCELLED, WorkspaceState.FAILED, WorkspaceState.CLEANED])
async def test_lsp_rejects_workspace_mismatch_and_inactive_state(tmp_path, state):
    service, workspace = _runtime(tmp_path, state=state)
    server = tmp_path / "server.py"
    server.write_text(FAKE_SERVER, encoding="utf-8")
    client = _client(service, workspace, server)
    result = await client.start(workspace.worktree_path.as_uri())
    assert result["ok"] is False
    assert result["diagnostic"].code == "server-unavailable"

    service, workspace = _runtime(tmp_path / "other")
    server = tmp_path / "other-server.py"
    server.write_text(FAKE_SERVER, encoding="utf-8")
    client = _client(service, workspace, server)
    result = await client.start((tmp_path / "wrong").as_uri())
    assert result["ok"] is False


async def test_missing_lsp_server_degrades_without_host_fallback(tmp_path):
    service, workspace = _runtime(tmp_path)
    client = LspClient(
        ("khaos-no-such-lsp",), execution_service=service,
        task_id="task", workspace_id="workspace", trusted_argv=("khaos-no-such-lsp",), timeout=0.1,
    )
    result = await client.start(workspace.worktree_path.as_uri())
    assert result["ok"] is False
    assert result["diagnostic"].code == "server-unavailable"


async def test_lsp_rejects_untrusted_server_command(tmp_path):
    service, workspace = _runtime(tmp_path)
    client = LspClient(
        (sys.executable, "server.py"), execution_service=service,
        task_id="task", workspace_id="workspace", trusted_argv=("other",),
    )
    result = await client.start(workspace.worktree_path.as_uri())
    assert result["ok"] is False
    assert result["diagnostic"].code == "untrusted-command"


async def test_lsp_timeout_eof_stderr_and_runtime_shutdown(tmp_path):
    service, workspace = _runtime(tmp_path)
    server = tmp_path / "server.py"
    server.write_text(FAKE_SERVER, encoding="utf-8")
    client = _client(service, workspace, server, timeout=0.05)
    assert (await client.start(workspace.worktree_path.as_uri()))["ok"]
    with pytest.raises(asyncio.TimeoutError):
        await client.request("sleep", {})
    await client.close()
    client = _client(service, workspace, server, timeout=1)
    assert (await client.start(workspace.worktree_path.as_uri()))["ok"]
    await client.request("stderr", {})
    await asyncio.sleep(0)
    assert client.stderr_truncated is True
    await service.shutdown()
    assert not service._active
    await client.close()


async def test_lsp_frame_parser_handles_partial_sticky_and_invalid_headers():
    reader = asyncio.StreamReader()
    first = json.dumps({"id": 1, "result": {}}).encode()
    second = json.dumps({"id": 2, "result": {"x": 1}}).encode()
    payload = (
        f"Content-Length: {len(first)}\r\n\r\n".encode() + first +
        f"Content-Length: {len(second)}\r\n\r\n".encode() + second
    )
    reader.feed_data(payload[:11])
    reader.feed_data(payload[11:])
    assert await _read_message(reader) == {"id": 1, "result": {}}
    assert await _read_message(reader) == {"id": 2, "result": {"x": 1}}
    invalid = asyncio.StreamReader()
    invalid.feed_data(b"Content-Length: nope\r\n\r\n")
    with pytest.raises(ValueError, match="Content-Length"):
        await _read_message(invalid)


async def test_lsp_eof_fails_pending_request(tmp_path):
    service, workspace = _runtime(tmp_path)
    server = tmp_path / "eof.py"
    server.write_text("pass\n", encoding="utf-8")
    client = _client(service, workspace, server, timeout=0.1)
    result = await client.start(workspace.worktree_path.as_uri())
    assert result["ok"] is False
    assert result["diagnostic"].code == "server-unavailable"


class _FakeManagedProcess:
    def __init__(self):
        self.execution_id = "fake-lsp"
        self.stdout = asyncio.StreamReader()
        self.stdin = object()
        self.returncode = None
        self.stderr_text = ""
        self.stderr_truncated = False

    async def write_stdin(self, payload):
        body = json.loads(payload.split(b"\r\n\r\n", 1)[1])
        if "id" in body:
            response = json.dumps({"jsonrpc": "2.0", "id": body["id"], "result": {"fake": True}}).encode()
            self.stdout.feed_data(f"Content-Length: {len(response)}\r\n\r\n".encode() + response)

    async def wait(self):
        self.returncode = 0
        return 0

    async def terminate(self):
        self.returncode = -15
        self.stdout.feed_eof()

    async def kill(self):
        self.returncode = -9
        self.stdout.feed_eof()


async def test_lsp_works_with_fake_managed_process(tmp_path):
    service, workspace = _runtime(tmp_path)
    fake = _FakeManagedProcess()
    service.start_managed_process = AsyncMock(return_value=fake)
    service.terminate = AsyncMock()
    client = _client(service, workspace, tmp_path / "trusted-server")
    assert (await client.start(workspace.worktree_path.as_uri()))["ok"]
    assert await client.request("fake", {}) == {"fake": True}
    await client.close()
    service.terminate.assert_awaited_once_with("fake-lsp")


async def test_execution_service_managed_process_backend_and_environment_fail_closed(tmp_path):
    service, workspace = _runtime(tmp_path)
    server = tmp_path / "server.py"
    server.write_text(FAKE_SERVER, encoding="utf-8")
    client = _client(service, workspace, server)
    assert (await client.start(workspace.worktree_path.as_uri()))["ok"]
    handle = client._process
    assert handle is not None
    context = service.managed_contexts[0]
    assert context.network_policy.value == "none"
    assert set(context.environment) == {"PATH", "LANG", "HOME", "TMPDIR"}
    assert not ({"SSH_AUTH_SOCK", "GH_TOKEN", "GITHUB_TOKEN", "AWS_ACCESS_KEY_ID"} & context.allowed_environment_keys)
    await client.close()

    unsupported = ExecutionService(HostExecutionBackend(), service.workspace_manager)
    client = _client(unsupported, workspace, server)
    result = await client.start(workspace.worktree_path.as_uri())
    assert result["ok"] is False
    assert "unsupported" in result["diagnostic"].message


def test_lsp_client_has_no_direct_subprocess():
    import khaos.coding.intelligence.lsp.client as module

    source = inspect.getsource(module)
    assert "create_subprocess_exec" not in source
    assert "create_subprocess_shell" not in source
