import pytest

from khaos.tools.registry import create_runtime_registry
from khaos.tools.sandbox_tools import sandbox_build, sandbox_exec


class MockDockerClient:
    def __init__(self):
        self.calls = []

    async def create(self, config):
        self.calls.append(("create", config))
        return "container-1"

    async def start(self, container_id, timeout):
        self.calls.append(("start", container_id, timeout))

    async def exec(self, container_id, command, timeout):
        self.calls.append(("exec", container_id, command, timeout))
        return {"returncode": 0, "stdout": "ok\n", "stderr": ""}

    async def stop(self, container_id, timeout):
        self.calls.append(("stop", container_id, timeout))

    async def remove(self, container_id, timeout):
        self.calls.append(("remove", container_id, timeout))

    async def build(self, dockerfile, context, tag, timeout):
        self.calls.append(("build", dockerfile, context, tag, timeout))
        return {"returncode": 0, "stdout": "built\n", "stderr": ""}


async def test_sandbox_exec_lifecycle_with_network_disabled(tmp_path):
    client = MockDockerClient()

    result = await sandbox_exec(
        "python -V",
        project_dir=str(tmp_path),
        network=False,
        timeout=5,
        client=client,
    )

    assert result["container_id"] == "container-1"
    assert result["network"] is False
    assert result["stdout"] == "ok\n"
    assert [call[0] for call in client.calls] == ["create", "start", "exec", "stop", "remove"]
    assert client.calls[0][1].network is False


async def test_sandbox_exec_cleanup_runs_after_exec_failure(tmp_path):
    class FailingClient(MockDockerClient):
        async def exec(self, container_id, command, timeout):
            self.calls.append(("exec", container_id, command, timeout))
            raise RuntimeError("exec failed")

    client = FailingClient()

    with pytest.raises(RuntimeError):
        await sandbox_exec("python -V", project_dir=str(tmp_path), client=client)

    assert [call[0] for call in client.calls] == ["create", "start", "exec", "stop", "remove"]


async def test_sandbox_build_uses_client(tmp_path):
    client = MockDockerClient()
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM scratch\n", encoding="utf-8")

    result = await sandbox_build(str(dockerfile), context=str(tmp_path), tag="khaos:test", client=client)

    assert result["tag"] == "khaos:test"
    assert result["stdout"] == "built\n"
    assert client.calls[0][0] == "build"


async def test_sandbox_exec_rejects_empty_command(tmp_path):
    with pytest.raises(ValueError):
        await sandbox_exec("", project_dir=str(tmp_path), client=MockDockerClient())


def test_runtime_registry_binds_sandbox_tools():
    registry = create_runtime_registry()

    assert registry.get("sandbox_exec").handler is not None
    assert registry.get("sandbox_build").handler is not None
    assert registry.get("sandbox_exec").modes == ["coding"]

