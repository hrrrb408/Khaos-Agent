import asyncio

import pytest

from khaos.tools.git_tools import git_branch, git_commit, git_diff, git_log
from khaos.tools.registry import create_runtime_registry


async def _git(repo, *args):
    process = await asyncio.create_subprocess_exec(
        "git",
        *args,
        cwd=str(repo),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await process.communicate()
    if process.returncode != 0:
        pytest.skip(f"git unavailable or failed: {stderr.decode()}")
    return stdout.decode()


async def _repo(tmp_path):
    await _git(tmp_path, "init")
    await _git(tmp_path, "config", "user.email", "test@example.com")
    await _git(tmp_path, "config", "user.name", "Tester")
    (tmp_path / "a.txt").write_text("one\n", encoding="utf-8")
    await _git(tmp_path, "add", "a.txt")
    await _git(tmp_path, "commit", "-m", "initial")
    return tmp_path


async def test_git_diff(tmp_path):
    repo = await _repo(tmp_path)
    (repo / "a.txt").write_text("two\n", encoding="utf-8")

    result = await git_diff(str(repo))

    assert result["returncode"] == 0
    assert "-one" in result["stdout"]


async def test_git_commit_and_log(tmp_path):
    repo = await _repo(tmp_path)
    (repo / "b.txt").write_text("b\n", encoding="utf-8")
    await _git(repo, "add", "b.txt")

    commit = await git_commit(str(repo), "add b")
    log = await git_log(str(repo), limit=1)

    assert commit["returncode"] == 0
    assert "add b" in log["stdout"]


async def test_git_branch_show_current(tmp_path):
    repo = await _repo(tmp_path)

    result = await git_branch(str(repo))

    assert result["returncode"] == 0
    assert result["stdout"].strip() in {"main", "master"}


def test_runtime_registry_binds_git_tools():
    registry = create_runtime_registry()

    assert registry.get("git_diff").handler is not None
    assert registry.get("git_commit").permission_level == "write"

