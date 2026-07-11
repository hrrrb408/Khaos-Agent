import subprocess
from pathlib import Path

from khaos.coding.workspace.recovery import discover_orphans


def test_dirty_orphan_requires_recovery(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "x@y"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "x"], cwd=repo, check=True)
    (repo / "x").write_text("x")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "base"], cwd=repo, check=True)
    orphan = tmp_path / "orphans" / "one"
    subprocess.run(["git", "worktree", "add", "-q", str(orphan)], cwd=repo, check=True)
    (orphan / "x").write_text("dirty")
    result = discover_orphans(orphan.parent)
    assert result[0].recovery_required is True
