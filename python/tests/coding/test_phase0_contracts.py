from pathlib import Path

from khaos.coding.contracts import (
    ChangeSet,
    ExecutionBackend,
    LanguageAdapter,
    ParsedFile,
    SourcePosition,
    SourceRange,
    TaskWorkspace,
    VerificationStep,
)


FIXTURE_ROOT = Path(__file__).parents[1] / "fixtures" / "repos"


def test_phase0_contracts_are_importable_and_typed():
    position = SourcePosition(line=0, character=0)
    source_range = SourceRange(start=position, end=position)
    parsed = ParsedFile(path=Path("main.py"), language="python")
    step = VerificationStep("preflight", "preflight", ("python", "-m", "compileall"), Path("."), 10)
    workspace = TaskWorkspace("w1", "t1", Path("repo"), Path("worktree"), "main", "abc", "khaos/task/t1", (Path("worktree"),))
    changeset = ChangeSet("c1", "w1", "abc", (), Path("patch"), "report")

    assert source_range.start == position
    assert parsed.language == "python"
    assert step.required is True
    assert workspace.writable_roots == (Path("worktree"),)
    assert changeset.base_sha == "abc"
    assert LanguageAdapter is not None
    assert ExecutionBackend is not None


def test_offline_language_fixtures_are_available():
    for name in ("python_basic", "javascript_basic", "typescript_basic", "go_basic", "rust_basic"):
        assert (FIXTURE_ROOT / name).is_dir()
