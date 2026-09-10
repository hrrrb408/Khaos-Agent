from __future__ import annotations

from pathlib import Path

import pytest

from khaos.evaluation.coding import (
    CommandExecution,
    CommandOracleSpec,
    CodingOracle,
    DiffOracleSpec,
    FileStateCheck,
    FileStateOracleSpec,
    FixtureManager,
    ReviewFinding,
    ReviewFindingExpectation,
    ReviewOracleSpec,
    FindingMatchMode,
    builtin_manifest_path,
    load_builtin_manifest,
    snapshot_tree,
    summarize_diff,
)
from khaos.evaluation.coding.sandbox import (
    CodingSandboxUnavailableError,
    build_oracle_execution_service,
)


class _StubCommandExecutor:
    def __init__(self, result: CommandExecution) -> None:
        self.result = result
        self.argv = None
        self.cwd = None
        self.timeout_seconds = None
        self.max_output_bytes = None
        self.environment = None
        self.hidden_present = False

    async def execute(
        self,
        argv,
        *,
        cwd,
        timeout_seconds,
        max_output_bytes,
        environment,
    ) -> CommandExecution:
        self.argv = argv
        self.cwd = cwd
        self.timeout_seconds = timeout_seconds
        self.max_output_bytes = max_output_bytes
        self.environment = environment
        self.hidden_present = (cwd / ".oracle-hidden" / "verify.py").is_file()
        return self.result


def _command_result(
    *,
    status: str,
    return_code: int | None,
    stdout_bytes: int = 0,
    stderr_bytes: int = 0,
    output_truncated: bool = False,
) -> CommandExecution:
    return CommandExecution(
        status=status,
        return_code=return_code,
        stdout_bytes=stdout_bytes,
        stderr_bytes=stderr_bytes,
        stdout_digest="a" * 64,
        stderr_digest="b" * 64,
        duration_ms=4,
        output_truncated=output_truncated,
    )


@pytest.mark.asyncio
async def test_fixture_hidden_material_is_not_in_agent_root(tmp_path) -> None:
    manifest_path = __import__(
        "khaos.evaluation.coding", fromlist=["builtin_manifest_path"]
    ).builtin_manifest_path()
    manager = FixtureManager(manifest_path, private_root=tmp_path)
    fixture = await manager.materialize(load_builtin_manifest().get("bugfix-python-cache"))
    try:
        assert not (fixture.agent_root / ".oracle-hidden").exists()
        assert not (fixture.agent_root / "verify.py").exists()
        oracle_workspace = await fixture.create_oracle_workspace(fixture.agent_root)
        try:
            assert (oracle_workspace.hidden_root / "verify.py").is_file()
            assert not (fixture.agent_root / ".oracle-hidden" / "verify.py").exists()
        finally:
            await oracle_workspace.cleanup()
    finally:
        await fixture.cleanup()


def test_diff_oracle_and_file_state_are_external_and_deterministic(tmp_path) -> None:
    before = {"src/a.py": b"old\n", "README.md": b"readme\n"}
    after = {"src/a.py": b"new\n", "README.md": b"readme\n", "src/b.py": b"added\n"}
    diff = summarize_diff(before, after)
    assert diff.changed_files == ("src/a.py", "src/b.py")
    assert diff.added_files == ("src/b.py",)
    assert diff.insertions == 2
    assert diff.deletions == 1


def test_diff_summary_records_deterministic_renames_and_binary_changes() -> None:
    diff = summarize_diff(
        {"old.txt": b"same\n", "data.bin": b"\x00old"},
        {"new.txt": b"same\n", "data.bin": b"\x00new"},
    )

    assert diff.renamed_files == ("old.txt -> new.txt",)
    assert diff.added_files == ()
    assert diff.deleted_files == ()
    assert diff.binary_files == ("data.bin",)


def test_diff_oracle_enforces_combined_line_bound() -> None:
    diff = summarize_diff({"src/a.py": b"old\n"}, {"src/a.py": b"new\n"})
    result = __import__("khaos.evaluation.coding.oracle", fromlist=["_diff"])._diff(
        DiffOracleSpec(max_diff_lines=1),
        diff,
    )

    assert diff.insertions + diff.deletions == 2
    assert not result.passed


@pytest.mark.asyncio
async def test_command_oracle_records_failure_and_timeout_without_raw_output(tmp_path) -> None:
    fixture_manager = FixtureManager(builtin_manifest_path(), private_root=tmp_path)
    fixture = await fixture_manager.materialize(
        load_builtin_manifest().get("bugfix-python-cache")
    )
    try:
        spec = CommandOracleSpec(
            argv=("python3", "verify.py"),
            hidden_files=("verify.py",),
            max_output_bytes=1024,
        )
        for status, return_code in (("failed", 7), ("timed-out", None)):
            executor = _StubCommandExecutor(
                _command_result(status=status, return_code=return_code)
            )
            result = await CodingOracle(executor).evaluate(
                spec,
                fixture=fixture,
                evaluated_root=fixture.agent_root,
                diff=summarize_diff({}, {}),
            )

            assert result.verdict.value == "FAIL"
            evidence = result.checks[0].evidence
            assert evidence["status"] == status
            assert evidence["return_code"] == return_code
            assert "stdout" not in evidence
            assert "stderr" not in evidence
            assert executor.cwd != fixture.agent_root
            assert executor.hidden_present
            assert executor.environment["PYTHONDONTWRITEBYTECODE"] == "1"
    finally:
        await fixture.cleanup()


@pytest.mark.asyncio
async def test_command_oracle_rejects_truncated_output_as_oracle_error(tmp_path) -> None:
    fixture_manager = FixtureManager(builtin_manifest_path(), private_root=tmp_path)
    fixture = await fixture_manager.materialize(
        load_builtin_manifest().get("bugfix-python-cache")
    )
    try:
        result = await CodingOracle(
            _StubCommandExecutor(
                _command_result(
                    status="passed",
                    return_code=0,
                    stdout_bytes=1024,
                    output_truncated=True,
                )
            )
        ).evaluate(
            CommandOracleSpec(
                argv=("python3", "verify.py"),
                hidden_files=("verify.py",),
                max_output_bytes=1024,
            ),
            fixture=fixture,
            evaluated_root=fixture.agent_root,
            diff=summarize_diff({}, {}),
        )

        assert result.verdict.value == "ORACLE_ERROR"
        assert result.error == "oracle command output exceeded its evidence bound"
    finally:
        await fixture.cleanup()


def test_snapshot_rejects_reserved_metadata_symlink(tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    target = tmp_path / "target"
    target.write_text("secret", encoding="utf-8")
    (root / ".git").symlink_to(target)

    with pytest.raises(Exception):
        snapshot_tree(root)


def test_review_oracle_matches_required_concepts_without_duplicate_use() -> None:
    from khaos.evaluation.coding.oracle import _review

    spec = ReviewOracleSpec(
        required_findings=(
            ReviewFindingExpectation(
                finding_id="race",
                category="concurrency",
                file="src/cache.py",
                line=10,
                concepts=("lock", "duplicate"),
            ),
        ),
        match_mode=FindingMatchMode.ALL,
    )
    result = _review(
        spec,
        (
            ReviewFinding(
                category="Concurrency",
                file="src/cache.py",
                line=12,
                concepts=("lock", "compute", "duplicate"),
            ),
        ),
    )
    assert result.passed


def test_review_oracle_reports_duplicates_and_false_positives() -> None:
    spec = ReviewOracleSpec(
        required_findings=(
            ReviewFindingExpectation(
                finding_id="race",
                category="concurrency",
                file="src/cache.py",
                line=10,
                concepts=("lock",),
            ),
        ),
        allow_extra_findings=False,
    )
    result = __import__("khaos.evaluation.coding.oracle", fromlist=["_review"])._review(
        spec,
        (
            ReviewFinding("concurrency", "src/cache.py", ("lock",), line=10),
            ReviewFinding("concurrency", "src/cache.py", ("lock",), line=11),
            ReviewFinding("style", "src/service.py", ("unused",), line=3),
        ),
    )

    assert not result.passed
    assert result.evidence["duplicate_count"] == 1
    assert result.evidence["false_positive_count"] == 1


@pytest.mark.asyncio
async def test_review_oracle_fails_when_evaluated_workspace_was_modified(tmp_path) -> None:
    fixture_manager = FixtureManager(builtin_manifest_path(), private_root=tmp_path)
    fixture = await fixture_manager.materialize(
        load_builtin_manifest().get("review-python-cache-race")
    )
    try:
        spec = ReviewOracleSpec(
            required_findings=(
                ReviewFindingExpectation(
                    finding_id="race",
                    category="concurrency",
                    file="src/cache.py",
                    concepts=("lock",),
                ),
            )
        )
        result = await CodingOracle().evaluate(
            spec,
            fixture=fixture,
            evaluated_root=fixture.agent_root,
            diff=summarize_diff({"a.py": b"old"}, {"a.py": b"new"}),
            review_findings=(
                ReviewFinding("concurrency", "src/cache.py", ("lock",)),
            ),
            read_only=True,
        )
        assert result.verdict.value == "FAIL"
        assert result.checks[-1].kind.value == "DIFF"
    finally:
        await fixture.cleanup()


@pytest.mark.asyncio
async def test_file_state_rejects_symlink_target(tmp_path) -> None:
    fixture_manager = FixtureManager(builtin_manifest_path(), private_root=tmp_path)
    fixture = await fixture_manager.materialize(
        load_builtin_manifest().get("review-python-cache-race")
    )
    try:
        target = fixture.agent_root / "src" / "outside.py"
        target.symlink_to(fixture.agent_root / "src" / "cache.py")
        spec = FileStateOracleSpec((FileStateCheck("src/outside.py"),))
        result = await CodingOracle().evaluate(
            spec,
            fixture=fixture,
            evaluated_root=fixture.agent_root,
            diff=summarize_diff({}, {}),
        )

        assert result.verdict.value == "ORACLE_ERROR"
    finally:
        await fixture.cleanup()


def test_snapshot_rejects_symlink(tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    target = tmp_path / "target"
    target.write_text("secret", encoding="utf-8")
    (root / "link").symlink_to(target)
    with pytest.raises(Exception):
        snapshot_tree(root)


@pytest.mark.asyncio
async def test_hidden_command_uses_existing_execution_service_adapter(tmp_path) -> None:
    manifest = load_builtin_manifest()
    scenario = manifest.get("bugfix-python-cache")
    manager = FixtureManager(
        __import__("khaos.evaluation.coding", fromlist=["builtin_manifest_path"]).builtin_manifest_path(),
        private_root=tmp_path,
    )
    fixture = await manager.materialize(scenario)
    try:
        service = await build_oracle_execution_service(
            principal_id="test-principal",
            project_id="test-project",
            runtime_id="oracle-runtime",
        )
    except CodingSandboxUnavailableError as exc:
        pytest.skip(f"kernel-enforced oracle backend unavailable: {exc}")
    try:
        target = fixture.agent_root / "src" / "cache.py"
        target.write_text(
            target.read_text(encoding="utf-8").replace(
                "return self._values.get(key) or default",
                "if key in self._values:\n            return self._values[key]\n        return default",
            ),
            encoding="utf-8",
        )
        before = {"src/cache.py": b"old"}
        after = {"src/cache.py": target.read_bytes()}
        result = await CodingOracle(
            __import__(
                "khaos.evaluation.coding", fromlist=["ExecutionServiceOracleExecutor"]
            ).ExecutionServiceOracleExecutor(service)
        ).evaluate(
            scenario.oracle,
            fixture=fixture,
            evaluated_root=fixture.agent_root,
            diff=summarize_diff(before, after),
        )
        assert result.verdict.value == "PASS"
        assert result.checks[0].kind.value == "COMMAND"
        assert result.checks[0].evidence["stdout_bytes"] >= 0
    finally:
        await service.close()
        await fixture.cleanup()


@pytest.mark.asyncio
async def test_command_adapter_rejects_injected_host_backend(tmp_path: Path) -> None:
    from khaos.coding.execution import ExecutionService, HostExecutionBackend, ProcessSupervisor
    from khaos.evaluation.coding import ExecutionServiceOracleExecutor
    from khaos.evaluation.coding.oracle import OracleError

    supervisor = ProcessSupervisor()
    service = ExecutionService(
        backend=HostExecutionBackend(supervisor),
        process_supervisor=supervisor,
    )
    try:
        with pytest.raises(OracleError, match="OS-enforced"):
            await ExecutionServiceOracleExecutor(service).execute(
                ("python3", "-c", "pass"),
                cwd=tmp_path,
                timeout_seconds=1,
                max_output_bytes=1024,
                environment={},
            )
    finally:
        await service.close()
