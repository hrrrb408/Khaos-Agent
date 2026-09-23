from __future__ import annotations

import runpy
from pathlib import Path

import pytest
from khaos.evaluation.coding import (
    CodingOracle,
    CommandExecution,
    CommandOracleSpec,
    DiffOracleSpec,
    FileStateCheck,
    FileStateOracleSpec,
    FindingMatchMode,
    FixtureManager,
    OracleError,
    ReviewFinding,
    ReviewFindingExpectation,
    ReviewOracleSpec,
    builtin_manifest_path,
    evaluate_review_findings,
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

    with pytest.raises(OracleError):
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


def test_review_oracle_matches_concepts_embedded_in_bounded_evidence() -> None:
    from khaos.evaluation.coding.oracle import _review

    spec = ReviewOracleSpec(
        required_findings=(
            ReviewFindingExpectation(
                finding_id="race",
                category="concurrency",
                file="src/cache.py",
                line=7,
                line_tolerance=3,
                concepts=("lock", "compute", "duplicate"),
            ),
        ),
        match_mode=FindingMatchMode.ALL,
    )
    result = _review(
        spec,
        (
            ReviewFinding(
                category="concurrency",
                file="src/cache.py",
                line=7,
                concepts=(
                    "a missing lock protects the shared cache",
                    "compute can run more than once for a duplicate key",
                ),
            ),
        ),
    )

    assert result.passed


def test_cache_race_contract_accepts_source_identifiers() -> None:
    scenario = load_builtin_manifest().get("review-python-cache-race")
    result = evaluate_review_findings(
        scenario.oracle,
        (
            ReviewFinding(
                category="concurrency",
                file="src/cache.py",
                line=7,
                concepts=("get_or_compute", "_values", "_compute"),
                severity="high",
            ),
        ),
    )

    assert scenario.version == 5
    assert result.passed


def test_legacy_review_oracle_accepts_separator_equivalent_categories() -> None:
    from khaos.evaluation.coding.oracle import _review

    spec = ReviewOracleSpec(
        required_findings=(
            ReviewFindingExpectation(
                finding_id="authority",
                category="authority-definition",
                file="src/authority.py",
                concepts=("AuthorityLease", "definition"),
            ),
        ),
        match_mode=FindingMatchMode.ALL,
    )
    result = _review(
        spec,
        (
            ReviewFinding(
                category="authority_definition",
                file="src/authority.py",
                concepts=("AuthorityLease",),
            ),
        ),
    )

    assert result.passed


def test_legacy_review_oracle_accepts_bare_consumer_role_category() -> None:
    from khaos.evaluation.coding.oracle import _review

    spec = ReviewOracleSpec(
        required_findings=(
            ReviewFindingExpectation(
                finding_id="consumer",
                category="authority-consumer",
                file="src/consumer.py",
                concepts=("consume_lease", "consumer"),
            ),
        ),
        match_mode=FindingMatchMode.ALL,
    )
    result = _review(
        spec,
        (
            ReviewFinding(
                category="consumer",
                file="src/consumer.py",
                concepts=("consume_lease",),
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
    with pytest.raises(OracleError):
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
async def test_hidden_cache_oracle_accepts_any_semantically_correct_fix(tmp_path) -> None:
    manifest = load_builtin_manifest()
    scenario = manifest.get("bugfix-python-cache")
    manager = FixtureManager(builtin_manifest_path(), private_root=tmp_path)
    fixture = await manager.materialize(scenario)
    try:
        service = await build_oracle_execution_service(
            principal_id="test-principal",
            project_id="test-project",
            runtime_id="oracle-runtime-semantic",
        )
    except CodingSandboxUnavailableError as exc:
        pytest.skip(f"kernel-enforced oracle backend unavailable: {exc}")
    try:
        target = fixture.agent_root / "src" / "cache.py"
        current = target.read_text(encoding="utf-8")
        assert "return self._values.get(key) or default" in current
        current = current.replace(
            "return self._values.get(key) or default",
            "value = self._values.get(key, _MISSING)\n        return default if value is _MISSING else value",
        )
        target.write_text(
            "_MISSING = object()\n\n" + current,
            encoding="utf-8",
        )
        result = await CodingOracle(
            __import__(
                "khaos.evaluation.coding", fromlist=["ExecutionServiceOracleExecutor"]
            ).ExecutionServiceOracleExecutor(service)
        ).evaluate(
            scenario.oracle,
            fixture=fixture,
            evaluated_root=fixture.agent_root,
            diff=summarize_diff(
                {"src/cache.py": b"return self._values.get(key) or default"},
                {"src/cache.py": target.read_bytes()},
            ),
        )
        assert result.verdict.value == "PASS"
    finally:
        await service.close()
        await fixture.cleanup()


def test_hidden_go_counter_oracle_accepts_equivalent_guard(tmp_path, monkeypatch) -> None:
    source = """
package counter

type Counter struct { balance int }

func (c *Counter) Decrement(delta int) bool {
    if delta < 0 || delta > c.balance {
        return false
    }
    c.balance -= delta
    return true
}
"""
    (tmp_path / "counter.go").write_text(source, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    hidden = builtin_manifest_path().parent / "bugfix-go-counter" / "hidden" / "verify.py"
    runpy.run_path(str(hidden), run_name="__main__")


def test_hidden_typescript_oracle_accepts_nullish_guard(tmp_path, monkeypatch) -> None:
    source = """
export type Config = { enabled: boolean; retries: number };

export function readEnabled(input: Partial<Config>): boolean {
  return input.enabled ?? true;
}
"""
    source_root = tmp_path / "src"
    source_root.mkdir()
    (source_root / "config.ts").write_text(source, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    hidden = (
        builtin_manifest_path().parent
        / "bugfix-typescript-config"
        / "hidden"
        / "verify.py"
    )
    runpy.run_path(str(hidden), run_name="__main__")


def test_hidden_typescript_oracle_accepts_explicit_undefined_ternary(
    tmp_path, monkeypatch
) -> None:
    source = """
export type Config = { enabled: boolean; retries: number };

export function readEnabled(input: Partial<Config>): boolean {
  return input.enabled === undefined ? true : input.enabled;
}
"""
    source_root = tmp_path / "src"
    source_root.mkdir()
    (source_root / "config.ts").write_text(source, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    hidden = (
        builtin_manifest_path().parent
        / "bugfix-typescript-config"
        / "hidden"
        / "verify.py"
    )
    runpy.run_path(str(hidden), run_name="__main__")


def test_hidden_typescript_oracle_rejects_truthiness_fallback(
    tmp_path, monkeypatch
) -> None:
    source = """
export type Config = { enabled: boolean; retries: number };

export function readEnabled(input: Partial<Config>): boolean {
  return input.enabled || true;
}
"""
    source_root = tmp_path / "src"
    source_root.mkdir()
    (source_root / "config.ts").write_text(source, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    hidden = (
        builtin_manifest_path().parent
        / "bugfix-typescript-config"
        / "hidden"
        / "verify.py"
    )
    with pytest.raises(AssertionError):
        runpy.run_path(str(hidden), run_name="__main__")


def test_hidden_browser_oracle_accepts_semantic_filter_and_status(
    tmp_path, monkeypatch
) -> None:
    source_root = tmp_path / "src"
    source_root.mkdir()
    (source_root / "app.html").write_text(
        """
<label><input type="radio" name="task-filter" value="all"></label>
<p id="filter-status" role="status" aria-live="polite"></p>
<script>
  const visible = 2;
  filter.addEventListener("change", applyFilter);
  status.textContent = `Showing ${visible} tasks`;
</script>
""",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    hidden = (
        builtin_manifest_path().parent
        / "browser-validated-feature"
        / "hidden"
        / "verify.py"
    )
    runpy.run_path(str(hidden), run_name="__main__")


def test_hidden_multifile_go_oracle_accepts_type_accumulator(tmp_path, monkeypatch) -> None:
    (tmp_path / "validate.go").write_text(
        "package pipeline\n\nfunc Validate(items []Item) []Item { return items }\n",
        encoding="utf-8",
    )
    (tmp_path / "pipeline.go").write_text(
        """package pipeline

type Accumulator struct { items []Item }

func NewAccumulator() *Accumulator { return &Accumulator{} }
func (a *Accumulator) Add(item Item) { a.items = append(a.items, item) }
func (a *Accumulator) Results() []Item { return a.items }
""",
        encoding="utf-8",
    )
    (tmp_path / "service.go").write_text(
        """package pipeline

func Process(items []Item) []Item {
    acc := NewAccumulator()
    for _, item := range Validate(items) { acc.Add(item) }
    return acc.Results()
}
""",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    hidden = (
        builtin_manifest_path().parent
        / "multifile-go-pipeline"
        / "hidden"
        / "verify.py"
    )
    runpy.run_path(str(hidden), run_name="__main__")


@pytest.mark.asyncio
async def test_command_adapter_rejects_injected_host_backend(tmp_path: Path) -> None:
    from khaos.coding.execution import (
        ExecutionService,
        HostExecutionBackend,
        ProcessSupervisor,
    )
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
