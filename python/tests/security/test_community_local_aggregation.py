"""Regression tests for deterministic Community Local aggregation."""

from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[3]


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


FETCH = _load_module(
    "fetch_security_producer_artifacts_contract",
    ROOT / "scripts" / "fetch_security_producer_artifacts.py",
)
COLLECT = _load_module(
    "collect_local_security_evidence_contract",
    ROOT / "scripts" / "collect_local_security_evidence.py",
)
VERIFY = _load_module(
    "verify_release_gate_runs_contract",
    ROOT / "scripts" / "verify_release_gate_runs.py",
)
FIXTURES = _load_module(
    "release_gate_verifier_fixtures",
    ROOT / "python/tests/security/test_release_gate_verifier.py",
)


COMMIT = "a" * 40
REPOSITORY = "owner/repo"


def _security_run(**overrides: object) -> dict[str, object]:
    result: dict[str, object] = {
        "id": 42,
        "repository": {"full_name": REPOSITORY},
        "head_repository": {"full_name": REPOSITORY},
        "name": "Security Closure Gate",
        "path": ".github/workflows/security-closure-gate.yml",
        "workflow_id": 1234,
        "head_sha": COMMIT,
        "event": "push",
        "head_branch": "main",
        "status": "completed",
        "conclusion": "success",
        "run_attempt": 1,
        "html_url": "https://example.invalid/security/42",
    }
    result.update(overrides)
    return result


def _aggregation_manifest(
    *, observer_run_id: int = 44, observer_head_sha: str = "d" * 40
) -> dict[str, object]:
    value: dict[str, object] = {
        "schema": VERIFY.COMMUNITY_LOCAL_AGGREGATION_SCHEMA,
        "target_sha": COMMIT,
        "evidence_status": "PROVEN",
        "reason": "all required producer-owned proofs passed",
        "upstream_security_closure": {
            "repository": "hrrrb408/Khaos-Agent",
            "workflow": "Security Closure Gate",
            "workflow_name": "Security Closure Gate",
            "workflow_file": "security-closure-gate.yml",
            "workflow_path": ".github/workflows/security-closure-gate.yml",
            "workflow_id": 322127705,
            "run_id": "1",
            "run_attempt": 1,
            "event": "push",
            "head_branch": "main",
            "head_sha": COMMIT,
            "ref": "refs/heads/main",
            "status": "completed",
            "conclusion": "success",
            "html_url": "https://example.invalid/security/1",
        },
        "aggregator": {
            "repository": "hrrrb408/Khaos-Agent",
            "workflow": "Community Local Security Closure",
            "workflow_file": "community-local-closure.yml",
            "run_id": str(observer_run_id),
            "run_attempt": 1,
            "event": "workflow_run",
            "ref": "refs/heads/main",
            "head_branch": "main",
            "head_sha": observer_head_sha,
            "runner_os": "Ubuntu",
            "job": "community-local-closure",
        },
        "producer_manifest_digest": "e" * 64,
    }
    value["manifest_digest"] = VERIFY._canonical_digest(value)
    return value


def _observer_run(run_id: int, *, head_sha: str = "d" * 40) -> dict[str, object]:
    return {
        "id": run_id,
        "database_id": run_id,
        "repository": {"full_name": "hrrrb408/Khaos-Agent"},
        "head_repository": {"full_name": "hrrrb408/Khaos-Agent"},
        "name": "Community Local Security Closure",
        "path": ".github/workflows/community-local-closure.yml",
        "workflow_id": 341723006,
        "head_sha": head_sha,
        "event": "workflow_run",
        "head_branch": "main",
        "status": "completed",
        "conclusion": "success",
        "run_attempt": 1,
        "html_url": f"https://example.invalid/community/{run_id}",
    }


def test_workflow_uses_completed_upstream_dependency_and_target_sha() -> None:
    path = ROOT / ".github/workflows/community-local-closure.yml"
    source = path.read_text(encoding="utf-8")
    parsed = yaml.safe_load(source)
    trigger = parsed.get("on", parsed.get(True))

    assert trigger == {
        "workflow_run": {
            "workflows": ["Security Closure Gate"],
            "types": ["completed"],
            "branches": ["main"],
        }
    }
    assert parsed["permissions"] == {"contents": "read", "actions": "read"}
    assert "\n  push:" not in source
    assert "workflow_dispatch:" not in source
    assert "github.event.workflow_run.head_sha" in source
    assert '--commit "$UPSTREAM_HEAD_SHA"' in source
    assert '--run-id "$UPSTREAM_RUN_ID"' in source
    assert "aggregation-manifest.json" in source
    assert "timeout-seconds" not in source


def test_fetcher_revalidates_the_event_named_run_without_searching_latest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    run = _security_run()

    def fake_json(_repo: str, endpoint: str) -> dict[str, object]:
        calls.append(endpoint)
        return run

    monkeypatch.setattr(FETCH, "_json", fake_json)
    selected = FETCH._select_security_run(
        REPOSITORY, "security-closure-gate.yml", COMMIT, "42"
    )

    assert calls == ["actions/runs/42"]
    assert selected["run_id"] == "42"
    assert selected["workflow_id"] == 1234
    assert selected["head_sha"] == COMMIT
    assert selected["event"] == "push"
    assert selected["run_attempt"] == 1


@pytest.mark.parametrize(
    "overrides",
    [
        {"head_sha": "b" * 40},
        {"name": "Other Workflow"},
        {"path": ".github/workflows/other.yml"},
        {"event": "workflow_dispatch"},
        {"head_branch": "feature"},
        {"status": "in_progress"},
        {"conclusion": "failure"},
        {"run_attempt": 2},
        {"repository": {"full_name": "attacker/repo"}},
        {"head_repository": {"full_name": "attacker/repo"}},
    ],
)
def test_fetcher_rejects_failed_rerun_or_wrong_upstream_identity(
    monkeypatch: pytest.MonkeyPatch, overrides: dict[str, object]
) -> None:
    monkeypatch.setattr(FETCH, "_json", lambda *_args: _security_run(**overrides))
    with pytest.raises(RuntimeError):
        FETCH._select_security_run(
            REPOSITORY, "security-closure-gate.yml", COMMIT, "42"
        )


def test_fetcher_artifact_retry_is_bounded_and_allows_eventual_visibility(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = {"producer-a", "producer-b"}
    responses = [
        [],
        [{"name": "producer-a", "id": 1}],
        [
            {"name": "producer-a", "id": 1},
            {"name": "producer-b", "id": 2},
        ],
    ]
    calls = 0
    sleeps: list[float] = []

    def fake_artifacts(_repo: str, _run_id: str) -> list[dict[str, object]]:
        nonlocal calls
        response = responses[min(calls, len(responses) - 1)]
        calls += 1
        return response

    monkeypatch.setattr(FETCH, "_artifacts", fake_artifacts)
    monkeypatch.setattr(FETCH.time, "sleep", sleeps.append)
    result = FETCH._wait_for_expected_artifacts(REPOSITORY, "42", expected)

    assert sorted(result) == sorted(expected)
    assert calls == 3
    assert len(sleeps) == 2


def test_fetcher_missing_artifact_fails_after_fixed_attempts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0
    sleeps: list[float] = []

    def fake_artifacts(_repo: str, _run_id: str) -> list[dict[str, object]]:
        nonlocal calls
        calls += 1
        return []

    monkeypatch.setattr(FETCH, "_artifacts", fake_artifacts)
    monkeypatch.setattr(FETCH.time, "sleep", sleeps.append)
    with pytest.raises(RuntimeError, match="bounded"):
        FETCH._wait_for_expected_artifacts(REPOSITORY, "42", {"producer-a"})

    assert calls == FETCH.ARTIFACT_RETRY_ATTEMPTS
    assert len(sleeps) == FETCH.ARTIFACT_RETRY_ATTEMPTS - 1


def test_fetcher_rejects_duplicate_artifact_names_without_overwriting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    FETCH_ARTIFACTS = [
        {"name": "producer-a", "id": 1},
        {"name": "producer-a", "id": 2},
    ]
    # The implementation must reject the duplicate before the dict projection
    # can silently choose one of the two records.
    monkeypatch.setattr(FETCH, "_artifacts", lambda _repo, _run_id: FETCH_ARTIFACTS)
    with pytest.raises(RuntimeError, match="duplicated"):
        FETCH._wait_for_expected_artifacts(
            REPOSITORY,
            "42",
            {"producer-a"},
        )


def test_collector_records_observer_sha_separately_from_target_sha(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GITHUB_REPOSITORY", "hrrrb408/Khaos-Agent")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "workflow_run")
    monkeypatch.setenv("GITHUB_REF", "refs/heads/main")
    monkeypatch.setenv("GITHUB_SHA", "d" * 40)
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "1")
    monkeypatch.setenv("GITHUB_RUN_ID", "44")
    monkeypatch.setenv("GITHUB_WORKFLOW", "Community Local Security Closure")
    monkeypatch.setenv("RUNNER_OS", "Ubuntu")
    monkeypatch.setenv("GITHUB_JOB", "community-local-closure")
    manifest = {
        "security_run": {"workflow": "Security Closure Gate", "run_id": "1"}
    }

    upstream, aggregator = COLLECT._identity(COMMIT, manifest)

    assert upstream["head_sha"] == COMMIT
    assert aggregator["head_sha"] == "d" * 40
    assert aggregator["run_id"] == "44"
    with monkeypatch.context() as context:
        context.setenv("GITHUB_RUN_ATTEMPT", "2")
        with pytest.raises(RuntimeError, match="attempt 1"):
            COLLECT._identity(COMMIT, manifest)


def test_release_verifier_accepts_and_rejects_digest_bound_sidecar() -> None:
    manifest = _aggregation_manifest()
    verified = VERIFY._verify_aggregation_manifest(
        manifest,
        repo="hrrrb408/Khaos-Agent",
        run_id=44,
        commit=COMMIT,
        observer_head_sha="d" * 40,
    )
    assert verified["manifest_digest"] == manifest["manifest_digest"]

    for field, replacement in (
        ("target_sha", "b" * 40),
        ("evidence_status", "UNKNOWN"),
    ):
        tampered = dict(manifest)
        tampered[field] = replacement
        unsigned = dict(tampered)
        unsigned.pop("manifest_digest", None)
        tampered["manifest_digest"] = VERIFY._canonical_digest(unsigned)
        with pytest.raises(RuntimeError):
            VERIFY._verify_aggregation_manifest(
                tampered,
                repo="hrrrb408/Khaos-Agent",
                run_id=44,
                commit=COMMIT,
                observer_head_sha="d" * 40,
            )

    wrong_upstream = dict(manifest)
    wrong_upstream["upstream_security_closure"] = dict(
        manifest["upstream_security_closure"], head_sha="b" * 40
    )
    wrong_unsigned = dict(wrong_upstream)
    wrong_unsigned.pop("manifest_digest", None)
    wrong_upstream["manifest_digest"] = VERIFY._canonical_digest(wrong_unsigned)
    with pytest.raises(RuntimeError, match="upstream identity"):
        VERIFY._verify_aggregation_manifest(
            wrong_upstream,
            repo="hrrrb408/Khaos-Agent",
            run_id=44,
            commit=COMMIT,
            observer_head_sha="d" * 40,
        )


def test_release_selector_is_order_independent_and_requires_one_exact_observer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = FIXTURES._local_evidence_payload()
    archive = FIXTURES._local_archive(
        payload, observer_run_id=44, observer_head_sha="d" * 40
    )
    artifact = {
        "id": 220,
        "name": f"local-security-evidence-{COMMIT}",
        "size_in_bytes": len(archive),
        "expired": False,
        "digest": f"sha256:{hashlib.sha256(archive).hexdigest()}",
        "workflow_run": {"id": 44},
    }
    decoy = _observer_run(43)
    selected_run = _observer_run(44)

    def fake_api(_repo: str, endpoint: str) -> dict[str, object]:
        if endpoint.startswith("actions/workflows/"):
            # The valid run deliberately appears after an unrelated completed
            # observer to prove selection does not depend on API ordering.
            return {"total_count": 2, "workflow_runs": [decoy, selected_run]}
        if endpoint == "actions/runs/43/artifacts?per_page=100":
            return {"total_count": 0, "artifacts": []}
        if endpoint == "actions/runs/44/artifacts?per_page=100":
            return {"total_count": 1, "artifacts": [artifact]}
        raise AssertionError(endpoint)

    monkeypatch.setattr(VERIFY, "_run_gh_api", fake_api)
    monkeypatch.setattr(VERIFY, "gh_api_bytes", lambda *_args, **_kwargs: archive)
    run, _artifacts, proof = VERIFY._select_community_local_run(
        "hrrrb408/Khaos-Agent", "community-local-closure.yml", COMMIT
    )

    assert run["id"] == 44
    assert proof["aggregator"]["run_id"] == "44"


def test_release_selector_rejects_duplicate_successful_observers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = FIXTURES._local_evidence_payload()
    archives = {
        44: FIXTURES._local_archive(payload, observer_run_id=44),
        45: FIXTURES._local_archive(payload, observer_run_id=45),
    }
    artifacts = {
        run_id: {
            "id": run_id,
            "name": f"local-security-evidence-{COMMIT}",
            "size_in_bytes": len(archive),
            "expired": False,
            "digest": f"sha256:{hashlib.sha256(archive).hexdigest()}",
            "workflow_run": {"id": run_id},
        }
        for run_id, archive in archives.items()
    }
    runs = [_observer_run(44), _observer_run(45)]

    def fake_api(_repo: str, endpoint: str) -> dict[str, object]:
        if endpoint.startswith("actions/workflows/"):
            return {"total_count": 2, "workflow_runs": runs}
        run_id = int(endpoint.split("/")[2])
        return {"total_count": 1, "artifacts": [artifacts[run_id]]}

    monkeypatch.setattr(VERIFY, "_run_gh_api", fake_api)
    monkeypatch.setattr(
        VERIFY,
        "gh_api_bytes",
        lambda _repo, endpoint, **_kwargs: archives[int(endpoint.split("/")[2])],
    )
    with pytest.raises(RuntimeError, match="not unique"):
        VERIFY._select_community_local_run(
            "hrrrb408/Khaos-Agent", "community-local-closure.yml", COMMIT
        )


def test_release_selector_rejects_a_successful_observer_without_target_artifact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_api(_repo: str, endpoint: str) -> dict[str, object]:
        if endpoint.startswith("actions/workflows/"):
            return {"total_count": 1, "workflow_runs": [_observer_run(44)]}
        return {"total_count": 0, "artifacts": []}

    monkeypatch.setattr(VERIFY, "_run_gh_api", fake_api)
    with pytest.raises(RuntimeError, match="not unique"):
        VERIFY._select_community_local_run(
            "hrrrb408/Khaos-Agent", "community-local-closure.yml", COMMIT
        )


def test_community_release_verifier_requires_the_selected_upstream_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    local_payload = FIXTURES._local_evidence_payload()
    local_archive = FIXTURES._local_archive(
        local_payload, observer_run_id=44, observer_head_sha="d" * 40
    )
    security_run = {
        "id": 1,
        "database_id": 1,
        "name": "Security Closure Gate",
        "path": ".github/workflows/security-closure-gate.yml",
        "workflow_id": 322127705,
        "head_sha": COMMIT,
        "event": "push",
        "head_branch": "main",
        "status": "completed",
        "conclusion": "success",
        "run_attempt": 1,
        "html_url": "https://example.invalid/security/1",
    }
    product_run = {
        "id": 2,
        "database_id": 2,
        "head_sha": COMMIT,
        "event": "push",
        "head_branch": "main",
        "status": "completed",
        "conclusion": "success",
        "run_attempt": 1,
        "workflow_id": 322127706,
    }
    local_run = _observer_run(44)
    local_artifact = {
        "id": 220,
        "name": f"local-security-evidence-{COMMIT}",
        "size_in_bytes": len(local_archive),
        "expired": False,
        "digest": f"sha256:{hashlib.sha256(local_archive).hexdigest()}",
        "workflow_run": {"id": 44},
    }

    def fake_api(_repo: str, endpoint: str) -> dict[str, object]:
        if endpoint.startswith("compare/"):
            return {"status": "identical", "ahead_by": 0, "behind_by": 0}
        if endpoint == "git/ref/heads/main":
            return {"object": {"sha": COMMIT}}
        if endpoint.startswith("actions/workflows/security-closure-gate.yml"):
            return {"total_count": 1, "workflow_runs": [security_run]}
        if endpoint.startswith("actions/workflows/product-integrity-gate.yml"):
            return {"total_count": 1, "workflow_runs": [product_run]}
        if endpoint.startswith("actions/workflows/community-local-closure.yml"):
            return {"total_count": 1, "workflow_runs": [local_run]}
        if endpoint == "actions/runs/1/artifacts?per_page=100":
            return {"total_count": 1, "artifacts": [FIXTURES._security_artifact()]}
        if endpoint == "actions/runs/2/artifacts?per_page=100":
            return {"total_count": 0, "artifacts": []}
        if endpoint == "actions/runs/44/artifacts?per_page=100":
            return {"total_count": 1, "artifacts": [local_artifact]}
        raise AssertionError(endpoint)

    monkeypatch.setattr(VERIFY, "_run_gh_api", fake_api)
    monkeypatch.setattr(
        VERIFY,
        "gh_api_bytes",
        lambda _repo, endpoint, **_kwargs: {
            "7": FIXTURES._security_archive(),
            "220": local_archive,
        }[endpoint.split("/")[2]],
    )
    monkeypatch.setattr(
        VERIFY,
        "_verify_external_producers",
        lambda *_args, **_kwargs: [{"policy_digest": "b" * 64}],
    )

    evidence = VERIFY.verify_release_gates(
        "hrrrb408/Khaos-Agent", COMMIT, profile="community-local"
    )

    local_record = evidence["gates"]["community_local"]
    assert local_record["target_sha"] == COMMIT
    assert local_record["head_sha"] == "d" * 40
    assert local_record["local_proof"]["upstream_security_closure"]["run_id"] == "1"
