"""Live-verifier contract regressions for multi-producer provenance."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import zipfile
from pathlib import Path
from typing import Any, Callable

import pytest

from khaos.security.local_closure import COMMUNITY_LOCAL_REQUIRED_PROOFS, canonical_digest


ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location(
    "verify_release_gate_runs_producer_tests",
    ROOT / "scripts" / "verify_release_gate_runs.py",
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

COMMIT = "a" * 40
POLICY = "b" * 64
RUN_ID = 9001


def _proof(
    proof_type: str,
    *,
    workflow: str = "Security Closure Gate",
    job: str | None = None,
    event: str = "push",
    ref: str = "refs/heads/main",
    commit: str = COMMIT,
    attempt: int = 1,
) -> tuple[dict[str, object], dict[str, bytes]]:
    if job is None:
        job = "compose-deployment" if proof_type in {
            "production_composition",
            "process_tree_escape",
            "resource_owner_closure",
        } else "community-local-producers"
    stdout = (
        b"production lifecycle stdout\n"
        if proof_type in {"process_tree_escape", "resource_owner_closure"}
        else f"{proof_type} stdout\n".encode()
    )
    stderr = b""
    junit = b'<testsuite tests="1" failures="0" errors="0" skipped="0"><testcase name="oracle"/></testsuite>'
    diagnostics = {
        "schema": "khaos.local-security-producer-diagnostics.v1",
        "proof_name": proof_type,
        "returncode": 0,
        "test_count": 1,
        "passed": 1,
        "skipped": 0,
        "failed": 0,
        "errors": 0,
        "skipped_reasons": [],
        "failure_details": [],
        "error_details": [],
        "junit_digest": hashlib.sha256(junit).hexdigest(),
        "stdout_digest": hashlib.sha256(stdout).hexdigest(),
        "stderr_digest": hashlib.sha256(stderr).hexdigest(),
    }
    producer_workflow = {
        "repository": "hrrrb408/Khaos-Agent",
        "workflow": workflow,
        "run_id": str(RUN_ID),
        "run_attempt": attempt,
        "event": event,
        "ref": ref,
        "head_sha": commit,
        "runner_os": "Linux",
        "job": job,
    }
    unsigned: dict[str, object] = {
        "schema": "khaos.local-security-producer-proof.v1",
        "proof_type": proof_type,
        "commit": commit,
        "policy_digest": POLICY,
        "profile": "community-local",
        "workflow": producer_workflow,
        "production_claim": proof_type in {
            "production_composition",
            "process_tree_escape",
            "resource_owner_closure",
        },
        "production_mode": proof_type in {
            "production_composition",
            "process_tree_escape",
            "resource_owner_closure",
        },
        "diagnostics": diagnostics,
        "result": "PASS",
    }
    if unsigned["production_claim"]:
        unsigned.update(
            {
                "runtime_composition_digest": "c" * 64,
                "production_composition_manifest_digest": "d" * 64,
                "launcher_digest": "e" * 64,
                "authority_profile": "native-production",
                "authority_proof_identity": {
                    "socket_path": "/run/khaos-authorityd/authorityd.sock",
                    "socket_owner_uid": 10003,
                    "public_key_digest": "f" * 64,
                    "authority_profile": "native-production",
                },
                "authority_proof_digest": canonical_digest(
                    {
                        "socket_path": "/run/khaos-authorityd/authorityd.sock",
                        "socket_owner_uid": 10003,
                        "public_key_digest": "f" * 64,
                        "authority_profile": "native-production",
                    }
                ),
                "host_backend_absent": True,
                "dev_fallback_absent": True,
            }
        )
    unsigned["evidence_digest"] = canonical_digest(unsigned)
    if proof_type == "production_composition":
        prefix = "production-composition-proof"
    elif proof_type in {"process_tree_escape", "resource_owner_closure"}:
        prefix = "production-lifecycle"
    else:
        prefix = proof_type
    files = {
        f"proof-{proof_type}.json": json.dumps(unsigned, sort_keys=True).encode(),
        f"junit-{prefix}.xml": junit,
        f"stdout-{prefix}.log": stdout,
        f"stderr-{prefix}.log": stderr,
    }
    if proof_type == "production_composition":
        files = {
            "production-composition-proof.json": files[f"proof-{proof_type}.json"],
            "production-composition-proof.junit.xml": junit,
            "production-composition-proof.stdout.log": stdout,
            "production-composition-proof.stderr.log": stderr,
        }
    elif proof_type in {"process_tree_escape", "resource_owner_closure"}:
        files = {
            f"production-{proof_type.replace('_', '-')}-proof.json": files[f"proof-{proof_type}.json"],
            "production-lifecycle.junit.xml": junit,
            "production-lifecycle.stdout.log": stdout,
            "production-lifecycle.stderr.log": stderr,
        }
    return unsigned, files


def _archive(files: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, value in sorted(files.items()):
            archive.writestr(name, value)
    return output.getvalue()


def _fixture(
    *,
    mutate: Callable[[dict[str, object]], None] | None = None,
    duplicate: bool = False,
    expired: bool = False,
    bad_artifact_digest: bool = False,
    rewrite_local: bool = False,
) -> tuple[dict[str, object], dict[str, bytes]]:
    proof_values: dict[str, dict[str, object]] = {}
    grouped: dict[str, dict[str, bytes]] = {
        "ordinary": {},
        "production_composition": {},
        "lifecycle": {},
    }
    for proof_type in COMMUNITY_LOCAL_REQUIRED_PROOFS:
        proof, files = _proof(proof_type)
        if mutate is not None and proof_type == "community_authority":
            mutate(proof)
            unsigned = dict(proof)
            unsigned.pop("evidence_digest", None)
            proof["evidence_digest"] = canonical_digest(unsigned)
            proof_files = [name for name in files if name.startswith("proof-")]
            files[proof_files[0]] = json.dumps(proof, sort_keys=True).encode()
        proof_values[proof_type] = proof
        if proof_type == "production_composition":
            key = "production_composition"
        elif proof_type in {"process_tree_escape", "resource_owner_closure"}:
            key = "lifecycle"
        else:
            key = "ordinary"
        grouped[key].update(files)
    if duplicate:
        grouped["ordinary"]["proof-duplicate.json"] = grouped["ordinary"][
            "proof-community_authority.json"
        ]
    archives = {key: _archive(files) for key, files in grouped.items()}
    artifact_ids = {"ordinary": 1, "production_composition": 2, "lifecycle": 3}
    artifacts: list[dict[str, object]] = []
    artifact_names: dict[str, str] = {}
    for key, archive in archives.items():
        name = MODULE.PRODUCER_ARTIFACTS[key].format(COMMIT)
        artifact_names[key] = name
        digest = hashlib.sha256(archive).hexdigest()
        if bad_artifact_digest and key == "ordinary":
            digest = "0" * 64
        artifacts.append(
            {
                "id": artifact_ids[key],
                "name": name,
                "expired": expired and key == "ordinary",
                "digest": f"sha256:{digest}",
                "workflow_run": {"id": RUN_ID},
            }
        )
    local_payloads: list[dict[str, object]] = []
    for proof_type in COMMUNITY_LOCAL_REQUIRED_PROOFS:
        if proof_type == "production_composition":
            key = "production_composition"
        elif proof_type in {"process_tree_escape", "resource_owner_closure"}:
            key = "lifecycle"
        else:
            key = "ordinary"
        producer = proof_values[proof_type]
        local_payloads.append(
            {
                "name": proof_type,
                "proof_type": proof_type,
                "status": "PASS",
                "profile": "community-local",
                "commit": COMMIT,
                "policy_digest": POLICY,
                "artifact_digest": hashlib.sha256(archives[key]).hexdigest(),
                "producer_artifact_name": artifact_names[key],
                "producer_evidence_digest": (
                    "0" * 64 if rewrite_local and proof_type == "community_authority" else producer["evidence_digest"]
                ),
                "provenance": producer["workflow"],
            }
        )
    jobs = [
        {
            "id": 101,
            "name": "community-local-producers",
            "status": "completed",
            "conclusion": "success",
            "workflow_name": "Security Closure Gate",
        },
        {
            "id": 102,
            "name": "docker-security / compose-deployment",
            "status": "completed",
            "conclusion": "success",
            "workflow_name": "Security Closure Gate",
        },
    ]
    security_record = {
        "run_id": RUN_ID,
        "workflow_name": "Security Closure Gate",
        "artifacts": artifacts,
    }
    local_record = {"local_proof": {"proof_payloads": local_payloads}}
    return {
        "security_record": security_record,
        "local_record": local_record,
        "jobs": jobs,
    }, {str(artifact_ids[key]): archive for key, archive in archives.items()}


def _run_fixture(monkeypatch: pytest.MonkeyPatch, fixture: tuple[dict[str, object], dict[str, bytes]]) -> list[dict[str, Any]]:
    records, payloads = fixture
    monkeypatch.setattr(
        MODULE,
        "_run_gh_api",
        lambda _repo, endpoint: {"jobs": records["jobs"]}
        if endpoint.endswith("/jobs?per_page=100")
        else {},
    )
    monkeypatch.setattr(
        MODULE,
        "gh_api_bytes",
        lambda _repo, endpoint, **_kwargs: payloads[endpoint.split("/")[2]],
    )
    return MODULE._verify_external_producers(
        "hrrrb408/Khaos-Agent",
        security_record=records["security_record"],
        local_record=records["local_record"],
        commit=COMMIT,
    )


def test_all_external_producers_are_live_verified(monkeypatch: pytest.MonkeyPatch) -> None:
    results = _run_fixture(monkeypatch, _fixture())
    assert len(results) == 10
    assert {result["proof_type"] for result in results} == set(COMMUNITY_LOCAL_REQUIRED_PROOFS)


def test_external_provenance_cannot_be_injected_at_the_gate_record_root(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture()
    records, _payloads = fixture
    local_record = records["local_record"]
    assert isinstance(local_record, dict)
    local_binding = local_record.pop("local_proof")
    assert isinstance(local_binding, dict)
    local_record["proof_payloads"] = local_binding["proof_payloads"]

    with pytest.raises(RuntimeError, match="live proof provenance binding"):
        _run_fixture(monkeypatch, fixture)


def test_duplicate_reusable_producer_jobs_are_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture()
    records, _payloads = fixture
    jobs = records["jobs"]
    assert isinstance(jobs, list)
    jobs.append(
        {
            "id": 103,
            "name": "docker-security / compose-deployment",
            "status": "completed",
            "conclusion": "success",
            "workflow_name": "Security Closure Gate",
        }
    )

    with pytest.raises(RuntimeError, match="compose-deployment.*not unique"):
        _run_fixture(monkeypatch, fixture)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda proof: proof.update({"commit": "f" * 40}),
        lambda proof: proof["workflow"].update({"event": "pull_request"}),
        lambda proof: proof["workflow"].update({"run_attempt": 2}),
        lambda proof: proof["workflow"].update({"job": "wrong-producer-job"}),
        lambda proof: proof["workflow"].update({"workflow": "Wrong Workflow"}),
    ],
    ids=["wrong-sha", "pr-run", "attempt-two", "wrong-job", "wrong-workflow"],
)
def test_external_producer_identity_mutations_are_rejected(
    monkeypatch: pytest.MonkeyPatch,
    mutate: Callable[[dict[str, object]], None],
) -> None:
    with pytest.raises(RuntimeError):
        _run_fixture(monkeypatch, _fixture(mutate=mutate))


@pytest.mark.parametrize(
    "kwargs",
    [
        {"duplicate": True},
        {"expired": True},
        {"bad_artifact_digest": True},
        {"rewrite_local": True},
    ],
    ids=["duplicate-proof", "stale-artifact", "digest-mismatch", "local-rewrite"],
)
def test_external_producer_integrity_mutations_are_rejected(
    monkeypatch: pytest.MonkeyPatch, kwargs: dict[str, object]
) -> None:
    with pytest.raises(RuntimeError):
        _run_fixture(monkeypatch, _fixture(**kwargs))
