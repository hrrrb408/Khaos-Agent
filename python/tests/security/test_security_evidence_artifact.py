"""Security Closure evidence artifact contract tests."""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts" / "build_security_closure_evidence.py"


def _module():
    specification = importlib.util.spec_from_file_location(
        "security_closure_evidence", SCRIPT
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _fragment() -> dict[str, object]:
    return {
        "commit": "a" * 40,
        "run_id": "run-1",
        "job": "browser-non-root-fullstack",
        "production_mode": True,
        "python_uid": 1001,
        "python_cap_eff": "0000000000000000",
        "host_fallback": False,
        "browser_helper_authenticated": True,
        "policy_digest": "1" * 64,
        "schema_digest": "2" * 64,
        "launcher_digest": "3" * 64,
        "helper_digest": "4" * 64,
    }


def test_final_artifact_has_exact_required_evidence(tmp_path: Path):
    module = _module()
    fragment = tmp_path / "fragment.json"
    output = tmp_path / "evidence.json"
    fragments = tmp_path / "test-fragments"
    fragments.mkdir()
    fragment.write_text(json.dumps(_fragment()), encoding="utf-8")
    for name in module.REQUIRED_TESTS:
        module.test_fragment(
            argparse.Namespace(
                commit="a" * 40,
                run_id="run-1",
                job=f"job-{name}",
                test=name,
                result="blocked",
                runner_os="Linux",
                production_mode="true",
                output=str(fragments / f"{name}.json"),
            )
        )

    module.final_artifact(argparse.Namespace(
        fragment=str(fragment), fragments_dir=str(fragments),
        commit="a" * 40, output=str(output)
    ))

    evidence = json.loads(output.read_text(encoding="utf-8"))
    assert evidence["commit"] == "a" * 40
    assert evidence["production_mode"] is True
    assert evidence["python_uid"] == 1001
    assert evidence["python_cap_eff"] == "0000000000000000"
    assert evidence["host_fallback"] is False
    assert evidence["browser_helper_authenticated"] is True
    assert set(evidence["tests"]) == set(module.REQUIRED_TESTS)
    assert {item["result"] for item in evidence["tests"].values()} == {"blocked"}
    assert all(len(item["digest"]) == 64 for item in evidence["tests"].values())


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("python_uid", 0),
        ("python_cap_eff", "0000000000200000"),
        ("host_fallback", True),
        ("browser_helper_authenticated", False),
    ),
)
def test_final_artifact_rejects_privileged_or_fallback_evidence(
    tmp_path: Path, field: str, value: object,
):
    module = _module()
    payload = _fragment()
    payload[field] = value
    fragment = tmp_path / "fragment.json"
    fragment.write_text(json.dumps(payload), encoding="utf-8")
    fragments = tmp_path / "fragments"
    fragments.mkdir()

    with pytest.raises(RuntimeError):
        module.final_artifact(argparse.Namespace(
            fragment=str(fragment), commit="a" * 40,
            fragments_dir=str(fragments),
            output=str(tmp_path / "evidence.json"),
        ))


def test_final_artifact_rejects_missing_or_forged_test_evidence(tmp_path: Path):
    module = _module()
    browser = tmp_path / "browser.json"
    browser.write_text(json.dumps(_fragment()), encoding="utf-8")
    fragments = tmp_path / "fragments"
    fragments.mkdir()
    module.test_fragment(
        argparse.Namespace(
            commit="a" * 40,
            run_id="run-1",
            job="schema-job",
            test="schema_injection",
            result="blocked",
            runner_os="Linux",
            production_mode="true",
            output=str(fragments / "schema.json"),
        )
    )
    forged = json.loads((fragments / "schema.json").read_text(encoding="utf-8"))
    forged["job"] = "forged-job"
    (fragments / "schema.json").write_text(json.dumps(forged), encoding="utf-8")

    with pytest.raises(RuntimeError, match="provenance invalid"):
        module.final_artifact(
            argparse.Namespace(
                fragment=str(browser),
                fragments_dir=str(fragments),
                commit="a" * 40,
                output=str(tmp_path / "evidence.json"),
            )
        )
