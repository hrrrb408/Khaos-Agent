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
    fragment.write_text(json.dumps(_fragment()), encoding="utf-8")

    module.final_artifact(argparse.Namespace(
        fragment=str(fragment), commit="a" * 40, output=str(output)
    ))

    evidence = json.loads(output.read_text(encoding="utf-8"))
    assert evidence["commit"] == "a" * 40
    assert evidence["production_mode"] is True
    assert evidence["python_uid"] == 1001
    assert evidence["python_cap_eff"] == "0000000000000000"
    assert evidence["host_fallback"] is False
    assert evidence["browser_helper_authenticated"] is True
    assert set(evidence["tests"].values()) == {"blocked"}


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

    with pytest.raises(RuntimeError):
        module.final_artifact(argparse.Namespace(
            fragment=str(fragment), commit="a" * 40,
            output=str(tmp_path / "evidence.json"),
        ))
