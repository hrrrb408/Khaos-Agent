#!/usr/bin/env python3
"""Run the non-production Community Local proof producers.

This command belongs to the Security Closure Gate, not to the Community Local
workflow.  Each record is derived from the pytest process and its JUnit file;
the caller cannot provide a result, a production flag, or provenance.
Production composition, process-tree, and resource-owner proofs are emitted
by their real Docker production producer instead.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

from khaos.security.producer_evidence import (
    build_test_producer_proof,
    write_producer_proof,
)

PRODUCER_TESTS: dict[str, tuple[str, ...]] = {
    "community_authority": (
        "python/tests/security/test_local_trust.py",
        "python/tests/security/test_authority_transport.py",
        "python/tests/security/test_authorityd_protocol.py",
        "python/tests/security/test_post_m7_production_trust.py",
        "python/tests/security/test_identity_isolation.py",
    ),
    "platform_kernel": (
        "python/tests/security/test_identity_isolation.py",
        "python/tests/security/test_kernel_helper_client_round11.py",
    ),
    "production_reachability": (
        "python/tests/security/test_production_reachability.py",
    ),
    "workspace_escape": (
        "python/tests/security/test_path_guard.py",
        "python/tests/coding/test_safe_workspace_fs.py",
        "python/tests/coding/test_workspace_boundary.py",
        "python/tests/coding/test_workspace_artifact_boundary.py",
    ),
    "approval_replay": (
        "python/tests/tools/test_authorization_contract.py",
        "python/tests/tools/test_approval_callback_boundary.py",
        "python/tests/agent/test_approval_broker.py",
        "python/tests/agent/test_operation_approval_ledger.py",
    ),
    "approval_substitution": (
        "python/tests/tools/test_authorization_contract.py",
        "python/tests/tools/test_approval_callback_boundary.py",
        "python/tests/tools/test_scheduler_boundaries.py",
        "python/tests/tools/test_execution_coordinator_boundary.py",
    ),
    "network_isolation": (
        "python/tests/security/test_network_guard.py",
        "python/tests/security/test_network_broker.py",
        "python/tests/tools/test_network_authority_integration.py",
        "python/tests/security/test_host_network_authority.py",
    ),
}


def _args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    return parser.parse_args()


def _write_timeout_junit(path: Path, detail: str) -> None:
    suite = ET.Element(
        "testsuite",
        {"name": "producer-timeout", "tests": "1", "errors": "1"},
    )
    ET.SubElement(suite, "error", {"message": detail})
    ET.ElementTree(suite).write(path, encoding="utf-8", xml_declaration=True)


def _run_one(repo_root: Path, output_dir: Path, name: str, tests: tuple[str, ...], commit: str) -> bool:
    with tempfile.TemporaryDirectory(prefix=f"khaos-producer-{name}-") as temporary:
        temporary_root = Path(temporary)
        junit = temporary_root / "results.xml"
        stdout = temporary_root / "stdout.log"
        stderr = temporary_root / "stderr.log"
        command = [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "-v",
            "--junitxml",
            str(junit),
            *tests,
        ]
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(repo_root / "python")
        try:
            with stdout.open("w", encoding="utf-8") as stdout_stream, stderr.open(
                "w", encoding="utf-8"
            ) as stderr_stream:
                completed = subprocess.run(
                    command,
                    cwd=repo_root,
                    env=environment,
                    stdout=stdout_stream,
                    stderr=stderr_stream,
                    check=False,
                    timeout=900,
                )
            returncode = completed.returncode
        except subprocess.TimeoutExpired as exc:
            returncode = 124
            _write_timeout_junit(junit, "pytest producer exceeded 900 second deadline")
            stdout.write_text(str(exc), encoding="utf-8")
            stderr.write_text("pytest producer timeout", encoding="utf-8")
        if not junit.is_file():
            _write_timeout_junit(junit, "pytest did not produce JUnit diagnostics")
        proof = build_test_producer_proof(
            proof_name=name,
            commit=commit,
            repo_root=repo_root,
            junit=junit,
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
        )
        diagnostics = proof["diagnostics"]
        assert isinstance(diagnostics, dict)
        output_dir.mkdir(parents=True, exist_ok=True)
        write_producer_proof(output_dir / f"proof-{name}.json", proof)
        (output_dir / f"diagnostics-{name}.json").write_text(
            json.dumps(diagnostics, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        shutil.copyfile(junit, output_dir / f"junit-{name}.xml")
        shutil.copyfile(stdout, output_dir / f"stdout-{name}.log")
        shutil.copyfile(stderr, output_dir / f"stderr-{name}.log")
        output = stdout.read_text(encoding="utf-8", errors="replace")
        error_output = stderr.read_text(encoding="utf-8", errors="replace")
        print(
            "producer proof "
            f"{name}: result={proof['result']} returncode={diagnostics['returncode']} "
            f"tests={diagnostics['test_count']} passed={diagnostics['passed']} "
            f"skipped={diagnostics['skipped']} failed={diagnostics['failed']} "
            f"errors={diagnostics['errors']}"
        )
        for label, values in (
            ("skipped test", diagnostics.get("skipped_reasons", [])),
            ("failing test", diagnostics.get("failure_details", [])),
            ("error", diagnostics.get("error_details", [])),
        ):
            for value in values:
                print(f"{name} {label}: {value}")
        if returncode != 0 and error_output.strip():
            print(f"{name} stderr: {error_output[-2000:]}", file=sys.stderr)
        if returncode != 0 and output.strip():
            print(f"{name} stdout: {output[-2000:]}", file=sys.stderr)
        return proof["result"] == "PASS"


def main() -> int:
    args = _args()
    repo_root = args.repo_root.resolve()
    output_dir = args.output_dir.resolve()
    failed = False
    for name, tests in PRODUCER_TESTS.items():
        if not _run_one(repo_root, output_dir, name, tests, args.commit):
            failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
