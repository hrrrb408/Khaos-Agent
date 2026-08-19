#!/usr/bin/env python3
"""Build the M6.9 security closure report from a VERIFIED evidence bundle.

This builder accepts exactly one trust input: ``--evidence-manifest``,
a bundle previously produced by ``verify_security_evidence.py``.  The
bundle is integrity-checked and every embedded manifest is re-verified
against the expected repository, the exact release commit, and the
release policy digest.  Arbitrary local files, CI run id strings, and
CLI booleans are not accepted as closure evidence; without a verified
bundle the report is ``NOT CLOSED (evidence incomplete)``.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from khaos.security.security_evidence import (
    REQUIRED_PROOF_TYPES,
    SecurityEvidenceManifest,
    load_verified_bundle,
    verify_evidence_manifests,
)

ROOT = Path(__file__).resolve().parents[1]

CLOSURE_CRITERIA = (
    ("Linux Security Closure Gate success on exact SHA", "security-closure-gate"),
    ("Product Integrity Gate success on exact SHA", "product-integrity-gate"),
    ("Linux real-kernel evidence on exact SHA", "linux-real-kernel"),
    ("macOS real native authority evidence on exact SHA", "macos-native-authority"),
    ("Windows real native authority evidence on exact SHA", "windows-native-authority"),
    ("Resource-owner terminal proof", "resource-owner-proof"),
    ("Exact-effect proof", "exact-effect-proof"),
)


def _git_head() -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return "unknown"
    return result.stdout.strip()


def render(
    *,
    commit: str,
    policy_digest: str,
    verified_bundle: dict | None,
    test_counts: str = "not-provided",
) -> str:
    status = "NOT CLOSED (evidence incomplete)"
    satisfied: list[tuple[str, bool, str]] = []
    if verified_bundle is not None:
        manifests = [
            SecurityEvidenceManifest.from_payload(payload)
            for payload in verified_bundle["manifests"]
        ]
        verification = verify_evidence_manifests(
            manifests,
            expected_commit=commit,
            expected_policy_digest=policy_digest,
        )
        present = verification.proof_types
        if verification.ok:
            status = "CLOSED"
        else:
            status = "NOT CLOSED (evidence rejected)"
        for label, proof_type in CLOSURE_CRITERIA:
            satisfied.append((label, proof_type in present, proof_type))
    else:
        for label, proof_type in CLOSURE_CRITERIA:
            satisfied.append((label, False, proof_type))
    lines = [
        "# M6.9 Security Closure Report",
        "",
        f"Status: **{status}**",
        "",
        "This report is generated exclusively from cryptographically bound CI",
        "evidence.  Local files, CI run id strings, and CLI booleans cannot",
        "produce a CLOSED status.",
        "",
        f"- Exact commit: `{commit}`",
        f"- Release policy digest: `{policy_digest or 'UNKNOWN'}`",
        f"- Full test counts: `{test_counts}`",
        "",
        "## Closure criteria matrix",
        "",
        "| Criterion | Evidence type | Present |",
        "| --- | --- | --- |",
    ]
    for label, ok, proof_type in satisfied:
        lines.append(f"| {label} | `{proof_type}` | {'YES' if ok else 'NO'} |")
    lines.extend(
        [
            "",
            "## Required evidence types",
            "",
            ", ".join(f"`{proof_type}`" for proof_type in sorted(REQUIRED_PROOF_TYPES)),
            "",
            "Any missing, duplicate, wrong-platform, wrong-workflow, wrong-commit,",
            "or wrong-policy-digest evidence keeps this report NOT CLOSED.",
            "",
        ]
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-manifest", type=Path, default=None)
    parser.add_argument("--commit", default=_git_head())
    parser.add_argument("--policy-digest", default="")
    parser.add_argument("--test-counts", default="not-provided")
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args(argv)
    verified_bundle = None
    if args.evidence_manifest is not None:
        try:
            verified_bundle = load_verified_bundle(args.evidence_manifest)
        except Exception as exc:  # noqa: BLE001 - CLI must turn any failure into NOT CLOSED
            print(f"evidence bundle rejected: {exc}", file=sys.stderr)
            verified_bundle = None
    report = render(
        commit=args.commit,
        policy_digest=args.policy_digest,
        verified_bundle=verified_bundle,
        test_counts=args.test_counts,
    )
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(report, encoding="utf-8")
    else:
        sys.stdout.write(report)
    # A rejected bundle must never yield exit 0 for automation consumers.
    if args.evidence_manifest is not None and verified_bundle is None:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
