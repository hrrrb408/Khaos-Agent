#!/usr/bin/env python3
"""Render the profile-aware Community Local security closure report.

The command is intentionally a consumer of evidence. It has no manual status
switch and rejects evidence that contains a pre-computed closure status. A
local test artifact can therefore produce a diagnostic
``NOT_CLOSED`` report, but it cannot manufacture release closure without the
separately verified exact-main GitHub provenance record.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from khaos.security.local_closure import (
    ClosureDecision,
    ClosureEvidence,
    LocalClosureStatus,
    LocalEvidenceError,
    LocalSecurityProfile,
    VerifiedGitHubProvenance,
    evaluate_local_security_closure,
    normalize_profile,
)


def _current_commit(repo_root: Path) -> str:
    return subprocess.check_output(
        ["git", "-C", str(repo_root), "rev-parse", "HEAD"],
        text=True,
    ).strip()


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LocalEvidenceError(f"cannot read JSON evidence {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise LocalEvidenceError(f"evidence {path} must contain a JSON object")
    return value


def _live_github_provenance(
    *,
    profile: LocalSecurityProfile,
    commit: str,
    repository: str,
) -> VerifiedGitHubProvenance:
    """Ask the live release verifier for a non-serializable capability."""
    scripts_dir = str(Path(__file__).resolve().parent)
    if scripts_dir not in sys.path:
        sys.path.insert(0, scripts_dir)
    from verify_release_gate_runs import verify_release_gates_for_closure

    return verify_release_gates_for_closure(
        repository,
        commit,
        profile=profile.value,
    )


def _decision_without_evidence(
    profile: LocalSecurityProfile,
    commit: str,
    *,
    reason: str,
) -> ClosureDecision:
    return ClosureDecision(
        profile=profile,
        commit=commit,
        status=LocalClosureStatus.NOT_CLOSED,
        satisfied_requirements=(),
        missing_requirements=(reason,),
        rejected_evidence=(),
        residual_risks=(),
    )


def _render(
    decision: ClosureDecision,
    *,
    evidence: ClosureEvidence | None,
    provenance_errors: tuple[str, ...],
    evidence_error: str = "",
) -> str:
    lines = [
        "# Khaos Community Local Security Profile",
        "",
        f"Status: {decision.status.value}",
        f"Profile: {decision.profile.value}",
        f"Commit: {decision.commit}",
        f"Evidence digest: {decision.evidence_digest or 'UNAVAILABLE'}",
        f"Provenance verified: {'YES' if decision.provenance is not None else 'NO'}",
        "",
        "## Closure decision",
        "",
        "### Satisfied requirements",
        "",
    ]
    lines.extend(f"- `{item}`" for item in decision.satisfied_requirements or ("none",))
    lines.extend(["", "### Blockers", ""])
    blockers = (*decision.missing_requirements, *decision.rejected_evidence, *provenance_errors)
    if evidence_error:
        blockers = (*blockers, evidence_error)
    lines.extend(f"- `{item}`" for item in blockers or ("none",))
    lines.extend(["", "## Profile status", ""])
    status = evidence.profile_status if evidence is not None else {}
    lines.extend(
        [
            f"- Apple Developer Program: `{status.get('apple_developer_program', 'NOT_APPLICABLE')}`",
            f"- Apple Team ID: `{status.get('apple_team_id', 'NOT_APPLICABLE')}`",
            f"- Signed XPC: `{status.get('signed_xpc', 'NOT_APPLICABLE')}`",
            f"- Notarization: `{status.get('notarization', 'NOT_APPLICABLE')}`",
            f"- macOS Signed Distribution: `{status.get('macos_signed_distribution', 'OPTIONAL_PROFILE_NOT_ENABLED')}`",
            f"- Hostile same-UID isolation: `{status.get('hostile_same_uid_isolation', 'NOT_CLAIMED')}`",
            f"- Second-maintainer independent review: `{status.get('independent_review', 'NOT_CLAIMED')}`",
        ]
    )
    lines.extend(["", "## Remaining residual risks", ""])
    lines.extend(f"- {risk}" for risk in (evidence.residual_risks if evidence else ("exact CI evidence is unavailable",)))
    lines.extend(
        [
            "",
            "This report is generated from typed evidence and exact provenance; it is not a handwritten status artifact.",
            "",
        ]
    )
    return "\n".join(lines)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--profile", default="community-local")
    parser.add_argument("--commit", default="")
    parser.add_argument(
        "--evidence",
        "--evidence-manifest",
        dest="evidence",
        type=Path,
        default=None,
    )
    parser.add_argument(
        "--github-repository",
        default="",
        help="query this GitHub repository live for exact release provenance",
    )
    parser.add_argument("--output", type=Path, default=None)
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    try:
        profile = normalize_profile(args.profile)
        head = _current_commit(args.repo_root)
        commit = args.commit or head
        if commit != head:
            raise LocalEvidenceError(
                f"evaluated commit {commit} is not the current exact HEAD {head}"
            )
        evidence: ClosureEvidence | None = None
        evidence_error = ""
        if args.evidence is None:
            decision = _decision_without_evidence(
                profile,
                commit,
                reason="CLOSURE_PENDING_EXACT_SHA_CI_EVIDENCE",
            )
        else:
            try:
                evidence = ClosureEvidence.from_payload(_load_json(args.evidence))
                if evidence.profile is not profile:
                    raise LocalEvidenceError("evidence profile does not match --profile")
            except (LocalEvidenceError, OSError) as exc:
                evidence_error = str(exc)
                decision = _decision_without_evidence(
                    profile, commit, reason="REJECTED_LOCAL_SECURITY_EVIDENCE"
                )
        provenance_errors: tuple[str, ...] = ()
        provenance: VerifiedGitHubProvenance | None = None
        if evidence is not None and args.github_repository:
            try:
                provenance = _live_github_provenance(
                    profile=profile,
                    commit=commit,
                    repository=args.github_repository,
                )
            except (LocalEvidenceError, OSError, RuntimeError, ValueError) as exc:
                provenance_errors = (
                    "CLOSURE_PENDING_EXACT_SHA_CI_EVIDENCE: " + str(exc),
                )
        elif evidence is not None:
            provenance_errors = ("CLOSURE_PENDING_EXACT_SHA_CI_EVIDENCE",)
        if evidence is not None:
            decision = evaluate_local_security_closure(
                evidence,
                expected_commit=commit,
                provenance=provenance,
            )
        report = _render(
            decision,
            evidence=evidence,
            provenance_errors=provenance_errors,
            evidence_error=evidence_error,
        )
        if args.output is not None:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(report, encoding="utf-8")
        else:
            print(report)
        return 0 if decision.status is LocalClosureStatus.CLOSED else 1
    except (LocalEvidenceError, OSError, subprocess.CalledProcessError) as exc:
        report = _render(
            _decision_without_evidence(
                normalize_profile(getattr(args, "profile", "community-local")),
                getattr(args, "commit", "") or "UNKNOWN",
                reason="REJECTED_CLOSURE_INPUT",
            ),
            evidence=None,
            provenance_errors=(),
            evidence_error=str(exc),
        )
        if getattr(args, "output", None) is not None:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(report, encoding="utf-8")
        else:
            print(report)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
