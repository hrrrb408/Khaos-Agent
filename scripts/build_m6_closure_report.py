#!/usr/bin/env python3
"""Build the evidence-bound M6 security closure report.

The default result is ``NOT CLOSED``.  ``CLOSED`` is intentionally
unreachable from local inputs: it requires a VERIFIED evidence manifest
bundle (``--evidence-manifest``) whose embedded manifests re-verify
against the exact release commit and the release policy digest, and
which contains every required proof type exactly once.  Arbitrary
local files, a CI run id string, and an ``--all-gates-success`` boolean
can no longer produce a closure claim — an unverified run id plus two
local files was previously accepted as closure evidence, which is
exactly the provenance gap M6.9 BATCH 5 closes.

Missing or unproven evidence remains ``UNKNOWN``/``QUARANTINED`` in the
report rather than becoming a green claim.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from khaos.security.security_evidence import (
    EXPECTED_REPOSITORY,
    SecurityEvidenceManifest,
    load_verified_bundle,
    verify_evidence_manifests,
    verify_manifests_against_github,
)
from khaos.security.evidence_provenance import (
    gh_fetch_artifact,
    gh_fetch_json,
)

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "docs" / "m6-security-closure-report.md"

FINDINGS = (
    {
        "id": "M6.1",
        "name": "Shell semantic authority",
        "root_cause": "Shell safety was previously inferred from token splitting and executable names.",
        "invariant": "Only a complete literal executable graph is SAFE; expansion or callback ambiguity requires approval.",
        "files": "python/khaos/security/shell_semantics.py; python/khaos/permissions; python/khaos/tools/terminal_tools.py",
        "before": "A shell expansion or callback could make the executed graph differ from the approved base command.",
        "after": "The immutable semantic AST binds expansions, pipelines, callbacks, redirections, and nested evaluators; unknown is not read-only.",
        "tests": "test_shell_semantics.py; M6 adversarial matrix",
        "evidence": "Local source-level; Linux/host execution remains CI-bound.",
        "limitations": "The parser is conservative and does not claim to be a shell interpreter.",
    },
    {
        "id": "M6.2",
        "name": "Native authority transports",
        "root_cause": "Native platforms lacked a production OS-owned authority transport with distinct identity proof.",
        "invariant": "Missing service identity, peer identity, protected key, or transport proof fails closed; no same-UID Python authority.",
        "files": "python/khaos/security/native_authority.py; packaging/macos; packaging/windows; rust/khaos-core/src/bin/khaos-authorityd-windows.rs",
        "before": "A platform adapter could be absent or simulated in the agent process.",
        "after": "macOS launchd/XPC and Windows Service-SID/Named Pipe contracts require external native proof and protected-key configuration.",
        "tests": "test_native_authority.py; cross-target Rust compile; native-authority-production-e2e.yml",
        "evidence": "Native E2E is CI/manual evidence and is UNKNOWN until real artifacts are supplied.",
        "limitations": "This workstation cannot produce hosted macOS/Windows service evidence.",
    },
    {
        "id": "M6.3",
        "name": "Pure TCB boundaries",
        "root_cause": "Protocol serialization, lifecycle transitions, and orchestration were distributed across stateful services.",
        "invariant": "Canonical serialization, schema validation, receipt transitions, owner transitions, and effect binding are pure typed functions.",
        "files": "python/khaos/security/protocol_boundary.py; docs/adr/ADR-021-pure-tcb-boundaries.md",
        "before": "Implicit object state could be mistaken for a valid receipt or closed resource.",
        "after": "Illegal transitions, unknown schema fields, and non-empty CLOSED ownership are rejected by pure boundary primitives.",
        "tests": "test_protocol_boundary.py with Hypothesis",
        "evidence": "Local property-based source-level evidence.",
        "limitations": "The external kernel/oracle portions remain platform CI responsibilities.",
    },
    {
        "id": "M6.4",
        "name": "Typed principal delegation",
        "root_cause": "Different ingress paths could converge on an underspecified principal identity.",
        "invariant": "Principal kind, parent, project, session, runtime, task, workspace, operation, resource, policy, expiry, and nonce stay bound; delegation is narrow-only.",
        "files": "python/khaos/security/principals.py; python/khaos/runtime/context.py; python/khaos/security/authorityd_protocol.py",
        "before": "A receipt or child task could be replayed across principals or sessions if only a principal id was checked.",
        "after": "Typed fields are carried through the receipt and execution plan; production authority rejects untyped or cross-session reuse.",
        "tests": "test_typed_principals.py; runtime and subagent regressions",
        "evidence": "Local authority protocol evidence.",
        "limitations": "A transport-root digest is an identity commitment, not a substitute for an external signed human delegation.",
    },
    {
        "id": "M6.5",
        "name": "Production reachability",
        "root_cause": "Manual inspection could miss a dev-only or host fallback reachable through a transitive import.",
        "invariant": "Generated production graph has no unresolved or forbidden edges from every composition root.",
        "files": "scripts/generate_production_reachability.py; docs/generated/production-reachability.md",
        "before": "A forbidden backend could be reachable even when no obvious direct call site used it.",
        "after": "The source-derived graph fails on unresolved modules or forbidden production targets.",
        "tests": "test_production_reachability.py; security-contract-matrix.yml",
        "evidence": "Generated local graph; exact-commit CI rerun required for release.",
        "limitations": "Static import reachability does not prove every runtime branch or kernel property.",
    },
    {
        "id": "M6.6",
        "name": "Release governance preparation",
        "root_cause": "The current repository has one maintainer and cannot truthfully claim independent review.",
        "invariant": "The hardened second-maintainer template requires approval, code-owner review, last-push approval, resolved threads, and both aggregate gates.",
        "files": ".github/CODEOWNERS; scripts/github-m6-hardened-ruleset.json; scripts/validate_m6_governance.py",
        "before": "A sole maintainer ruleset could not provide independent review evidence.",
        "after": "Security-critical ownership and a machine-validated hardened template are ready, while current evidence remains explicitly single-maintainer.",
        "tests": "test_m6_governance.py",
        "evidence": "Repository configuration preparation only; independent human review is external.",
        "limitations": "Do not enable the hardened template until a second authorized maintainer exists.",
    },
    {
        "id": "M6.7",
        "name": "Upstream Codex security watch",
        "root_cause": "The fixed upstream baseline was not automatically checked for new security-relevant metadata.",
        "invariant": "Watch output is review-only metadata; it cannot copy, apply, or synchronize upstream source.",
        "files": "scripts/watch_upstream_codex_security.py; .github/workflows/upstream-codex-security-watch.yml; docs/upstream-codex.md",
        "before": "A floating upstream HEAD could silently change the security comparison baseline.",
        "after": "The current SHA is fixed and the scheduled watcher emits semantic review candidates only.",
        "tests": "test_upstream_codex_security_watch.py",
        "evidence": "Remote metadata watch; candidate assessment is a human review step.",
        "limitations": "An empty candidate list is not a proof that Khaos is secure.",
    },
    {
        "id": "M6.8",
        "name": "Final adversarial closure",
        "root_cause": "Attack surfaces were covered by separate tests without one postcondition-oriented matrix.",
        "invariant": "SUCCESS requires exact effect; CLOSED requires independent terminal resource proof; otherwise state is failed, unknown, or quarantined.",
        "files": "python/tests/security/test_m6_adversarial_matrix.py; python/khaos/security/protocol_boundary.py",
        "before": "A return code or local object state could be mistaken for physical cleanup or exact effect.",
        "after": "The matrix checks negative postconditions across replay, mutation, path races, process, network, lifecycle, and fallback boundaries.",
        "tests": "M6 adversarial matrix plus existing real-kernel/resource-owner suites",
        "evidence": "Local matrix and CI-only kernel/native evidence are kept separate.",
        "limitations": "No local report may claim CLOSED without the required native and exact-commit CI artifacts.",
    },
    {
        "id": "M6.9",
        "name": "Real security closure",
        "root_cause": "Native frontends forwarded to backends that did not exist on macOS/Windows; the transport probe stood in for an E2E; proofs were static digests; delegation digests were caller-supplied; closure was a CLI attestation; git branch argv matched by name; native CI assumed state runners do not have.",
        "invariant": "Native authority proofs are signed challenge-responses bound to designated code requirements; delegations are authority-issued and one-shot; closure requires verified evidence manifests; SAFE argv semantics are proven, not name-matched.",
        "files": "ADR-022/023; authorityd.py; authorityd_windows.py; native_authority.py; principals.py; delegation_issuer.py; security_evidence.py; shell_semantics.py; native-authority-production-e2e.yml; production_composition_manifest.py",
        "before": "A transport probe, two local files, or a parent digest could all masquerade as security evidence.",
        "after": "Real frontend/backend chains, signed attestations, authority-owned delegation registry, provenance-verified closure, per-command argv proofs, real CI provisioning.",
        "tests": "test_native_authority_backend/attestation; test_delegation_authority_owned; test_security_evidence_provenance; test_argv_semantic_policy; test_windows_authority_lifecycle; test_production_composition_manifest; test_tcb_boundaries",
        "evidence": "Local fail-closed tests green; hosted macOS/Windows real E2E remains CI evidence (UNKNOWN until artifacts exist).",
        "limitations": "Native runners and release SHA evidence are external; this report stays NOT CLOSED without them.",
    },
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
    commit: str = "not-provided",
    ci_run: str = "not-provided",
    test_counts: str = "not-provided",
    native_evidence: tuple[str, ...] = (),
    all_gates_success: bool = False,
    evidence_bundle: dict | None = None,
    policy_digest: str = "",
    github_fetch_json: object = None,
    github_fetch_artifact: object = None,
) -> str:
    # CLOSED is reachable ONLY through a verified evidence bundle whose
    # embedded manifests re-verify against this exact commit and the
    # release policy digest AND whose runs/jobs/artifacts are re-resolved
    # against the live GitHub API.  Local files, run id strings, booleans,
    # and self-consistent local JSON are recorded but never treated as
    # proof: a bundle forged offline fails the GitHub recheck.
    closed = False
    evidence_status = "UNKNOWN (no verified evidence bundle provided)"
    if evidence_bundle is not None:
        try:
            manifests = [
                SecurityEvidenceManifest.from_payload(payload)
                for payload in evidence_bundle["manifests"]
            ]
            verification = verify_evidence_manifests(
                manifests,
                expected_commit=commit,
                expected_policy_digest=policy_digest,
            )
            if not verification.ok:
                evidence_status = (
                    "REJECTED: " + "; ".join(verification.errors[:5])
                )
            elif github_fetch_json is None or github_fetch_artifact is None:
                evidence_status = (
                    "REJECTED: GitHub provenance recheck unavailable "
                    "(closure requires live API re-verification of every run, job, and artifact)"
                )
            else:
                recheck = verify_manifests_against_github(
                    manifests,
                    fetch_json=github_fetch_json,
                    fetch_artifact=github_fetch_artifact,
                )
                if recheck.ok:
                    closed = True
                    evidence_status = "VERIFIED CI evidence bundle (GitHub-provenance rechecked)"
                else:
                    evidence_status = (
                        "REJECTED: " + "; ".join(recheck.errors[:5])
                    )
        except Exception as exc:  # noqa: BLE001 - any bundle failure stays NOT CLOSED
            evidence_status = f"REJECTED: {exc}"
    status = "CLOSED" if closed else "NOT CLOSED (evidence incomplete)"
    lines = [
        "# M6 Security Architecture Closure Report",
        "",
        f"Status: **{status}**",
        "",
        "This report is evidence-bound. A local green test run is not a closure claim.",
        "",
        f"- Exact commit: `{commit}`",
        f"- CI run evidence: `{ci_run}`",
        f"- Full test counts: `{test_counts}`",
        f"- Native evidence: `{', '.join(native_evidence) if native_evidence else 'UNKNOWN'}`",
        f"- All required gates explicitly successful: `{all_gates_success}`",
        f"- Verified evidence bundle: `{evidence_status}`",
        "",
        "## Finding closure matrix",
        "",
        "| Finding | Root cause | Invariant | Modified files | Exploit before | Why impossible after | Tests | Evidence / limitation |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for finding in FINDINGS:
        lines.append(
            "| {id} {name} | {root_cause} | {invariant} | `{files}` | {before} | {after} | `{tests}` | {evidence} {limitations} |".format(**finding)
        )
    lines.extend(
        [
            "",
            "## Evidence classification",
            "",
            "- **Local:** pure protocol, identity, parser, graph, and negative tests executed on this workstation.",
            "- **CI-only:** Linux namespaces/cgroups/nftables, Docker, full product matrices, and hosted platform tests.",
            "- **Native CI/manual:** real launchd/XPC and Windows Service-SID/Named Pipe artifacts; mock output is never accepted.",
            "- **Unknown/external:** independent human review, remote WORM audit, and any missing native artifact.",
            "",
            "The report must remain NOT CLOSED whenever an independent resource oracle, exact approved effect proof, native proof, or required CI run is missing.",
            "",
        ]
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    parser.add_argument("--commit", default=_git_head())
    parser.add_argument("--ci-run", default="not-provided")
    parser.add_argument("--test-counts", default="not-provided")
    parser.add_argument("--native-evidence", nargs="*", default=[])
    parser.add_argument("--all-gates-success", action="store_true")
    parser.add_argument("--check-template", action="store_true")
    parser.add_argument("--evidence-manifest", type=Path, default=None)
    parser.add_argument("--policy-digest", default="")
    args = parser.parse_args(argv)
    evidence_bundle = None
    if args.evidence_manifest is not None:
        try:
            evidence_bundle = load_verified_bundle(args.evidence_manifest)
        except Exception as exc:  # noqa: BLE001 - CLI reports rejection, not crash
            print(f"evidence bundle rejected: {exc}", file=sys.stderr)
    rendered = render(
        commit=args.commit,
        ci_run=args.ci_run,
        test_counts=args.test_counts,
        native_evidence=tuple(args.native_evidence),
        all_gates_success=args.all_gates_success,
        evidence_bundle=evidence_bundle,
        policy_digest=args.policy_digest,
        # Live-API recheck is mandatory whenever a bundle is offered: a
        # locally synthesized bundle must never reach CLOSED even when its
        # strings are perfectly self-consistent.
        github_fetch_json=(
            gh_fetch_json(EXPECTED_REPOSITORY) if evidence_bundle is not None else None
        ),
        github_fetch_artifact=(
            gh_fetch_artifact(EXPECTED_REPOSITORY) if evidence_bundle is not None else None
        ),
    )
    if args.check_template:
        if not TEMPLATE.is_file() or "Status: **NOT CLOSED" not in TEMPLATE.read_text(encoding="utf-8"):
            print("M6 report template must remain explicitly not closed", file=sys.stderr)
            return 1
        if any(marker not in rendered for marker in ("M6.1", "M6.8", "UNKNOWN", "CI-only")):
            print("M6 report is missing required evidence-bound sections", file=sys.stderr)
            return 1
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    if args.evidence_manifest is not None and evidence_bundle is None:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
