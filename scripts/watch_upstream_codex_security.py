#!/usr/bin/env python3
"""Produce a review-only semantic watch report for upstream Codex.

This tool reads commit metadata and changed paths from a blobless mirror.  It
never copies, applies, checks out, or synchronizes upstream source.  A report
is a review candidate only; a human must decide whether Khaos has a matching
attack surface and implement an independent fix.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

UPSTREAM = "https://github.com/openai/codex"
SECURITY_PATH_PREFIXES = (
    "codex-rs/core/src/tools/",
    "codex-rs/core/src/exec",
    "codex-rs/core/src/sandbox",
    "codex-rs/protocol/",
    "codex-rs/app-server-protocol/",
    "codex-rs/app-server/",
    "codex-rs/exec-server/",
    "codex-rs/sandboxing/",
    "codex-rs/linux-sandbox/",
    "codex-rs/windows-sandbox-rs/",
    ".github/workflows/",
)
SECURITY_KEYWORDS = (
    "sandbox",
    "permission",
    "approval",
    "security",
    "exec",
    "protocol",
    "credential",
    "isolation",
    "escape",
)


def run_git(mirror: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(mirror), *args],
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )
    return result.stdout


def remote_head(url: str) -> str:
    result = subprocess.run(
        ["git", "ls-remote", url, "HEAD"],
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )
    fields = result.stdout.split()
    value = fields[0] if fields else ""
    if len(value) != 40 or any(character not in "0123456789abcdef" for character in value):
        raise RuntimeError("upstream HEAD is not a full hexadecimal commit")
    return value


def _security_path(path: str) -> bool:
    return path.startswith(SECURITY_PATH_PREFIXES)


def _security_subject(subject: str) -> bool:
    lowered = subject.lower()
    return any(keyword in lowered for keyword in SECURITY_KEYWORDS)


def parse_log(output: str) -> list[dict[str, Any]]:
    """Parse ``git log --name-only`` metadata without reading blobs."""
    commits: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if "\x1f" in line:
            sha, subject = line.split("\x1f", 1)
            current = {"sha": sha, "subject": subject, "paths": []}
            commits.append(current)
        elif current is not None and line:
            current["paths"].append(line)
    return commits


def semantic_candidates(commits: list[dict[str, Any]]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for commit in commits:
        paths = sorted({str(path) for path in commit.get("paths", [])})
        relevant_paths = [path for path in paths if _security_path(path)]
        subject = str(commit.get("subject", ""))
        subject_relevant = _security_subject(subject)
        if not relevant_paths and not subject_relevant:
            continue
        reasons = []
        if relevant_paths:
            reasons.append("security-relevant path")
        if subject_relevant:
            reasons.append("security-relevant commit subject")
        candidates.append(
            {
                "commit": str(commit.get("sha", "")),
                "subject": subject,
                "relevant_paths": relevant_paths,
                "reason": ", ".join(reasons),
                "review_questions": [
                    "Does this change alter an OS-enforced execution or approval boundary?",
                    "Does Khaos have the same operation, protocol, or lifecycle attack surface?",
                    "If yes, can the Khaos negative test reproduce the precondition and prove the postcondition?",
                ],
            }
        )
    return candidates


def build_report(
    *, baseline_sha: str, head_sha: str, commits: list[dict[str, Any]], source: str
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "upstream": UPSTREAM,
        "baseline_sha": baseline_sha,
        "head_sha": head_sha,
        "source": source,
        "review_only": True,
        "auto_sync": False,
        "source_copy_or_apply": False,
        "candidates": semantic_candidates(commits),
        "limitations": [
            "This report contains commit/path metadata only; it is not a source diff.",
            "A human must review the candidate and implement any Khaos change independently.",
            "An empty candidate list means no matching metadata was observed, not that Khaos is secure.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mirror", type=Path)
    parser.add_argument("--url", default=UPSTREAM)
    parser.add_argument("--baseline-sha", required=True)
    parser.add_argument("--head-sha")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    head_sha = args.head_sha or remote_head(args.url)
    commits: list[dict[str, Any]] = []
    source = "remote HEAD only; no mirror supplied"
    if args.mirror is not None:
        output = run_git(
            args.mirror,
            "log",
            "--no-renames",
            "--format=%H%x1f%s",
            "--name-only",
            f"{args.baseline_sha}..{head_sha}",
        )
        commits = parse_log(output)
        source = f"blobless git mirror: {args.mirror}"
    report = build_report(
        baseline_sha=args.baseline_sha,
        head_sha=head_sha,
        commits=commits,
        source=source,
    )
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output is not None and not args.check:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    if args.check:
        if report["review_only"] is not True or report["auto_sync"] is not False:
            print("upstream watch is not review-only", file=sys.stderr)
            return 1
    else:
        sys.stdout.write(encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
