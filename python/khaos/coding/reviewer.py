"""Deterministic read-only ChangeSet reviewer."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ReviewReport:
    conclusion: str
    findings: tuple[str, ...]
    read_only: bool = True


class ReadOnlyReviewer:
    """Review diff text without exposing write capabilities."""

    def review(self, *, goal: str, patch: str, verification_passed: bool) -> ReviewReport:
        findings: list[str] = []
        if not verification_passed:
            findings.append("verification did not pass")
        if "rm -rf" in patch or "skip" in patch.lower() and "test" in patch.lower():
            findings.append("potentially unsafe or test-bypassing change")
        if not patch.strip():
            findings.append("empty changeset")
        conclusion = "approved" if not findings else "changes-requested"
        return ReviewReport(conclusion, tuple(findings))
