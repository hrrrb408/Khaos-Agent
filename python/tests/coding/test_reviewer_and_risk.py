from khaos.coding.reviewer import ReadOnlyReviewer
from khaos.coding.workspace.risk import assess_patch


def test_reviewer_is_read_only_and_requests_changes_for_failed_verification():
    report = ReadOnlyReviewer().review(goal="fix bug", patch="diff --git a/test.py b/test.py", verification_passed=False)
    assert report.read_only is True
    assert report.conclusion == "changes-requested"


def test_risk_report_flags_sensitive_files():
    report = assess_patch("+new content", (".github/workflows/ci.yml",))
    assert report.level == "critical"
    assert report.reasons
