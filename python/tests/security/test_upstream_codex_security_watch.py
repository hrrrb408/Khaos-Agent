"""The Codex watch is metadata-only and cannot become a sync mechanism."""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts" / "watch_upstream_codex_security.py"


def _module():
    spec = importlib.util.spec_from_file_location("codex_watch", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_only_security_paths_or_security_subjects_become_candidates():
    module = _module()
    commits = [
        {"sha": "a" * 40, "subject": "docs: update prose", "paths": ["docs/README.md"]},
        {"sha": "b" * 40, "subject": "fix: sandbox escape", "paths": ["docs/README.md"]},
        {"sha": "c" * 40, "subject": "refactor", "paths": ["codex-rs/linux-sandbox/src/lib.rs"]},
    ]
    candidates = module.semantic_candidates(commits)
    assert [item["commit"] for item in candidates] == ["b" * 40, "c" * 40]


def test_report_is_explicitly_review_only():
    module = _module()
    report = module.build_report(
        baseline_sha="a" * 40,
        head_sha="b" * 40,
        commits=[],
        source="fixture",
    )
    assert report["review_only"] is True
    assert report["auto_sync"] is False
    assert report["source_copy_or_apply"] is False
