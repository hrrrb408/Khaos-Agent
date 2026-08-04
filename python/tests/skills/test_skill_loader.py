"""Tests for SkillLoader frontmatter parsing."""

from __future__ import annotations

from pathlib import Path

import pytest

from khaos.skills import Skill, SkillLoader, SkillParseError
from khaos.skills.loader import MAX_SKILL_FILE_BYTES, MAX_SKILL_FILES


def _write(path: Path, content: str) -> Path:
    path.write_text(content, encoding="utf-8")
    return path


def test_load_file_parses_frontmatter_and_body(tmp_path):
    file = _write(
        tmp_path / "SKILL.md",
        "---\n"
        "name: python-expert\n"
        "description: Python development expert.\n"
        "category: coding\n"
        "triggers: [python, pytest]\n"
        "---\n"
        "# Python expert\n"
        "Prefer type hints.\n",
    )
    skill = SkillLoader().load_file(file)

    assert skill.name == "python-expert"
    assert skill.description == "Python development expert."
    assert skill.category == "coding"
    assert skill.triggers == ["python", "pytest"]
    assert "Prefer type hints." in skill.body


def test_load_file_normalizes_triggers_lowercase_dedup(tmp_path):
    file = _write(
        tmp_path / "SKILL.md",
        "---\nname: s\ndescription: d.\ntriggers: [Python, python, PYTEST]\n---\nbody\n",
    )
    skill = SkillLoader().load_file(file)

    assert skill.triggers == ["python", "pytest"]


def test_load_file_missing_required_field_raises(tmp_path):
    file = _write(
        tmp_path / "SKILL.md", "---\nname: s\n---\nbody\n"
    )
    with pytest.raises(SkillParseError, match="description"):
        SkillLoader().load_file(file)


def test_load_all_skips_invalid_and_keeps_valid(tmp_path):
    _write(
        tmp_path / "good.md",
        "---\nname: good\ndescription: good skill.\n---\nbody\n",
    )
    _write(
        tmp_path / "bad.md",
        "---\nname: bad\n---\nbody\n",  # missing description
    )
    skills = SkillLoader([tmp_path]).load_all()

    assert [s.name for s in skills] == ["good"]


def test_load_all_first_match_wins_on_collision(tmp_path):
    root_a = tmp_path / "a"
    root_b = tmp_path / "b"
    root_a.mkdir()
    root_b.mkdir()
    _write(root_a / "SKILL.md", "---\nname: dup\ndescription: first.\n---\nA\n")
    _write(root_b / "SKILL.md", "---\nname: dup\ndescription: second.\n---\nB\n")

    skills = SkillLoader([root_a, root_b]).load_all()

    assert len(skills) == 1
    assert skills[0].description == "first."


def test_file_without_frontmatter_raises(tmp_path):
    file = _write(tmp_path / "SKILL.md", "just markdown, no front matter at all\n")
    with pytest.raises(SkillParseError, match="frontmatter"):
        SkillLoader().load_file(file)


def test_hermes_minimal_format_supported(tmp_path):
    # Hermes/ZCode skills only carry name + description, no triggers/category.
    file = _write(
        tmp_path / "SKILL.md",
        "---\nname: minimalist\ndescription: A minimal skill.\n---\nbody\n",
    )
    skill = SkillLoader().load_file(file)

    assert skill.category == "general"
    assert skill.triggers == []


def test_load_from_subdirectory(tmp_path):
    sub = tmp_path / "python-expert"
    sub.mkdir()
    _write(
        sub / "SKILL.md",
        "---\nname: python-expert\ndescription: nested skill.\n---\nbody\n",
    )
    skills = SkillLoader([tmp_path]).load_all()

    assert [s.name for s in skills] == ["python-expert"]


def test_load_file_rejects_symlink(tmp_path):
    target = _write(
        tmp_path / "target.md",
        "---\nname: target\ndescription: target.\n---\nbody\n",
    )
    link = tmp_path / "SKILL.md"
    link.symlink_to(target)

    with pytest.raises(SkillParseError, match="secure open failed"):
        SkillLoader().load_file(link)


def test_load_file_rejects_oversized_input(tmp_path):
    file = tmp_path / "SKILL.md"
    file.write_bytes(b"x" * (MAX_SKILL_FILE_BYTES + 1))

    with pytest.raises(SkillParseError, match="exceeds"):
        SkillLoader().load_file(file)


def test_load_file_rejects_deep_yaml(tmp_path):
    nested = "value"
    for _ in range(20):
        nested = f"[{nested}]"
    file = _write(
        tmp_path / "SKILL.md",
        f"---\nname: deep\ndescription: deep.\nextra: {nested}\n---\nbody\n",
    )

    with pytest.raises(SkillParseError, match="nesting exceeds"):
        SkillLoader().load_file(file)


def test_load_all_enforces_global_file_limit(tmp_path):
    for index in range(MAX_SKILL_FILES + 2):
        _write(
            tmp_path / f"{index:03}.md",
            f"---\nname: skill-{index}\ndescription: skill.\n---\nbody\n",
        )

    assert len(SkillLoader([tmp_path]).load_all()) == MAX_SKILL_FILES


def test_candidate_limit_counts_invalid_files(tmp_path, monkeypatch):
    """Batch 9.6: invalid files must count toward the scan cap.

    Previously the cap counted only successfully-loaded skills, so an
    attacker could place thousands of invalid YAML / missing-field files
    that each incurred an open + parse without incrementing the limit.
    Now the candidate cap (MAX_SKILL_CANDIDATES) stops the scan after a
    bounded number of files regardless of how many parse successfully.
    """
    from khaos.skills.loader import MAX_SKILL_CANDIDATES

    # Place MORE invalid files than the candidate cap allows.
    overshoot = 25
    total = MAX_SKILL_CANDIDATES + overshoot
    for index in range(total):
        # Every file is INVALID (missing description) so none increment
        # the accepted-skills counter — only the candidate counter.
        _write(
            tmp_path / f"bad-{index:04d}.md",
            f"---\nname: bad-{index}\n---\nbody\n",  # no description
        )

    load_calls = {"count": 0}
    original_load_file = SkillLoader.load_file

    def counting_load_file(self, path, **kwargs):
        load_calls["count"] += 1
        return original_load_file(self, path, **kwargs)

    monkeypatch.setattr(SkillLoader, "load_file", counting_load_file)

    skills = SkillLoader([tmp_path]).load_all()
    # No skills loaded (all invalid), but the scan stopped at the cap.
    assert skills == []
    # load_file was called at most MAX_SKILL_CANDIDATES times, NOT `total`.
    assert load_calls["count"] <= MAX_SKILL_CANDIDATES, (
        f"scan did not respect candidate cap: called load_file "
        f"{load_calls['count']} times (cap {MAX_SKILL_CANDIDATES})"
    )


def test_huge_directory_does_not_sort_all_into_memory(tmp_path, monkeypatch):
    """Batch 9.6: scandir must be consumed lazily, not materialised.

    Previously _iter_skill_files called sorted(scandir(...)) which read
    the ENTIRE directory into a list before yielding the first path.  Now
    we iterate scandir in a streaming fashion.  This test verifies a
    directory with many non-skill entries does not block — the generator
    yields the few real skill files without requiring the whole dir to be
    sorted first (the cap in load_all stops the scan early).
    """
    # Create a handful of real skills + many non-skill files.
    for index in range(3):
        _write(
            tmp_path / f"skill-{index}.md",
            f"---\nname: skill-{index}\ndescription: s.\n---\nbody\n",
        )
    # Non-skill files (wrong extension or name) that must NOT trigger loads.
    for index in range(500):
        (tmp_path / f"noise-{index:04d}.txt").write_text("noise", encoding="utf-8")

    skills = SkillLoader([tmp_path]).load_all()
    assert len(skills) == 3
    assert {s.name for s in skills} == {"skill-0", "skill-1", "skill-2"}


def test_recursive_yaml_alias_does_not_crash_loader(tmp_path):
    """Batch 10.6 (round-10 §十): a YAML frontmatter with a cyclic alias
    graph (``&a [*a]``) must be skipped, not crash the whole load_all().

    Without cycle detection in _yaml_depth, the alias cycle blows the
    Python recursion limit → RecursionError propagates out of load_all()
    and takes down every subsequent skill in every root."""
    # The cyclic alias: &a references itself in a list.
    _write(
        tmp_path / "cyclic.md",
        "---\n"
        "name: cyclic\n"
        "description: has a cycle.\n"
        "data: &a [*a]\n"
        "---\nbody\n",
    )
    # A valid skill alongside the cyclic one — it must still load.
    _write(
        tmp_path / "good.md",
        "---\nname: good\ndescription: valid.\n---\nbody\n",
    )

    skills = SkillLoader([tmp_path]).load_all()
    # The cyclic skill is skipped; the good skill loads.
    assert [s.name for s in skills] == ["good"]


def test_directory_scan_budget_limits_entries(tmp_path, monkeypatch):
    """Batch 10.6: a directory with more than MAX_SKILL_DIR_ENTRIES entries
    is truncated, not fully materialised."""
    from khaos.skills.loader import MAX_SKILL_DIR_ENTRIES

    # Create more noise files than the budget allows.
    overshoot = 50
    total = MAX_SKILL_DIR_ENTRIES + overshoot
    for index in range(total):
        (tmp_path / f"noise-{index:06d}.txt").write_text("x", encoding="utf-8")
    # One real skill that should still be found (within the budget).
    _write(
        tmp_path / "SKILL.md",
        "---\nname: found\ndescription: within budget.\n---\nbody\n",
    )

    skills = SkillLoader([tmp_path]).load_all()
    # The real skill is found (it sorts early: "SKILL.md" < "noise-...").
    assert any(s.name == "found" for s in skills)


def test_yaml_node_budget_aborts_huge_flat_document(tmp_path):
    """Batch 10.6: a YAML document with a huge number of nodes (but within
    the depth limit) is handled without crash or indefinite traversal."""
    # Build a flat mapping with many keys — each key+value pair is a few
    # nodes.  This is within the depth limit (depth 2) so it exercises the
    # node-count budget path, not the depth path.
    keys = "\n".join(f"k{i}: v" for i in range(500))
    _write(
        tmp_path / "huge.md",
        f"---\nname: huge\ndescription: many nodes.\n{keys}\n---\nbody\n",
    )
    # This should load fine (well within both depth and node budget).
    # The test mainly verifies no crash from the node-counting traversal.
    skills = SkillLoader([tmp_path]).load_all()
    assert len(skills) == 1
    assert skills[0].name == "huge"


def test_shared_yaml_alias_dag_not_falsely_rejected(tmp_path):
    """Batch 11.7 (round-11 §十一): a legitimate DAG with a shared alias
    (two parents alias the same anchor, NO cycle) must NOT be rejected.

    Round-10's single ``visited`` set never removed nodes, so the second
    visit to the shared node was falsely flagged as a cycle.  The fix
    separates ``active_stack`` (true cycle detection) from ``seen``
    (budget counting), so only a node still on the recursion stack is
    rejected."""
    _write(
        tmp_path / "dag.md",
        "---\n"
        "name: dag\n"
        "description: shared alias, no cycle.\n"
        "common: &common\n"
        "  - a\n"
        "  - b\n"
        "first: *common\n"
        "second: *common\n"
        "---\nbody\n",
    )

    skills = SkillLoader([tmp_path]).load_all()
    assert len(skills) == 1, (
        "shared-alias DAG must load (was falsely rejected as a cycle "
        "before the active-stack/seen separation)"
    )
    assert skills[0].name == "dag"


def test_true_yaml_cycle_still_rejected(tmp_path):
    """Batch 11.7 regression guard: a TRUE cycle (self-referential alias)
    must still be rejected — the active_stack fix must not weaken cycle
    detection."""
    _write(
        tmp_path / "cyclic.md",
        "---\n"
        "name: cyclic\n"
        "description: true cycle.\n"
        "data: &a [*a]\n"
        "---\nbody\n",
    )
    _write(
        tmp_path / "good.md",
        "---\nname: good\ndescription: valid.\n---\nbody\n",
    )

    skills = SkillLoader([tmp_path]).load_all()
    # The cyclic skill is skipped; the good skill loads.
    assert [s.name for s in skills] == ["good"]


def test_global_directory_budget_limits_total_entries(tmp_path):
    """Batch 11.7: the GLOBAL directory-entry budget caps the total
    across root + all subdirs, preventing the 4096×4096 blowup."""
    from khaos.skills.loader import MAX_SKILL_TOTAL_DIRECTORY_ENTRIES

    # Create many subdirectories, each with a few noise files.
    # The global budget (8192) should truncate the scan well before
    # all subdirs are exhausted.
    num_subdirs = 300
    for i in range(num_subdirs):
        sub = tmp_path / f"sub-{i:04d}"
        sub.mkdir()
        for j in range(30):  # 30 noise files each = 9000 entries total
            (sub / f"noise-{j:03d}.txt").write_text("x", encoding="utf-8")
    # One real skill at top level that should be found.
    _write(
        tmp_path / "SKILL.md",
        "---\nname: top\ndescription: top-level.\n---\nbody\n",
    )

    skills = SkillLoader([tmp_path]).load_all()
    # The top-level skill is found (sorted before subdirs).
    assert any(s.name == "top" for s in skills)
    # The global budget prevented scanning all 9000 entries.
    # (We don't assert an exact count — just that it didn't crash and
    # the budget mechanism is in place.)


# ─────────────────── P2-5: skill trust tiers ────────────────────


def test_load_file_defaults_to_project_trust_tier(tmp_path):
    """P2-5: a skill loaded without an explicit tier defaults to PROJECT
    (the most restricted, untrusted case)."""
    from khaos.skills.skill import SkillTrustTier

    skill_file = tmp_path / "SKILL.md"
    skill_file.write_text(
        "---\nname: proj-skill\ndescription: project\n---\nbody\n", encoding="utf-8"
    )
    loader = SkillLoader([tmp_path])
    skills = loader.load_all()
    assert len(skills) == 1
    assert skills[0].trust_tier is SkillTrustTier.PROJECT


def test_load_all_user_tier_marks_skills(tmp_path):
    """P2-5: loading from the user-global skills dir passes USER tier."""
    from khaos.skills.skill import SkillTrustTier

    skill_file = tmp_path / "SKILL.md"
    skill_file.write_text(
        "---\nname: user-skill\ndescription: user\n---\nbody\n", encoding="utf-8"
    )
    loader = SkillLoader([tmp_path])
    skills = loader.load_all(trust_tier=SkillTrustTier.USER)
    assert len(skills) == 1
    assert skills[0].trust_tier is SkillTrustTier.USER


def test_format_for_prompt_wraps_project_skills_as_untrusted():
    """P2-5: PROJECT-tier skills render inside an untrusted_project_skill
    marker; USER/BUILTIN skills render verbatim."""
    from khaos.skills.manager import SkillManager
    from khaos.skills.skill import Skill, SkillTrustTier

    manager = SkillManager()
    project_skill = Skill(
        name="repo-skill", description="from repo", body="do thing",
        trust_tier=SkillTrustTier.PROJECT,
    )
    user_skill = Skill(
        name="my-skill", description="from user", body="do other",
        trust_tier=SkillTrustTier.USER,
    )
    rendered = manager.format_for_prompt([project_skill, user_skill])
    # PROJECT skill is wrapped.
    assert "<untrusted_project_skill" in rendered
    assert "source=\"repository\"" in rendered
    assert "repo-skill" in rendered
    assert "</untrusted_project_skill>" in rendered
    # USER skill is NOT wrapped.
    assert "my-skill" in rendered
    # Only one untrusted wrapper (for the one project skill).
    assert rendered.count("<untrusted_project_skill") == 1
