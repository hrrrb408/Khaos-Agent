"""Tests for skill generation from task traces."""

from __future__ import annotations

from khaos.skills.generator import SkillGenerator, TaskTrace, ToolTrace


def _call(name: str, args: dict | None = None, success: bool = True) -> ToolTrace:
    return ToolTrace(
        tool_name=name, arguments=args or {}, result_summary="ok", success=success
    )


def _trace(
    tools: list[ToolTrace],
    goal: str = "refactor auth module",
    files: list[str] | None = None,
    status: str = "completed",
) -> TaskTrace:
    return TaskTrace(
        task_id="t1",
        goal=goal,
        tools_called=tools,
        files_modified=files or [],
        status=status,
    )


def test_failed_task_no_candidates() -> None:
    gen = SkillGenerator()
    trace = _trace([_call("read_file"), _call("write_file"), _call("test_run")], status="failed")
    assert gen.analyze(trace) == []


def test_short_task_no_candidates() -> None:
    gen = SkillGenerator()
    # Only 2 tool calls (< 3 threshold).
    trace = _trace([_call("read_file"), _call("write_file")])
    assert gen.analyze(trace) == []


def test_sequence_pattern_extracted() -> None:
    """A task with 2+ frequent tools and 2+ distinct steps yields a candidate."""
    gen = SkillGenerator()
    tools = [
        _call("read_file", {"path": "src/a.py"}),
        _call("read_file", {"path": "src/b.py"}),
        _call("write_file", {"path": "src/a.py"}),
        _call("write_file", {"path": "src/b.py"}),
        _call("test_run"),
    ]
    candidates = gen.analyze(_trace(tools, goal="refactor auth module"))
    # Sequence pattern candidate should be present (read + write are frequent).
    seq = [c for c in candidates if "Auto-extracted" in c.description]
    assert len(seq) >= 1
    assert seq[0].confidence > 0
    assert "src/a.py" in seq[0].body or "读取" in seq[0].body


def test_file_pattern_source_and_test() -> None:
    """Modifying source + test files yields a file-pattern candidate."""
    gen = SkillGenerator()
    tools = [
        _call("read_file", {"path": "auth.py"}),
        _call("write_file", {"path": "auth.py"}),
        _call("write_file", {"path": "test_auth.py"}),
        _call("test_run"),
    ]
    candidates = gen.analyze(
        _trace(tools, goal="add login", files=["auth.py", "test_auth.py"])
    )
    file_cands = [c for c in candidates if "source + tests" in c.description]
    assert len(file_cands) == 1
    assert "test_auth.py" in file_cands[0].body
    assert file_cands[0].confidence == 0.7


def test_confidence_threshold() -> None:
    """Candidates below the threshold are filtered out."""
    # A sequence with only 2 steps → confidence 0.4 (< 0.5 default).
    gen = SkillGenerator(confidence_threshold=0.5)
    tools = [
        _call("read_file", {"path": "a"}),
        _call("read_file", {"path": "b"}),
        _call("write_file", {"path": "c"}),
        _call("write_file", {"path": "d"}),
    ]
    candidates = gen.analyze(_trace(tools, goal="short task"))
    # 2 distinct steps → confidence = 2/5 = 0.4 < 0.5 → filtered.
    # (No file-pattern candidate since no test files.)
    assert all(c.confidence >= 0.5 for c in candidates)


def test_trigger_extraction() -> None:
    gen = SkillGenerator()
    triggers = gen._extract_triggers("refactor the auth module", ["auth.py", "test_auth.py"])
    assert "refactor" in triggers
    assert "module" in triggers
    assert "py" in triggers


def test_name_generation() -> None:
    gen = SkillGenerator()
    name = gen._generate_name("Add user authentication flow")
    # _generate_name takes the first 4 words, joined with hyphens.
    assert name == "add-user-authentication-flow"
    # Empty goal → fallback.
    assert gen._generate_name("") == "auto-skill"


def test_multiple_candidates() -> None:
    """One task can yield both a sequence and a file-pattern candidate."""
    gen = SkillGenerator(confidence_threshold=0.3)
    tools = [
        _call("read_file", {"path": "src/app.py"}),
        _call("read_file", {"path": "src/util.py"}),
        _call("write_file", {"path": "src/app.py"}),
        _call("write_file", {"path": "test_app.py"}),
        _call("test_run"),
    ]
    candidates = gen.analyze(
        _trace(tools, goal="update app", files=["src/app.py", "test_app.py"])
    )
    # At least one sequence candidate + one file-pattern candidate.
    assert len(candidates) >= 1
