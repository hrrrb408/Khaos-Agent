from __future__ import annotations

import json
from types import SimpleNamespace

from khaos.coding.context_engine.contracts import (
    ContextMetricsSnapshot,
    ContextSelection,
    ContextSelectionIdentity,
)
from khaos.coding.context_engine.observability import project_context_selection
from khaos.evaluation.coding import (
    LEGACY_OBSERVABILITY_NOT_AVAILABLE,
    CodingQualificationRecordV1,
    CodingResultState,
    CodingTraceCollector,
    CodingVerdict,
    project_review_findings,
)
from khaos.evaluation.coding.observability import (
    MAX_REVIEW_CONCEPTS,
    MAX_REVIEW_FINDINGS,
)
from khaos.evaluation.coding.oracle import ReviewFinding
from khaos.security.credentials import SecretValue
from khaos.security.secret_redaction import SecretRedactor


def _finding(index: int) -> ReviewFinding:
    return ReviewFinding(
        category=f"category-{index}",
        file=f"src/file_{index}.py",
        concepts=(f"symbol_{index}", "invariant"),
    )


def _forged_finding(
    *,
    category: object = "category",
    file: object = "src/file.py",
    concepts: object = ("concept",),
) -> ReviewFinding:
    """Build malformed typed-shaped input for the projection boundary only."""

    finding = object.__new__(ReviewFinding)
    object.__setattr__(finding, "category", category)
    object.__setattr__(finding, "file", file)
    object.__setattr__(finding, "concepts", concepts)
    object.__setattr__(finding, "line", 1)
    object.__setattr__(finding, "severity", "high")
    return finding


def _context_item(
    item_id: str,
    *,
    kind: str = "file_region",
    source: str = "repo_intelligence",
    layer: str = "L2",
    path: str | None = "src/main.py",
    symbol: str | None = None,
    metadata: dict[str, object] | None = None,
    truncated: bool = False,
    compressed: bool = False,
) -> SimpleNamespace:
    return SimpleNamespace(
        item_id=item_id,
        kind=SimpleNamespace(value=kind),
        source=SimpleNamespace(value=source),
        layer=SimpleNamespace(value=layer),
        path=path,
        symbol=symbol,
        metadata=metadata or {},
        digest="a" * 64,
        token_count=7,
        byte_count=28,
        truncated=truncated,
        compressed=compressed,
    )


def test_review_finding_projection_is_ordered_bounded_and_non_mutating() -> None:
    findings = tuple(_finding(index) for index in range(MAX_REVIEW_FINDINGS + 1))
    before = findings[0]

    projection = project_review_findings(findings)

    assert projection["typed_finding_original_count"] == MAX_REVIEW_FINDINGS + 1
    assert projection["typed_finding_persisted_count"] == MAX_REVIEW_FINDINGS
    assert projection["typed_finding_projection_truncated"] is True
    rows = projection["typed_findings"]
    assert isinstance(rows, list)
    assert len(rows) == MAX_REVIEW_FINDINGS
    assert rows[0]["ordinal"] == 0
    assert rows[-1]["ordinal"] == MAX_REVIEW_FINDINGS - 1
    assert rows[0]["file"] == "src/file_0.py"
    assert "line" not in rows[0]
    assert "severity" not in rows[0]
    assert before == findings[0]
    assert projection["typed_finding_projection_digest"]


def test_review_finding_projection_redacts_path_concept_and_control_canaries() -> None:
    secret = "synthetic-review-secret-7d6f"
    redactor = SecretRedactor()
    redactor.register(SecretValue(secret))
    attack_files = (
        "/tmp/outside.py",
        "../outside.py",
        "src/../outside.py",
        r"src\outside.py",
        "C:/outside.py",
        ".oracle-hidden/expected.py",
        f"src/api_key={secret}",
        "src/name\x00.py",
        "src/" + ("x" * 600) + ".py",
    )
    attack_concepts = (
        "Authorization: Bearer " + secret,
        "api_key=" + secret,
        "concept\x00control",
        "concept\nline",
        "x" * 300,
        "入口",
    )

    findings = [
        _forged_finding(file=file_name, concepts=("safe",))
        for file_name in attack_files
    ]
    findings.extend(
        _forged_finding(concepts=(concept,)) for concept in attack_concepts
    )
    findings.append(_forged_finding(concepts=("duplicate", "duplicate")))
    projection = project_review_findings(findings, redactor=redactor)
    serialized = json.dumps(projection, ensure_ascii=False, sort_keys=True)

    assert secret not in serialized
    assert all(
        row["file"] == "workspace:unsafe"
        for row in projection["typed_findings"][: len(attack_files)]
    )
    concept_rows = projection["typed_findings"][len(attack_files) :]
    assert concept_rows[0]["concepts"] == ["[REDACTED_CONCEPT]"]
    assert concept_rows[1]["concepts"] == ["[REDACTED_CONCEPT]"]
    assert concept_rows[2]["concepts"] == ["[REDACTED_CONCEPT]"]
    assert concept_rows[3]["concepts"] == ["[REDACTED_CONCEPT]"]
    assert concept_rows[4]["concepts"] == ["[REDACTED_CONCEPT]"]
    assert concept_rows[5]["concepts"] == ["入口"]
    assert projection["typed_finding_persisted_count"] == len(findings)
    assert projection["typed_finding_values_redacted"] is True


def test_review_finding_concept_projection_preserves_count_when_bounded() -> None:
    finding = _forged_finding(
        concepts=tuple(f"concept-{index}" for index in range(MAX_REVIEW_CONCEPTS + 1))
    )

    projection = project_review_findings((finding,))
    row = projection["typed_findings"][0]

    assert row["concepts_original_count"] == MAX_REVIEW_CONCEPTS + 1
    assert row["concepts_persisted_count"] == MAX_REVIEW_CONCEPTS
    assert row["concepts_truncated"] is True
    assert projection["typed_finding_persisted_count"] == 1


def test_context_selection_projection_keeps_order_and_separates_eviction() -> None:
    repo = _context_item("repo-1", symbol="AuthorityLease")
    tool = _context_item(
        "tool-1",
        kind="tool_result",
        source="tool",
        layer="L3",
        path=None,
        truncated=True,
    )
    history = _context_item(
        "history-1",
        kind="conversation",
        source="conversation",
        layer="L1",
        path=None,
    )
    evicted = _context_item("evicted-1", path="src/evicted.py")
    selection = ContextSelection(
        selected=(repo, tool, history),
        evicted=(evicted,),
        compressed=(tool,),
        truncated_count=1,
    )

    projection = project_context_selection(selection)
    rows = projection["selection_items"]

    assert projection["selection_items_original_count"] == 4
    assert projection["selection_items_persisted_count"] == 4
    assert projection["selection_items_projection_truncated"] is False
    assert projection["selected_repository_paths"] == ["src/main.py"]
    assert projection["automatic_repo_items_selected"] == 1
    assert projection["tool_acquired_items_selected"] == 1
    assert projection["non_repository_items_selected"] == 1
    assert [row["item_id"] for row in rows] == [
        "repo-1",
        "tool-1",
        "history-1",
        "evicted-1",
    ]
    assert rows[0]["selection_ordinal"] == 0
    assert rows[2]["source_channel"] == "history"
    assert rows[1]["compressed"] is True
    assert rows[3]["evicted"] is True
    assert rows[3]["eviction_ordinal"] == 0
    assert "payload" not in json.dumps(projection)


def test_context_selection_projection_redacts_hidden_and_secret_metadata() -> None:
    secret = "sk-synthetic-context-secret-1a2b"
    selection = ContextSelection(
        selected=(
            _context_item(
                "hidden-oracle-item",
                path=".oracle-hidden/golden.py",
                symbol="Authorization: Bearer " + secret,
                metadata={
                    "symbols": ["safe_symbol", "api_key=" + secret],
                    "symbol_count": 4,
                    "relation_count": 2,
                    "evidence_record_count": 3,
                },
            ),
        )
    )

    projection = project_context_selection(selection)
    row = projection["selection_items"][0]
    serialized = json.dumps(projection, ensure_ascii=False, sort_keys=True)

    assert secret not in serialized
    assert row["item_id"] == "item:unsafe"
    assert row["path"] == "workspace:unsafe"
    assert row["path_redacted"] is True
    assert row["symbols"][0] == "[REDACTED_SYMBOL]"
    assert row["symbols"][1] == "safe_symbol"
    assert row["symbols_redacted"] is True
    assert row["relation_count"] == 2
    assert row["evidence_record_count"] == 3


def test_context_selection_projection_caps_late_items_without_dropping_count() -> None:
    selected = tuple(
        _context_item(f"row-{index}", path=f"src/{index}.py")
        for index in range(130)
    )

    projection = project_context_selection(ContextSelection(selected=selected))

    assert projection["selection_items_original_count"] == 130
    assert projection["selection_items_persisted_count"] == 128
    assert projection["selection_items_projection_truncated"] is True
    assert projection["selection_items"][-1]["selection_ordinal"] == 127


def test_trace_persists_typed_findings_and_exact_context_with_count_join() -> None:
    secret = "synthetic-trace-secret-3c91"
    redactor = SecretRedactor()
    redactor.register(SecretValue(secret))
    finding = _finding(1)
    selection = ContextSelection(
        selected=(_context_item("repo-1", symbol="AuthorityLease"),)
    )
    context = SimpleNamespace(
        context_digest="b" * 64,
        requirements_digest="c" * 64,
        cache_hit=False,
        partial=False,
        selection=selection,
        selection_identity=ContextSelectionIdentity(
            selection_id="ctxsel-1",
            selection_sequence=1,
            selection_reason="INITIAL_BUILD",
            selection_digest=project_context_selection(selection)["selection_digest"],
        ),
    )
    collector = CodingTraceCollector(
        max_events=32,
        run_id="run-typed-attribution",
        secret_redactor=redactor,
    )

    collector.record_context_selection(context)
    collector.record_response_observation(
        '{"findings":[],"note":"Authorization: Bearer ' + secret + '"}',
        {"typed_parse_status": "PASS", "typed_finding_count": 1},
        turn_id="turn-1",
        findings=(finding,),
    )
    collector.record_semantic_review(
        {
            "review_findings_pass": False,
            "required_finding_count": 2,
            "submitted_finding_count": 1,
            "matched_finding_count": 0,
            "unmatched_finding_count": 2,
            "extra_finding_count": 1,
        }
    )
    metrics = collector.finish(
        verdict=CodingVerdict.FAIL,
        agent_status="COMPLETED",
        completion_status="completed",
    )
    payload = json.dumps(
        {
            "metrics": metrics.to_payload(),
            "events": [event.to_payload() for event in collector.events],
        },
        ensure_ascii=False,
        sort_keys=True,
    )

    response = metrics.observability["response_observability"]
    context_observation = metrics.observability["context"]
    assert secret not in payload
    assert response["typed_finding_detail_status"] == "AVAILABLE"
    assert response["typed_finding_original_count"] == 1
    assert response["typed_finding_persisted_count"] == 1
    assert response["typed_findings"][0]["ordinal"] == 0
    assert context_observation["selection_items_original_count"] == 1
    assert context_observation["selection_items_persisted_count"] == 1
    assert context_observation["selection_detail_status"] == "AVAILABLE"
    assert collector.reconcile(metrics)["status"] == "PASS"

    response_event = next(
        event
        for event in collector.events
        if event.event_type == "response_parse_evaluated"
    )
    context_event = next(
        event for event in collector.events if event.event_type == "context_selected"
    )
    assert response_event.safe_event_metadata["typed_findings"] == response[
        "typed_findings"
    ]
    assert context_event.safe_event_metadata["selection_items"] == context_observation[
        "selection_items"
    ]


def test_context_metrics_snapshot_preserves_exact_selection_detail() -> None:
    item = _context_item("repo-1", path="src/main.py")
    projection = project_context_selection(ContextSelection(selected=(item,)))
    collector = CodingTraceCollector(max_events=16, run_id="run-context-snapshot")
    collector.record_context_metrics(
        ContextMetricsSnapshot(
            context_selection_digest=projection["selection_digest"],
            context_selected_repository_paths=("src/main.py",),
            context_automatic_repo_items_selected=1,
            context_tool_acquired_items_selected=0,
            context_non_repository_items_selected=0,
            context_selection_observability_schema_version=1,
            context_selection_detail_status="AVAILABLE",
            context_selection_metadata=tuple(projection["selection_items"]),
            context_selection_projection_original_count=1,
            context_selection_projection_persisted_count=1,
            context_selection_projection_truncated=False,
        )
    )
    metrics = collector.finish(
        verdict=CodingVerdict.FAIL,
        agent_status="COMPLETED",
        completion_status="completed",
    )

    context = metrics.observability["context"]
    assert context["selection_items"] == projection["selection_items"]
    assert context["selection_items_original_count"] == 1
    assert context["selection_items_projection_truncated"] is False


def test_qualification_reader_distinguishes_available_empty_from_legacy_missing() -> None:
    common = {
        "run_id": "run-reader",
        "result_state": CodingResultState.FAILURE,
        "provider": "offline-provider",
        "model": "offline-model",
        "source_sha": "3c1095ff69b1a5d800d96eb61e8b88a47fceca14",
        "working_tree_identity": None,
        "provider_config_digest": None,
        "suite_id": "m8-provider-qualification",
        "suite_version": 2,
        "suite_digest": "a" * 64,
        "scenario_id": "p4-readonly-authority",
        "scenario_version": 2,
        "scenario_digest": "b" * 64,
        "fixture_digest": None,
        "prompt_digest": None,
        "system_prompt_digest": None,
        "tool_schema_digest": None,
        "policy_digest": None,
        "budgets": {"max_tool_calls": 24},
        "timeout_seconds": 300,
        "credential_ref": None,
        "reasoning_configuration": {},
        "metrics": {},
        "started_at": "2026-09-13T00:00:00+00:00",
        "finished_at": "2026-09-13T00:00:01+00:00",
    }
    available = CodingQualificationRecordV1(
        **common,
        stages=(
            {
                "observability": {
                    "response_observability": {"typed_findings": []},
                    "context": {"selection_items": []},
                }
            },
        ),
    )
    legacy = CodingQualificationRecordV1(**common, stages=())

    assert available.typed_finding_detail() == []
    assert available.context_selection_detail() == []
    assert legacy.typed_finding_detail() == LEGACY_OBSERVABILITY_NOT_AVAILABLE
    assert legacy.context_selection_detail() == LEGACY_OBSERVABILITY_NOT_AVAILABLE


def test_semantic_near_miss_join_is_offline_and_excludes_hidden_oracle_ids() -> None:
    # This oracle is intentionally test-local and is never put in the
    # candidate projection or a qualification artifact.
    hidden_oracle = {
        "authority-definition": {
            "category": "authority-definition",
            "file": "src/authority.py",
            "concepts": {"AuthorityLease", "issue_lease", "definition"},
        }
    }
    candidate = project_review_findings(
        (
            ReviewFinding(
                category="authority-definition",
                file="src/authority.py",
                concepts=("AuthorityLease", "issue_lease", "near-miss"),
            ),
        )
    )
    candidate_row = candidate["typed_findings"][0]
    expected = hidden_oracle["authority-definition"]
    candidate_concepts = set(candidate_row["concepts"])
    joined = {
        "category": candidate_row["category"] == expected["category"],
        "file": candidate_row["file"] == expected["file"],
        "concept_overlap": len(candidate_concepts & expected["concepts"]),
    }
    serialized_candidate = json.dumps(candidate, ensure_ascii=False, sort_keys=True)

    assert joined == {"category": True, "file": True, "concept_overlap": 2}
    assert "finding_id" not in serialized_candidate
    assert "authority-definition" not in candidate_row
