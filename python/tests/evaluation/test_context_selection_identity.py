"""M8 context-selection event/snapshot identity closure tests."""

from __future__ import annotations

from dataclasses import replace

import pytest
from khaos.coding.context_engine import (
    ContextBudget,
    ContextEngineService,
    ContextItem,
    ContextItemKind,
    ContextLayer,
    ContextMetricsSnapshot,
    ContextRequirements,
    ContextSelection,
    ContextSelectionIdentity,
    ContextSelectionReason,
    ContextSource,
    ContextTrust,
    ModelContext,
)
from khaos.coding.context_engine.observability import project_context_selection
from khaos.evaluation.coding import CodingTraceCollector, CodingVerdict


def _item(payload: str = "return 1", *, item_id: str = "item-1") -> ContextItem:
    return ContextItem(
        kind=ContextItemKind.FILE_REGION,
        payload=payload,
        layer=ContextLayer.L2,
        source=ContextSource.REPO_INTELLIGENCE,
        trust=ContextTrust.UNTRUSTED_REPO,
        workspace_id="workspace-1",
        generation="generation-1",
        path="src/example.py",
        priority=100,
        item_id=item_id,
        sequence=1,
    )


def _requirements() -> ContextRequirements:
    return ContextRequirements(
        task_id="task-1",
        workspace_id="workspace-1",
        generation="generation-1",
        budget=ContextBudget(total_tokens=256, total_bytes=4096),
    )


def _model_context(
    selection_id: str | None,
    sequence: int | None,
    reason: str | None,
    *,
    selection: ContextSelection | None = None,
) -> ModelContext:
    selected = selection or ContextSelection(selected=(_item(),))
    projection = project_context_selection(selected)
    identity = (
        ContextSelectionIdentity(
            selection_id=selection_id or "ctxsel-legacy",
            selection_sequence=sequence or 1,
            selection_reason=reason or ContextSelectionReason.BUILD.value,
            selection_digest=str(projection["selection_digest"]),
        )
        if selection_id is not None
        else None
    )
    return ModelContext(
        messages=(),
        selection=selected,
        requirements_digest="b" * 64,
        context_digest="c" * 64,
        selection_identity=identity,
    )


def _finish(*contexts: ModelContext) -> tuple[CodingTraceCollector, object]:
    collector = CodingTraceCollector(max_events=64, run_id="context-identity-test")
    for context in contexts:
        collector.record_context_selection(context)
    metrics = collector.finish(
        verdict=CodingVerdict.PASS,
        agent_status="COMPLETED",
        completion_status="completed",
    )
    return collector, metrics


@pytest.mark.asyncio
async def test_context_engine_emits_identity_for_initial_rebalance_and_cache_hit() -> None:
    engine = ContextEngineService(
        default_budget=ContextBudget(total_tokens=256, total_bytes=4096)
    )
    collector = CodingTraceCollector(max_events=64, run_id="context-engine-identity")
    engine.bind_selection_observer(
        lambda context, repo_bundle=None: collector.record_context_selection(
            context,
            repo_bundle=repo_bundle,
        )
    )
    requirements = _requirements()
    first = await engine.build(
        requirements,
        [_item()],
        selection_reason=ContextSelectionReason.INITIAL_BUILD,
    )

    # This exercises the production rebalance path.  It must emit a second
    # event even if the resulting projection happens to be unchanged.
    rebalanced_messages = await engine.rebalance_messages(
        first.messages,
        requirements=requirements,
    )
    assert rebalanced_messages

    # A cache hit is also an effective build invocation: it gets a new
    # invocation id while retaining the same safe content digest.
    same_content = await engine.build(
        requirements,
        [_item()],
        selection_reason=ContextSelectionReason.REBALANCE,
    )
    changed_content = await engine.build(
        requirements,
        [_item("return 2")],
        selection_reason=ContextSelectionReason.REBALANCE,
    )
    snapshot = engine.metrics_snapshot()
    collector.record_context_metrics(snapshot)
    metrics = collector.finish(
        verdict=CodingVerdict.PASS,
        agent_status="COMPLETED",
        completion_status="completed",
    )

    assert first.selection_identity is not None
    assert same_content.selection_identity is not None
    assert changed_content.selection_identity is not None
    assert first.selection_identity.selection_id != same_content.selection_identity.selection_id
    assert (
        first.selection_identity.selection_digest
        == same_content.selection_identity.selection_digest
    )
    assert (
        first.selection_identity.selection_digest
        != changed_content.selection_identity.selection_digest
    )
    events = [event for event in collector.events if event.event_type == "context_selected"]
    assert [event.safe_event_metadata["selection_id"] for event in events] == [
        "ctxsel-1",
        "ctxsel-2",
        "ctxsel-3",
        "ctxsel-4",
    ]
    assert [event.safe_event_metadata["selection_sequence"] for event in events] == [1, 2, 3, 4]
    assert events[0].safe_event_metadata["selection_reason"] == "INITIAL_BUILD"
    assert events[1].safe_event_metadata["selection_reason"] == "REBALANCE"
    assert snapshot.context_selection_id == "ctxsel-4"
    assert snapshot.context_selection_count == 4
    assert snapshot.context_initial_selection_id == "ctxsel-1"
    assert snapshot.context_rebalance_count == 3
    assert len(snapshot.context_selection_history) == 4
    assert metrics.context_selection_id == "ctxsel-4"
    assert collector.reconcile(metrics)["status"] == "PASS"


def test_same_digest_different_identity_is_valid_and_history_is_retained() -> None:
    selection = ContextSelection(selected=(_item(),))
    first = _model_context("ctxsel-1", 1, "INITIAL_BUILD", selection=selection)
    second = _model_context("ctxsel-2", 2, "REBALANCE", selection=selection)

    collector, metrics = _finish(first, second)
    context = metrics.observability["context"]
    assert context["selection_history"] == [
        {
            "selection_id": "ctxsel-1",
            "selection_sequence": 1,
            "selection_reason": "INITIAL_BUILD",
            "selection_digest": context["selection_history"][0]["selection_digest"],
        },
        {
            "selection_id": "ctxsel-2",
            "selection_sequence": 2,
            "selection_reason": "REBALANCE",
            "selection_digest": context["selection_history"][1]["selection_digest"],
        },
    ]
    assert context["selection_history"][0]["selection_digest"] == context["selection_history"][1]["selection_digest"]
    assert collector.reconcile(metrics)["status"] == "PASS"


@pytest.mark.parametrize(
    ("contexts", "expected_code"),
    [
        (
            (
                _model_context("ctxsel-1", 1, "INITIAL_BUILD"),
                _model_context("ctxsel-1", 2, "REBALANCE"),
            ),
            "DUPLICATE_SELECTION_ID",
        ),
        (
            (
                _model_context("ctxsel-1", 1, "INITIAL_BUILD"),
                _model_context("ctxsel-3", 3, "REBALANCE"),
                _model_context("ctxsel-2", 2, "REBALANCE"),
            ),
            "SELECTION_SEQUENCE_OUT_OF_ORDER",
        ),
    ],
)
def test_context_identity_negative_sequence_checks(
    contexts: tuple[ModelContext, ...],
    expected_code: str,
) -> None:
    collector, metrics = _finish(*contexts)
    result = collector.reconcile(metrics)
    assert result["status"] == "OBSERVABILITY_DEFECT"
    assert expected_code in result["mismatches"]


def test_context_identity_rejects_missing_final_event_and_digest_mismatch() -> None:
    collector, metrics = _finish(_model_context("ctxsel-1", 1, "INITIAL_BUILD"))
    original_observability = dict(metrics.observability)
    original_context = dict(original_observability["context"])

    missing_context = dict(original_context)
    missing_context["final_context_selection_id"] = "ctxsel-missing"
    missing_observability = dict(original_observability)
    missing_observability["context"] = missing_context
    missing = replace(metrics, observability=missing_observability)
    missing_result = collector.reconcile(missing)
    assert "FINAL_SELECTION_EVENT_MISSING" in missing_result["mismatches"]

    digest_context = dict(original_context)
    digest_context["final_context_selection_digest"] = "d" * 64
    digest_observability = dict(original_observability)
    digest_observability["context"] = digest_context
    digest_mismatch = replace(metrics, observability=digest_observability)
    digest_result = collector.reconcile(digest_mismatch)
    assert "SELECTION_DIGEST_MISMATCH" in digest_result["mismatches"]


def test_context_identity_rejects_missing_final_id_and_count_mismatch() -> None:
    context = _model_context("ctxsel-1", 1, "INITIAL_BUILD")
    collector, metrics = _finish(context)
    original_observability = dict(metrics.observability)
    original_context = dict(original_observability["context"])

    missing_context = dict(original_context)
    missing_context["final_context_selection_id"] = None
    missing_context["selection_id"] = None
    missing_observability = dict(original_observability)
    missing_observability["context"] = missing_context
    missing = replace(metrics, observability=missing_observability)
    missing_result = collector.reconcile(missing)
    assert "FINAL_SELECTION_ID_MISSING" in missing_result["mismatches"]

    count_context = dict(original_context)
    count_context["selected_count"] = 99
    count_observability = dict(original_observability)
    count_observability["context"] = count_context
    count_mismatch = replace(metrics, observability=count_observability)
    count_result = collector.reconcile(count_mismatch)
    assert "SELECTION_COUNT_MISMATCH" in count_result["mismatches"]


def test_context_identity_keeps_legacy_artifact_readable_without_inference() -> None:
    legacy = _model_context(None, None, None)
    collector, metrics = _finish(legacy)
    context = metrics.observability["context"]
    assert context["selection_identity_status"] == "LEGACY_NO_SELECTION_ID"
    assert context["final_context_selection_id"] is None
    result = collector.reconcile(metrics)
    assert result["status"] == "OBSERVABILITY_DEFECT"
    assert "LEGACY_NO_SELECTION_ID" in result["mismatches"]


def test_context_metrics_snapshot_without_identity_is_explicitly_legacy() -> None:
    selection = ContextSelection(selected=(_item(),))
    projection = project_context_selection(selection)
    collector = CodingTraceCollector(max_events=16, run_id="legacy-snapshot")
    collector.record_context_metrics(
        ContextMetricsSnapshot(
            context_selection_digest=projection["selection_digest"],
            context_selection_metadata=tuple(projection["selection_items"]),
            context_selection_observability_schema_version=1,
            context_selection_detail_status="AVAILABLE",
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
    assert context["selection_identity_status"] == "LEGACY_NO_SELECTION_ID"
    assert metrics.context_selection_id is None
