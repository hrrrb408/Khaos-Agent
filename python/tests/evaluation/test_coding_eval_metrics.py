from __future__ import annotations

from types import SimpleNamespace

from khaos.agent import Message
from khaos.evaluation.coding import CodingTraceCollector, CodingVerdict


def test_trace_metrics_deduplicate_streamed_tool_projection_and_capture_effort() -> None:
    collector = CodingTraceCollector(max_events=32, max_model_turns=4, max_tool_calls=8)
    call = {"id": "call-1", "name": "write_file", "arguments": {"content": "secret"}}

    collector.record_message(
        Message(role="assistant", content="", event="tool_call", tool_calls=[call])
    )
    collector.record_message(Message(role="assistant", content="", tool_calls=[call]))
    collector.record_message(
        Message(
            role="tool",
            content="{}",
            metadata={"name": "write_file", "success": True, "duration_ms": 2},
        )
    )
    collector.record_message(Message(role="assistant", content="verify"))
    collector.record_message(
        Message(
            role="tool",
            content="{}",
            metadata={"name": "test_run", "success": False, "duration_ms": 3},
        )
    )
    collector.record_message(
        Message(
            role="tool",
            content="{}",
            metadata={"name": "test_run", "success": True, "duration_ms": 3},
        )
    )
    collector.record_message(
        Message(role="system", content="permission_request", event="permission_request")
    )
    collector.record("agent_event", "recovery.no_progress")

    metrics = collector.finish(
        verdict=CodingVerdict.PASS,
        agent_status="COMPLETED",
        completion_status="completed",
        input_tokens=10,
        output_tokens=6,
        oracle_pass_count=1,
        diff_changed_files=1,
        diff_insertions=2,
        diff_deletions=1,
    )

    assert metrics.model_calls == 2
    assert metrics.model_turns == 2
    assert metrics.tool_calls == 1
    assert metrics.write_calls == 1
    assert metrics.edit_attempts == 1
    assert metrics.failed_test_runs == 1
    assert metrics.successful_test_runs == 1
    assert metrics.final_green is True
    assert metrics.approval_count == 1
    assert metrics.no_progress_count == 1
    assert metrics.recovery_count == 1
    assert metrics.total_tokens == 16
    assert all("secret" not in event.to_payload()["name"] for event in collector.events)


def test_trace_collector_deduplicates_streamed_assistant_chunks() -> None:
    collector = CodingTraceCollector(max_events=32, max_model_turns=4, max_tool_calls=8)
    collector.record_message(
        Message(
            role="assistant",
            content="part one",
            metadata={"turn_id": "turn-1", "attempt_id": "attempt-1"},
        )
    )
    collector.record_message(
        Message(
            role="assistant",
            content="part two",
            metadata={"turn_id": "turn-1", "attempt_id": "attempt-1"},
        )
    )

    metrics = collector.finish(
        verdict=CodingVerdict.PASS,
        agent_status="COMPLETED",
        completion_status="completed",
    )

    assert metrics.model_calls == 1
    assert metrics.model_turns == 1


def test_trace_metrics_capture_repository_intelligence_counters() -> None:
    collector = CodingTraceCollector(max_events=32, max_model_turns=4, max_tool_calls=8)
    collector.record_repository_metrics(
        SimpleNamespace(
            query_count=7,
            cache_hit_count=2,
            cache_miss_count=5,
            full_index_count=1,
            incremental_refresh_count=3,
            parsed_file_count=12,
            reparsed_file_count=3,
            semantic_query_count=6,
            lexical_fallback_count=1,
            stale_query_count=0,
            context_candidate_file_count=18,
            context_selected_file_count=4,
            context_selected_symbol_count=9,
        )
    )

    metrics = collector.finish(
        verdict=CodingVerdict.PASS,
        agent_status="COMPLETED",
        completion_status="completed",
    )

    assert metrics.to_payload()["repo_intelligence_queries"] == 7
    assert metrics.repo_intelligence_cache_hits == 2
    assert metrics.repo_index_incremental_refreshes == 3
    assert metrics.repo_files_reparsed == 3
    assert metrics.context_selected_symbol_count == 9


def test_trace_limits_fail_closed() -> None:
    collector = CodingTraceCollector(max_events=8, max_model_turns=1, max_tool_calls=1)
    collector.record_message(Message(role="assistant", content="first"))

    try:
        collector.record_message(Message(role="assistant", content="second"))
    except ValueError as exc:
        assert "model-turn" in str(exc)
    else:
        raise AssertionError("model-turn bound did not fail closed")
