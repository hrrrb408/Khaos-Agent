from __future__ import annotations

import json
from dataclasses import replace
from types import SimpleNamespace

import pytest
from khaos.agent import Message
from khaos.coding.context_engine.observability import project_context_selection
from khaos.evaluation.coding import CodingTraceCollector, CodingVerdict
from khaos.routing.model_client import ProviderRequestObservation
from khaos.security.credentials import SecretValue
from khaos.security.secret_redaction import SecretRedactor


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
    assert collector.reconcile(metrics)["status"] == "PASS"


def test_trace_records_provider_request_observations_without_provider_messages() -> None:
    collector = CodingTraceCollector(max_events=16, run_id="provider-observation-test")
    collector.record_provider_observations(
        [
            ProviderRequestObservation(
                provider="zhipu-coding",
                model="glm-5.3-flash",
                attempt=1,
                max_attempts=3,
                status_code=200,
                started_at="2026-09-13T00:00:00+00:00",
                latency_ms=42,
                first_byte_latency_ms=9,
                retryable=False,
                provider_error_type=None,
                provider_message="must not be persisted",
            )
        ]
    )
    metrics = collector.finish(
        verdict=CodingVerdict.AGENT_ERROR,
        agent_status="ERROR",
        completion_status=None,
    )

    assert metrics.provider_requests == 1
    assert metrics.provider_usage_status == "PROVIDER_NOT_REPORTED"
    provider = metrics.observability["provider"]
    assert provider["provider_requests"] == 1
    assert provider["status_counts"] == {"200": 1}
    assert provider["usage_status"] == "PROVIDER_NOT_REPORTED"
    assert "provider_message" not in provider["requests"][0]


def test_trace_records_provider_usage_totals_without_provider_response_data() -> None:
    collector = CodingTraceCollector(max_events=16, run_id="provider-usage-test")
    collector.record_provider_observations(
        [
            ProviderRequestObservation(
                provider="zhipu-coding",
                model="glm-5.3-flash",
                attempt=1,
                max_attempts=3,
                status_code=429,
                started_at="2026-09-13T00:00:00+00:00",
                latency_ms=4,
                first_byte_latency_ms=None,
                retryable=True,
                provider_error_type="rate_limit",
            ),
            ProviderRequestObservation(
                provider="zhipu-coding",
                model="glm-5.3-flash",
                attempt=2,
                max_attempts=3,
                status_code=200,
                started_at="2026-09-13T00:00:01+00:00",
                latency_ms=42,
                first_byte_latency_ms=9,
                retryable=False,
                input_tokens=11,
                output_tokens=7,
                total_tokens=18,
                response_model="glm-5.3-flash",
            ),
        ]
    )
    metrics = collector.finish(
        verdict=CodingVerdict.PASS,
        agent_status="COMPLETED",
        completion_status="completed",
    )

    assert metrics.provider_usage_status == "PROVIDER_PARTIAL"
    assert metrics.input_tokens == 11
    assert metrics.output_tokens == 7
    assert metrics.total_tokens == 18
    provider = metrics.observability["provider"]
    assert provider["input_tokens"] == 11
    assert provider["output_tokens"] == 7
    assert provider["total_tokens"] == 18
    assert provider["usage_status"] == "PROVIDER_PARTIAL"
    assert provider["requests"][1]["response_model"] == "glm-5.3-flash"
    assert provider["requests"][0]["input_tokens"] is None


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


def test_trace_collector_counts_tool_only_model_response_with_identity() -> None:
    collector = CodingTraceCollector(max_events=32, max_model_turns=4, max_tool_calls=8)
    collector.record_message(
        Message(
            role="assistant",
            content="",
            event="tool_call",
            metadata={"turn_id": "turn-1", "attempt_id": "attempt-1"},
            tool_calls=[{"id": "call-1", "name": "read_file", "arguments": {}}],
        )
    )
    collector.record_message(
        Message(
            role="tool",
            content="{}",
            metadata={"name": "read_file", "success": True},
        )
    )

    metrics = collector.finish(
        verdict=CodingVerdict.TIMEOUT,
        agent_status="TIMEOUT",
        completion_status=None,
    )

    assert metrics.model_calls == 1
    assert metrics.model_turns == 1
    assert metrics.tool_calls == 1


def test_trace_collector_distinguishes_model_responses_in_one_agent_turn() -> None:
    collector = CodingTraceCollector(max_events=32, max_model_turns=4, max_tool_calls=8)
    for response_id, call_id in (("response-1", "call-1"), ("response-2", "call-2")):
        collector.record_message(
            Message(
                role="assistant",
                content="",
                event="tool_call",
                metadata={
                    "turn_id": "turn-1",
                    "attempt_id": "attempt-1",
                    "model_response_id": response_id,
                },
                tool_calls=[{"id": call_id, "name": "read_file", "arguments": {}}],
            )
        )

    metrics = collector.finish(
        verdict=CodingVerdict.TIMEOUT,
        agent_status="TIMEOUT",
        completion_status=None,
    )

    assert metrics.model_calls == 2
    assert metrics.model_turns == 2
    assert metrics.tool_calls == 2


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


@pytest.mark.parametrize(
    ("status", "reason_code"),
    (
        ("completed", "COMPLETED"),
        ("not_complete", "NOT_COMPLETE"),
        ("rejected", "REJECTED"),
        ("stale", "STALE"),
        ("authority_insufficient", "AUTHORITY_INSUFFICIENT"),
        ("error", "ERROR"),
    ),
)
def test_completion_observability_preserves_typed_gate_outcomes(
    status: str,
    reason_code: str,
) -> None:
    collector = CodingTraceCollector(max_events=32, run_id="run-gate-observation")
    collector.record_message(
        Message(
            role="system",
            content="completion proposal evaluated",
            event="completion_evaluated",
            metadata={"status": "accepted", "turn_id": "turn-1"},
        )
    )
    collector.record_message(
        Message(
            role="system",
            content="completion gate evaluated",
            event="completion_gated",
            metadata={
                "status": status,
                "reason": "model-controlled diagnostic text must not persist",
                "generation": "workspace-generation-1",
                "decision_digest": "a" * 64,
                "evidence_digest": "b" * 64,
                "turn_id": "turn-1",
            },
        )
    )

    metrics = collector.finish(
        verdict=CodingVerdict.PASS if status == "completed" else CodingVerdict.FAIL,
        agent_status="COMPLETED",
        completion_status=status,
    )

    completion = metrics.observability["completion"]
    assert completion["proposal_reached"] is True
    assert completion["gate_reached"] is True
    assert completion["gate_status"] == status
    assert completion["gate_reason_code"] == reason_code
    assert completion["gate_authority"] == "CompletionGate"
    assert completion["gate_generation"] == "workspace-generation-1"
    assert metrics.completion_acceptances == int(status == "completed")
    assert metrics.completion_rejections == int(status != "completed")
    assert completion["gate_evidence_digest"] == "b" * 64
    assert completion["decision_digest"] == "a" * 64
    assert "model-controlled diagnostic text" not in json.dumps(metrics.to_payload())
    assert collector.reconcile(metrics)["status"] == "PASS"


def test_completion_observability_distinguishes_not_reached_and_terminal() -> None:
    collector = CodingTraceCollector(max_events=32, run_id="run-gate-not-reached")
    collector.record_message(
        Message(
            role="system",
            content="terminal",
            event="done",
            metadata={"terminal_status": "timeout", "turn_id": "turn-1"},
        )
    )

    metrics = collector.finish(
        verdict=CodingVerdict.TIMEOUT,
        agent_status="TIMEOUT",
        completion_status="timeout",
    )

    completion = metrics.observability["completion"]
    assert completion["proposal_reached"] is False
    assert completion["gate_reached"] is False
    assert completion["gate_status"] == "NOT_REACHED"
    assert metrics.terminal_reason == "timeout"
    assert collector.reconcile(metrics)["status"] == "PASS"


def test_trace_metrics_capture_m8_7_extension_counters_and_context_bounds() -> None:
    collector = CodingTraceCollector()
    collector.record_context_metrics(
        SimpleNamespace(
            active_skills=2,
            extension_context_bytes=321,
            extension_tool_schema_bytes=123,
        )
    )
    collector.record_extension_metrics(
        {
            "extension_calls": 4,
            "mcp_calls": 3,
            "mcp_failures": 1,
            "hook_invocations": 2,
            "hook_failures": 1,
        }
    )
    metrics = collector.finish(
        verdict=CodingVerdict.PASS,
        agent_status="COMPLETED",
        completion_status="completed",
    )

    assert metrics.extension_calls == 4
    assert metrics.mcp_calls == 3
    assert metrics.mcp_failures == 1
    assert metrics.hook_invocations == 2
    assert metrics.hook_failures == 1
    assert metrics.active_skills == 2
    assert metrics.extension_context_bytes == 321
    assert metrics.extension_tool_schema_bytes == 123
    assert metrics.to_payload()["mcp_failures"] == 1


def test_trace_observer_limits_do_not_stop_agent_loop() -> None:
    collector = CodingTraceCollector(max_events=8, max_model_turns=1, max_tool_calls=1)
    collector.record_message(Message(role="assistant", content="first"))
    collector.record_message(Message(role="assistant", content="second"))

    metrics = collector.finish(
        verdict=CodingVerdict.PASS,
        agent_status="COMPLETED",
        completion_status="completed",
    )

    assert metrics.model_turns == 2
    assert metrics.trace_truncated is False


def test_trace_v2_preserves_exact_tool_names_and_categories() -> None:
    collector = CodingTraceCollector(max_events=32, run_id="run-exact")
    for index, name in enumerate(
        ("file_info", "list_directory", "tree_view", "file_search_content")
    ):
            collector.record_message(
                Message(
                    role="assistant",
                    content="",
                    event="tool_call",
                metadata={
                    "turn_id": f"turn-{index}",
                    "model_response_id": f"response-{index}",
                },
                tool_calls=[
                    {
                        "id": f"call-{index}",
                        "name": name,
                        "arguments": {"path": "src/example.py"},
                    }
                ],
            )
        )
            collector.record_message(
                Message(
                    role="tool",
                    content="",
                    tool_call_id=f"call-{index}",
                metadata={
                    "name": name,
                    "success": True,
                    "result_count": index + 1,
                    "output_digest": "a" * 64,
                },
            )
        )

    metrics = collector.finish(
        verdict=CodingVerdict.PASS,
        agent_status="COMPLETED",
        completion_status="completed",
    )

    assert metrics.tool_calls_by_exact_name == {
        "file_info": 1,
        "file_search_content": 1,
        "list_directory": 1,
        "tree_view": 1,
    }
    assert metrics.tool_calls_by_name == metrics.tool_calls_by_exact_name
    assert metrics.tool_calls_by_category["metadata"] == 1
    assert metrics.tool_calls_by_category["navigation"] == 2
    assert metrics.tool_calls_by_category["content_search"] == 1
    assert all(event.schema_version == 2 for event in collector.events)
    assert {event.tool_name for event in collector.events if event.event_type == "tool_call"} == {
        "file_info",
        "list_directory",
        "tree_view",
        "file_search_content",
    }


def test_trace_v2_binds_pending_results_and_redacts_canary() -> None:
    canary = "synthetic-trace-secret-7e3c"
    redactor = SecretRedactor()
    redactor.register(SecretValue(canary))
    collector = CodingTraceCollector(
        max_events=16,
        run_id="run-redaction",
        secret_redactor=redactor,
    )
    collector.record_message(
        Message(
            role="assistant",
            content="",
            event="tool_call",
            metadata={"turn_id": "turn-1", "model_response_id": "response-1"},
            tool_calls=[
                {
                    "id": "call-1",
                    "name": "read_file",
                    "arguments": {"path": "src/main.py", "query": canary},
                }
            ],
        )
    )
    collector.record_message(
        Message(
            role="tool",
            content="",
            tool_call_id="call-1",
            metadata={
                "name": "read_file",
                "success": False,
                "error_code": "PERMISSION_DENIED",
                "error": canary,
                "output": canary,
                "output_truncated": True,
            },
        )
    )
    collector.record_message(
        Message(
            role="system",
            content="",
            event="done",
            metadata={"terminal_status": "completed"},
        )
    )
    metrics = collector.finish(
        verdict=CodingVerdict.PASS,
        agent_status="COMPLETED",
        completion_status="completed",
    )

    payload = json.dumps([event.to_payload() for event in collector.events], sort_keys=True)
    assert canary not in payload
    result = next(event for event in collector.events if event.event_type == "tool_result")
    assert result.tool_call_id == "call-1"
    assert result.turn_id == "turn-1"
    assert result.tool_error_class == "PERMISSION_DENIED"
    assert result.result_truncated is True
    assert result.tool_state == "FAILURE"
    assert metrics.pending_tool_calls == 0
    assert metrics.tool_call_states == {"FAILURE": 1}
    assert any(event.event_type == "terminal" for event in collector.events)


def test_trace_capacity_marks_truncation_and_continues_accounting() -> None:
    collector = CodingTraceCollector(max_events=2, run_id="run-capacity")
    for index in range(4):
        collector.record("agent_event", f"event-{index}")

    metrics = collector.finish(
        verdict=CodingVerdict.PASS,
        agent_status="COMPLETED",
        completion_status="completed",
    )

    assert len(collector.events) == 2
    assert metrics.trace_truncated is True
    assert metrics.trace_dropped_event_count >= 2


def test_trace_v2_classifies_pending_and_unbound_results() -> None:
    collector = CodingTraceCollector(max_events=32, run_id="run-pending")
    collector.record_message(
        Message(
            role="assistant",
            content="",
            event="tool_call",
            metadata={"turn_id": "turn-1", "model_response_id": "response-1"},
            tool_calls=[
                {"id": "call-pending", "name": "read_file", "arguments": {}}
            ],
        )
    )
    collector.record_terminal("cancelled")
    collector.record_message(
        Message(
            role="tool",
            content="",
            tool_call_id="call-unbound",
            metadata={"name": "read_file", "success": True},
        )
    )

    metrics = collector.finish(
        verdict=CodingVerdict.TIMEOUT,
        agent_status="TIMEOUT",
        completion_status=None,
    )

    states = [
        event.tool_state
        for event in collector.events
        if event.event_type == "tool_result"
    ]
    assert states == ["CANCELLED", "MISSING_RESULT"]
    assert metrics.tool_call_states == {
        "CANCELLED": 1,
        "MISSING_RESULT": 1,
    }
    assert metrics.pending_tool_calls == 0


def test_trace_reconciliation_reports_observer_defect_without_mutating_runtime() -> None:
    collector = CodingTraceCollector(max_events=32, run_id="run-reconcile")
    collector.record_message(
        Message(
            role="assistant",
            content="",
            event="tool_call",
            metadata={"turn_id": "turn-1", "model_response_id": "response-1"},
            tool_calls=[{"id": "call-1", "name": "read_file", "arguments": {}}],
        )
    )
    metrics = collector.finish(
        verdict=CodingVerdict.PASS,
        agent_status="COMPLETED",
        completion_status="completed",
    )
    assert collector.reconcile(metrics)["status"] == "PASS"
    assert collector.reconcile(replace(metrics, tool_calls=metrics.tool_calls + 1))["status"] == (
        "OBSERVABILITY_DEFECT"
    )


def test_observability_records_response_gate_and_context_without_model_text() -> None:
    collector = CodingTraceCollector(max_events=32, run_id="run-observability")
    secret = "synthetic-observability-secret-4a1f"
    redactor = SecretRedactor()
    redactor.register(SecretValue(secret))
    collector.set_secret_redactor(redactor)
    selection = SimpleNamespace(
        selected=(
            SimpleNamespace(
                item_id="repo-item-1",
                kind=SimpleNamespace(value="document"),
                source=SimpleNamespace(value="repo_intelligence"),
                layer=SimpleNamespace(value="L1"),
                path="src/main.py",
                truncated=False,
                compressed=False,
            ),
            SimpleNamespace(
                item_id="tool-item-1",
                kind=SimpleNamespace(value="tool_output"),
                source=SimpleNamespace(value="tool"),
                layer=SimpleNamespace(value="L2"),
                path=None,
                truncated=True,
                compressed=False,
            ),
        ),
        evicted=(),
        compressed=(),
        truncated_count=1,
    )
    collector.record_context_selection(
        SimpleNamespace(
            context_digest="a" * 64,
            requirements_digest="b" * 64,
            cache_hit=False,
            partial=False,
            selection=selection,
            selection_identity=SimpleNamespace(
                selection_id="ctxsel-1",
                selection_sequence=1,
                selection_reason="INITIAL_BUILD",
                selection_digest=project_context_selection(selection)["selection_digest"],
            ),
        )
    )
    collector.record_response_observation(
        f'{{"findings":[],"note":"{secret}"}}',
        {
            "format": "PLAIN_JSON_OBJECT",
            "parse_attempted": True,
            "json_decode_status": "PASS",
            "schema_validation_status": "PASS",
            "typed_parse_status": "PASS",
            "typed_finding_count": 0,
        },
        turn_id="turn-1",
    )
    collector.record_message(
        Message(
            role="system",
            content="completion gate evaluated",
            event="completion_gated",
            metadata={
                "status": "rejected",
                "decision_digest": "c" * 64,
                "reason": secret,
                "task_id": "task-1",
            },
        )
    )
    metrics = collector.finish(
        verdict=CodingVerdict.FAIL,
        agent_status="COMPLETED",
        completion_status="completed",
    )

    payload = json.dumps(
        {"metrics": metrics.to_payload(), "events": [event.to_payload() for event in collector.events]},
        sort_keys=True,
    )
    assert secret not in payload
    assert metrics.observability_schema_version == 1
    assert metrics.observability["response_observability"]["present"] is True
    assert metrics.observability["completion"]["gate_reached"] is True
    assert metrics.observability["completion"]["gate_status"] == "rejected"
    assert metrics.observability["completion"]["gate_authority"] == "CompletionGate"
    assert metrics.observability["context"]["selected_repository_paths"] == ["src/main.py"]
    assert metrics.observability["context"]["automatic_repo_items_selected"] == 1
    assert metrics.observability["context"]["tool_acquired_items_selected"] == 1
    event_types = [event.event_type for event in collector.events]
    assert event_types.index("context_selected") < event_types.index("response_parse_evaluated")
    assert event_types.index("response_parse_evaluated") < event_types.index("completion_gated")
    assert collector.reconcile(metrics)["status"] == "PASS"
