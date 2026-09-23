"""Fresh real-provider qualification probes for the M8 coding gate.

The qualification gate is deliberately smaller than the coding benchmark.  It
only proves that one configured model can traverse the provider wire contract
and the production-shaped read-only AgentLoop path before a coding task is
allowed to run.  All returned data is bounded metadata; model text, tool
arguments, file contents, and credential material are never included.
"""

from __future__ import annotations

import asyncio
import hashlib
import shutil
import tempfile
import time
import uuid
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

from khaos.agent.core import Message
from khaos.db import Database
from khaos.evaluation.coding.contracts import (
    REVIEW_CATEGORY_CONTRACT_V3,
    CodingScenarioKind,
    CodingVerdict,
    ReviewOracleSpec,
    digest_payload,
)
from khaos.evaluation.coding.fixtures import FixtureManager
from khaos.evaluation.coding.manifest import (
    builtin_manifest_path,
    load_builtin_manifest,
)
from khaos.evaluation.coding.metrics import CodingTraceCollector
from khaos.evaluation.coding.oracle import ReviewFinding, evaluate_review_findings
from khaos.evaluation.coding.results import utc_timestamp
from khaos.evaluation.coding.runtime_invoker import RuntimeCodingAgentInvoker
from khaos.routing.model_client import ProviderRequestObservation

_DIRECT_PROBE_TIMEOUT_SECONDS = 45
_P3_TIMEOUT_SECONDS = 120
_P4_TIMEOUT_SECONDS = 300
_P3_MAX_TURNS = 8
_P3_MAX_TOOLS = 8
_P4_MAX_TURNS = 12
_P4_MAX_TOOLS = 24
_READ_ONLY_TOOL_NAMES = frozenset(
    {
        "read_file",
        "search_files",
        "list_directory",
        "file_info",
        "tree_view",
        "file_search_content",
        "code_search",
        "code_symbols",
        "git_diff",
        "git_log",
        "git_status",
        "git_pr_body",
    }
)


def _observation_summary(
    observations: Iterable[ProviderRequestObservation],
) -> dict[str, object]:
    """Return bounded provider-attempt metadata without response bodies."""

    values = tuple(observations)
    statuses = Counter(
        str(item.status_code) if item.status_code is not None else "NONE"
        for item in values
    )
    errors = Counter(item.provider_error_type or "none" for item in values)
    usage_rows = [
        (item.input_tokens, item.output_tokens, item.total_tokens)
        for item in values
        if any(
            token_count is not None
            for token_count in (
                item.input_tokens,
                item.output_tokens,
                item.total_tokens,
            )
        )
    ]
    usage_complete_count = sum(
        all(token_count is not None for token_count in row)
        for row in usage_rows
    )
    usage_totals = tuple(
        _sum_optional_ints(row[index] for row in usage_rows)
        for index in range(3)
    )
    returned_models = tuple(
        dict.fromkeys(
            item.response_model
            for item in values
            if item.response_model is not None
        )
    )
    usage_status = (
        "PROVIDER_NOT_REPORTED"
        if not usage_rows
        else "PROVIDER_REPORTED"
        if usage_complete_count == len(values)
        else "PROVIDER_PARTIAL"
    )
    return {
        "provider_requests": len(values),
        "provider_retries": sum(max(0, item.attempt - 1) for item in values),
        "statuses": dict(sorted(statuses.items())),
        "typed_provider_errors": dict(sorted(errors.items())),
        "input_tokens": usage_totals[0],
        "output_tokens": usage_totals[1],
        "total_tokens": usage_totals[2],
        "usage_status": usage_status,
        "provider_returned_model_id": (
            returned_models[0]
            if len(returned_models) == 1
            else "MULTIPLE / PROVIDER_REPORTED"
            if returned_models
            else "UNKNOWN / PROVIDER_NOT_REPORTED"
        ),
    }


def _provider_failure_class(
    observations: Iterable[ProviderRequestObservation],
    error: BaseException | None = None,
) -> str | None:
    """Map observed provider failures to stable, secret-free categories."""

    values = tuple(observations)
    for item in values:
        error_markers = " ".join(
            str(value or "")
            for value in (
                item.provider_error_type,
                item.provider_error_code,
                item.provider_message,
            )
        ).casefold()
        if any(
            marker in error_markers
            for marker in (
                "context_length",
                "context limit",
                "context window",
                "token limit",
                "too many tokens",
                "request too large",
            )
        ) or item.status_code in {413}:
            return "PROVIDER_CONTEXT_LIMIT"
        if any(
            marker in error_markers
            for marker in (
                "invalid_model",
                "model_not_found",
                "model not found",
                "unknown model",
            )
        ):
            return "PROVIDER_INVALID_MODEL_OR_ENDPOINT"
        if item.status_code in {401, 403}:
            return "PROVIDER_AUTHENTICATION"
        if item.status_code == 404:
            return "PROVIDER_INVALID_MODEL_OR_ENDPOINT"
        if item.status_code == 429 or item.provider_error_type == "rate_limit":
            return "PROVIDER_RATE_LIMIT"
        if item.status_code is not None and 500 <= item.status_code <= 599:
            return (
                "PROVIDER_INTERNAL_ERROR"
                if any(marker in error_markers for marker in ("internal", "server_error"))
                else "PROVIDER_UNAVAILABLE"
            )
        if item.provider_error_type in {"context_limit", "context_length"}:
            return "PROVIDER_CONTEXT_LIMIT"
        if item.provider_error_type in {"invalid_model", "model_not_found"}:
            return "PROVIDER_INVALID_MODEL_OR_ENDPOINT"
        if item.provider_error_type == "transport_error":
            return "PROVIDER_TRANSPORT"
        if item.provider_error_type == "http_error":
            return "PROVIDER_HTTP_ERROR"
        if item.provider_error_type == "internal_error":
            return "PROVIDER_INTERNAL_ERROR"
        if item.provider_error_type == "timeout":
            return "PROVIDER_TIMEOUT"
    if isinstance(error, TimeoutError) or _has_timeout_cause(error):
        return "PROVIDER_TIMEOUT"
    if error is not None and type(error).__name__ in {
        "ProviderError",
        "ModelRateLimitError",
        "ModelUnavailableError",
    }:
        return "PROVIDER_ADAPTER_ERROR"
    return None


def _has_timeout_cause(error: BaseException | None) -> bool:
    """Detect wrapped transport timeouts without retaining provider text."""

    current = error
    for _ in range(4):
        if current is None:
            return False
        if "timeout" in type(current).__name__.casefold():
            return True
        current = current.__cause__ or current.__context__
    return False


def _terminal_response(messages: Iterable[Message]) -> bool:
    """Return whether a provider stream delivered a normal terminal marker."""

    return any(
        message.stop_reason in {"end_turn", "stop"}
        for message in messages
        if isinstance(message, Message)
    )


def _assistant_text(messages: Iterable[Message]) -> str:
    """Join response text in memory for a tiny semantic check only."""

    return "".join(
        message.content
        for message in messages
        if isinstance(message, Message) and message.role == "assistant"
    )


def _tool_calls(messages: Iterable[Message]) -> list[dict[str, object]]:
    """Project provider tool calls to a bounded in-memory list."""

    calls: list[dict[str, object]] = []
    for message in messages:
        if not isinstance(message, Message):
            continue
        for call in message.tool_calls[:8]:
            if isinstance(call, dict):
                calls.append(call)
            if len(calls) >= 8:
                return calls
    return calls


def _is_valid_echo_call(call: Mapping[str, object]) -> bool:
    """Validate the bounded synthetic P1 tool-call shape."""

    arguments = call.get("arguments")
    return (
        call.get("name") == "echo_ack"
        and isinstance(arguments, Mapping)
        and arguments.get("value") == "ACK"
    )


async def _stream_direct(
    router: Any,
    messages: list[Message],
    *,
    tools: list[dict[str, object]] | None = None,
    timeout_seconds: int = _DIRECT_PROBE_TIMEOUT_SECONDS,
) -> list[Message]:
    """Run one direct provider probe through the configured router."""

    result: list[Message] = []
    async with asyncio.timeout(timeout_seconds):
        async for message in router.call("coding", messages, tools=tools):
            if len(result) >= 64:
                raise ValueError("qualification response chunk bound exceeded")
            result.append(message)
    return result


def _full_production_tool_schemas() -> list[dict[str, object]]:
    """Build the actual coding registry schema surface without executing tools."""

    # Keep this import lazy: the product CLI establishes the normal package
    # import order before qualification starts, while direct library imports
    # should not create a new circular-import edge.
    from khaos.tools import create_runtime_registry

    registry = create_runtime_registry()
    return [
        {
            "type": "function",
            "function": {
                "name": definition.name,
                "description": definition.description,
                "parameters": definition.parameters,
            },
        }
        for definition in registry.list_by_mode("coding")
    ]


def _trace_payload(trace: CodingTraceCollector) -> list[dict[str, object]]:
    """Retain the complete bounded Trace v2 projection."""

    return [event.to_payload() for event in trace.events]


def evaluate_p4_v2_findings(
    findings: Iterable[ReviewFinding],
    oracle: object,
    *,
    completed: bool,
    side_effect_free: bool,
) -> tuple[bool, dict[str, object]]:
    """Evaluate P4-v2 evidence without treating effort as correctness.

    The task is intentionally a read-only repository-understanding probe.  Its
    oracle is the public typed review contract, while completion and the
    read-only invariant remain independent runtime facts.  Tool/turn counts
    are reported as metrics but are not acceptance criteria.
    """

    required = getattr(oracle, "required_findings", ())
    allow_extra = getattr(oracle, "allow_extra_findings", True)
    match_mode = str(getattr(getattr(oracle, "match_mode", "ALL"), "value", "ALL"))
    actual = tuple(findings)
    matched: list[str] = []
    used: set[int] = set()
    duplicate_indices: set[int] = set()
    for expected in required:
        candidates = [
            index
            for index, finding in enumerate(actual)
            if (
                expected.category.casefold() == finding.category.casefold()
                and expected.file == finding.file
                and all(
                    concept.casefold()
                    in {item.casefold() for item in finding.concepts}
                    for concept in expected.concepts
                )
            )
        ]
        unused = [index for index in candidates if index not in used]
        if unused:
            used.add(unused[0])
            matched.append(expected.finding_id)
            duplicate_indices.update(unused[1:])
        else:
            duplicate_indices.update(candidates)
    false_positive_indices = set(range(len(actual))) - used - duplicate_indices
    extra_count = len(duplicate_indices) + len(false_positive_indices)
    findings_pass = (
        len(matched) == len(required)
        if match_mode == "ALL"
        else bool(matched)
    )
    if not allow_extra and extra_count:
        findings_pass = False
    passed = bool(completed and side_effect_free and findings_pass)
    return passed, {
        "review_findings_pass": findings_pass,
        "matched_finding_ids": matched,
        "required_finding_count": len(required),
        "submitted_finding_count": len(actual),
        "extra_finding_count": extra_count,
        "normal_completion": completed,
        "read_only_invariant": side_effect_free,
    }


def evaluate_p4_v3_findings(
    findings: Iterable[ReviewFinding],
    oracle: object,
    *,
    completed: bool,
    side_effect_free: bool,
    response_observation: Mapping[str, object] | None = None,
) -> tuple[bool, dict[str, object]]:
    """Evaluate P4-v3 findings using the canonical typed review contract."""

    actual = tuple(findings)
    if not isinstance(oracle, ReviewOracleSpec):
        return False, {
            "review_findings_pass": False,
            "failure_class": "OUTPUT_CONTRACT_FAILURE",
            "category_contract": REVIEW_CATEGORY_CONTRACT_V3,
            "normal_completion": completed,
            "read_only_invariant": side_effect_free,
        }
    if oracle.category_contract != REVIEW_CATEGORY_CONTRACT_V3:
        return False, {
            "review_findings_pass": False,
            "failure_class": "OUTPUT_CONTRACT_FAILURE",
            "category_contract": oracle.category_contract,
            "normal_completion": completed,
            "read_only_invariant": side_effect_free,
        }
    if isinstance(response_observation, Mapping) and any(
        response_observation.get(name) == "FAIL"
        for name in (
            "json_decode_status",
            "schema_validation_status",
            "typed_parse_status",
        )
    ):
        return False, {
            "review_findings_pass": False,
            "failure_class": "OUTPUT_CONTRACT_FAILURE",
            "evaluation_layer": "OUTPUT_CONTRACT_FAILURE",
            "semantic_evaluation": "NOT_ATTEMPTED",
            "category_contract": REVIEW_CATEGORY_CONTRACT_V3,
            "required_finding_count": len(oracle.required_findings),
            "submitted_finding_count": len(actual),
            "normal_completion": completed,
            "read_only_invariant": side_effect_free,
        }
    check = evaluate_review_findings(oracle, actual)
    passed = bool(completed and side_effect_free and check.passed)
    evidence = dict(check.evidence)
    evidence.update(
        {
            "review_findings_pass": check.passed,
            "failure_class": None if check.passed else "SEMANTIC_REVIEW_FAILURE",
            "evaluation_layer": "SEMANTIC_REVIEW",
            "semantic_evaluation": "PERFORMED",
            "category_contract": REVIEW_CATEGORY_CONTRACT_V3,
            "normal_completion": completed,
            "read_only_invariant": side_effect_free,
        }
    )
    return passed, evidence


def _runtime_metrics(
    trace: CodingTraceCollector,
    *,
    agent_status: str,
    completion_status: str | None,
):
    """Create a local metrics snapshot without persisting a benchmark result."""

    verdict = (
        CodingVerdict.PASS
        if agent_status == "COMPLETED"
        else CodingVerdict.AGENT_ERROR
    )
    return trace.finish(
        verdict=verdict,
        agent_status=agent_status,
        completion_status=completion_status,
    )


async def _run_read_only_agent_probe(
    router: Any,
    database: Database,
    observations: list[ProviderRequestObservation],
    *,
    run_id: str,
    model: str,
    provider: str,
    probe: str,
    prompt: str,
    timeout_seconds: int,
    max_model_turns: int,
    max_tool_calls: int,
    principal_id: str,
    project_id: str,
    private_root: Path,
    p4_scenario_id: str = "p4-readonly-authority",
) -> dict[str, object]:
    """Run P3 or P4 through the real AgentLoop on a disposable fixture."""

    manifest = load_builtin_manifest()
    base = manifest.get(
        p4_scenario_id if probe == "P4" else "bugfix-python-cache"
    )
    scenario = replace(
        base,
        kind=CodingScenarioKind.CODE_REVIEW,
        user_prompt=prompt,
        digest="",
        limits=replace(
            base.limits,
            timeout_seconds=float(timeout_seconds),
            max_model_turns=max_model_turns,
            max_tool_calls=max_tool_calls,
            max_tool_events=max(128, max_tool_calls * 8),
        ),
    )
    fixture_manager = FixtureManager(
        builtin_manifest_path(),
        private_root=private_root / f"{probe}-fixtures",
    )
    fixture = None
    agent = None
    trace = CodingTraceCollector(
        max_events=max(128, max_tool_calls * 8),
        max_model_turns=max_model_turns,
        max_tool_calls=max_tool_calls,
        run_id=run_id,
    )
    started_observations = len(observations)
    started = time.monotonic()
    cleanup_ok = True
    source_unchanged: bool | None = None
    fixture_digest: str | None = None
    repository_base_revision: str | None = None
    error: BaseException | None = None
    try:
        fixture = await fixture_manager.materialize(scenario)
        fixture_digest = fixture.fixture_digest
        repository_base_revision = fixture.base_revision
        invoker = RuntimeCodingAgentInvoker(
            database,
            router,
            principal_id=principal_id,
            project_id=project_id,
            model=model,
            provider=provider,
        )
        try:
            async with asyncio.timeout(timeout_seconds + 30):
                agent = await invoker.run(scenario, fixture, trace)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - bounded probe boundary
            error = exc
        if agent is not None and agent.completed:
            try:
                final_root = agent.final_root
                if not isinstance(final_root, (str, Path)):
                    raise TypeError("agent final root is not path-like")
                source_unchanged = (
                    fixture.digest_evaluated_tree(Path(final_root))
                    == fixture.source_digest
                )
            except (OSError, ValueError):
                source_unchanged = False
        metrics = _runtime_metrics(
            trace,
            agent_status=agent.status if agent is not None else "ERROR",
            completion_status=(agent.completion_status if agent is not None else None),
        )
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # noqa: BLE001 - bounded probe boundary
        error = exc
        metrics = _runtime_metrics(
            trace,
            agent_status="ERROR",
            completion_status=None,
        )
    finally:
        if agent is not None and agent.cleanup is not None:
            try:
                await asyncio.shield(agent.cleanup())
            except BaseException:  # noqa: BLE001 - cleanup is reported, not raised
                cleanup_ok = False
        if fixture is not None:
            try:
                await asyncio.shield(fixture.cleanup())
            except BaseException:  # noqa: BLE001 - cleanup is reported, not raised
                cleanup_ok = False

    tool_names = set(metrics.tool_calls_by_name)
    side_effect_free = (
        metrics.editing_calls == 0
        and metrics.terminal_calls == 0
        and metrics.test_calls == 0
        and metrics.browser_calls == 0
        and not (tool_names - _READ_ONLY_TOOL_NAMES)
        and source_unchanged is True
    )
    completed = agent is not None and agent.completed
    stage_observations = observations[started_observations:]
    provider_failure = _provider_failure_class(stage_observations, error)
    if error is not None:
        failure_class = provider_failure or type(error).__name__
    elif not completed:
        failure_class = provider_failure or (
            "TOOL_BUDGET_EXHAUSTED"
            if agent is not None
            and (
                agent.status == "TOOL_BUDGET_EXHAUSTED"
                or metrics.terminal_reason == "TOOL_BUDGET_EXHAUSTED"
            )
            else "AGENT_LOOP_FAILURE"
        )
    elif not side_effect_free:
        failure_class = "READ_ONLY_CONTRACT_FAILURE"
    else:
        failure_class = None
    p4_evidence: dict[str, object] | None = None
    if probe == "P3":
        semantic_pass = (
            completed
            and metrics.read_file_calls >= 1
            and side_effect_free
        )
    else:
        if scenario.review_category_contract == REVIEW_CATEGORY_CONTRACT_V3:
            response_observation = metrics.observability.get(
                "response_observability"
            )
            semantic_pass, p4_evidence = evaluate_p4_v3_findings(
                agent.review_findings if agent is not None else (),
                scenario.oracle,
                completed=completed,
                side_effect_free=side_effect_free,
                response_observation=(
                    response_observation
                    if isinstance(response_observation, Mapping)
                    else None
                ),
            )
        else:
            semantic_pass, p4_evidence = evaluate_p4_v2_findings(
                agent.review_findings if agent is not None else (),
                scenario.oracle,
                completed=completed,
                side_effect_free=side_effect_free,
            )
        if (
            isinstance(p4_evidence, Mapping)
            and isinstance(p4_evidence.get("failure_class"), str)
        ):
            failure_class = p4_evidence["failure_class"]
        trace.record_semantic_review(p4_evidence)
        metrics = _runtime_metrics(
            trace,
            agent_status=agent.status if agent is not None else "ERROR",
            completion_status=(agent.completion_status if agent is not None else None),
        )
    if provider_failure is not None:
        semantic_pass = False
    payload: dict[str, object] = {
        "probe": probe,
        "result": "PASS" if semantic_pass else "FAIL",
        "real_model": True,
        "real_agent_loop": True,
        "agent_status": agent.status if agent is not None else "ERROR",
        "completion_status": agent.completion_status if agent is not None else None,
        "model_turns": metrics.model_turns,
        "tool_calls": metrics.tool_calls,
        "tool_calls_by_name": dict(sorted(metrics.tool_calls_by_name.items())),
        "tool_calls_by_exact_name": dict(
            sorted(metrics.tool_calls_by_exact_name.items())
        ),
        "tool_calls_by_category": dict(
            sorted(metrics.tool_calls_by_category.items())
        ),
        "read_file_calls": metrics.read_file_calls,
        "editing_calls": metrics.editing_calls,
        "terminal_calls": metrics.terminal_calls,
        "test_calls": metrics.test_calls,
        "browser_calls": metrics.browser_calls,
        "completion_acceptances": metrics.completion_acceptances,
        "completion_rejections": metrics.completion_rejections,
        "source_unchanged": source_unchanged,
        "fixture_digest": fixture_digest,
        "repository_base_revision": repository_base_revision,
        "scenario_id": scenario.scenario_id,
        "scenario_version": scenario.version,
        "scenario_digest": scenario.digest,
        "review_category_contract": scenario.review_category_contract,
        "side_effect_free": side_effect_free,
        "cleanup_ok": cleanup_ok,
        "trace_event_count": len(trace.events),
        "trace_digest": metrics.trace_digest,
        "trace": _trace_payload(trace),
        "trace_schema_version": metrics.trace_schema_version,
        "trace_truncated": metrics.trace_truncated,
        "trace_dropped_event_count": metrics.trace_dropped_event_count,
        "trace_reconciliation": trace.reconcile(metrics),
        "observability_schema_version": metrics.observability_schema_version,
        "observability": metrics.observability,
        "response_observability": metrics.observability.get(
            "response_observability", {}
        ),
        "completion_observability": metrics.observability.get("completion", {}),
        "repository_context_observability": metrics.observability.get(
            "repository_context", {}
        ),
        "context_observability": metrics.observability.get("context", {}),
        "semantic_review_observability": metrics.observability.get(
            "semantic_review", {}
        ),
        "pending_tool_calls": metrics.pending_tool_calls,
        "tool_call_states": dict(sorted(metrics.tool_call_states.items())),
        "terminal_reason": metrics.terminal_reason,
        "budget": {
            "max_model_turns": max_model_turns,
            "max_tool_calls": max_tool_calls,
            "timeout_seconds": timeout_seconds,
        },
        "p4_evidence": p4_evidence if probe == "P4" else None,
        "provider_failure_class": provider_failure,
        "failure_class": failure_class,
        **_observation_summary(stage_observations),
        "elapsed_ms": int((time.monotonic() - started) * 1000),
    }
    return payload


def _stage_result(
    *,
    name: str,
    result: str,
    started: float,
    observations: list[ProviderRequestObservation],
    response: list[Message] | None = None,
    error: BaseException | None = None,
    extra: dict[str, object] | None = None,
) -> dict[str, object]:
    """Build a bounded direct-probe result."""

    stage_observations = observations
    provider_failure = _provider_failure_class(stage_observations, error)
    payload: dict[str, object] = {
        "probe": name,
        "result": result,
        "terminal_response": (
            _terminal_response(response) if response is not None else False
        ),
        "response_chunks": len(response) if response is not None else 0,
        "provider_failure_class": provider_failure,
        "failure_class": provider_failure or (type(error).__name__ if error else None),
        **_observation_summary(stage_observations),
        "elapsed_ms": int((time.monotonic() - started) * 1000),
    }
    if extra:
        payload.update(extra)
    return payload


async def run_provider_qualification(
    router: Any,
    *,
    model: str,
    provider: str,
    observations: list[ProviderRequestObservation],
    principal_id: str,
    project_id: str,
    config_digest: str,
    source_sha: str,
    working_tree_identity: str | None = None,
    policy_digest: str | None = None,
    credential_ref: str | None = None,
    p4_scenario_id: str = "p4-readonly-authority",
) -> dict[str, object]:
    """Run fresh P0-P4 qualification probes sequentially.

    The caller is responsible for constructing the router and explicitly
    unlocking its CredentialSession before invoking this function.  A failed
    stage stops the sequence and no later provider request is attempted.
    """

    run_id = f"m8-qualification-{uuid.uuid4().hex}"
    private_root = Path(tempfile.mkdtemp(prefix="khaos-m8-qualification-"))
    database = Database(private_root / "state.db")
    manifest = load_builtin_manifest()
    stages: list[dict[str, object]] = []
    started = time.monotonic()
    started_at = utc_timestamp()

    async def direct_stage(
        name: str,
        messages: list[Message],
        *,
        tools: list[dict[str, object]] | None = None,
        validator: Any,
    ) -> bool:
        before = len(observations)
        stage_started = time.monotonic()
        response: list[Message] | None = None
        error: BaseException | None = None
        try:
            response = await _stream_direct(router, messages, tools=tools)
            passed, extra = validator(response)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - provider probe boundary
            passed = False
            extra = {}
            error = exc
        stage = _stage_result(
            name=name,
            result="PASS" if passed else "FAIL",
            started=stage_started,
            observations=observations[before:],
            response=response,
            error=error,
            extra=extra,
        )
        stages.append(stage)
        return bool(passed) and stage.get("provider_failure_class") is None

    try:
        await database.connect()
        await database.run_migrations()

        if not await direct_stage(
            "P0",
            [Message(role="user", content="Reply exactly ACK.")],
            validator=lambda response: (
                _assistant_text(response).strip().upper() == "ACK"
                and not _tool_calls(response)
                and _terminal_response(response),
                {
                    "ack_exact": _assistant_text(response).strip().upper() == "ACK",
                    "tool_calls": len(_tool_calls(response)),
                },
            ),
        ):
            return _qualification_payload(
                run_id,
                model,
                provider,
                config_digest,
                source_sha,
                stages,
                started,
                started_at=started_at,
                working_tree_identity=working_tree_identity,
                policy_digest=policy_digest,
                credential_ref=credential_ref,
                p4_scenario_id=p4_scenario_id,
            )

        synthetic_tool = [
            {
                "type": "function",
                "function": {
                    "name": "echo_ack",
                    "description": "Return the supplied acknowledgement value.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "value": {"type": "string", "enum": ["ACK"]},
                        },
                        "required": ["value"],
                        "additionalProperties": False,
                    },
                },
            }
        ]
        p1_before = len(observations)
        p1_started = time.monotonic()
        p1_first: list[Message] | None = None
        p1_second: list[Message] | None = None
        p1_error: BaseException | None = None
        try:
            p1_first = await _stream_direct(
                router,
                [
                    Message(
                        role="user",
                        content=(
                            "Call the synthetic echo_ack tool exactly once with "
                            '{"value":"ACK"}, then wait for its result and finish.'
                        ),
                    )
                ],
                tools=synthetic_tool,
            )
            calls = _tool_calls(p1_first)
            valid_call = next(
                (
                    call
                    for call in calls
                    if _is_valid_echo_call(call)
                ),
                None,
            )
            if valid_call is None:
                raise ValueError("synthetic tool call was not valid")
            call_id = str(valid_call.get("id") or "qualification-call")
            assistant_call = Message(
                role="assistant",
                content="",
                tool_calls=[valid_call],
                stop_reason="tool_use",
            )
            p1_second = await _stream_direct(
                router,
                [
                    Message(
                        role="user",
                        content=(
                            "Call the synthetic echo_ack tool exactly once with "
                            '{"value":"ACK"}, then wait for its result and finish.'
                        ),
                    ),
                    assistant_call,
                    Message(
                        role="tool",
                        tool_call_id=call_id,
                        content='{"ok":true,"value":"ACK"}',
                    ),
                ],
                tools=synthetic_tool,
            )
            p1_passed = _terminal_response(p1_second) and not _tool_calls(p1_second)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - provider probe boundary
            p1_passed = False
            p1_error = exc
        p1_calls = _tool_calls(p1_first or [])
        p1_stage = _stage_result(
            name="P1",
            result="PASS" if p1_passed else "FAIL",
            started=p1_started,
            observations=observations[p1_before:],
            response=p1_second or p1_first,
            error=p1_error,
            extra={
                "synthetic_tool": "echo_ack",
                "valid_tool_call": any(_is_valid_echo_call(call) for call in p1_calls),
                "tool_calls": len(p1_calls),
                "tool_result_round_trip": p1_second is not None,
            },
        )
        stages.append(p1_stage)
        if not p1_passed or p1_stage.get("provider_failure_class") is not None:
            return _qualification_payload(
                run_id,
                model,
                provider,
                config_digest,
                source_sha,
                stages,
                started,
                started_at=started_at,
                working_tree_identity=working_tree_identity,
                policy_digest=policy_digest,
                credential_ref=credential_ref,
                p4_scenario_id=p4_scenario_id,
            )

        production_tools = _full_production_tool_schemas()
        surface_digest = hashlib.sha256(
            repr(production_tools).encode("utf-8")
        ).hexdigest()
        if not await direct_stage(
            "P2",
            [
                Message(
                    role="user",
                    content=(
                        "This is a production tool-schema compatibility probe. "
                        "Do not call any tool. Reply exactly SURFACE_ACK."
                    ),
                )
            ],
            tools=production_tools,
            validator=lambda response: (
                _terminal_response(response) or bool(_tool_calls(response)),
                {
                    "production_tool_count": len(production_tools),
                    "production_tool_schema_digest": surface_digest,
                    "unexpected_tool_calls": len(_tool_calls(response)),
                },
            ),
        ):
            return _qualification_payload(
                run_id,
                model,
                provider,
                config_digest,
                source_sha,
                stages,
                started,
                started_at=started_at,
                working_tree_identity=working_tree_identity,
                policy_digest=policy_digest,
                credential_ref=credential_ref,
                p4_scenario_id=p4_scenario_id,
            )

        p3 = await _run_read_only_agent_probe(
            router,
            database,
            observations,
            model=model,
            provider=provider,
            run_id=run_id,
            probe="P3",
            prompt=(
                "This is a read-only AgentLoop qualification probe. Use the "
                "available read_file tool to inspect public file src/cache.py. "
                "Do not edit files, run commands, use network/browser tools, or "
                "call any write or test tool. After the read, reply briefly."
            ),
            timeout_seconds=_P3_TIMEOUT_SECONDS,
            max_model_turns=_P3_MAX_TURNS,
            max_tool_calls=_P3_MAX_TOOLS,
            principal_id=principal_id,
            project_id=project_id,
            private_root=private_root,
        )
        stages.append(p3)
        if p3.get("result") != "PASS" or p3.get("provider_failure_class") is not None:
            return _qualification_payload(
                run_id,
                model,
                provider,
                config_digest,
                source_sha,
                stages,
                started,
                started_at=started_at,
                working_tree_identity=working_tree_identity,
                policy_digest=policy_digest,
                credential_ref=credential_ref,
                p4_scenario_id=p4_scenario_id,
            )
        stages.append(
            await _run_read_only_agent_probe(
                router,
                database,
                observations,
                model=model,
                provider=provider,
                run_id=run_id,
                probe="P4",
                prompt=manifest.get(p4_scenario_id).user_prompt,
                timeout_seconds=_P4_TIMEOUT_SECONDS,
                max_model_turns=_P4_MAX_TURNS,
                max_tool_calls=_P4_MAX_TOOLS,
                principal_id=principal_id,
                project_id=project_id,
                private_root=private_root,
                p4_scenario_id=p4_scenario_id,
            )
        )
        return _qualification_payload(
            run_id,
            model,
            provider,
            config_digest,
            source_sha,
            stages,
            started,
            started_at=started_at,
            working_tree_identity=working_tree_identity,
            policy_digest=policy_digest,
            credential_ref=credential_ref,
            p4_scenario_id=p4_scenario_id,
        )
    finally:
        await database.close()
        await asyncio.to_thread(shutil.rmtree, private_root, True)


def _qualification_payload(
    run_id: str,
    model: str,
    provider: str,
    config_digest: str,
    source_sha: str,
    stages: list[dict[str, object]],
    started: float,
    *,
    started_at: str | None = None,
    working_tree_identity: str | None = None,
    policy_digest: str | None = None,
    credential_ref: str | None = None,
    p4_scenario_id: str = "p4-readonly-authority",
) -> dict[str, object]:
    """Build the final safe qualification record."""

    passed = bool(stages) and all(stage.get("result") == "PASS" for stage in stages)
    manifest = load_builtin_manifest()
    p4_scenario = manifest.get(p4_scenario_id)
    p4_stage = next(
        (stage for stage in stages if stage.get("probe") == "P4"),
        {},
    )
    p2_stage = next(
        (stage for stage in stages if stage.get("probe") == "P2"),
        {},
    )
    suite_payload = {
        "suite_id": "m8-provider-qualification",
        "suite_version": 2,
        "p4_scenario_digest": p4_scenario.digest,
        "p3_budget": {
            "max_model_turns": _P3_MAX_TURNS,
            "max_tool_calls": _P3_MAX_TOOLS,
            "timeout_seconds": _P3_TIMEOUT_SECONDS,
        },
        "p4_budget": {
            "max_model_turns": _P4_MAX_TURNS,
            "max_tool_calls": _P4_MAX_TOOLS,
            "timeout_seconds": _P4_TIMEOUT_SECONDS,
        },
    }
    if p4_scenario_id != "p4-readonly-authority":
        suite_payload["p4_scenario_id"] = p4_scenario_id
    prompt_path = Path(__file__).resolve().parents[4] / "prompts" / "coding.md"
    system_prompt_digest = (
        hashlib.sha256(prompt_path.read_bytes()).hexdigest()
        if prompt_path.is_file()
        else None
    )
    finished_at = utc_timestamp()
    returned_model_ids = tuple(
        dict.fromkeys(
            str(stage["provider_returned_model_id"])
            for stage in stages
            if isinstance(stage, Mapping)
            and isinstance(stage.get("provider_returned_model_id"), str)
            and not str(stage["provider_returned_model_id"]).startswith("UNKNOWN /")
        )
    )
    usage_rows = [
        (
            stage.get("input_tokens"),
            stage.get("output_tokens"),
            stage.get("total_tokens"),
        )
        for stage in stages
        if isinstance(stage, Mapping)
        and any(
            type(stage.get(name)) is int
            for name in ("input_tokens", "output_tokens", "total_tokens")
        )
    ]
    usage_complete_count = sum(
        all(type(row[index]) is int for index in range(3))
        for row in usage_rows
    )
    usage_totals = tuple(
        _sum_optional_ints(row[index] for row in usage_rows)
        for index in range(3)
    )
    usage_statuses = {
        str(stage.get("usage_status"))
        for stage in stages
        if isinstance(stage, Mapping)
        and isinstance(stage.get("usage_status"), str)
    }
    qualification_usage_status = (
        "PROVIDER_REPORTED"
        if usage_rows
        and usage_complete_count == len(stages)
        and usage_statuses <= {"PROVIDER_REPORTED"}
        else "PROVIDER_PARTIAL"
        if usage_rows
        else "PROVIDER_NOT_REPORTED"
    )
    return {
        "schema_version": 1,
        "qualification_version": 2,
        "observability_schema_version": 1,
        "qualification": "PASS" if passed and len(stages) == 5 else "FAIL",
        "run_id": run_id,
        "provider": provider,
        "model": model,
        "provider_returned_model_id": (
            returned_model_ids[0]
            if len(returned_model_ids) == 1
            else "MULTIPLE / PROVIDER_REPORTED"
            if returned_model_ids
            else "UNKNOWN / PROVIDER_NOT_REPORTED"
        ),
        "adapter": "ModelRouter -> ModelClient -> openai_compatible",
        "source_sha": source_sha,
        "config_digest": config_digest,
        "provider_config_digest": config_digest,
        "working_tree_identity": working_tree_identity,
        "credential_ref": credential_ref,
        "suite_id": suite_payload["suite_id"],
        "suite_version": suite_payload["suite_version"],
        "suite_digest": digest_payload(suite_payload),
        "scenario_id": p4_scenario.scenario_id,
        "scenario_version": p4_scenario.version,
        "scenario_digest": p4_scenario.digest,
        "fixture_digest": p4_stage.get("fixture_digest"),
        "repository_base_revision": p4_stage.get("repository_base_revision"),
        "prompt_digest": hashlib.sha256(
            p4_scenario.user_prompt.encode("utf-8")
        ).hexdigest(),
        "system_prompt_digest": system_prompt_digest,
        "tool_schema_digest": p2_stage.get("production_tool_schema_digest"),
        "policy_digest": policy_digest,
        "budgets": {
            "p3": suite_payload["p3_budget"],
            "p4": suite_payload["p4_budget"],
        },
        "reasoning_configuration": {
            "reasoning_effort": "UNKNOWN / NOT_REPORTED",
            "sampling": "UNKNOWN / NOT_REPORTED",
        },
        "started_at": started_at or finished_at,
        "finished_at": finished_at,
        "stages": stages,
        "observability_reconciliation": [
            stage.get("trace_reconciliation")
            for stage in stages
            if stage.get("trace_reconciliation") is not None
        ],
        "provider_requests": sum(
            _provider_request_count(stage) for stage in stages
        ),
        "input_tokens": usage_totals[0],
        "output_tokens": usage_totals[1],
        "total_tokens": usage_totals[2],
        "usage_status": qualification_usage_status,
        "secret_values_printed": False,
        "elapsed_ms": int((time.monotonic() - started) * 1000),
    }


def _provider_request_count(stage: Mapping[str, object]) -> int:
    """Read one already-sanitized provider request count."""

    value = stage.get("provider_requests")
    return value if type(value) is int and value >= 0 else 0


def _sum_optional_ints(values: Iterable[object]) -> int | None:
    """Sum present integer values without treating missing usage as zero."""

    present = [value for value in values if type(value) is int]
    return sum(cast(int, value) for value in present) if present else None


__all__ = [
    "evaluate_p4_v2_findings",
    "evaluate_p4_v3_findings",
    "run_provider_qualification",
]
