"""Tests for CostTracker."""

from __future__ import annotations

from khaos.coding.cost_tracker import (
    DEFAULT_PRICE_PER_MILLION,
    CostTracker,
    SessionCostReport,
    TurnCost,
)


def test_add_tokens_accumulate_into_current_turn():
    tracker = CostTracker("s1")
    tracker.add_input_tokens(100)
    tracker.add_input_tokens(50)
    tracker.add_output_tokens(30)
    tracker.add_output_tokens(20)
    tracker.add_tool_tokens(10)
    tracker.add_tool_tokens(5)

    turn = tracker.finish_turn()
    assert turn.input_tokens == 150
    assert turn.output_tokens == 50
    assert turn.tool_tokens == 15
    assert turn.total_tokens == 215


def test_finish_turn_computes_total_and_estimated_cost():
    tracker = CostTracker(
        "s1",
        input_price_per_million=2.0,
        output_price_per_million=8.0,
    )
    tracker.add_input_tokens(1000)
    tracker.add_output_tokens(500)
    tracker.add_tool_tokens(200)

    turn = tracker.finish_turn()
    assert turn.turn_number == 1
    assert turn.total_tokens == 1700
    # input: 1000 * 2/1e6 = 0.002
    # output+tool: 700 * 8/1e6 = 0.0056
    # total: 0.0076
    assert abs(turn.estimated_cost_usd - 0.0076) < 1e-9


def test_finish_turn_resets_accumulators():
    tracker = CostTracker("s1")
    tracker.add_input_tokens(100)
    tracker.finish_turn()

    # Second turn starts empty.
    second = tracker.finish_turn()
    assert second.input_tokens == 0
    assert second.output_tokens == 0
    assert second.total_tokens == 0
    assert second.estimated_cost_usd == 0.0


def test_finish_turn_assigns_increasing_turn_numbers():
    tracker = CostTracker("s1")
    t1 = tracker.finish_turn()
    t2 = tracker.finish_turn()
    t3 = tracker.finish_turn()
    assert [t1.turn_number, t2.turn_number, t3.turn_number] == [1, 2, 3]


def test_get_report_aggregates_multiple_turns():
    tracker = CostTracker(
        "s1",
        input_price_per_million=2.0,
        output_price_per_million=8.0,
    )
    tracker.add_input_tokens(1000)
    tracker.add_output_tokens(500)
    tracker.add_tool_tokens(200)
    tracker.finish_turn()

    tracker.add_input_tokens(2000)
    tracker.add_output_tokens(1000)
    tracker.finish_turn()

    report = tracker.get_report()
    assert isinstance(report, SessionCostReport)
    assert report.session_id == "s1"
    assert report.turn_count == 2
    assert report.total_input_tokens == 3000
    assert report.total_output_tokens == 1500
    assert report.total_tool_tokens == 200
    assert report.total_tokens == 4700
    # turn1 cost 0.0076 + turn2 (input 2000*2/1e6=0.004, output 1000*8/1e6=0.008) = 0.012
    assert abs(report.total_estimated_cost_usd - (0.0076 + 0.012)) < 1e-9
    assert len(report.turns) == 2
    assert report.turns[0].turn_number == 1


def test_format_summary_contains_all_components():
    tracker = CostTracker("s1")
    tracker.add_input_tokens(8000)
    tracker.add_output_tokens(3500)
    tracker.add_tool_tokens(845)
    tracker.finish_turn()

    summary = tracker.format_summary()
    assert summary.startswith("📊 Session Cost:")
    assert "12,345 tokens" in summary  # 8000 + 3500 + 845
    assert "input: 8,000" in summary
    assert "output: 3,500" in summary
    assert "tools: 845" in summary
    assert "≈ $" in summary


def test_format_summary_returns_empty_when_no_tokens():
    tracker = CostTracker("s1")
    assert tracker.format_summary() == ""

    # Even after a zero-token turn, no tokens consumed → empty summary.
    tracker.finish_turn()
    assert tracker.format_summary() == ""


def test_current_turn_number_starts_at_one_and_increments():
    tracker = CostTracker("s1")
    assert tracker.current_turn_number == 1
    tracker.finish_turn()
    assert tracker.current_turn_number == 2
    tracker.finish_turn()
    assert tracker.current_turn_number == 3


def test_negative_token_counts_are_ignored():
    tracker = CostTracker("s1")
    tracker.add_input_tokens(-100)
    tracker.add_output_tokens(-50)
    tracker.add_tool_tokens(-10)
    turn = tracker.finish_turn()
    assert turn.input_tokens == 0
    assert turn.output_tokens == 0
    assert turn.tool_tokens == 0


def test_default_prices_match_constants():
    # Confirm the constructor falls back to DEFAULT_PRICE_PER_MILLION.
    tracker = CostTracker("s1")
    tracker.add_input_tokens(1_000_000)
    tracker.add_output_tokens(1_000_000)
    turn = tracker.finish_turn()
    assert abs(turn.estimated_cost_usd - (DEFAULT_PRICE_PER_MILLION["input"] + DEFAULT_PRICE_PER_MILLION["output"])) < 1e-6


def test_turn_cost_dataclass_defaults():
    cost = TurnCost(turn_number=1)
    assert cost.input_tokens == 0
    assert cost.output_tokens == 0
    assert cost.tool_tokens == 0
    assert cost.total_tokens == 0
    assert cost.estimated_cost_usd == 0.0
