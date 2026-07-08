"""Tests for SubAgentRunner (Phase 8).

Focuses on the pure helpers (_build_subagent_system_prompt / _collect_result).
A full ``run()`` integration is intentionally skipped — it would require
mocking the entire AgentLoop / router / db / tool scheduler stack.
"""
from __future__ import annotations

import pytest

from khaos.agent.core import Message
from khaos.subagents.runner import SubAgentRunner
from khaos.subagents.spawner import SubAgentTask


def _runner(**overrides) -> SubAgentRunner:
    """Build a SubAgentRunner with placeholder dependencies (not exercised here)."""
    defaults = dict(
        router=object(),
        db=object(),
        mode_manager=object(),
        tool_scheduler=object(),
    )
    defaults.update(overrides)
    return SubAgentRunner(**defaults)


# ───────────────────────── _build_subagent_system_prompt ─────────────────────────


def test_build_prompt_with_context():
    runner = _runner()
    task = SubAgentTask(id="t1", goal="为 module_a.py 写测试", context="使用 pytest", tools=[])
    prompt = runner._build_subagent_system_prompt(task)

    assert "你是 Khaos 子代理 #t1" in prompt
    assert "为 module_a.py 写测试" in prompt
    assert "使用 pytest" in prompt
    assert "专注于你的任务" in prompt
    assert "完成后报告结果" in prompt


def test_build_prompt_without_context():
    runner = _runner()
    task = SubAgentTask(id="42", goal="run lint", context="", tools=[])
    prompt = runner._build_subagent_system_prompt(task)

    assert "子代理 #42" in prompt
    assert "run lint" in prompt
    # 约束段总是存在
    assert "约束：" in prompt


def test_build_prompt_contains_constraints_block():
    runner = _runner()
    task = SubAgentTask(id="x", goal="g", context="", tools=[])
    prompt = runner._build_subagent_system_prompt(task)
    for line in (
        "- 专注于你的任务，不要做范围外的事情",
        "- 完成后报告结果",
        "- 遇到无法解决的问题，报告错误信息",
    ):
        assert line in prompt


# ───────────────────────────────── _collect_result ────────────────────────────────


async def test_collect_result_last_assistant_message():
    runner = _runner()
    messages = [
        Message(role="user", content="hello"),
        Message(role="assistant", content="first"),
        Message(role="assistant", content="final answer"),
    ]
    assert await runner._collect_result(messages) == "final answer"


async def test_collect_result_empty_messages_returns_placeholder():
    runner = _runner()
    assert await runner._collect_result([]) == "[子代理未产生有效输出]"


async def test_collect_result_all_empty_returns_placeholder():
    runner = _runner()
    messages = [
        Message(role="user", content="x"),
        Message(role="assistant", content=""),
        Message(role="system", content="done"),
    ]
    assert await runner._collect_result(messages) == "[子代理未产生有效输出]"


async def test_collect_result_only_tool_calls_joins_assistant_messages():
    """最后一条 assistant 消息只有 tool_calls（空 content），应拼接所有 assistant 内容。"""
    runner = _runner()
    messages = [
        Message(role="user", content="do it"),
        Message(role="assistant", content="thinking step 1"),
        Message(role="tool", content="result", tool_call_id="c1"),
        Message(role="assistant", content="thinking step 2"),
        # 最后一条 assistant：空 content，仅 tool_calls
        Message(role="assistant", content="", tool_calls=[{"id": "c2", "name": "x"}]),
    ]
    result = await runner._collect_result(messages)
    # 拼接所有非空 assistant content
    assert "thinking step 1" in result
    assert "thinking step 2" in result


async def test_collect_result_prefers_non_empty_over_tool_calls():
    """若最后存在一条非空 assistant 内容，优先取它而非拼接。"""
    runner = _runner()
    messages = [
        Message(role="assistant", content="earlier"),
        Message(role="assistant", content="", tool_calls=[{"id": "c1"}]),
        Message(role="assistant", content="the real final"),
    ]
    assert await runner._collect_result(messages) == "the real final"


async def test_collect_result_whitespace_only_treated_as_empty():
    runner = _runner()
    messages = [Message(role="assistant", content="   \n  ")]
    assert await runner._collect_result(messages) == "[子代理未产生有效输出]"
