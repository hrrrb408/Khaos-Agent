"""Token 消耗和估算费用追踪器。"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# 每 1M token 的估算价格（USD），用于成本估算
# 实际价格由 config 或 runtime 决定，这里是 fallback 默认值
DEFAULT_PRICE_PER_MILLION = {
    "input": 2.0,
    "output": 8.0,
}


@dataclass
class TurnCost:
    """单轮对话的 token 消耗。"""

    turn_number: int
    input_tokens: int = 0
    output_tokens: int = 0
    tool_tokens: int = 0
    total_tokens: int = 0
    estimated_cost_usd: float = 0.0


@dataclass
class SessionCostReport:
    """整个会话的费用汇总。"""

    session_id: str
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    total_tool_tokens: int = 0
    total_tokens: int = 0
    total_estimated_cost_usd: float = 0.0
    turn_count: int = 0
    turns: list[TurnCost] = field(default_factory=list)


class CostTracker:
    """追踪会话级别的 token 消耗和估算费用。"""

    def __init__(
        self,
        session_id: str = "",
        input_price_per_million: float = DEFAULT_PRICE_PER_MILLION["input"],
        output_price_per_million: float = DEFAULT_PRICE_PER_MILLION["output"],
    ):
        self.session_id = session_id
        # 转换为「每个 token」的价格，便于直接相乘。
        self._input_price = input_price_per_million / 1_000_000
        self._output_price = output_price_per_million / 1_000_000
        self._turns: list[TurnCost] = []
        self._current_input_tokens: int = 0
        self._current_output_tokens: int = 0
        self._current_tool_tokens: int = 0
        # 下一轮的编号；finish_turn 后递增。当前轮次 = _turn_number + 1。
        self._turn_number: int = 0

    def add_input_tokens(self, count: int) -> None:
        """累加当前轮的输入 token。"""
        if count < 0:
            return
        self._current_input_tokens += count

    def add_output_tokens(self, count: int) -> None:
        """累加当前轮的输出 token。"""
        if count < 0:
            return
        self._current_output_tokens += count

    def add_tool_tokens(self, count: int) -> None:
        """累加当前轮的工具输出 token。"""
        if count < 0:
            return
        self._current_tool_tokens += count

    def finish_turn(self) -> TurnCost:
        """结束当前轮，记录并返回该轮的 TurnCost。

        会重置当前轮的累加器并推进到下一轮。
        """
        self._turn_number += 1
        total = (
            self._current_input_tokens
            + self._current_output_tokens
            + self._current_tool_tokens
        )
        cost = (
            self._current_input_tokens * self._input_price
            + (self._current_output_tokens + self._current_tool_tokens)
            * self._output_price
        )
        turn_cost = TurnCost(
            turn_number=self._turn_number,
            input_tokens=self._current_input_tokens,
            output_tokens=self._current_output_tokens,
            tool_tokens=self._current_tool_tokens,
            total_tokens=total,
            estimated_cost_usd=cost,
        )
        self._turns.append(turn_cost)
        # 重置当前轮累加器，为下一轮做准备。
        self._current_input_tokens = 0
        self._current_output_tokens = 0
        self._current_tool_tokens = 0
        return turn_cost

    def get_report(self) -> SessionCostReport:
        """生成会话级别的费用报告。"""
        total_input = sum(t.input_tokens for t in self._turns)
        total_output = sum(t.output_tokens for t in self._turns)
        total_tool = sum(t.tool_tokens for t in self._turns)
        total_cost = sum(t.estimated_cost_usd for t in self._turns)
        return SessionCostReport(
            session_id=self.session_id,
            total_input_tokens=total_input,
            total_output_tokens=total_output,
            total_tool_tokens=total_tool,
            total_tokens=total_input + total_output + total_tool,
            total_estimated_cost_usd=total_cost,
            turn_count=len(self._turns),
            turns=list(self._turns),
        )

    def format_summary(self) -> str:
        """格式化费用摘要字符串，用于展示给用户。

        格式：
        ``📊 Session Cost: 12,345 tokens (input: 8,000 + output: 3,500 + tools: 845) ≈ $0.04``

        如果 total_tokens == 0 返回空字符串。
        """
        report = self.get_report()
        if report.total_tokens == 0:
            return ""
        return (
            f"📊 Session Cost: {report.total_tokens:,} tokens "
            f"(input: {report.total_input_tokens:,} + "
            f"output: {report.total_output_tokens:,} + "
            f"tools: {report.total_tool_tokens:,}) "
            f"≈ ${report.total_estimated_cost_usd:.2f}"
        )

    @property
    def current_turn_number(self) -> int:
        """当前轮次（从 1 开始）。"""
        return self._turn_number + 1
