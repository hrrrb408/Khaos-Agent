"""Auto-generate skill candidates from successful task traces.

当一个 coding 任务成功完成时，分析其工具调用序列，提取出可复用的流程，
生成 SKILL.md 格式的技能文件。
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class ToolTrace:
    """一次工具调用的记录。"""

    tool_name: str
    arguments: dict
    result_summary: str
    success: bool
    timestamp: float = 0.0


@dataclass
class TaskTrace:
    """一个完整的任务轨迹。"""

    task_id: str
    goal: str
    tools_called: list[ToolTrace] = field(default_factory=list)
    files_modified: list[str] = field(default_factory=list)
    test_results: list[dict] = field(default_factory=list)
    status: str = "completed"  # completed / failed
    duration_seconds: float = 0.0
    mode: str = "coding"


@dataclass
class SkillCandidate:
    """从任务轨迹中提取的技能候选。"""

    name: str
    description: str
    category: str = "coding"
    triggers: list[str] = field(default_factory=list)
    body: str = ""
    confidence: float = 0.0  # 0-1，提取置信度
    source_task_id: str = ""


class SkillGenerator:
    """从任务轨迹中生成技能候选。"""

    def __init__(self, confidence_threshold: float = 0.5):
        self.confidence_threshold = confidence_threshold

    def analyze(self, trace: TaskTrace) -> list[SkillCandidate]:
        """分析一个任务轨迹，提取技能候选。

        只分析成功的任务（status == "completed"）。
        策略：
        1. 工具调用序列模式：连续 3+ 次相似调用（同类工具 + 相似参数模式）
        2. 修改文件集合：涉及特定文件类型的组合（如总是同时改 .py + test_.py）
        3. 测试验证模式：特定的测试命令参数
        """
        if trace.status != "completed":
            return []
        if len(trace.tools_called) < 3:
            return []  # 太短的任务不值得生成技能

        candidates: list[SkillCandidate] = []

        # 策略 1：工具序列模式
        sequence_candidates = self._extract_sequence_patterns(trace)
        candidates.extend(sequence_candidates)

        # 策略 2：文件组合模式
        file_candidates = self._extract_file_patterns(trace)
        candidates.extend(file_candidates)

        # 过滤低置信度
        return [c for c in candidates if c.confidence >= self.confidence_threshold]

    def _extract_sequence_patterns(self, trace: TaskTrace) -> list[SkillCandidate]:
        """提取工具调用序列模式。"""
        candidates: list[SkillCandidate] = []

        # 统计工具使用频率
        tool_counts: dict[str, int] = {}
        tool_examples: dict[str, dict] = {}
        for call in trace.tools_called:
            tool_counts[call.tool_name] = tool_counts.get(call.tool_name, 0) + 1
            if call.tool_name not in tool_examples:
                tool_examples[call.tool_name] = call.arguments

        # 找出高频工具
        frequent_tools = {
            name for name, count in tool_counts.items() if count >= 2
        }

        if len(frequent_tools) >= 2:
            # 生成流程描述
            steps: list[str] = []
            for call in trace.tools_called:
                if call.tool_name in frequent_tools:
                    step = self._describe_tool_call(call)
                    if step and step not in steps:
                        steps.append(step)

            if len(steps) >= 2:
                name = self._generate_name(trace.goal)
                description = f"Auto-extracted from task: {trace.goal[:100]}"
                body = self._format_skill_body(
                    name=name,
                    goal=trace.goal,
                    steps=steps,
                    files_modified=trace.files_modified,
                )
                triggers = self._extract_triggers(trace.goal, trace.files_modified)
                candidates.append(
                    SkillCandidate(
                        name=name,
                        description=description,
                        body=body,
                        triggers=triggers,
                        confidence=min(1.0, len(steps) / 5.0),
                        source_task_id=trace.task_id,
                    )
                )

        return candidates

    def _extract_file_patterns(self, trace: TaskTrace) -> list[SkillCandidate]:
        """提取文件修改组合模式。"""
        if not trace.files_modified:
            return []

        # 检查是否同时修改了源码和对应测试
        source_files = [f for f in trace.files_modified if not f.startswith("test_") and f.endswith(".py")]
        test_files = [f for f in trace.files_modified if "test" in f.lower() and f.endswith(".py")]

        if source_files and test_files:
            # 这是一个"代码+测试"模式
            name = self._generate_name(f"test-{trace.goal[:30]}")
            description = f"Pattern: modify source + tests for {trace.goal[:80]}"
            body = (
                f"# Skill: {name}\n\n"
                f"## 流程\n\n"
                f"1. 修改源码文件\n"
                f"2. 修改/新增对应测试文件\n"
                f"3. 运行测试验证\n"
                f"\n## 涉及文件\n\n"
                + "\n".join(f"- {f}" for f in trace.files_modified)
            )
            candidates = [SkillCandidate(
                name=name,
                description=description,
                body=body,
                triggers=self._extract_triggers(trace.goal, trace.files_modified),
                confidence=0.7,
                source_task_id=trace.task_id,
            )]
            return candidates

        return []

    def _describe_tool_call(self, call: ToolTrace) -> str:
        """用自然语言描述一次工具调用。"""
        name = call.tool_name
        args = call.arguments
        if name == "read_file":
            return f"读取 {args.get('path', '?')}"
        if name == "write_file":
            return f"写入 {args.get('path', '?')}"
        if name == "patch":
            return f"编辑 {args.get('path', '?')}"
        if name == "terminal":
            cmd = args.get("command", "?")[:60]
            return f"执行: {cmd}"
        if name == "test_run":
            return f"运行测试"
        return f"{name}"

    def _generate_name(self, goal: str) -> str:
        """从目标描述生成技能名。"""
        # 提取关键短语
        words = goal.lower().replace("-", " ").split()[:4]
        name = "-".join(words)
        # 去除特殊字符
        name = "".join(c for c in name if c.isalnum() or c in "-_")
        return name[:50] if name else "auto-skill"

    def _extract_triggers(self, goal: str, files: list[str]) -> list[str]:
        """从目标和文件名提取触发关键词。"""
        triggers: set[str] = set()
        # 从目标中提取关键词
        for word in goal.lower().split():
            if len(word) > 3:
                triggers.add(word)
        # 从文件扩展名提取
        for f in files:
            ext = f.rsplit(".", 1)[-1] if "." in f else ""
            if ext:
                triggers.add(ext)
        return list(triggers)[:10]

    def _format_skill_body(
        self, name: str, goal: str, steps: list[str],
        files_modified: list[str],
    ) -> str:
        """格式化技能 body。"""
        sections = [
            f"## 目标",
            f"{goal}",
            f"",
            f"## 步骤",
            f"",
        ]
        for i, step in enumerate(steps, 1):
            sections.append(f"{i}. {step}")
        if files_modified:
            sections.append(f"")
            sections.append(f"## 涉及文件")
            sections.append(f"")
            for f in files_modified:
                sections.append(f"- {f}")
        return "\n".join(sections)
