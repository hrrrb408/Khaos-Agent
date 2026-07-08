"""Real subagent runner that creates isolated AgentLoop instances."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Optional

from khaos.agent.core import AgentConfig, AgentLoop, Message, SimpleTokenEngine
from khaos.subagents.spawner import SubAgentTask

if TYPE_CHECKING:
    from khaos.coding.context import CodingContextBuilder
    from khaos.memory.manager import MemoryManager
    from khaos.skills.manager import SkillManager

logger = logging.getLogger(__name__)


class SubAgentRunner:
    """为每个子任务创建独立 AgentLoop 实例并执行。

    每个子代理拥有：
    - 独立 session_id（parent_session_id + "/" + task_id）
    - 独立 system prompt（根据任务定制）
    - 独立工具集（限定为子集或全部）
    - 独立 token 预算（默认比主 agent 低）
    - 独立记忆空间（不与主 agent 共享，但可选择性继承）
    """

    def __init__(
        self,
        router,                          # ModelRouter 实例
        db,                              # Database 实例
        mode_manager,                    # ModeManager 实例
        tool_scheduler,                  # ToolScheduler 实例
        memory_manager: Optional["MemoryManager"] = None,  # 可选，默认不共享记忆
        skill_manager: Optional["SkillManager"] = None,    # 可选
        coding_context_builder: Optional["CodingContextBuilder"] = None,  # 可选
        token_engine: Optional[SimpleTokenEngine] = None,  # SimpleTokenEngine
        max_turns: int = 30,            # 子代理轮次限制（比主 agent 低）
        max_budget_tokens: int = 100000,  # 子代理 token 预算（比主 agent 低）
        stream_timeout: int = 60,        # 子代理超时（比主 agent 低）
        inherit_memory: bool = False,    # 是否从父会话继承记忆
    ):
        self.router = router
        self.db = db
        self.mode_manager = mode_manager
        self.tool_scheduler = tool_scheduler
        self.memory_manager = memory_manager
        self.skill_manager = skill_manager
        self.coding_context_builder = coding_context_builder
        self.token_engine = token_engine or SimpleTokenEngine()
        self.max_turns = max_turns
        self.max_budget_tokens = max_budget_tokens
        self.stream_timeout = stream_timeout
        self.inherit_memory = inherit_memory

    async def run(self, task: SubAgentTask) -> str:
        """执行子任务并返回结果字符串。

        步骤：
        1. 创建独立 session_id: "{parent_session_id}/{task_id}"
        2. 创建独立的 AgentConfig（降低限制）
        3. 构建 system prompt（定制版，注入到 mode prompt 之后）
        4. 创建 AgentLoop 实例（共享 router/db/mode_manager，独立 config）
        5. 执行 run(task.goal, session_id) 并收集所有消息
        6. 提取最终 assistant 回复作为结果
        """
        session_id = f"{task.parent_session_id}/{task.id}"
        config = AgentConfig(
            max_turns=self.max_turns,
            max_budget_tokens=self.max_budget_tokens,
            stream_timeout=self.stream_timeout,
        )
        # 保证子代理 session 已持久化（与 spawn() 的 create_session 对齐）。
        await self.db.create_session(session_id)

        loop = AgentLoop(
            config=config,
            mode_manager=self.mode_manager,
            router=self.router,
            db=self.db,
            tool_scheduler=self.tool_scheduler,
            memory_manager=self.memory_manager if self.inherit_memory else None,
            skill_manager=self.skill_manager,
            token_engine=self.token_engine,
            coding_context_builder=self.coding_context_builder,
        )

        logger.info(
            "SubAgentRunner starting: task=%s session=%s goal=%r",
            task.id,
            session_id,
            task.goal,
        )

        messages: list[Message] = []
        async for message in loop.run(task.goal, session_id):
            messages.append(message)

        return await self._collect_result(messages)

    def _build_subagent_system_prompt(self, task: SubAgentTask) -> str:
        """构建子代理专用的 system prompt。

        格式：
            你是 Khaos 子代理 #{task.id}。
            你的任务：{task.goal}

            {task.context（如果有）}

            约束：
            - 专注于你的任务，不要做范围外的事情
            - 完成后报告结果
            - 遇到无法解决的问题，报告错误信息
        """
        lines = [
            f"你是 Khaos 子代理 #{task.id}。",
            f"你的任务：{task.goal}",
        ]
        if task.context:
            lines.append("")
            lines.append(task.context)
        lines.extend(
            [
                "",
                "约束：",
                "- 专注于你的任务，不要做范围外的事情",
                "- 完成后报告结果",
                "- 遇到无法解决的问题，报告错误信息",
            ]
        )
        return "\n".join(lines)

    async def _collect_result(self, messages: list[Message]) -> str:
        """从消息列表中提取最终结果。

        策略：
        1. 找到（按时间顺序的）最后一条 assistant 消息
        2. 若其 content 非空（去空白后），直接返回它
        3. 否则（空 content 或只有 tool_calls），拼接所有 assistant 消息的非空 content
        4. 若拼接仍为空，返回 "[子代理未产生有效输出]"
        """
        # 1. 找到最后一条 assistant 消息
        last_assistant: Optional[Message] = None
        for message in reversed(messages):
            if message.role == "assistant":
                last_assistant = message
                break

        # 2. 最后一条 assistant 非空 → 直接返回
        if last_assistant is not None and last_assistant.content.strip():
            return last_assistant.content

        # 3. 最后一条为空/只有 tool_calls → 拼接所有 assistant 非空 content
        assistant_texts = [
            message.content
            for message in messages
            if message.role == "assistant" and message.content.strip()
        ]
        if assistant_texts:
            return "\n".join(assistant_texts)

        # 4. 全部为空
        return "[子代理未产生有效输出]"
