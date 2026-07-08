"""P0-A agent loop with mock streaming model support."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import AsyncIterator, Optional

logger = logging.getLogger(__name__)


class StopReason(Enum):
    """Reasons an agent turn can stop."""

    END_TURN = "end_turn"
    TOOL_USE = "tool_use"
    MAX_TURNS = "max_turns"
    MAX_BUDGET = "max_budget"
    USER_ABORT = "user_abort"
    ERROR = "error"


@dataclass
class AgentConfig:
    """Agent runtime limits."""

    max_turns: int = 100
    max_budget_tokens: int = 500000
    stream_timeout: int = 120
    compression_threshold: int = 128000
    # Token budget for the injected project-structure tree (coding mode only).
    project_structure_token_budget: int = 2000


@dataclass
class Message:
    """Chat message used by the agent loop and SSE encoder."""

    role: str
    content: str
    tool_calls: list[dict] = field(default_factory=list)
    tool_call_id: Optional[str] = None
    token_count: int = 0
    created_at: float = 0.0
    stop_reason: str | None = None
    event: str | None = None
    metadata: dict = field(default_factory=dict)


class SimpleTokenEngine:
    """Small token counter placeholder until the Rust tokenizer lands."""

    def count_tokens(self, text: str) -> int:
        """Return a deterministic approximate token count."""
        return len(text.split()) if text.strip() else 0


class AgentLoop:
    """Agent core loop for P0-A."""

    def __init__(
        self,
        config: AgentConfig,
        mode_manager,
        router,
        db,
        tool_scheduler=None,
        confirm_callback=None,
        context_compressor=None,
        memory_manager=None,
        error_handler=None,
        token_engine: SimpleTokenEngine | None = None,
        skill_manager=None,
        project_root=None,
        coding_context_builder=None,
    ):
        self.config = config
        self.mode_manager = mode_manager
        self.router = router
        self.db = db
        self.tool_scheduler = tool_scheduler
        self.confirm_callback = confirm_callback
        self.compressor = context_compressor
        self.memory_manager = memory_manager
        self.error_handler = error_handler
        self.token_engine = token_engine or SimpleTokenEngine()
        self.skill_manager = skill_manager
        # Coding-mode context building. ``project_root`` may be a str or Path;
        # left as-is (not resolved) so callers can pass relative paths.
        self.project_root = project_root
        self.coding_context_builder = coding_context_builder

    async def run(self, user_input: str, session_id: str) -> AsyncIterator[Message]:
        """
        Stream one user turn through the model router.

        P0-A intentionally skips real tools, permissions, memory injection, and
        compression. It persists the user message immediately and persists the
        aggregated assistant message after streaming completes.
        """
        total_tokens = 0
        try:
            messages = await self._build_context(session_id, user_input)
            user_msg = Message(
                role="user",
                content=user_input,
                token_count=self.token_engine.count_tokens(user_input),
                created_at=time.time(),
            )
            await self.db.insert_message(session_id, user_msg)
            messages.append(user_msg)
            total_tokens += user_msg.token_count

            turn_count = 0

            while turn_count < self.config.max_turns:
                empty_response_retries = 0
                if await self._check_compression(messages):
                    if self.compressor is not None:
                        result = await self.compressor.compress(
                            messages,
                            self.config.compression_threshold,
                        )
                        messages = result.messages
                while True:
                    assistant_content = ""
                    tool_calls: list[dict] = []
                    stop_reason = StopReason.END_TURN.value

                    async for chunk in self.router.call(
                        self.mode_manager.mode_config.preferred_model_function,
                        messages,
                    ):
                        if chunk.content:
                            chunk.token_count = self.token_engine.count_tokens(chunk.content)
                            chunk.created_at = time.time()
                            assistant_content += chunk.content
                            total_tokens += chunk.token_count
                            yield chunk
                        if chunk.tool_calls:
                            tool_calls.extend(chunk.tool_calls)
                            for tool_call in chunk.tool_calls:
                                yield Message(
                                    role="assistant",
                                    content="",
                                    tool_calls=[tool_call],
                                    event="tool_call",
                                    metadata=tool_call,
                                    created_at=time.time(),
                                )
                        if chunk.stop_reason:
                            stop_reason = chunk.stop_reason

                    if assistant_content.strip() or tool_calls or stop_reason == StopReason.TOOL_USE.value:
                        break
                    if empty_response_retries >= 1:
                        yield Message(
                            role="system",
                            content="model returned an empty response",
                            stop_reason="error",
                            event="error",
                            metadata={
                                "code": "EMPTY_MODEL_RESPONSE",
                                "message": "Model returned no text or tool calls.",
                            },
                            created_at=time.time(),
                        )
                        return
                    empty_response_retries += 1
                    logger.warning("empty model response, retrying once: session=%s", session_id)

                assistant_msg = Message(
                    role="assistant",
                    content=assistant_content,
                    tool_calls=tool_calls,
                    token_count=self.token_engine.count_tokens(assistant_content),
                    created_at=time.time(),
                    stop_reason=stop_reason,
                )
                messages.append(assistant_msg)
                await self.db.insert_message(session_id, assistant_msg)
                turn_count += 1

                if stop_reason != StopReason.TOOL_USE.value:
                    break

                if self.tool_scheduler is None:
                    yield Message(
                        role="system",
                        content="error: tool scheduler is not configured",
                        stop_reason="error",
                        event="error",
                    )
                    return

                async for event in self.tool_scheduler.stream_batch(
                    tool_calls,
                    self.mode_manager.current_mode.value,
                    session_id=session_id,
                    confirm_callback=self.confirm_callback,
                ):
                    if event.permission_request is not None:
                        request = event.permission_request
                        yield Message(
                            role="system",
                            content="permission_request",
                            event="permission_request",
                            metadata={
                                "id": request.tool_call_id,
                                "name": request.name,
                                "arguments": request.arguments,
                                "level": request.level,
                                "target": request.target,
                                "reason": request.reason,
                            },
                            created_at=time.time(),
                        )
                    if event.result is not None:
                        result = event.result
                        content = json.dumps(
                            {
                                "success": result.success,
                                "output": result.output,
                                "error": result.error,
                            },
                            ensure_ascii=False,
                        )
                        tool_msg = Message(
                            role="tool",
                            content=content,
                            tool_call_id=result.tool_call_id,
                            token_count=self.token_engine.count_tokens(content),
                            event="tool_result",
                            metadata={
                                "id": result.tool_call_id,
                                "name": result.name,
                                "success": result.success,
                                "output": result.output,
                                "error": result.error,
                                "duration_ms": result.duration_ms,
                            },
                            created_at=time.time(),
                        )
                        messages.append(tool_msg)
                        await self.db.insert_message(session_id, tool_msg)
                        yield tool_msg

            else:
                stop_reason = StopReason.MAX_TURNS.value

            yield Message(
                role="system",
                content="done",
                token_count=total_tokens,
                stop_reason=stop_reason,
                created_at=time.time(),
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.error("Agent loop error: %s", exc, exc_info=True)
            if self.error_handler is not None:
                error_event = await self.error_handler.handle(exc, session_id)
                yield error_event.to_message()
            else:
                yield Message(
                    role="system",
                    content=f"error: {exc}",
                    stop_reason="error",
                    event="error",
                    metadata={"code": "INTERNAL_ERROR", "message": str(exc)},
                )

    async def _build_context(self, session_id: str, user_input: str = "") -> list[Message]:
        """Build the P0-A context from mode prompt and persisted messages.

        In coding mode (when ``project_root`` is set) this also injects:

        1. The project structure tree into the *system* prompt (see
           :meth:`_build_system_prompt`) — kept small (≤ token budget).
        2. The contents of files relevant to ``user_input`` as an extra
           ``# Relevant Files`` system message appended *after* the persisted
           history, so the model sees them just before the current turn.

        Neither injection happens in office mode or when ``project_root`` is
        unset, so non-coding behaviour is unchanged.
        """
        messages = [
            Message(
                role="system",
                content=await self._build_system_prompt(session_id, user_input),
                token_count=0,
            )
        ]
        messages.extend(await self.db.list_messages(session_id))

        relevant = self._build_relevant_files_message(user_input)
        if relevant is not None:
            messages.append(relevant)

        return messages

    async def _build_system_prompt(self, session_id: str, user_input: str = "") -> str:
        prompt = await self.mode_manager.load_system_prompt()
        if self.memory_manager is not None:
            memory_text = await self.memory_manager.inject(session_id)
            if memory_text:
                prompt = f"{prompt}\n\n{memory_text}"
        if self.skill_manager is not None:
            mode = self.mode_manager.current_mode.value
            matched = self.skill_manager.match(mode, user_input)
            skill_text = self.skill_manager.format_for_prompt(matched)
            if skill_text:
                prompt = f"{prompt}\n\n{skill_text}"

        structure = self._build_project_structure()
        if structure:
            prompt = f"{prompt}\n\n{structure}"

        return prompt

    def _is_coding_mode(self) -> bool:
        """Return True when the active mode is coding and a project root is set."""
        if self.project_root is None:
            return False
        try:
            return self.mode_manager.current_mode.value == "coding"
        except AttributeError:
            return False

    def _build_project_structure(self) -> str:
        """Return a ``# Project Structure`` block for the system prompt.

        Only populated in coding mode. The tree is trimmed to the configured
        token budget so it never dominates the system prompt.
        """
        if not self._is_coding_mode():
            return ""
        builder = self.coding_context_builder
        if builder is None:
            return ""
        try:
            from pathlib import Path

            root = Path(self.project_root).expanduser().resolve()
            index = builder.indexer.scan(root)
        except (OSError, FileNotFoundError, NotADirectoryError) as exc:
            logger.warning("coding project structure scan failed: %s", exc)
            return ""
        except Exception as exc:  # noqa: BLE001 — scan must never break the loop
            logger.warning("coding project structure scan errored: %s", exc)
            return ""

        tree = str(index.get("tree", ""))
        budget = getattr(self.config, "project_structure_token_budget", 2000)
        trimmed = self._trim_to_budget(tree, budget)
        return f"# Project Structure\n\n{trimmed}"

    def _build_relevant_files_message(self, user_input: str):
        """Return a ``# Relevant Files`` system Message, or None.

        Aggregates the file contents collected by the coding context builder
        into one fenced block per file. Returns None outside coding mode or
        when no relevant files are found.
        """
        if not self._is_coding_mode():
            return None
        builder = self.coding_context_builder
        if builder is None:
            return None
        try:
            from pathlib import Path

            root = Path(self.project_root).expanduser().resolve()
            context_files = builder.build(user_input, root, target_files=None)
        except (OSError, FileNotFoundError, NotADirectoryError) as exc:
            logger.warning("coding relevant-files build failed: %s", exc)
            return None
        except Exception as exc:  # noqa: BLE001 — context build must not break the loop
            logger.warning("coding relevant-files build errored: %s", exc)
            return None

        if not context_files:
            return None

        blocks: list[str] = ["# Relevant Files\n"]
        try:
            root_for_rel = Path(self.project_root).expanduser().resolve()
        except (OSError, ValueError):
            root_for_rel = None
        for entry in context_files:
            path = entry["path"]
            content = entry["content"]
            if root_for_rel is not None:
                try:
                    display = str(Path(path).relative_to(root_for_rel))
                except ValueError:
                    display = str(path)
            else:
                display = str(path)
            language = self._language_for_path(str(path))
            blocks.append(f"## {display}\n```{language}\n{content}\n```\n")

        text = "\n".join(blocks)
        return Message(
            role="system",
            content=text,
            token_count=self.token_engine.count_tokens(text),
        )

    def _trim_to_budget(self, text: str, budget: int) -> str:
        """Trim ``text`` to approximately ``budget`` tokens, on line boundaries."""
        if not text or budget <= 0:
            return ""
        if self.token_engine.count_tokens(text) <= budget:
            return text
        lines = text.splitlines()
        kept: list[str] = []
        used = 0
        for line in lines:
            line_tokens = self.token_engine.count_tokens(line)
            if used + line_tokens > budget:
                break
            kept.append(line)
            used += line_tokens
        if not kept:
            kept = lines[:1]
        kept.append(f"... (trimmed, {len(lines) - len(kept)} more lines)")
        return "\n".join(kept)

    @staticmethod
    def _language_for_path(path: str) -> str:
        """Map a file extension to a fenced-code language hint."""
        suffix = path.rsplit(".", 1)[-1].lower() if "." in path else ""
        mapping = {
            "py": "python",
            "go": "go",
            "rs": "rust",
            "js": "javascript",
            "jsx": "jsx",
            "ts": "typescript",
            "tsx": "tsx",
            "md": "markdown",
            "toml": "toml",
            "yaml": "yaml",
            "yml": "yaml",
            "json": "json",
            "txt": "text",
        }
        return mapping.get(suffix, "")

    async def _check_compression(self, messages: list[Message]) -> bool:
        total_tokens = sum(
            message.token_count or self.token_engine.count_tokens(message.content)
            for message in messages
        )
        return total_tokens > self.config.compression_threshold
