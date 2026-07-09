"""Integration test: the verify-fix loop is wired end-to-end through AgentLoop.

This does **not** call a real model. A sequenced mock router + scheduler
replays the full closed loop:

    round 1: model emits a test_run tool_call
          → scheduler returns a FAILED test result
          → AgentLoop injects a ``## 测试失败`` guidance message
    round 2: model (seeing the failure context) emits test_run again
          → scheduler returns a PASSED test result
          → loop ends cleanly

The critical assertion: the failure-context message injected by the loop
must appear in the messages handed to the router on round 2, proving the
inject → re-run link is actually wired.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import AsyncIterator

from khaos.agent import AgentConfig, AgentLoop, Message
from khaos.coding.verify_fix import VerifyFixLoop
from khaos.db import Database
from khaos.modes import Mode, ModeManager
from khaos.tools.scheduler import SchedulerEvent, ToolResult


# ---------------------------------------------------------------------------
# Scaffolding helpers (inlined to stay self-contained — the repo's other
# integration tests do not cross-import between test modules).
# ---------------------------------------------------------------------------


async def create_test_db(path: Path) -> Database:
    """Create a migrated test database."""
    db = Database(path)
    await db.connect()
    await db.run_migrations()
    return db


def write_prompts(root: Path) -> None:
    """Create minimal prompt files required by ModeManager."""
    prompts = root / "prompts"
    prompts.mkdir()
    (prompts / "office.md").write_text("office prompt", encoding="utf-8")
    (prompts / "coding.md").write_text("coding prompt", encoding="utf-8")


async def create_mode_manager(db: Database, root: Path, mode: Mode = Mode.OFFICE) -> ModeManager:
    """Create and initialize a mode manager."""
    manager = ModeManager(db, project_root=root)
    if mode is not Mode.OFFICE:
        await manager.switch(mode)
    return manager


class MockRouter:
    """Streaming router mock that records the messages seen on each call."""

    def __init__(self, responses: list[list[Message]]):
        self.responses = responses
        self.call_count = 0
        self.messages_per_call: list[list[Message]] = []

    async def call(
        self, function: str, messages: list[Message]
    ) -> AsyncIterator[Message]:
        del function
        self.call_count += 1
        # Snapshot the message list the model actually received this round.
        self.messages_per_call.append(list(messages))
        chunks = self.responses[self.call_count - 1]
        for chunk in chunks:
            yield chunk


class SequencedToolScheduler:
    """Scheduler double that returns a *different* event batch per call.

    Unlike the simple mock that always replays one fixed list, this one
    advances through ``batches`` so the first ``stream_batch`` can return a
    failure and the second a pass.
    """

    def __init__(self, batches: list[list[SchedulerEvent]]):
        self.batches = batches
        self.call_count = 0
        self.seen_tool_calls: list[list[dict]] = []

    async def stream_batch(
        self,
        tool_calls: list[dict],
        mode: str,
        session_id: str | None = None,
        confirm_callback=None,
    ):
        del mode, session_id, confirm_callback
        self.call_count += 1
        self.seen_tool_calls.append(tool_calls)
        events = self.batches[self.call_count - 1]
        for event in events:
            yield event


def _test_result_output(*, failed: int, passed: int, failed_cases=None) -> str:
    """JSON-encode a test_run-shaped output payload."""
    return json.dumps(
        {
            "success": failed == 0,
            "passed": passed,
            "failed": failed,
            "errors": 0,
            "exit_code": 0 if failed == 0 else 1,
            "failed_cases": failed_cases or [],
            "summary": f"{passed} passed" if failed == 0 else f"{failed} failed",
        },
        ensure_ascii=False,
    )


class TestVerifyFixLoopWired:
    async def test_failed_then_passed_injects_guidance_and_reruns(self, tmp_path):
        write_prompts(tmp_path)
        db = await create_test_db(tmp_path / "khaos.db")
        await db.create_session("s-vf", mode="coding")

        # The same test_run tool_call shape is used in both rounds.
        run_tests_call = {
            "id": "call-run",
            "name": "test_run",
            "arguments": {"command": "pytest", "cwd": "."},
        }

        router = MockRouter(
            [
                # Round 1: model decides to run the tests.
                [
                    Message(
                        role="assistant",
                        content="",
                        tool_calls=[run_tests_call],
                        stop_reason="tool_use",
                    ),
                ],
                # Round 2: model has seen the failure context and "fixes" it,
                # then re-runs the tests.
                [
                    Message(
                        role="assistant",
                        content="",
                        tool_calls=[run_tests_call],
                        stop_reason="tool_use",
                    ),
                ],
                # Round 3: tests pass, model wraps up.
                [
                    Message(role="assistant", content="all green now"),
                    Message(role="assistant", content="", stop_reason="end_turn"),
                ],
            ]
        )

        failing_case = {
            "name": "test_add",
            "file": "tests/test_math.py",
            "line": 12,
            "error": "AssertionError: expected 2, got 3",
        }
        scheduler = SequencedToolScheduler(
            [
                # First test_run → FAILED.
                [
                    SchedulerEvent(
                        event="tool_result",
                        result=ToolResult(
                            tool_call_id="call-run",
                            name="test_run",
                            success=False,
                            output=_test_result_output(
                                failed=1, passed=0, failed_cases=[failing_case]
                            ),
                        ),
                    ),
                ],
                # Second test_run → PASSED.
                [
                    SchedulerEvent(
                        event="tool_result",
                        result=ToolResult(
                            tool_call_id="call-run",
                            name="test_run",
                            success=True,
                            output=_test_result_output(failed=0, passed=1),
                        ),
                    ),
                ],
            ]
        )

        loop = AgentLoop(
            AgentConfig(),
            await create_mode_manager(db, tmp_path, Mode.CODING),
            router,
            db,
            tool_scheduler=scheduler,
            verify_fix_loop=VerifyFixLoop(max_fix_attempts=3),
        )

        events = [message async for message in loop.run("make tests pass", "s-vf")]

        # --- The model was driven through exactly three rounds. ---
        assert router.call_count == 3
        # --- The scheduler was invoked twice (two test_run calls). ---
        assert scheduler.call_count == 2

        # --- A verify_fix guidance event was emitted to the stream. ---
        verify_fix_events = [m for m in events if m.event == "verify_fix"]
        assert len(verify_fix_events) == 1
        guidance = verify_fix_events[0].content
        assert "测试失败" in guidance
        assert "test_add" in guidance
        assert "tests/test_math.py" in guidance

        # --- THE critical assertion: round 2's router input contains the
        #     injected failure context. This proves inject → re-run links up.
        round2_messages = router.messages_per_call[1]
        assert any(
            m.role == "system" and "测试失败" in m.content and "test_add" in m.content
            for m in round2_messages
        ), "failure-context guidance was not visible to the model on re-run"

        # --- The loop self-recovered: final assistant message is the success
        #     message, and no "verify_fix_report" (exhaustion) was emitted.
        assert events[-1].stop_reason == "end_turn"
        assert not any(m.event == "verify_fix_report" for m in events)
        await db.close()

    async def test_loop_exhausted_emits_final_report(self, tmp_path):
        """When every attempt fails, the loop emits a final report and stops."""
        write_prompts(tmp_path)
        db = await create_test_db(tmp_path / "khaos.db")
        await db.create_session("s-vf-exhaust", mode="coding")

        run_tests_call = {
            "id": "call-run",
            "name": "test_run",
            "arguments": {"command": "pytest", "cwd": "."},
        }
        failing_case = {
            "name": "test_stub",
            "file": "tests/test_x.py",
            "line": 1,
            "error": "boom",
        }
        failed_output = _test_result_output(
            failed=1, passed=0, failed_cases=[failing_case]
        )

        # Model keeps re-running the tests; scheduler always fails.
        # max_fix_attempts=2 → after 2 fixes the loop is exhausted.
        router = MockRouter(
            [
                [Message(role="assistant", content="", tool_calls=[run_tests_call], stop_reason="tool_use")],
                [Message(role="assistant", content="", tool_calls=[run_tests_call], stop_reason="tool_use")],
                [Message(role="assistant", content="giving up", stop_reason="end_turn")],
            ]
        )
        scheduler = SequencedToolScheduler(
            [
                [SchedulerEvent(event="tool_result", result=ToolResult(
                    tool_call_id="call-run", name="test_run", success=False, output=failed_output))],
                [SchedulerEvent(event="tool_result", result=ToolResult(
                    tool_call_id="call-run", name="test_run", success=False, output=failed_output))],
            ]
        )
        loop = AgentLoop(
            AgentConfig(),
            await create_mode_manager(db, tmp_path, Mode.CODING),
            router,
            db,
            tool_scheduler=scheduler,
            verify_fix_loop=VerifyFixLoop(max_fix_attempts=2),
        )

        events = [message async for message in loop.run("fix it", "s-vf-exhaust")]

        # Two guidance injections (one per failed attempt), then a report.
        assert len([m for m in events if m.event == "verify_fix"]) == 2
        report_events = [m for m in events if m.event == "verify_fix_report"]
        assert len(report_events) == 1
        assert "共 2 次尝试" in report_events[0].content
        assert "仍然失败" in report_events[0].content
        await db.close()

    async def test_passing_test_does_not_trigger_loop(self, tmp_path):
        """A green test_run never injects verify-fix guidance."""
        write_prompts(tmp_path)
        db = await create_test_db(tmp_path / "khaos.db")
        await db.create_session("s-vf-pass", mode="coding")

        run_tests_call = {
            "id": "call-run",
            "name": "test_run",
            "arguments": {"command": "pytest", "cwd": "."},
        }
        router = MockRouter(
            [
                [Message(role="assistant", content="", tool_calls=[run_tests_call], stop_reason="tool_use")],
                [Message(role="assistant", content="done"), Message(role="assistant", content="", stop_reason="end_turn")],
            ]
        )
        scheduler = SequencedToolScheduler(
            [
                [SchedulerEvent(event="tool_result", result=ToolResult(
                    tool_call_id="call-run", name="test_run", success=True,
                    output=_test_result_output(failed=0, passed=5)))],
            ]
        )
        loop = AgentLoop(
            AgentConfig(),
            await create_mode_manager(db, tmp_path, Mode.CODING),
            router,
            db,
            tool_scheduler=scheduler,
            verify_fix_loop=VerifyFixLoop(),
        )

        events = [message async for message in loop.run("run tests", "s-vf-pass")]

        assert not any(m.event == "verify_fix" for m in events)
        assert not any(m.event == "verify_fix_report" for m in events)
        await db.close()
