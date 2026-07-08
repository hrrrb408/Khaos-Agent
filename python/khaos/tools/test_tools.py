"""Test feedback-loop tools for coding mode.

Runs a test command, parses runner output (pytest / jest / vitest / go test,
plus a generic keyword fallback) and returns a structured JSON result that the
agent loop can reason about when fixing failing tests.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shlex
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Hard cap for any single test invocation.
TEST_RUN_TIMEOUT: int = 120


async def test_run(command: str, cwd: str) -> str:
    """Run a test command and return a structured JSON summary.

    The command is split with :mod:`shlex` and executed via
    :func:`asyncio.create_subprocess_exec` so no shell is spawned. ``stdout``
    and ``stderr`` are merged, captured, and parsed by the runner-specific
    parser best matching ``command``.
    """
    if not command or not command.strip():
        return json.dumps(
            {"success": False, "error": "command must not be empty"},
            ensure_ascii=False,
        )

    workdir = str(Path(cwd).expanduser().resolve())
    try:
        parts = shlex.split(command)
    except ValueError as exc:
        return json.dumps(
            {"success": False, "error": f"invalid command: {exc}"},
            ensure_ascii=False,
        )

    try:
        process = await asyncio.create_subprocess_exec(
            *parts,
            cwd=workdir,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
    except FileNotFoundError as exc:
        logger.warning("test command not found: %s", parts[0] if parts else "")
        return json.dumps(
            {
                "success": False,
                "passed": 0,
                "failed": 0,
                "errors": 0,
                "exit_code": -1,
                "failed_cases": [],
                "summary": f"command not found: {exc}",
            },
            ensure_ascii=False,
        )

    try:
        stdout_data, _ = await asyncio.wait_for(
            process.communicate(), timeout=TEST_RUN_TIMEOUT
        )
    except asyncio.TimeoutError:
        try:
            process.kill()
        except ProcessLookupError:
            pass
        await process.wait()
        return json.dumps(
            {
                "success": False,
                "passed": 0,
                "failed": 0,
                "errors": 0,
                "exit_code": -1,
                "failed_cases": [],
                "summary": f"command timed out after {TEST_RUN_TIMEOUT}s",
            },
            ensure_ascii=False,
        )

    output = stdout_data.decode("utf-8", errors="replace")
    exit_code = int(process.returncode or 0)
    result = _parse_result(command, output, exit_code)
    logger.info(
        "test_run parsed: passed=%d failed=%d errors=%d exit=%d",
        result["passed"],
        result["failed"],
        result["errors"],
        exit_code,
    )
    return json.dumps(result, ensure_ascii=False)


def _parse_result(command: str, output: str, exit_code: int) -> dict[str, Any]:
    """Dispatch to the runner-specific parser and assemble the result."""
    framework = _detect_framework(command)
    parser = {
        "pytest": _parse_pytest,
        "jest": _parse_jest,
        "go": _parse_go,
    }.get(framework)

    if parser is not None:
        parsed = parser(output)
    else:
        parsed = _parse_generic(output)

    # Backstop: a runner-specific parse that found nothing while the process
    # clearly failed is almost always a format we don't recognise yet — fall
    # back to keyword scanning so the agent still sees the failures.
    if (
        framework != "generic"
        and parsed["passed"] == 0
        and parsed["failed"] == 0
        and parsed["errors"] == 0
        and exit_code != 0
    ):
        fallback = _parse_generic(output)
        if fallback["failed"] or fallback["errors"] or fallback["failed_cases"]:
            parsed = fallback

    failed = parsed["failed"]
    errors = parsed["errors"]
    return {
        "success": exit_code == 0 and failed == 0 and errors == 0,
        "passed": parsed["passed"],
        "failed": failed,
        "errors": errors,
        "exit_code": exit_code,
        "failed_cases": parsed["failed_cases"],
        "summary": _format_summary(parsed["passed"], failed, errors, exit_code),
    }


def _detect_framework(command: str) -> str:
    """Infer the test runner from the command text."""
    lowered = command.lower()
    if "pytest" in lowered:
        return "pytest"
    if "jest" in lowered or "vitest" in lowered:
        return "jest"
    if "go test" in lowered or lowered.startswith("go test"):
        return "go"
    return "generic"


def _format_summary(passed: int, failed: int, errors: int, exit_code: int) -> str:
    """Render a human-readable summary line."""
    parts: list[str] = []
    if passed:
        parts.append(f"{passed} passed")
    if failed:
        parts.append(f"{failed} failed")
    if errors:
        parts.append(f"{errors} errors")
    if not parts:
        return "no results parsed" if exit_code != 0 else "passed"
    return ", ".join(parts)


def _count_matches(pattern: str, text: str) -> int:
    """Return the integer from the first ``(\\d+)`` group of ``pattern``."""
    match = re.search(pattern, text)
    return int(match.group(1)) if match else 0


def _find_line_for_file(text: str, file_ref: str) -> int | None:
    """Best-effort lookup of a failing line number for ``file_ref``.

    Matches both pytest traceback style (``file.py:12:``) and stack-frame
    style (``file.js:12:34``). Falls back to a basename match.
    """
    if not file_ref:
        return None
    for candidate in (file_ref, os.path.basename(file_ref)):
        pattern = re.compile(
            r"(?<![\w/.])" + re.escape(candidate) + r":(\d+)(?::\d+)?"
        )
        match = pattern.search(text)
        if match:
            return int(match.group(1))
    return None


def _split_pytest_nodeid(nodeid: str) -> tuple[str, str]:
    """Split a pytest node id into ``(file, test_name)``."""
    if "::" in nodeid:
        file_part, _, name_part = nodeid.partition("::")
        # Class::method style — keep the trailing segments as the name.
        name = name_part.rsplit("::", 1)[-1] if "::" in name_part else name_part
        return file_part, name
    return nodeid, nodeid


def _parse_pytest(text: str) -> dict[str, Any]:
    """Parse pytest output, including the short test summary line."""
    passed = _count_matches(r"(\d+)\s+passed", text)
    failed = _count_matches(r"(\d+)\s+failed", text)
    errors = _count_matches(r"(\d+)\s+errors?\b", text)

    failed_cases: list[dict[str, Any]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("FAILED "):
            continue
        rest = stripped[len("FAILED ") :]
        if " - " in rest:
            nodeid, reason = rest.split(" - ", 1)
        else:
            nodeid, reason = rest, ""
        file_ref, name = _split_pytest_nodeid(nodeid)
        failed_cases.append(
            {
                "name": name,
                "file": file_ref,
                "error": reason,
                "line": _find_line_for_file(text, file_ref),
            }
        )

    return {
        "passed": passed,
        "failed": failed,
        "errors": errors,
        "failed_cases": failed_cases,
    }


def _parse_jest(text: str) -> dict[str, Any]:
    """Parse jest and vitest output."""
    passed = failed = errors = 0

    # jest: "Tests: 1 failed, 3 passed, 4 total"
    jest_match = re.search(
        r"Tests:\s+(\d+)\s+failed,\s+(\d+)\s+passed", text
    )
    vitest_match = re.search(
        r"Tests\s+(\d+)\s+failed\s*\|\s*(\d+)\s+passed", text
    )
    if jest_match:
        failed = int(jest_match.group(1))
        passed = int(jest_match.group(2))
    elif vitest_match:
        failed = int(vitest_match.group(1))
        passed = int(vitest_match.group(2))

    # vitest-only "1 failed (1)" with no passed segment.
    if failed == 0 and passed == 0:
        only_failed = re.search(r"Tests\s+(\d+)\s+failed\s*\(", text)
        if only_failed:
            failed = int(only_failed.group(1))

    failed_cases: list[dict[str, Any]] = []

    # jest-style failures: "● name" followed by "at ... (file:line:col)".
    jest_names = [line.strip()[1:].strip() for line in text.splitlines()
                  if line.strip().startswith("●")]
    jest_frames = re.findall(r"at .+?\(([^()]+):(\d+):\d+\)", text)
    for index, name in enumerate(jest_names):
        file_ref = line_no = None
        error = ""
        if index < len(jest_frames):
            file_ref = jest_frames[index][0]
            line_no = int(jest_frames[index][1])
        failed_cases.append(
            {
                "name": name,
                "file": file_ref or "",
                "error": error,
                "line": line_no,
            }
        )

    # vitest-style failures: "FAIL  file > path" + "❯ file:line:col".
    vitest_blocks = re.finditer(
        r"^FAIL\s+(\S+)\s+>\s+(.+?)(?:\n(.*?))?(?=\nFAIL\s|\nTest Files|\Z)",
        text,
        re.MULTILINE | re.DOTALL,
    )
    for match in vitest_blocks:
        file_ref = match.group(1)
        name = match.group(2).strip()
        body = match.group(3) or ""
        error_match = re.search(
            r"^(?:Error|AssertionError):\s*(.+)$", body, re.MULTILINE
        )
        error = error_match.group(1).strip() if error_match else ""
        line_no = _find_line_for_file(text, file_ref)
        failed_cases.append(
            {
                "name": name,
                "file": file_ref,
                "error": error,
                "line": line_no,
            }
        )

    return {
        "passed": passed,
        "failed": failed,
        "errors": errors,
        "failed_cases": failed_cases,
    }


def _parse_go(text: str) -> dict[str, Any]:
    """Parse ``go test`` (verbose) output.

    ``go test -v`` prints ``file.go:line: msg`` detail lines *while* a subtest
    runs and only emits ``--- FAIL: name`` afterwards, so we keep the most
    recent detail line around and attach it to the failure that follows.
    """
    passed = failed = errors = 0
    failed_cases: list[dict[str, Any]] = []

    pending_detail: tuple[str, int, str] | None = None
    for line in text.splitlines():
        fail_match = re.match(r"^--- FAIL:\s+(\S+)", line)
        pass_match = re.match(r"^--- PASS:\s+(\S+)", line)
        detail = re.match(r"^\s+(\S+\.go):(\d+):\s*(.*)$", line)

        if detail:
            pending_detail = (
                detail.group(1),
                int(detail.group(2)),
                detail.group(3),
            )
            continue
        if fail_match:
            failed += 1
            case: dict[str, Any] = {
                "name": fail_match.group(1),
                "file": "",
                "error": "",
                "line": None,
            }
            if pending_detail is not None:
                case["file"], case["line"], case["error"] = pending_detail
                pending_detail = None
            failed_cases.append(case)
            continue
        if pass_match:
            passed += 1
            pending_detail = None
            continue

    # Non-verbose runs only print "FAIL\t<pkg>"; surface at least one failure.
    if failed == 0 and passed == 0 and re.search(r"^FAIL\b", text, re.MULTILINE):
        failed = 1

    return {
        "passed": passed,
        "failed": failed,
        "errors": errors,
        "failed_cases": failed_cases,
    }


def _parse_generic(text: str) -> dict[str, Any]:
    """Keyword-based fallback for unknown runners.

    Recognises a few common summary phrasings (mocha ``N passing / N failing``,
    bare ``FAILED`` markers) and otherwise counts failure-looking lines.
    """
    passed = _count_matches(r"(\d+)\s+passing", text) or _count_matches(
        r"(\d+)\s+passed", text
    )
    failed = _count_matches(r"(\d+)\s+failing", text) or _count_matches(
        r"(\d+)\s+failed", text
    )
    errors = _count_matches(r"(\d+)\s+errors?\b", text)

    failed_cases: list[dict[str, Any]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if re.match(r"^(FAILED|FAIL:|✗|✘)\b", stripped):
            failed_cases.append(
                {
                    "name": stripped,
                    "file": "",
                    "error": "",
                    "line": _find_line_for_file(text, stripped),
                }
            )

    # Last resort: presence of a standalone "FAIL" exit marker.
    if failed == 0 and errors == 0 and re.search(r"^FAIL\b", text, re.MULTILINE):
        failed = 1

    return {
        "passed": passed,
        "failed": failed,
        "errors": errors,
        "failed_cases": failed_cases,
    }
