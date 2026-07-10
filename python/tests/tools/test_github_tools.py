import json
from unittest.mock import AsyncMock, patch

from khaos.tools.github_tools import GITHUB_TOOL_SPECS, github_create_pr, github_read_issue


async def test_create_pr_and_draft_arguments():
    with patch("khaos.tools.github_tools._gh", new=AsyncMock(return_value={"returncode": 0, "stdout": "https://github/pull/1"})) as gh:
        result = json.loads(await github_create_pr("Fix", "Body", draft=True))
    assert result["created"] and result["url"].endswith("/1")
    assert "--draft" in gh.await_args.args[0]


async def test_read_issue_json_and_specs():
    with patch("khaos.tools.github_tools._gh", new=AsyncMock(return_value={"returncode": 0, "data": {"number": 7}})):
        result = json.loads(await github_read_issue(7))
    assert result["number"] == 7
    assert {item["name"] for item in GITHUB_TOOL_SPECS} == {"github_create_pr", "github_read_issue", "github_comment_issue", "github_request_review"}
