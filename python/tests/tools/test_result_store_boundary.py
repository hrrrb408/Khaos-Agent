"""Contract tests for the runtime-owned idempotent result store."""

import pytest
from khaos.exceptions import PermissionDeniedError
from khaos.tools.result_store import ToolResultStore
from khaos.tools.scheduler_models import ToolResult


def _result(tool_call_id: str) -> ToolResult:
    return ToolResult(tool_call_id=tool_call_id, name="echo", success=True)


@pytest.mark.asyncio
async def test_store_round_trips_results_and_canonical_argument_digests() -> None:
    store = ToolResultStore(max_entries=2)
    first_digest = store.digest_arguments({"a": 1, "b": 2})
    reordered_digest = store.digest_arguments({"b": 2, "a": 1})

    assert first_digest == reordered_digest
    await store.put("operation-1", first_digest, _result("call-1"))
    cached = await store.get("operation-1", reordered_digest)

    assert cached is not None
    assert cached.tool_call_id == "call-1"


@pytest.mark.asyncio
async def test_store_rejects_argument_digest_reuse() -> None:
    store = ToolResultStore()
    await store.put("operation-1", "a" * 64, _result("call-1"))

    with pytest.raises(PermissionDeniedError, match="different tool arguments"):
        await store.get("operation-1", "b" * 64)


@pytest.mark.asyncio
async def test_store_evicts_oldest_unrelated_entry_only() -> None:
    store = ToolResultStore(max_entries=2)
    await store.put("operation-1", "a" * 64, _result("call-1"))
    await store.put("operation-2", "b" * 64, _result("call-2"))
    await store.put("operation-1", "a" * 64, _result("call-1-new"))
    await store.put("operation-3", "c" * 64, _result("call-3"))

    assert (await store.get("operation-1", "a" * 64)).tool_call_id == "call-1-new"
    assert await store.get("operation-2", "b" * 64) is None
    assert (await store.get("operation-3", "c" * 64)).tool_call_id == "call-3"


def test_store_requires_positive_cache_limit() -> None:
    with pytest.raises(ValueError, match="positive integer"):
        ToolResultStore(max_entries=0)
