from unittest.mock import AsyncMock, MagicMock

from khaos.runtime.factory import RuntimeResult


async def test_runtime_aclose_calls_memory_manager_close():
    memory = MagicMock()
    memory.aclose = AsyncMock()
    result = RuntimeResult(MagicMock(), MagicMock(), None, None, MagicMock(), memory, MagicMock(), None)
    await result.aclose()
    memory.aclose.assert_awaited_once()
