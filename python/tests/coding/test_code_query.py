import sqlite3
from pathlib import Path

import pytest

from khaos.coding.intelligence import CodeQueryService
from khaos.coding.intelligence.index import IndexStore


@pytest.mark.asyncio
async def test_query_service_definition_and_dependencies(tmp_path: Path):
    source = tmp_path / "sample.py"
    source.write_text("from pathlib import Path\ndef build():\n    return Path('.')\n", encoding="utf-8")
    service = CodeQueryService(IndexStore(sqlite3.connect(":memory:")))
    await service.store.refresh("p1", [source])
    assert (await service.find_definition("p1", "build"))["name"] == "build"
    assert await service.find_dependencies("p1", source) == ["pathlib"]
