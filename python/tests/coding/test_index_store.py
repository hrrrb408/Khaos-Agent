import sqlite3
from pathlib import Path

import pytest

from khaos.coding.intelligence.index import IndexStore


@pytest.mark.asyncio
async def test_index_refresh_is_incremental_and_queryable(tmp_path: Path):
    source = tmp_path / "sample.py"
    source.write_text("import os\ndef build():\n    return os.getcwd()\n", encoding="utf-8")
    store = IndexStore(sqlite3.connect(":memory:"))
    assert await store.refresh("p1", [source]) == {"changed": 1, "skipped": 0, "failed": 0}
    assert await store.refresh("p1", [source]) == {"changed": 0, "skipped": 1, "failed": 0}
    assert (await store.find_symbols("p1", "build"))[0]["name"] == "build"
    assert await store.imports_for("p1", source) == ["os"]
    source.write_text("def changed():\n    pass\n", encoding="utf-8")
    assert (await store.refresh("p1", [source]))["changed"] == 1
    assert await store.find_symbols("p1", "build") == []


@pytest.mark.asyncio
async def test_index_remove_cleans_symbols(tmp_path: Path):
    source = tmp_path / "sample.go"
    source.write_text("package main\nfunc Build() {}\n", encoding="utf-8")
    store = IndexStore(sqlite3.connect(":memory:"))
    await store.refresh("p1", [source])
    await store.remove("p1", source)
    assert await store.find_symbols("p1", "Build") == []
