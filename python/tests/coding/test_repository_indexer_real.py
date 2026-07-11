from __future__ import annotations

import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest

pytestmark = pytest.mark.tree_sitter_real
pytest.importorskip("tree_sitter")

from khaos.coding.intelligence.index import IndexStore, RepositoryIndexer, RepositoryParseStateCache
from khaos.coding.intelligence.query import CodeQueryService
import khaos.coding.intelligence.index.repository as repository_module


def _repo(root: Path) -> None:
    files = {
        "app.py": "import os\ndef build():\n    return os.getcwd()\n",
        "app.js": "import x from 'pkg'; export function run(){ return x(); }\n",
        "app.ts": "import {T} from 'types'; export function typed(): T { return make<T>(); }\n",
        "view.tsx": "export const View = () => <button onClick={() => run()}/>;\n",
        "main.go": "package main\nimport \"fmt\"\nfunc Build(){fmt.Println(1)}\n",
        "lib.rs": "use std::fmt; pub fn build(){println!(\"x\");}\n",
        "unknown.xyz": "ignored",
    }
    for name, content in files.items(): (root / name).write_text(content, encoding="utf-8")
    (root / "binary.py").write_bytes(b"x\x00y")
    (root / ".git").mkdir(); (root / ".git" / "ignored.py").write_text("def ignored(): pass")


@pytest.mark.asyncio
async def test_multilanguage_repository_e2e_increment_delete_rename_error_repair(tmp_path: Path) -> None:
    _repo(tmp_path); store = IndexStore(sqlite3.connect(":memory:", check_same_thread=False)); indexer = RepositoryIndexer(store)
    first = await indexer.index("repo", tmp_path)
    assert first["parsed_files"] == 6 and first["unsupported_files"] == 1
    assert first["statuses"]["binary.py"] == "rejected-binary"
    for path in ("app.py", "app.js", "app.ts", "view.tsx", "main.go", "lib.rs"):
        record = await store.file_record("repo", path); assert record and record["parser_source"] == "tree-sitter"
        counts = await store.semantic_counts("repo", path); assert counts["code_symbols"] > 0
    second = await indexer.index("repo", tmp_path)
    assert second["parsed_files"] == 0 and second["unchanged_files"] == 7
    (tmp_path / "app.py").write_text("import os\ndef build():\n    return os.getcwd() or 2\n")
    changed = await indexer.index("repo", tmp_path)
    assert changed["statuses"]["app.py"] == "indexed-incremental" and changed["parsed_files"] == 1
    (tmp_path / "view.tsx").write_text("export const View = () => <button onClick={() => updated()}/>;\n")
    assert (await indexer.index("repo", tmp_path))["statuses"]["view.tsx"] == "indexed-incremental"
    (tmp_path / "main.go").unlink(); deleted = await indexer.index("repo", tmp_path)
    assert deleted["statuses"]["main.go"] == "deleted" and await store.file_record("repo", "main.go") is None
    (tmp_path / "lib.rs").rename(tmp_path / "renamed.rs"); renamed = await indexer.index("repo", tmp_path)
    assert renamed["statuses"]["lib.rs"] == "deleted" and renamed["statuses"]["renamed.rs"] == "indexed-full"
    (tmp_path / "app.py").write_text("def safe(): good()\ndef broken(: bad(\ndef later(): final()\n")
    broken = await indexer.index("repo", tmp_path); assert broken["statuses"]["app.py"] in {"indexed-incremental", "indexed-full-fallback"}
    assert (await store.semantic_counts("repo", "app.py"))["code_diagnostics"] > 0
    (tmp_path / "app.py").write_text("def safe(): good()\ndef later(): final()\n")
    repaired = await indexer.index("repo", tmp_path); assert repaired["statuses"]["app.py"] in {"indexed-incremental", "indexed-full-fallback"}
    assert (await store.semantic_counts("repo", "app.py"))["code_diagnostics"] == 0


@pytest.mark.asyncio
async def test_cache_is_repository_path_and_dialect_bound(tmp_path: Path) -> None:
    one = tmp_path / "one"; two = tmp_path / "two"; one.mkdir(); two.mkdir()
    for root in (one, two): (root / "same.ts").write_text("const x:number=1")
    store = IndexStore(sqlite3.connect(":memory:", check_same_thread=False)); indexer = RepositoryIndexer(store)
    await indexer.index("one", one); await indexer.index("two", two)
    assert indexer.cache.stats()["entries"] == 2
    (one / "same.ts").rename(one / "same.tsx"); (one / "same.tsx").write_text("const x=<div/>")
    report = await indexer.index("one", one)
    assert report["statuses"]["same.ts"] == "deleted" and report["statuses"]["same.tsx"] == "indexed-full"


def test_cache_lru_entry_byte_and_single_state_limits(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(repository_module, "MAX_PARSE_STATE_ENTRIES", 2); monkeypatch.setattr(repository_module, "MAX_PARSE_STATE_BYTES", 40_000); monkeypatch.setattr(repository_module, "MAX_SINGLE_STATE_BYTES", 20_000)
    cache = RepositoryParseStateCache()
    from khaos.coding.intelligence import LanguageRegistry
    for index in range(3):
        result = LanguageRegistry().parse(file_path=f"{index}.py", content=f"def f{index}(): pass".encode())
        cache.put("r", "root", f"{index}.py", result.parse_state, 20, index)
    assert cache.stats()["entries"] <= 2 and cache.stats()["evictions"] >= 1
    huge = LanguageRegistry().parse(file_path="huge.py", content=b"#" * 5000)
    monkeypatch.setattr(repository_module, "MAX_SINGLE_STATE_BYTES", 100)
    before = cache.stats()["entries"]; cache.put("r", "root", "huge.py", huge.parse_state, 5000, 1)
    assert cache.stats()["entries"] == before


@pytest.mark.asyncio
async def test_store_failure_preserves_old_index_and_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "x.py"; source.write_text("def old(): pass")
    store = IndexStore(sqlite3.connect(":memory:", check_same_thread=False)); indexer = RepositoryIndexer(store); await indexer.index("r", tmp_path)
    old_record = await store.file_record("r", "x.py"); old_cache = indexer.cache.find("r", repository_module._root_identity(tmp_path.resolve()), "x.py")
    source.write_text("def new(): pass")
    async def fail(*args, **kwargs): raise RuntimeError("transaction failure")
    monkeypatch.setattr(store, "write_parse_result", fail)
    report = await indexer.index("r", tmp_path)
    assert report["statuses"]["x.py"] == "parse-failed"
    assert (await store.file_record("r", "x.py"))["content_hash"] == old_record["content_hash"]
    assert indexer.cache.find("r", repository_module._root_identity(tmp_path.resolve()), "x.py").content_hash == old_cache.content_hash


@pytest.mark.asyncio
async def test_paths_symlinks_ignore_close_and_legacy_query(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir(); (tmp_path / "src" / "x.py").write_text("def FindMe(): pass")
    (tmp_path / "vendor").mkdir(); (tmp_path / "vendor" / "ignored.py").write_text("def Bad(): pass")
    outside = tmp_path.parent / "outside.py"; outside.write_text("def Outside(): pass")
    (tmp_path / "escape.py").symlink_to(outside)
    store = IndexStore(sqlite3.connect(":memory:", check_same_thread=False)); indexer = RepositoryIndexer(store)
    report = await indexer.index("r", tmp_path)
    assert "src/x.py" in report["statuses"] and "vendor/ignored.py" not in report["statuses"] and "escape.py" in report["rejected_paths"]
    service = CodeQueryService(store); assert (await service.find_symbols("r", "FindMe"))[0]["path"] == "src/x.py"
    await indexer.close(); assert indexer.cache.stats()["entries"] == 0
    with pytest.raises(RuntimeError): await indexer.index("r", tmp_path)


@pytest.mark.asyncio
async def test_full_reindex_clears_state_and_is_deterministic(tmp_path: Path) -> None:
    (tmp_path / "x.py").write_text("def f(): return g()")
    store = IndexStore(sqlite3.connect(":memory:", check_same_thread=False)); indexer = RepositoryIndexer(store)
    first = await indexer.index("r", tmp_path); second = await indexer.index("r", tmp_path, full_reindex=True)
    assert first["statuses"]["x.py"] == "indexed-full" and second["statuses"]["x.py"] == "indexed-full"
    assert await store.semantic_counts("r", "x.py") == await store.semantic_counts("r", "x.py")


@pytest.mark.asyncio
async def test_1000_file_refresh_scaling_and_lru(tmp_path: Path) -> None:
    for index in range(1000): (tmp_path / f"f_{index:04}.py").write_text(f"def f_{index}(): return call_{index}()\n")
    store = IndexStore(sqlite3.connect(":memory:", check_same_thread=False)); indexer = RepositoryIndexer(store)
    first = await indexer.index("perf", tmp_path); assert first["parsed_files"] == 1000
    second = await indexer.index("perf", tmp_path); assert second["parsed_files"] == 0 and second["unchanged_files"] == 1000
    for index in range(10): (tmp_path / f"f_{index:04}.py").write_text(f"def f_{index}(): return changed_{index}()\n")
    changed = await indexer.index("perf", tmp_path); assert changed["parsed_files"] == 10 and changed["unchanged_files"] == 990
    for index in range(10): (tmp_path / f"f_{index:04}.py").unlink()
    deleted = await indexer.index("perf", tmp_path); assert deleted["deleted_files"] == 10 and deleted["parsed_files"] == 0
    assert indexer.cache.stats()["entries"] <= repository_module.MAX_PARSE_STATE_ENTRIES and indexer.cache.stats()["evictions"] > 0
