# ADR-052: Memory SQL belongs to the database repository

状态：accepted

## 决策

`Database` 只拥有 SQLite 连接生命周期、全局写事务锁、迁移和公开的
`read_connection()` 读租约。记忆表的 SQL 和 row shape 由
`python/khaos/db/repositories/memories.py::MemorySqlRepository` 独占。

`memory.repository.SqliteMemoryRepository` 只是组合根导出的类型适配器；它不再
转发到 `Database.get_memory()` 等 facade 方法。读操作必须使用
`Database.read_connection()`，写操作必须使用 `Database.transaction()`，因此
repository 不会创建第二个连接，也不会取得独立的 commit 权。

## 删除的旁路

以下 `Database` memory facade 方法已删除：`upsert_memory`、`get_memory`、
`delete_memory`、`delete_memory_by_id`、`list_memories`、`search_memories`、
`touch_memory`。生产调用者和并发测试都通过 `MemoryRepository`/`MemorySqlRepository`
端口访问记忆表。

## 验证

- `python/tests/memory`、F-02 project-isolation 和 F-01 cross-domain transaction
  tests 通过。
- 边界测试检查 `Database` 不再发布记忆方法，防止后续调用者重新添加转发壳。
- 连接关闭仍由 `DatabaseConnection` 统一协调，读租约和写锁的生命周期不变。
