# ADR-026: Make SQLite connection lifecycle a bounded context

状态：accepted

日期：2026-08-21

## 背景

`python/khaos/db/database.py` 同时包含物理连接开关、迁移 runner、事务 owner 和多个
领域 repository。连接生命周期的锁、reader lease 和 close quarantine 与领域 SQL 混在
一起，导致任何数据库重构都必须重新审查全部业务方法。

## 决策

`python/khaos/db/connection.py` 是物理 SQLite connection boundary 的唯一 owner。它负责：

- writer/reader 两个句柄的原子初始化与 query-only reader；
- connection generation、lifecycle lock、close admission fence 和 quarantine；
- reader operation lease 与有界 drain；
- `:memory:` 的 shared-cache URI；
- 无 `aiosqlite` 环境下的最小 async fallback。

`Database` 仍拥有 transaction owner、migration runner 和领域写事务。它通过显式
`DatabaseConnection` 调用获取句柄；旧的 `_conn`、`_reader_conn` 等属性只是迁移期兼容
视图，不得成为新的 writer。迁移 registry 冻结的方法与 `_MigrationConnection` 不移动，
避免篡改已发布 schema manifest。记忆 SQL 是第一个完成的领域抽取，由
`db/repositories/memories.py` 独占（见 ADR-052）。

## 迁移与删除条件

先把只读 repository 迁移到 connection port，再迁移写事务；每个 repository 必须有
characterization/negative tests。所有生产调用者不再直接读取 facade 的 underscored
connection views 后，删除这些 views，并把 migration runner 接到明确的 migration port。

## 证据

- `python/tests/db/test_connection_boundary.py` 固化唯一 owner、close fence 和 reader
  drain 语义。
- 现有 lifecycle/admission/migration tests 继续覆盖兼容 facade，确保迁移期间行为不变。
