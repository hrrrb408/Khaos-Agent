# ADR-027: Make session and message SQL a bounded repository

状态：accepted

日期：2026-08-21

## 背景

`Database` 既负责 SQLite 连接/reader lease/事务，又直接拼接 sessions、messages
和 messages_fts 的 SQL。这样新增历史查询时很容易绕过 owner scope、读 lease 或
唯一 transaction owner；同时 SQL 形状和连接生命周期无法分别测试。

## 决策

`python/khaos/db/repositories/sessions.py` 是 sessions/messages 查询与行转换的
唯一 owner。`SessionRepository` 接收 facade 已经选择并授权的连接，只负责：

- sessions/messages/messages_fts 的 SQL 形状；
- principal/project 条件的显式组合；
- SQLite row 到 `Message`/字典的转换。

它不打开或关闭连接、不提交或回滚事务，也不决定调用者是否有权使用某个 owner
scope。`Database` 仍是兼容 facade，负责 read lease、transaction、审计和迁移，
并把这些边界传给 repository。

## 迁移和删除条件

先迁移只读查询，再迁移 message 写入；每个方法必须由 facade 的 characterization
tests 覆盖 owner、分页、窗口、FTS 和错误路径。所有生产调用者改为 facade/repository
port 后，才能删除 `Database` 中对应的 SQL 和迁移期 connection views；不得在 facade
与 repository 中长期维护两套查询。

## 证据

- `python/tests/db/test_session_repository_boundary.py` 覆盖 repository wiring、
  独立 owner scope、窗口排序和 before/after 计数。
- `test_database.py`、session search、chat replay/identity 回归测试继续覆盖兼容
  facade 的公开行为。
