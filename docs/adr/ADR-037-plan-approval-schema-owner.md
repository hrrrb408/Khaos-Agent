# ADR-037: Give plan approval schema and migrations one owner

状态：accepted

日期：2026-08-22

## 背景

`PlanApprovalStore` 同时定义 `APPROVAL_SCHEMA`、SQLite post-schema column probes、
partial indexes 和 approval/authorization/lease/execution 状态机。schema 变化因此很容易
和业务 SQL 一起被修改，测试也无法区分“迁移已完成”与“状态转换仍正确”。旧
`_post_schema` 名称还暗示迁移属于 store 私有实现，而不是数据库边界。

## 决策

`python/khaos/coding/planning/approval/schema.py` 是 plan approval/execution schema
和 idempotent migration 的唯一 owner，提供 `APPROVAL_SCHEMA` 与 `upgrade_schema`。
`PlanApprovalStore` 只拥有连接上的 CAS 状态、receipt、lease、execution journal 和
transaction；它通过显式导入消费 schema。`store.APPROVAL_SCHEMA` 保留一个迁移周期的
兼容导出，不再定义第二份字符串或 `_post_schema`。

## 迁移和删除条件

新增表、列、索引或兼容迁移必须先修改 schema owner，再补空库/旧库升级测试；不得在
状态方法里执行未记录的 DDL。完成所有旧 import 迁移后删除 `store.APPROVAL_SCHEMA`
兼容导出，保留 `approval.schema` 作为唯一入口。

## 证据

- `python/tests/coding/test_approval_schema_boundary.py` 固化 schema identity、重复
  upgrade 的幂等性、关键 authority 表存在性及 store 不再暴露 `_post_schema`。
- M4 Batch 2 approval/concurrency/closure 回归共 151 passed，证明迁移没有改变 CAS、
  receipt、epoch 和 restart 行为。
