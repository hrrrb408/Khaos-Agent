# ADR-038: Give plan approval reads one owner

状态：accepted

日期：2026-08-22

## 背景

`PlanApprovalStore` 既执行 CAS/receipt/lease 写入，又直接拼接 approval request、decision、
audit event 和 authorization 的查询与 row conversion。这样只读调用很容易被误改成隐式
提交或连接生命周期操作，也让状态写入与查询的回归边界混在一起。

## 决策

`python/khaos/coding/planning/approval/read_model.py` 是 approval request、decision、
audit event 和 execution authorization 只读 SQL 与 row conversion 的唯一 owner。
`PlanApprovalReadModel` 只接收已有连接，禁止打开/关闭连接、commit、DDL 和任何写 SQL。
`PlanApprovalStore` 仍保留一周期的公开读取兼容方法和私有 row-converter alias，但实现
只委托给 read model；事务性写入仍由 store 拥有，直到后续有独立 writer/recovery owner。

## 证据与删除条件

- `python/tests/coding/test_approval_read_model_boundary.py` 用只读连接代理证明查询不
  会 commit 或 close，并覆盖 store 的兼容读取入口。
- 现有 approval/concurrency/closure 回归继续通过，证明 SQL 与转换行为未改变。
- 所有生产调用迁移到 read model 或更高层 service 后，删除 store 的读取兼容 alias；
  不在 read model 中添加事务写入以维持单一状态 owner。
