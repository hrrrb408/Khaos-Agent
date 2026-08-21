# ADR-035: Isolate the approval callback adapter lifecycle

状态：accepted

日期：2026-08-22

## 背景

`ToolScheduler` 既编排 permission/authority，又直接管理 UI/Gateway approval callback
的线程池、semaphore、deadline、response schema 和 shutdown。同步 callback 的线程无法
强制中止；如果 scheduler 在 worker 仍运行时报告 CLOSED，后续 runtime 可能丢失审批
结果或复用一个仍有副作用的 adapter。

## 决策

`python/khaos/tools/approval_callback.py` 的 `ApprovalCallbackRunner` 是 approval
adapter 生命周期唯一 owner：它负责严格 response normalization、binding payload
projection、异步/同步 callback deadline、bounded admission 和 worker terminal proof。
`ToolScheduler._confirm` 只保留迁移期委托入口；runner 不拥有 permission policy、receipt
签发或 capability consume。

## 迁移和删除条件

新增 approval UI、Gateway 或插件必须通过 `ApprovalCallbackRunner`，不得在 scheduler、
transport 或 handler 中创建未约束的 executor/线程。完成 `ToolAuthorization` seam 后，
删除 scheduler 的 `_confirm` 兼容方法，并让 authorization coordinator 直接持有 runner。
无法在关闭 deadline 内证明 worker 已终止时必须保留 quarantine，禁止返回 CLOSED。

## 证据

- `python/tests/tools/test_approval_callback_boundary.py` 覆盖 schema 拒绝、binding
  payload、async/sync callback、关闭后拒绝、deadline 与容量耗尽。
- scheduler 的 event-loop starvation、approval timeout、malformed response 和
  confirmation 回归测试在 runner 委托后继续通过。
