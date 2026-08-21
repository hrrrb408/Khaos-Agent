# ADR-034: Make runtime idempotent results one owned store

状态：accepted

日期：2026-08-22

## 背景

`ToolScheduler` 同时维护工具 admission、durable operation claim、in-process
idempotency cache、结果淘汰和等待者唤醒。结果缓存的 lock、argument digest 和 eviction
策略散落在 claim、finish、replay 三条路径中，容易在新增执行分支时形成第二套 replay
语义；重启后的 durable operation row 也容易被误当成可直接 replay 的本地结果。

## 决策

`python/khaos/tools/result_store.py` 是单个 scheduler runtime 的 idempotent result
cache 唯一 owner。它负责 canonical argument digest、并发保护、冲突拒绝和 bounded
eviction；durable DB operation row 仍是跨进程/重启 authority。`ToolScheduler` 只调用
store，不再直接读写 cache dict、cache lock 或淘汰策略，也不把 store 当作新的执行
authority。

## 迁移和删除条件

新的执行路径必须通过 `ToolResultStore.get/put` 才能复用结果；禁止在 scheduler、handler
或 permission adapter 中重新维护 idempotency dict。后续提取
`ToolExecutionCoordinator` 时，operation claim/event map 必须与 result store 的职责
保持显式分离；本地结果缺失或 durable row 仍为 running 时只能返回 UNKNOWN/quarantine。

## 证据

- `python/tests/tools/test_result_store_boundary.py` 覆盖 canonical digest、参数冲突、
  oldest-entry eviction 和非法 cache limit。
- `python/tests/tools/test_tool_scheduler.py` 的 replay、并发、重启和 conflict 场景在
  新 store 下保持通过。
- `ToolScheduler` 不再定义 `_IdempotencyRecord`、`_idempotency_lock` 或
  `_idempotency_results`；canonical digest 实现由 `security/protocol_boundary.py`
  统一拥有。
