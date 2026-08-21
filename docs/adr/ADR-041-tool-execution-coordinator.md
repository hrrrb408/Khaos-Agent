# ADR-041: Give authority-bound tool invocation one owner

状态：accepted

日期：2026-08-22

## 背景

`ToolScheduler._execute_one_impl` 既负责审批状态，又直接拼装 process/office/sandbox/
network/step authority context，调用 handler，并把任意返回值归一化成 effect outcome。
这使新的执行后端很容易绕过统一的 `effect_id`、timeout 或 `ExecutionAuthority` 注入。

## 决策

`python/khaos/tools/execution_coordinator.py` 的 `ToolExecutionCoordinator` 是已授权
单步调用的唯一 dispatch owner：

- 在 handler 前注入 process/office/sandbox/network/step/execution authority；
- 通过 `ToolInvocationBroker` 调用并强制 timeout；
- 通过 `ToolResultCodec` 归一化 effect outcome；
- 不做 admission、permission、operation claim、budget 或 audit，避免跨越其他状态 owner。

`ToolScheduler` 继续负责批次并发、审批事件和结果投影，并只通过 coordinator 进入
handler。后续可将 scheduler 的 effect/result terminalization 迁入同一 bounded context，
但不得重新把 authority context 拼装回 scheduler。

## 证据与删除条件

- `python/tests/tools/test_execution_coordinator_boundary.py` 固化 authority/effect 注入、
  handler 调用和 scheduler 无直接 broker invoke 旁路。
- scheduler/codec/operation/idempotency 回归继续通过；所有直接 handler 调用迁移后，删除
  scheduler 的 execution compatibility path。
