# ADR-048: Give dispatched tool results one terminalization owner

状态：accepted

日期：2026-08-22

## 背景

`ToolScheduler._execute_one_impl` 需要覆盖取消、异常、业务失败、结果投影失败和成功五个
终态分支。每个分支此前都直接调用 audit、`ToolOperationStore.finish` 和
`put_result`，而 `_execute_one` 另外负责 phase terminalization。分支之间很容易遗漏
audit、忘记唤醒同一 idempotency operation 的等待者，或在 durable finalization 改写结果后
缓存了旧对象。

## 决策

`python/khaos/tools/result_finalizer.py` 的 `ToolResultFinalizer` 是 dispatched tool
终态的唯一 owner：

- `terminalize` 委托 immutable `ToolPhaseCoordinator`，把 effect/delivery 证据写入最终 phase；
- `audit_best_effort` 统一 audit failure 的可见 warning 语义，不把 audit 故障伪装成 handler
  失败；
- `finish_and_store` 先完成 durable operation ownership，再发布最终结果到 runtime cache，
  并支持保留“handler 尚未开始”时不写 cache 的边界。

`ToolScheduler` 只决定何时进入该边界和构造 `ToolResult`，不再直接拥有 terminal phase、
audit 或 result-store 写入。`ToolOperationStore` 仍是 durable claim/wait/finish 的底层
owner，finalizer 不复制 operation 状态机。

## 证据与删除条件

- `python/tests/tools/test_result_finalizer_boundary.py` 固化 audit failure、finish/store
  顺序和 scheduler 无直接终态写入。
- 工具调度回归测试覆盖取消、异常、业务失败、delivery degraded、成功和幂等重启路径。
- 当所有调用方迁移到 `ToolResultFinalizer` 后，scheduler 中只保留 operation scope 的
  recovery 投影；其余历史 compatibility wrappers 已删除。
