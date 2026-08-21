# ADR-040: Give tool-operation idempotency one owner

状态：accepted

日期：2026-08-22

## 背景

`ToolScheduler` 同时维护 runtime 内 claim/event map、durable operation row 的 CAS、
waiter recovery、effect id 更新和 terminal result replay。这个状态机和 permission、
handler dispatch 混在一个文件中，导致重启 orphan、重复参数冲突和 finalize 失败很难单独
测试，也容易在新执行路径中漏掉 durable claim。

## 决策

`python/khaos/tools/operation_store.py` 的 `ToolOperationStore` 是 tool-operation
idempotency 的唯一 owner：

- `scope` 绑定 principal/project/session/task/workspace 与 tool；
- `claim`、`wait`、`update_effect_id` 和 `finish` 统一本地 waiter 与 durable row 语义；
- `ToolResultStore` 只负责 runtime bounded replay cache，operation store 负责何时读取、
  何时终态化；
- scheduler 的旧私有方法仅保留一周期委托，不得重新访问 operation DB 或维护第二套 map。

## 证据与删除条件

- `python/tests/tools/test_operation_store_boundary.py` 固化 scope 身份绑定、无连接生命周期
  旁路，以及 scheduler 不再直接访问 durable operation API。
- tool scheduler/idempotency/result 回归继续通过；所有调用者迁移到 `ToolOperationStore`
  后删除 scheduler 的私有兼容委托。
