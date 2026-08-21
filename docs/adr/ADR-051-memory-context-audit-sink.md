# ADR-051: Context-bound memory audit sink

状态：accepted

## 背景

`MemoryService` 以前以 `Database` 为构造参数，并在每个请求中临时创建
`MemoryStore`。第一轮边界重构已经隔离了 `MemoryRepository`，但 RPC 仍缺少
一个能同时满足两件事的审计边界：共享 SQLite/hash-chain writer，以及每个
`RequestContext` 的 principal/project/session attribution。

直接复用服务器级 `AuditLogger` 会把 API 请求记成服务器的 principal；为每个
请求新建 logger 又会复制文件描述符、anchor 和关闭责任。

## 决策

1. `AuditLogger` 是进程级的唯一 durable writer，独占 SQLite hash chain、文件
   fd、anchor 和生命周期。
2. `AuditLogger.bind(...)` 生成不可变 `AuditBinding`/`BoundAuditLogger`。绑定只能
   改变经过认证的 principal、runtime 和 transport attribution；project 与
   policy digest 必须匹配 root logger，否则 fail closed。
3. `BoundAuditLogger` 只提供 log/query/verify 操作；`close()` 不关闭 root writer。
4. `MemoryService` 只依赖 `MemoryRepository` 和 root audit sink，并从
   `RequestContext` 为每次调用建立绑定；`MemoryStore` 只接受 repository，不能再
   接受 raw `Database`。

## 终态与测试

- 无 session 的事件写入 `NULL`，不能把空字符串伪装成 session identity。
- 跨 principal/project 的 bind、memory read/write/delete 和 audit query 必须
  保持隔离。
- `python/tests/memory/test_memory_boundaries.py` 固化构造器边界和 RPC 审计归属；
  memory/audit/principal/runtime 回归套件覆盖了上述路径。

## 后续删除条件

不存在 `MemoryStore(db, ...)` 或 `MemoryService(db)` 调用者后，任何新代码不得
恢复兼容构造器；新的 RPC 服务应复用 context-bound sink，而不是创建第二个
`AuditLogger`。
