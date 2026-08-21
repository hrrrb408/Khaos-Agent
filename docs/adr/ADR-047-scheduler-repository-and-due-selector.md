# ADR-047: Give the scheduler persistence port and due selection one owner each

状态：accepted

日期：2026-08-22

## 背景

`CronEngine` 同时编排 tick、任务状态、恢复、journal、executor 和所有 scheduled-task
数据库调用。即使 SQL 由 `Database` 执行，engine 仍直接知道每个表操作的名称、project
scope 和 identity CAS 参数；tick 也在长循环中内联 due-task 过滤。两处重复的边界让后续
迁移很容易漏掉 project/policy 绑定，或在新分支绕过 pending-persistence/executor fence。

## 决策

### ScheduledTaskRepository

`python/khaos/scheduler/repository.py` 的 `ScheduledTaskRepository` 是 scheduler 到
持久化层的唯一端口。它在构造时绑定 project identity，负责把 scheduler 语义映射到
`Database` 的 task CRUD、lease/CAS、recovery 和 operation-journal 方法；所有读取自动带
project scope，claim 同时绑定 principal、project 和 policy snapshot。它不拥有 SQLite
connection、schema 或 engine lifecycle。

`CronEngine.db` 保留一周期兼容可用性属性，生产调用通过 `_task_repository`；既有测试对
底层 Database 方法的 monkeypatch 仍能观察到调用，因为 adapter 保留同一 database 对象。

### DueTaskSelector

`python/khaos/scheduler/due_selector.py` 的 `DueTaskSelector` 是纯函数 owner，统一应用
enabled、PENDING、next-run、pending-persistence 和 in-flight execution 五个 tick gate。
它不修改 task、不启动 coroutine、不访问 database；per-task lock 和 degraded 最终闸门
仍由 engine 负责。

## 证据与删除条件

- `python/tests/scheduler/test_scheduler_boundaries.py` 覆盖 project-scoped repository
  调用和无副作用的 due selection。
- `python/tests/scheduler/` 全部 202 个测试通过，证明 lease/recovery/control CAS、
  journal replay、生命周期和 tick 行为保持不变。
- 后续把 Database 的 scheduled-task SQL 迁入正式 repository implementation 后，删除
  facade 兼容 `db` 属性和 engine 中对应的可用性分支；任何新 scheduler path 必须只消费
  repository port 与 selector，不得再直接访问 Database。
