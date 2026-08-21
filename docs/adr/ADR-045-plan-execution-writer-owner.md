# ADR-045: Give planned-execution writes one owner

状态：accepted

日期：2026-08-22

## 背景

`PlanApprovalStore` 原本同时实现 approval ledger、execution-run 状态转换、attestation
持久化、terminal seal 和 crash recovery。这样同一组 SQL 与事务语义有两个潜在入口：
调用方可以把 approval facade 当作执行写入仓库，后续也很容易在 facade 中继续增加第二套
执行状态逻辑。读取已经由 ADR-044 收敛后，写入仍缺少明确 owner。

## 决策

`python/khaos/coding/planning/approval/execution_writer.py` 的
`PlanExecutionWriter` 是 planned execution 写入与恢复的唯一 owner。它接收已经打开的
SQLite connection 和 `PlanExecutionReadModel`，但不拥有 connection 生命周期、approval
authority 或 runtime composition。它负责：

- execution run 的创建、CAS 状态转换和 rollback resume；
- initial/final/rollback attestation 的 canonical 持久化；
- recovery/rollback seal 与 terminal tombstone 的原子提交；
- recovered terminal/no-mutation 状态的 proof 校验、poison scope 清理和审计写入。

所有属于上述范围的事务都在 writer 内完成，并在失败时回滚。`PlanApprovalStore` 只保留
一个迁移周期的公开兼容委托；委托不能复制 SQL 或改变参数/错误语义。审计回调使用动态
兼容 hook，以便既有测试和 runtime 注入仍能观察同一事务中的 audit failure。

edit journal 的独立 owner 由 ADR-046 定义；approval ledger、lease 和 receipt 仍由 store
的其他 owner 负责，不放入 execution writer。

## 证据与删除条件

- `python/tests/coding/test_execution_writer_boundary.py` 证明 facade 只委托、writer
  承担真实状态转换，并且 writer 不关闭外部 connection。
- Batch 3 durability、attestation、terminal、baseline recovery、rollback ownership
  和 directory-sync 回归测试继续覆盖原有 CAS、proof 和回滚语义。
- 所有 execution-run、attestation、terminal recovery 生产调用迁移到 writer 或更高层
  coordinator 后，删除 store 的对应兼容委托及动态 audit hook。
