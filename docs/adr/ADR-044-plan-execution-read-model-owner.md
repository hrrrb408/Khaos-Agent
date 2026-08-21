# ADR-044: Give planned-execution reads one owner

状态：accepted

日期：2026-08-22

## 背景

`PlanApprovalStore` 同时承担执行 run、编辑日志、journal progress 以及初始、最终和
rollback attestation 的只读 SQL 与反序列化。恢复与验证代码因此必须依赖一个包含大量
事务写入职责的 facade，后续修改容易把读取路径误改成写入或绕过 verified proof 的权威
校验。

## 决策

`python/khaos/coding/planning/approval/execution_read_model.py` 是 planned execution
记录和 proof 查询的唯一 owner。`PlanExecutionReadModel` 只接收已有连接，禁止打开/关闭
连接、commit、rollback、DDL 和写 SQL。它负责：

- execution run 查询与 `PlanExecutionRun` row conversion；
- incomplete run、edit journal 和 journal progress 查询；
- 三类 attestation 的 canonical JSON 解析、normalization 和 digest 校验；
- `VERIFIED` run 读取时的 authority verifier 前置检查，缺少强制 verifier 时 fail closed。

`PlanApprovalStore` 保留一周期的公开兼容委托；原子状态转换、journal/attestation 写入
和 recovery seal 仍由 store 拥有，不在 read model 中引入第二个 writer。

## 证据与删除条件

- `python/tests/coding/test_execution_read_model_boundary.py` 用只读连接代理证明 read
  model 不会管理连接生命周期或写入，并覆盖 verified 读取的 authority 闸门。
- 现有 recovery、rollback、verification 回归继续通过，证明 SQL/反序列化语义未改变。
- 所有生产调用迁移到 read model 或更高层 service 后，删除 store 的执行读取兼容方法和
  `_row_to_execution_run` alias。
