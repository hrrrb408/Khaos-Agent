# ADR-030: Give deterministic planning explicit immutable limits

状态：accepted

日期：2026-08-21

## 背景

`DeterministicPlanningService` 用 tuple 下标保存 depth、node、file、symbol、edge
和 test budget。调用方只能从签名猜测每个数字的含义，override 时容易错位；计划、
impact traversal 和 verification selection 也难以共享同一组可审计上限。

## 决策

`python/khaos/coding/planning/limits.py` 的不可变 `PlanningLimits` 是 planning
traversal budget 的唯一命名来源。它负责：

- 以字段名表达七个边界，而不是位置 tuple；
- 在构造时拒绝负数/非整数；
- 通过 `override()` 生成单次请求的副本，不修改 service 默认值；
- 生成 `ImpactTraversalBudget` 所需的显式 kwargs。

Planning service 仍拥有只读查询、evidence、risk 和 plan digest；该模块不执行工具、
写 workspace、创建 ChangeSet 或改变 approval 状态。

## 迁移和删除条件

新的 plan/verification budget 必须增加到 `PlanningLimits`，不能在 service 中新增
tuple 下标或裸常量。完成 plan store/read-model 拆分后，service 的兼容构造参数可由
composition root 转换为 `PlanningLimits`，再删除长参数列表。

## 证据

- `python/tests/coding/test_planning_limits.py` 覆盖 named override 和 fail-closed
  参数校验。
- `test_planning_impact_analysis.py`、M4 planning closure/performance tests 继续
  覆盖 traversal truncation、digest 稳定性和风险升级。
