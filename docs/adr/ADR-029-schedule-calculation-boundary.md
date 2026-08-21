# ADR-029: Isolate schedule calculation from the cron engine

状态：accepted

日期：2026-08-21

## 背景

`CronEngine` 同时管理生命周期、任务 ownership、持久化 CAS、lease recovery、执行
和 cron/ISO/interval 解析。时间计算是纯逻辑，却只能通过启动一个完整 engine 测试，
使边界行为难以复核，也让解析错误混入执行状态机。

## 决策

`python/khaos/scheduler/calculator.py` 的 `ScheduleCalculator` 是 schedule value
到 next-run timestamp 的唯一 owner。它：

- 只消费 `ScheduledTask.schedule` 和显式 clock；
- 支持现有 ISO、interval 和简化 minute/hour cron 语义；
- 对 malformed/out-of-range 输入使用有界的一小时 fallback，不修改 task；
- 不打开数据库、不启动 asyncio、不提交状态。

`CronEngine` 仅通过兼容 facade 方法调用 calculator，仍拥有 task lifecycle、lease、
execution 和 persistence。

## 迁移和删除条件

所有新的 schedule 解析调用必须使用 `ScheduleCalculator`；当 engine 外部调用者完成
迁移后，删除 `_compute_next_run` facade 和任何重复 cron 解析。高级 cron 语法必须先
扩展 calculator 的明确 grammar 和测试，不能在 engine 中添加特例。

## 证据

- `python/tests/scheduler/test_schedule_calculator.py` 覆盖显式 clock、优先级、跨日、
  malformed fallback 和纯性。
- `python/tests/scheduler/test_cron_engine.py` 及 batch 3.1.10/14/16B 回归测试继续
  覆盖 engine 的 lease/recovery/ownership 语义。
