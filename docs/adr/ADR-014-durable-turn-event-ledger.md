# ADR-014：Durable Turn Event Ledger

## 状态

接受并实施（2026-07-15）。

## 决策

AgentLoop 的一次用户输入由 server-issued `turn_id` 和 `attempt_id` 标识。SQLite
`agent_turns` 是 turn 终态权威，`agent_turn_events` 是该 turn 的单调 append stream。
`TurnCoordinator` 是唯一写者：创建 turn 与 `turn.started` 同事务；后续 append 必须精确
匹配当前 sequence；terminal event 与 completed/interrupted/failed status 同事务提交。

Coordinator 在内存中校验 tool call/result 配对与 approval wait 前置 call。result-before-call、
重复 result、重复 terminal 和 terminal 后迟到 event 全部拒绝。正常 done 只有在 terminal
事务落盘后才向 SSE/TUI adapter 可见；异常与取消分别先写 failed/interrupted。

进程内第一次创建 turn 前会执行一次 crash recovery：所有遗留 running turn 追加
`turn.interrupted(reason=process-restart)` 并进入 interrupted。恢复不能根据已有 assistant
消息或 tool output 猜测 completed。

## 兼容

现有 `Message` stream 保留一个迁移周期。done/error/tool/approval message metadata 增加
turn ID、attempt ID 和 event sequence；Gateway/TUI 可逐步切换到 typed event，而无需并行
维护第二套 turn 状态机。

## 不变量

- `turn.started` 后恰有一个 durable terminal；
- sequence 无 gap、重复或倒退；
- terminal 对外可见前已经提交；
- tool result 必须对应同 turn 内未消费的 call；
- crash recovery 只能 interrupted，不能 completed；
- Task status 是投影，不得反向覆盖 turn ledger。

## 回滚

reader 可以暂时继续消费 legacy Message adapter，但 writer 不得回退到只写 messages 表。
ledger 写入失败时停止 turn，不允许发送无 durable terminal 的 done。
