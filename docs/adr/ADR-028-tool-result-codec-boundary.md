# ADR-028: Isolate the tool-result protocol codec

状态：accepted

日期：2026-08-21

## 背景

`ToolScheduler` 同时负责 admission、permission、authority、handler dispatch、
审计和把 handler 返回值投影为 `ToolResult`。结果分类和 durable operation JSON
编解码本身是一个独立安全边界：错误形状不能被误报为成功 mutation，未知字段不能
成为执行状态，损坏的 durable row 必须进入不可重试的 reconciliation 状态。

## 决策

`python/khaos/tools/result_codec.py` 的 `ToolResultCodec` 是结果协议的唯一 owner，
负责：

- typed `ToolExecutionOutcome`/`EffectOutcome` 与 legacy payload 的归一化；
- effect status、effect id、reconciliation hint 的边界校验；
- `ToolResult` 的 durable JSON 编解码和未知字段过滤；
- malformed durable result 的 fail-closed unresolved projection。

`ToolScheduler` 只编排时序、权限和效果，不再复制结果分类/序列化逻辑。

## 迁移和删除条件

结果消费者统一导入 `ToolResult`/`ToolExecutionOutcome`/`ToolResultCodec`，旧的
`ToolScheduler._normalize_effect_outcome` 等实现不再恢复。下一步将 runtime-scoped
idempotency cache 与 durable operation claim 从 scheduler 提取为 `ToolResultStore`，
但必须继续复用本 ADR 的 codec，不能出现第二套 JSON schema。

## 证据

- `python/tests/tools/test_result_codec_boundary.py` 覆盖 legacy failure、typed
  metadata 校验、未知字段和 malformed durable row。
- scheduler、operation、tool regression tests 继续覆盖调度器对 codec 的集成行为。
