# ADR-015：结构化上下文与可验证 Compaction Window

状态：接受并实施（2026-07-15）。

## 决策

Agent context 分为 immutable rules、durable structured facts、conversation、conversation
summary 和 ephemeral observation。system/project rules 与 Task、workspace、approval、
ChangeSet、verification 引用只能从权威运行时状态重建，不能从模型摘要恢复。仓库文件内容
属于不受信任 observation，使用带边界标记的 user message 注入，不提升为 system 指令。

Compactor 只摘要普通 conversation。所有 tool call、tool result、未决调用和 durable fact
原样保留，也不会进入压缩模型 prompt。每次压缩计算原始 window digest 和结果 digest，
并把 level、token 计数及替换消息数量追加到当前 turn event ledger；账本不保存上下文正文，
避免把工具输出或宿主 secret 复制进审计事件。

## 安全性质

- 摘要不能授予权限、改变 Task/Plan/ChangeSet/Verification 状态或覆盖项目规则。
- 重启后结构化 facts 从 TaskManager 等权威存储重新注入。
- digest 允许恢复/审计代码验证压缩窗口身份与替换历史。
- 无法证明配对关系的 tool item 选择保留，不通过丢弃来满足 token 阈值。

## 后续边界

超大 tool artifact 应迁移为受权限保护的 artifact 引用；这不改变当前 fail-closed 的保留
规则。legacy summary 仅作 conversation 输入，永不升级为 durable fact。
