# ADR-006：Coding Intelligence 分层与渐进降级

## 状态

已接受（Phase 0）。

## 决策

Coding Intelligence 分为 Language Registry、解析适配器、持久化索引和查询服务四层。Tree-sitter 与 LSP 是可选增强；现有 `CodeParser` 作为 Legacy/Fallback Adapter 保留。

## 原因

确定性解析、索引和查询需要可测试且可离线运行。可选依赖不可用时，Agent 仍必须能工作并返回明确的降级诊断。

## 替代方案

- 只依赖 LSP：部署和版本耦合过高，无法覆盖无 Server 环境。
- 直接重写现有 parser：破坏兼容性并扩大回归范围。
- 只使用文本搜索：无法稳定提供定义、引用和依赖关系。

## 回滚与兼容

新服务通过注入启用；未注入时继续走现有 Legacy API。任一增强层失败只影响该层，不影响基础文本/Legacy 召回。
