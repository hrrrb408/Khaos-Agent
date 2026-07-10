# Coding Runtime Alignment Gap Analysis

> M1 Foundation 基线：`f33be3285b76cb37c0d834e3559d190274fabd0f`
> 当前分支：`feature/coding-runtime-alignment`

## 状态标签

- **implemented**：组件代码存在并可被单元测试导入。
- **integrated**：已接入真实运行时路径。
- **enforced**：运行时无法通过普通调用绕过。
- **verified**：已有端到端或安全测试证明。
- **experimental**：尚未承诺稳定性，不能作为强制安全保证。

## 组件状态

| 组件 | 组件代码 | 运行时接入 | 安全保证 | 备注 |
|---|---|---|---|---|
| WorkspaceManager | implemented | experimental | experimental | 已可创建 Worktree，但尚未接入 AgentLoop 全链路 |
| ChangeSet | implemented | experimental | experimental | 已有内容 hash，尚未完成 patch artifact 与 apply 链 |
| ApprovalBroker | implemented | integrated | experimental | 工具审批已接入；ChangeSet 应用绑定仍待 M2 |
| HostExecutionBackend | implemented | experimental | experimental | 当前为 host argv 执行，尚非 macOS/Linux 强制沙箱 |
| Docker sandbox 参数 | implemented | experimental | experimental | 参数已强化，但尚未限定为活动 TaskWorkspace |
| terminal | implemented | experimental | experimental | 仍有旧兼容入口，尚未统一进入 ExecutionService |
| test_run | implemented | experimental | experimental | 尚未完整委托 VerificationPipeline/ExecutionService |
| sandbox_exec | implemented | experimental | experimental | 旧 Docker 入口仍存在 |
| VerificationPipeline | implemented | integrated | experimental | 基础步骤执行已接入 Host backend |
| LanguageRegistry/索引/LSP | implemented | experimental | experimental | M2 阶段冻结后续增强，不宣称完整能力 |

## 明确不作出的保证

- 当前 M1/M2 之前版本**不宣称** Agent 已被强制限制在 Task Worktree。
- 当前 Host backend **不宣称**实现 macOS/Linux 强制网络隔离。
- 当前 Docker 入口**不宣称**拒绝所有任意宿主路径挂载。
- 配置中的 `network_policy: none` 不能替代 OS 或容器级隔离。

## M2 目标

M2 只处理真实执行链、Workspace Boundary、ExecutionService、ChangeSet 审批应用和安全生命周期测试。完成条件以端到端证据为准；组件存在但未接入的能力仍保持 `experimental`。
