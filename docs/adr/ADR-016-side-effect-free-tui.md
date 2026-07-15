# ADR-016：无副作用 TUI 与绑定审批视图

状态：接受并实施（2026-07-15）。

## 决策

TUI 是 event renderer 和 RPC/runtime client，不是执行 backend。写工具完成后的 diff preview
只能来自工具结果中已经生成的 `diff`/`patch` artifact；没有 artifact 就不展示。TUI 禁止为
预览自行调用 host Git、shell 或文件系统 mutation API。

Approval dialog 从 server-issued request 构造不可变 view model，展示 tool、target、level、
principal、task、workspace、binding digest、arguments digest、profile digest 和剩余有效期。
过期 challenge、重复 pending tool call ID 与 expiry 后点击全部拒绝。动态 target/name/scope
必须进行 markup escape，避免仓库内容或命令控制确认 UI 的表现。

UI callback 只表达用户意图，不授予 capability。Scheduler 仍须在服务器侧 resolve 并一次性
consume ApprovalBroker challenge 后才允许 dispatch。

## 回滚

可以关闭 diff preview 或退回旧 Message renderer，但不得恢复 TUI host subprocess，也不得
隐藏 binding scope/digest/expiry 后继续允许审批。
