# ADR-007：Coding Task 使用独立 Git Worktree

## 状态

已接受（Phase 0）。

## 决策

可写 Coding Task 默认创建独立 Worktree，并将其作为唯一 writable root。主工作树默认只读；回写必须生成 ChangeSet 并经过审批。

`git worktree add` 完成后立即固定 Worktree `.git` 指针的 dev/inode、完整内容摘要、
解析后的 admin dir 及 repository `.git` identity。Linux、macOS 与 Docker 沙箱都将
该指针作为只读例外；大小写不敏感文件系统上的 `.GIT` 等别名同样视为保护名称。
每次执行前后及 ChangeSet/commit 前必须重新验证 identity。宿主 Git 只能使用固定
`--git-dir` 与 `--work-tree`，并禁用 system/global config、hooks、fsmonitor 和 external
diff；不得再次通过 Worktree 内的指针动态选择 admin dir。identity 漂移时恢复固定指针
仅用于强制移除 disposable Worktree，不允许继续执行或提交。

## 原因

物理隔离比路径约定更能降低误写主仓库、并发任务互相污染和审批后 Diff 漂移的风险。

## 替代方案

- 直接在主工作树修改：实现简单，但无法满足安全边界。
- 自动 stash 后复用主树：会改变用户状态且难以恢复，故不采用。

## 回滚与兼容

只读任务继续支持现有路径。Worktree 创建失败时返回结构化错误，不裸回退到主工作树。
