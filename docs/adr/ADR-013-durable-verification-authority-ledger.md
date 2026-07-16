# ADR-013：持久化 Verification Authority Ledger

## 状态

接受并实施（2026-07-15）。

## 决策

Trusted Verification 的 proof/success authority 继续由独立 spawn 子进程持有，父 Agent
进程只能通过继承 Pipe 和随机 capability 调用固定 RPC。每个 boot 在
verification storage parent 下使用随机名 0700 私有目录和
`O_CREAT | O_EXCL | O_NOFOLLOW` 创建独立 SQLite ledger；退出后保留供审计，
但不在下一 boot 重用其 writer 或 capability。

Ledger 中的 proof 与 success 全部以 `boot_id` 为 scope；新 boot 可以只读审计保留的旧 ledger，但
`require-proof`/`require-success` 只查询当前 boot，所以持久化不等于允许跨 boot replay。
accepted、rejected、boot-started 和 boot-stopped 事件写入 append-only event 表。每条事件
保存 canonical payload、previous hash 和 SHA-256 event hash；Authority 启动必须从头验证
hash chain，发现截断后的重写、插入或内容修改即拒绝启动。

状态写入与对应 accepted audit event 在同一 SQLite transaction 中提交。IPC token/sequence
错误和语义拒绝也会记录不含原始敏感参数的事件；参数仅以 canonical digest 保存。

## 不变量

- authority ledger process 必须与 Agent PID 不同；
- proof/success 只在签发 boot 内有效；
- 每个旧 boot ledger 必须保留且其 hash chain 可验证；
- ledger chain 损坏时不得新发 authority；
- authority process crash 不得使主 verification DB 推断成功；
- durable ledger 不替代 CleanupProof、storage identity 或 success CAS 的任一检查。

## 威胁边界

该机制防御不持有 authority Pipe/FD 的插件、sandbox 项目代码和独立进程。当前单用户
Desktop 模型仍不声称防御可调试可信 Runtime 的同 UID 主体或 root；覆盖该主体需要独立
OS 用户与 peer-credential broker，而不是在 Agent 进程中增加另一个 secret。

## 回滚

不得回滚到临时、退出删除的 authority ledger。若 ledger 无法验证，应禁用 Trusted
Verification 并要求受控修复/重新验证，不能忽略旧链或自动创建空链覆盖。
