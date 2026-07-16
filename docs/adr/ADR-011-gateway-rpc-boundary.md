# ADR-011：Gateway RPC 边界与资源所有权

## 状态

部分接受并实施（2026-07-15）。

## 决策

Gateway 为所有 REST、SSE 与 NDJSON 响应发送 `X-Khaos-Protocol-Version: 1`。普通请求体
最多 1 MiB，平台 webhook 最多 2 MiB。结构化 JSON 只接受 schema 已知字段和单个顶层
值；超限、未知字段、尾随第二个值全部在调用 Python 服务前拒绝。

使用 API key 认证时，session 与 task 在创建时绑定认证 middleware 派生的 principal。
后续 stream、confirm、mode、task get/cancel/approve/reject/events/artifacts 必须匹配 owner；
客户端 JSON 内的 principal 不具有权威性。Gateway 重启后无法证明 owner 的既有资源在
认证态下拒绝访问，不以“未知等于允许”恢复服务。

Task SSE 使用持久化 `sequence` 作为 SSE `id`，客户端可通过 `Last-Event-ID` 跳过已经
消费的事件。HTTP client 断线或取消时，stream handler 立即退出，并让同一个 request
context 取消传播到 Agent/Task client。Gateway 不创建绕过这一链路的后台转发 goroutine。

Python UDS 在验证 peer UID 后还必须取得 kernel peer PID。由 CLI 托管时绑定
已启动 Gateway PID；分离启动时在第一个有效 HMAC 请求上 TOFU 绑定 PID，
后续其他同 UID PID 拒绝。Boot master capability 由托管父进程通过继承 pipe FD
传递；容器使用不可写 Docker secret 且共享受信控制面 PID namespace，默认
禁止 capability 环境变量。每个 RPC method 使用 master HMAC 派生的独立 key，
因此 Approval、Memory、Channel、Task 和 Chat 不共用同一 method capability scope。

## 不变量

- 请求在 body limit 和 strict decode 通过前不得产生 Agent/Task side effect；
- principal A 不能读取、确认、切换或取消 principal B 的 session/task；
- ownership 缺失时认证请求 fail closed；
- SSE replay cursor 单调，只过滤 `sequence <= Last-Event-ID`；
- 断线不允许 handler 永久阻塞在上游 channel。
- 已认证 Gateway PID 外的同 UID 进程不得 dispatch RPC；peer PID 不可用时 fail closed。
- 一个 method 的派生 MAC 不得重放到另一 method。
- 只有 Telegram、Discord、Slack、WeChat 这类已实现平台签名校验的 webhook 路径可
  绕过 Gateway API key；generic 与未知平台必须先通过 Gateway API key。
- Generic webhook 必须配置至少 32 字符 secret，并验证 timestamp、one-shot message ID、
  body SHA-256 与 `X-Khaos-Signature` HMAC；Slack 与 generic 均拒绝过期及重放请求。

## 剩余工作

- 将 session/task owner 放入 Python durable source of truth，支持 Gateway 无损重启；
- 从统一 schema 生成 Gateway、TUI、IDE client，增加显式版本协商而不只是响应 header；
- 为上游 channel 队列深度、慢消费者与丢弃策略增加可观测 backpressure 指标；
- webhook 平台身份与 Khaos principal 的联合审计仍需统一。

## 回滚

可以关闭新协议客户端功能，但不得移除 body limit、strict JSON 或 ownership 检查。若
durable owner 服务不可用，认证资源访问继续拒绝，不回退到仅凭资源 ID 授权。
