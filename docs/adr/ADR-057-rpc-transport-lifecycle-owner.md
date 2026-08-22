# ADR-057: Give Go RPC connection lifecycle one owner

状态：accepted

日期：2026-08-22

## 背景

`go/internal/platform/python_client.go` 同时负责 Unix socket 拨号、deadline、context
取消、连接关闭、认证 envelope 和各个 service method。这样一个 transport 变更会触碰
所有业务调用点，也容易让 streaming 与 unary 调用拥有不同的取消语义。

## 决策

- `go/internal/platform/rpc_transport.go` 是 Go 侧 RPC 连接生命周期的唯一 owner。
- `RPCTransport` 只负责建立一个 byte stream；`UnixRPCTransport` 负责绝对 Unix socket
  路径校验、DialContext 和 deadline。
- `RPCConnection` 绑定 context cancellation，并在 `Close` 时释放 cancellation hook 与
  底层连接。它嵌入 `net.Conn`，因此不会让 transport 解释 RPC envelope 或 service payload。
- `PythonClient` 继续拥有 HMAC、协议 negotiation、JSON envelope 和业务方法；它只能通过
  `OpenRPCConnection` 获得连接。测试可注入内存 transport，但生产默认只能使用
  `UnixRPCTransport`。

## 不变量与删除条件

- 相对路径、TCP 风格地址在拨号前 fail closed。
- context 取消必须释放阻塞 decoder/scanner；unary 与 streaming 调用共享同一 close 语义。
- transport 不读取或修改 JSON 字段，不计算 protocol/feature digest。
- 后续若加入 Windows named pipe 或其他 native transport，只新增 `RPCTransport` 实现，
  不在 `PythonClient` 复制连接状态机。

## 证据

- `go/internal/platform/rpc_transport_test.go` 覆盖注入 transport、绝对路径拒绝和 context
  取消关闭 peer stream。
- 既有 `python_client_*` 测试继续覆盖签名、principal、project/policy claims、negotiation
  与大 frame streaming，证明 transport 抽取没有改变 wire contract。
