# ADR-049: Keep RPC protocol symbols in the protocol module

状态：accepted

日期：2026-08-22

## 背景

`grpc_server.py` 已经通过 `khaos.rpc.protocol` 完成协议实现迁移，但仍在 transport
模块重新导出版本常量、认证器和 `_rpc_*` helper。这样会让调用方误以为 transport 是
协议 owner，也会让后续 Go/Python feature negotiation 修改产生两个可见入口。

## 决策

- `python/khaos/rpc/protocol.py` 是 Python RPC protocol 的唯一 public owner；`khaos.rpc`
  package facade 只导出 domain services，不重新导出 protocol symbols；
- `grpc_server.py` 只持有私有模块引用 `_rpc_protocol` 并消费其 API，不再导出 protocol
  constants、`GatewayRPCAuthenticator`、`RPCProtocolError` 或 `_rpc_*` helpers；
- 服务测试和生产调用方直接从 `khaos.rpc.protocol` 导入协议对象，从
  `khaos.grpc_server` 导入 transport/service 对象；
- Go 的 wire contract 仍由 `go/internal/platform/rpc_contract.go` 持有，跨语言字段
  变化必须同时更新两端 contract tests。

## 证据与删除条件

- `python/tests/security/test_rpc_protocol_boundary.py` 断言 transport 不再暴露第二套
  protocol surface；negotiation/principal tests 直接依赖 protocol owner。
- `python/khaos/grpc_server.py` 不再包含 protocol alias assignments，内部引用全部通过
  `_rpc_protocol`，因此无法静默形成第二份常量或 helper。
