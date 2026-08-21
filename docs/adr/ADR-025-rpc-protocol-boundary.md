# ADR-025: Isolate the authenticated RPC protocol boundary

状态：accepted

日期：2026-08-21

## 背景

`python/khaos/grpc_server.py` 同时承担了 Unix-socket transport、进程启动、服务装配和
RPC wire-contract 校验。这样会让协议变更必须加载完整 runtime，也容易在 transport
分支中复制认证、版本协商或错误码逻辑。

## 决策

`python/khaos/rpc/protocol.py` 是 Python 侧 RPC wire contract 的唯一 owner。它只包含：

- 版本、schema、feature 和错误码常量；
- Initialize/metadata 校验与 feature digest；
- project/policy binding claim 校验；
- peer identity、nonce、payload digest 和 method-scoped HMAC 验证。

该模块不得导入 Agent service、数据库、runtime factory 或 transport lifecycle。服务和
transport 只能消费它返回的已校验结果。

## 兼容与迁移

`grpc_server.py` 继续 re-export 旧名称一个迁移周期，以避免一次性修改外部调用者；这些
导入不拥有实现，也不得新增协议逻辑。迁移完成的判据是生产代码和测试只从
`khaos.rpc.protocol` 导入协议类型，随后删除 grpc 兼容导出并更新 inventory。

## 证据

- `python/tests/security/test_rpc_protocol_boundary.py` 固化 owner identity、未知字段、
  feature digest、scope drift 和 fail-closed 行为。
- `python/tests/security/test_rpc_negotiation.py` 继续覆盖真实 UDS 的 Initialize → service
  negotiation，属于 transport/CI 边界测试。
