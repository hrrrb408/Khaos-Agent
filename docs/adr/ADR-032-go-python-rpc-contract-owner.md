# ADR-032: Give the Go/Python RPC contract one owner

状态：accepted

日期：2026-08-21

## 背景

`go/internal/platform/python_client.go` 同时实现 Unix transport、request signing、
connection lifecycle 和 RPC protocol version/features。修改 transport 时容易悄悄
改变 negotiation contract；Python `rpc/protocol.py` 和 Go client 还可能各自维护一套
feature digest 规则。

## 决策

`go/internal/platform/rpc_contract.go` 负责 Go 侧的 RPC version、schema version、
feature set 和 deterministic feature digest。`python_client.go` 只消费这些常量并负责
transport/auth envelope；Python `khaos.rpc.protocol` 仍是 Python 侧协议 authority，
两侧通过 golden/negotiation tests 对齐。

## 迁移和删除条件

新增 RPC feature 只能修改 contract owner，并同步 Python protocol、generated inventory
和 negotiation tests；不得在 client method 中写版本字面量。后续 schema 生成完成后，
手写常量替换为生成 artifact，但 transport 不重新拥有 schema。

## 证据

- `go/internal/platform/rpc_contract_test.go` 固化版本与 digest 稳定性。
- Go `python_client_*` tests 和 Python RPC negotiation/boundary tests 继续覆盖 auth、
  project/policy claims、unknown-field rejection 和 initialization。
