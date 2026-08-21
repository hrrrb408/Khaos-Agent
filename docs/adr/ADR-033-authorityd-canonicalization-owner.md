# ADR-033: Give authorityd canonical wire encoding one owner

状态：accepted

日期：2026-08-21

## 背景

`authorityd_protocol.py` 和 `authorityd.py` 都曾保留 `_canonical`/`_digest` 私有包装器。
这些包装器只是重复实现 `protocol_boundary.py` 的跨语言 canonical JSON 与 SHA-256
规则，却让签名 receipt、审计事件和 socket response 可能在不同入口产生分叉。
authorityd 是安全边界；这里不能靠“两个实现目前恰好相同”维持协议一致性。

## 决策

`python/khaos/security/protocol_boundary.py` 是 canonical JSON bytes 与 canonical
digest 的唯一 owner。`authorityd_protocol.py` 的 receipt、intent、resource 和 client
wire encoding，以及 `authorityd.py` 的审计事件、receipt signature、challenge
signature 和 response framing 都直接消费该 owner；authorityd 模块不再导入或定义
同义的私有包装器。

## 迁移和删除条件

新增签名/摘要字段必须调用 `canonical_json_bytes` 或 `canonical_digest`，不得重新引入
局部 `json.dumps`、`hashlib.sha256` 包装器。跨语言协议变化必须同步 protocol boundary
contract tests、authorityd tests、ADR 和 generated inventory。

## 证据

- `python/tests/security/test_protocol_boundary.py` 固化 canonical encoding/digest
  的稳定性与拒绝非 JSON 值行为。
- `python/tests/security/test_authorityd_protocol.py`、`test_native_authority.py`
  覆盖 receipt 签名、socket framing、审计事件和 native authority 交互。
- `authorityd.py` 与 `authorityd_protocol.py` 不再暴露 `_canonical`/`_digest` 私有协议
  入口；ruff、针对性安全测试和生成 inventory 必须通过。
