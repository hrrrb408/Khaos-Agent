# ADR-058: Give native receipt binding and verification one owner

状态：accepted

日期：2026-08-22

## 背景

Rust exec launcher 既要编排 FD、session、rlimit 和 `exec`，又要理解 signed
authority receipt 的字段、时间窗口、operation/resource 绑定和 Ed25519 校验。若后续
再加入 native backend，复制这些检查会形成“验证通过但绑定不同”的 TCB 分叉。

## 决策

- `rust/khaos-core/src/authority_receipt.rs` 是 native receipt verification 的唯一 owner。
- `ReceiptBinding` 在解析 receipt 前固定 operation 与 resource digest；空值、NUL 和超长
  identity 直接 fail closed。
- `ReceiptVerifier` 唯一拥有 FD bounded read、schema/时间校验、签名验证和 binding proof；
  成功返回不可变的 `VerifiedReceipt`，失败不返回部分授权状态。
- `khaos-exec-launcher` 只消费 verifier 的成功结果，然后执行 session、rlimit、FD 清理和
  native `exec`；它不重新读取或解释 receipt JSON。

## 不变量与删除条件

- receipt 必须同时绑定预期 operation 和预期 resource digest；合法但属于其他效果的
  receipt 不能被复用。
- public key 与 receipt 仍从已打开 FD 读取并受字节上限约束；路径/业务对象不进入 Rust
  验证边界。
- 新 native launcher 只能复用 `ReceiptVerifier`，不能复制 `verify_json_bound` 或自行
  解析 `authorization_epoch`。

## 证据

- `authority_receipt.rs` 单元测试覆盖完整 Python 签名向量、篡改、未来时间、空 binding，
  并断言成功结果带有 operation/resource/epoch typed proof。
- `cargo test --locked --no-default-features --bin khaos-exec-launcher` 覆盖 launcher 使用
  的实际 receipt 模块。
