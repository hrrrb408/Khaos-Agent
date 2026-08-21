# ADR-036: Give approval binding/request projection one owner

状态：accepted

日期：2026-08-22

## 背景

`ToolScheduler._stream_batch_impl` 曾同时计算 arguments/profile/policy/resource digest，
构造 `ApprovalBinding`，再手工复制字段生成 `PermissionRequest`。这段代码既是
permission decision 的调用点，也是 approval UI 的 wire contract；字段增加或默认值
改变时，broker、UI 和 dispatch revalidation 可能看到不同的 binding。

## 决策

`python/khaos/tools/authorization.py` 负责把 server-owned tool/context state 投影为
`ApprovalBinding` 和 `PermissionRequest`。它是纯 contract builder：不调用
`PermissionEngine`、不注册/消费 broker receipt、不执行工具。arguments/profile/policy/
resource digest schema 在这里集中定义，并由 dispatch 使用同一 binding 字段重新验证。

## 迁移和删除条件

新增 approval 字段必须先扩展 contract builder、binding/request value object 和负向测试，
禁止在 scheduler、transport 或 UI 中手工复制一份 digest payload。完成
`ToolAuthorization` coordinator 后，scheduler 只消费 coordinator 输出，不再拥有
binding/request 的字段装配逻辑。

## 证据

- `python/tests/tools/test_authorization_contract.py` 固化参数、profile、policy、resource
  和 receipt identity 的绑定，以及 request 对 binding 的复用。
- scheduler 的 approval/revalidation 回归继续通过，证明迁移没有改变 broker/dispatch
  语义。
