# Khaos — AGENTS.md

> 给 AI 开发团队的编码规范和项目上下文
> 任何参与 Khaos 开发的 AI Agent（Hermes、GPT、Codex）都必须先读取此文件

---

## 项目概述

**Khaos（混沌）** 是一个通用 AI Agent 平台，具备双模式切换能力。

- **办公模式**：通用 agent，对话式交互，多工具多模型
- **Coding 模式**：agentic coding，对标 Claude Code + Codex
- **架构**：Python（上层 Agent 逻辑）+ Go（中间层 API 网关）+ Rust（底层性能瓶颈）
- **协议**：MIT
- **存储**：SQLite + FTS5

开发团队：AI 三剑客（Hermes + GPT + Codex）编码，瑞邦产品经理。

---

## 目录结构

```
khaos/
├── AGENTS.md                ← 你在这里
├── KHAOS.md                 ← 项目根指令（加载优先级 1）
├── config.yaml              ← 运行时配置
│
├── python/                  # 上层：Agent 逻辑
│   ├── khaos/
│   │   ├── agent/           # Agent 核心循环、上下文、压缩
│   │   ├── modes/           # 模式管理
│   │   ├── tools/           # 工具注册、调度、实现
│   │   │   ├── note_tools.py        # Office 增强：笔记工具
│   │   │   ├── markdown_tools.py    # Office 增强：Markdown 工具
│   │   │   ├── clipboard_tools.py   # Office 增强：剪贴板工具
│   │   │   ├── orchestrator_tools.py # Orchestrator 工具
│   │   │   └── permission_tools.py  # 权限管理工具
│   │   ├── memory/          # 三层记忆（Phase 3：TTL/冲突/主动提取）
│   │   ├── skills/          # 技能系统（Phase 3：声明式 SKILL.md + 触发匹配）
│   │   ├── audit/           # 审计日志（Phase 3：结构化记录 + 查询）
│   │   ├── cli/             # CLI 入口点
│   │   ├── tui/             # 全屏 TUI（Phase 4：Textual + Rich，斜杠命令）
│   │   ├── permissions/     # 权限引擎
│   │   ├── security/        # 安全模块：命令、路径、敏感信息防护
│   │   ├── subagents/       # 子代理（Runner、Planner、Service）
│   │   ├── routing/         # 模型路由（Phase 3：MoA；Phase 4：多 provider 架构）
│   │   ├── rust_bridge.py   # PyO3 桥接（Phase 3：token；Phase 4：file_ops/exec）
│   │   └── db/              # 数据库模型、迁移
│   └── tests/
│
├── go/                      # 中间层：API 网关
│   ├── cmd/gateway/         # 入口
│   └── internal/
│       ├── api/             # REST/SSE 端点（含 /api/audit）
│       ├── auth/            # 认证
│       ├── rate/            # 限流
│       └── platform/        # 平台接入
│
├── rust/                    # 底层：性能瓶颈
│   └── khaos-core/          # Phase 3：PyO3 cdylib _khaos_core
│       ├── src/
│       │   ├── token.rs     # Token 启发式计数
│       │   └── executor.rs  # 并行执行器（tokio）
│       └── .cargo/config.toml # macOS dynamic_lookup 链接
│
├── prompts/                 # System Prompt 文件
│   ├── office.md
│   └── coding.md
│
└── docs/                    # 设计文档
    ├── 需求规格说明书.md
    ├── 概要设计文档.md
    ├── 详细设计文档.md
    └── 测试计划.md
```

---

## 设计文档索引

修改任何模块前，必须先阅读对应的设计文档。

| 模块 | 详细设计章节 | 数据库表 |
|------|-------------|----------|
| Agent 核心循环 | LLD §1.1 | sessions, messages |
| 模式管理 | LLD §1.2 | user_config |
| 工具系统 | LLD §1.3 | tools |
| 记忆系统 | LLD §1.4 | memories, memory_fts5 |
| 技能系统 (Phase 3) | — (skills/) | — (磁盘 SKILL.md) |
| 审计日志 (Phase 3) | — (audit/) | audit_log |
| TUI 界面 (Phase 4) | FR-015 | — |
| 权限引擎 | LLD §1.5 | permissions |
| 子代理 | LLD §1.6 | subagent_tasks |
| 模型路由 | LLD §1.7 | — |
| MoA (Phase 3) | — (routing/moa.py) | — |
| 多 Provider (Phase 4) | — (routing/providers/) | — |
| Go API 网关 | LLD §2 | audit_log |
| Rust FFI (Phase 3) | LLD §3 | — |
| 数据库 DDL | LLD §4 | 全部 |

---

## 编码规范

### Python

```python
# 风格：遵循 PEP 8
# 类型注解：所有公开函数必须有完整类型注解
# 异步：所有 I/O 操作使用 async/await
# 字符串：f-string，不用 format() 或 %
# 导入：绝对导入，不用相对导入

# 正确 ✅
from khaos.agent.core import AgentLoop
from khaos.tools.registry import ToolRegistry

async def run(self, user_input: str, session_id: str) -> AsyncIterator[Message]:
    ...

# 错误 ❌
from ..agent.core import AgentLoop
def run(self, user_input, session_id):
    ...
```

**命名：**
- 类名：PascalCase（`AgentLoop`, `MemoryStore`）
- 函数/方法：snake_case（`run`, `build_context`, `inject_memory`）
- 私有方法：单下划线前缀（`_build_context`, `_match_pattern`）
- 常量：UPPER_SNAKE_CASE（`DEFAULT_CONTEXT_FILES`, `MAX_TURNS`）
- 模块/文件：snake_case（`agent_loop.py`, `memory_store.py`）

**异步：**
- 所有涉及 I/O 的函数必须是 `async`
- 使用 `asyncio`，不用 `threading`
- 数据库操作用 `aiosqlite`（异步 SQLite）
- HTTP 调用用 `httpx`（异步 HTTP client）
- 文件操作用 `aiofiles`（异步文件 IO）

**错误处理：**
- 自定义异常放在模块的 `exceptions.py` 中
- 异常类继承 `KhaosError`（基类）
- 不用裸 `except:`，必须指定异常类型
- 工具执行失败不算致命错误，返回 `ToolResult(success=False)` 让模型重决策

```python
# khaos/exceptions.py

class KhaosError(Exception):
    """Khaos 基础异常"""
    pass

class ModelUnavailableError(KhaosError):
    pass

class ToolNotFoundError(KhaosError):
    pass

class PermissionDeniedError(KhaosError):
    pass

class SubAgentLimitError(KhaosError):
    pass

class CompressionCircuitOpenError(KhaosError):
    """连续压缩失败，熔断器打开"""
    pass
```

**数据类：**
- 优先使用 `dataclass`，不用 Pydantic（减少依赖）
- 需要验证时用 `dataclass` + 手动 `__post_init__`

```python
from dataclasses import dataclass, field
from typing import Optional

@dataclass
class Memory:
    id: Optional[int]
    scope: MemoryScope
    key: str
    value: str
    ttl: int = 604800
    confidence: MemoryConfidence = MemoryConfidence.MEDIUM
```

**日志：**
- 使用标准库 `logging`，不用第三方库
- Logger 命名：`logging.getLogger(__name__)`
- 级别：DEBUG（调试信息）、INFO（关键流程节点）、WARNING（可恢复问题）、ERROR（需要人工介入）

```python
import logging

logger = logging.getLogger(__name__)

async def run(self, ...):
    logger.info("Agent loop started: session=%s", session_id)
    logger.debug("Token count: %d", total_tokens)
    logger.error("Model timeout after %ds, triggering fallback", timeout)
```

**测试：**
- 文件命名：`test_<module>.py`（与被测模块同目录或 `tests/` 下镜像结构）
- 使用 `pytest`，不用 `unittest`
- fixture 放在 `conftest.py`
- Mock 外部依赖（模型 API、Docker、文件系统）

```python
# tests/conftest.py
import pytest
import sqlite3
from khaos.db import Database

@pytest.fixture
def db():
    conn = sqlite3.connect(":memory:")
    database = Database(conn)
    database.run_migrations()
    yield database
    conn.close()

@pytest.fixture
def mock_router():
    """返回预设响应的模型路由 mock"""
    router = MagicMock(spec=ModelRouter)
    return router
```

### Go

```go
// 风格：遵循 Effective Go + go vet
// 包命名：小写单词，不用下划线（package api, 不是 package api_gateway）
// 错误处理：显式检查 error，不用 panic
// 注释：导出函数必须有 godoc 注释

// 正确 ✅
// HandleChat creates a new chat session and returns SSE stream.
func (h *Handler) HandleChat(w http.ResponseWriter, r *http.Request) error {
    ...
}

// 错误 ❌
func HandleChat(w, r) { ... }
```

**命名：**
- 包名：小写单词
- 导出：PascalCase（`HandleChat`, `ChatResponse`）
- 未导出：camelCase（`parseSSE`, `matchRoute`）
- 常量：PascalCase 或 UPPER_SNAKE_CASE
- 接口：单方法用 `-er` 后缀（`Reader`, `Handler`, `Streamer`）

**测试：**
- 文件命名：`*_test.go`（与被测文件同目录）
- 使用标准 `testing` 包
- 表驱动测试

```go
func TestHandleChat(t *testing.T) {
    tests := []struct {
        name    string
        request ChatRequest
        want    int
    }{
        {"valid request", ChatRequest{Message: "hello"}, http.StatusOK},
        {"empty message", ChatRequest{Message: ""}, http.StatusBadRequest},
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            ...
        })
    }
}
```

### Rust

```rust
// 风格：遵循 rustfmt + clippy
// 错误处理：Result<T, E>，不用 unwrap()（测试代码除外）
// 注释：公开函数必须有 /// 文档注释
// 所有权：尽量减少 clone()，用引用传递

// 正确 ✅
/// Count tokens in the given text using the specified model's tokenizer.
#[pyfunction]
fn count_tokens(text: &str, model: &str) -> usize {
    tiktoken::count(text, model)
}

// 错误 ❌
fn count_tokens(text: String, model: String) -> usize {
    tiktoken::count(&text, &model)
}
```

**命名：**
- 函数/方法：snake_case
- 类型/结构体：PascalCase
- 模块：snake_case
- 常量：UPPER_SNAKE_CASE
- 布尔：`is_`/`has_` 前缀（`is_circuit_open`, `has_network`）

**错误处理：**
- 自定义错误类型用 `thiserror`
- PyO3 绑定错误用 `PyErr`

```rust
use thiserror::Error;

#[derive(Error, Debug)]
pub enum KhaosError {
    #[error("model unavailable: {0}")]
    ModelUnavailable(String),

    #[error("sandbox error: {0}")]
    SandboxError(#[from] SandboxError),

    #[error("token count exceeded: {current} > {max}")]
    TokenBudgetExceeded { current: usize, max: usize },
}
```

**测试：**
- 单元测试写在同文件 `#[cfg(test)] mod tests`
- 集成测试放在 `tests/` 目录
- 使用 `assert!`, `assert_eq!`, `assert_ne!`

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_count_tokens_empty() {
        assert_eq!(count_tokens("", "gpt-4"), 0);
    }

    #[test]
    fn test_count_tokens_english() {
        let count = count_tokens("Hello, world!", "gpt-4");
        assert!(count > 0);
    }
}
```

---

## Git 规范

### 分支策略

```
main          ← 稳定分支，每次 Phase 完成合并
dev           ← 开发分支，日常开发合并到这里
feature/xxx   ← 功能分支，从 dev 创建
fix/xxx       ← 修复分支，从 dev 创建
```

### 提交信息

```
<type>(<scope>): <description>

type:
  feat     新功能
  fix      修复
  refactor 重构（不改行为）
  test     测试
  docs     文档
  chore    构建/配置/工具链

scope:
  agent    Agent 核心
  tools    工具系统
  memory   记忆系统
  modes    模式管理
  perm     权限
  routing  模型路由
  gateway  Go 网关
  token    Rust Token 引擎
  executor Rust 工具执行器
  sandbox  Rust Docker 沙箱
  fts      Rust FTS5

示例:
  feat(agent): implement core while(true) loop with SSE streaming
  fix(sandbox): handle container creation timeout gracefully
  test(memory): add FTS5 search integration tests
  refactor(routing): extract fallback chain into separate function
```

### 提交粒度

- 每个提交做一件事（原子提交）
- 提交前必须通过对应的测试
- 不要提交调试代码、临时文件、API Key

---

## 开发流程

### 添加新功能

1. 先阅读 `docs/详细设计文档.md` 中对应模块的设计
2. 如果设计需要调整，先修改设计文档，再写代码
3. 先写测试（TDD），再写实现
4. 确保测试通过：`make test`
5. 提交，格式：`feat(<scope>): <description>`

### 添加新工具

1. 在 `python/khaos/tools/registry.py` 的 `register_builtin_tools()` 中注册
2. 在 `python/khaos/tools/` 下创建实现文件
3. 实现必须包含：参数验证、超时控制、错误处理
4. 在 `python/tests/tools/test_<tool>.py` 中编写测试
5. 在 `LLD §1.3` 中更新工具清单

### 添加新的 Provider

1. 在 `config.yaml` 的 `providers` 下添加配置
2. 实现 `python/khaos/routing/provider.py` 中的适配逻辑
3. 在 `python/tests/routing/test_provider.py` 中编写测试

### 数据库变更

1. 在 `python/khaos/db/migrations/` 下创建新的迁移文件（递增编号）
2. 迁移文件只包含 ALTER / CREATE 语句，不修改已有表结构（向后兼容）
3. 更新 `LLD §4` 中的 DDL
4. 在测试中验证迁移（空库迁移 + 已有数据迁移）

---

## 架构决策记录

### ADR-001: 三层架构（Python/Go/Rust）

**状态**：已定

**理由**：
- Python：AI/ML 生态最丰富，prompt 工程和工具定义是 I/O 密集型，开发效率最高
- Go：高并发低延迟，适合 API 网关、SSE 长连接、多平台接入
- Rust：Token 解析和并行执行是 CPU 密集型高频操作，需要零开销抽象和内存安全

**约束**：Python 和 Rust 通过 PyO3 FFI 通信，Python 和 Go 通过 gRPC 通信。

### ADR-002: 单层子代理，不嵌套

**状态**：已定

**理由**：嵌套导致上下文丢失、错误传播不可追踪、Token 消耗指数增长。让单层子代理够强（给够上下文/工具/自主权）比多层嵌套弱子代理更可控制。

**约束**：`SubAgentConfig.max_spawn_depth = 1`，子代理不能再 spawn 子代理。

### ADR-003: 权限默认 ask-every

**状态**：已定

**理由**：安全优先。用户逐步授权提升为 auto-approve，而不是默认放权再收紧。

**约束**：新工具调用默认需要用户确认，除非已有匹配的持久化规则。

### ADR-004: 命令切换模式，不自动切换

**状态**：已定

**理由**：AI 不替用户做决定。检测到疑似任务时只提醒，用户确认后才切换。

**约束**：`/mode coding` 和 `/mode office` 是唯一切换入口。

### ADR-005: SQLite + FTS5

**状态**：已定

**理由**：轻量嵌入式，本地部署无需额外服务。FTS5 提供段落级 BM25 全文检索。

**约束**：开启 WAL 模式，使用参数化查询防 SQL 注入。

---

## 关键约束

1. **不复制 Claude Code 源码**：自定义非开源许可证，可学习架构设计但不可复制粘贴
2. **不引入重量级依赖**：Python 层用标准库 + 少量精选依赖（httpx, aiosqlite, aiofiles），Go 层用标准库 + gin/echo，Rust 层用 tokio + rusqlite + tiktoken
3. **所有写操作必须记录审计日志**：audit_log 表记录所有写操作
4. **环境变量中不出现明文 API Key**：日志脱敏，配置文件支持 `${ENV_VAR}` 引用
5. **错误可恢复优先**：工具执行失败不算致命错误，返回模型重决策；模型超时自动 fallback
6. **测试先行**：新代码必须有对应测试，覆盖率不低于 60%

---

## Makefile 命令

```makefile
# 开发
make dev          # 启动开发环境（Go 网关 + Python Agent）
make build        # 编译全部（Go + Rust）
make test         # 运行全部测试（pytest + go test + cargo test）
make test-python  # 只跑 Python 测试
make test-go      # 只跑 Go 测试
make test-rust    # 只跑 Rust 测试
make lint         # 代码检查（ruff + go vet + clippy）
make migrate      # 运行数据库迁移
make clean        # 清理构建产物

# Docker
make sandbox-build    # 构建沙箱镜像
make sandbox-run      # 启动沙箱容器
```

---

## 快速开始

### Docker 部署

```bash
docker compose up -d
# Agent: localhost:50051
# Gateway: localhost:8080
```

### 本地开发

```bash
# Python
pip install -e .
khaos start --db khaos.db

# Go 网关
cd go && go run ./cmd/gateway/ --python-agent 127.0.0.1:50051

# 运行测试
khaos test --all
```

### 配置

编辑 `config.yaml` 设置 LLM provider、API key 等。

---

*最后更新：2026-07-08*
*维护者：瑞邦 + Hermes Agent*
