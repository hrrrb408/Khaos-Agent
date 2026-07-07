# Khaos（混沌）

通用 AI Agent 平台 + Coding Agent 双模式，从零打造。

## 架构

```
Web(Next.js) → Go API网关(REST+SSE) → Python Agent → LLM API
                     ↕                    ↕
                SQLite(只读查询)      Rust(PyO3)
                                        ├── Token 引擎
                                        └── 并行执行器
```

**三层架构：**
- **Python（上层）**：Agent 核心、工具系统、记忆、权限、技能、MoA、gRPC Server
- **Go（中间层）**：API 网关、认证、限流、SSE 代理
- **Rust（底层）**：Token 计数、并行工具执行（PyO3 原生扩展）

## 功能

- 双模式切换：办公模式 + Coding 模式（`/mode office` / `/mode coding`）
- 工具系统：文件读写、终端、Docker 沙箱、Git、浏览器、代码搜索
- 权限引擎：auto-approve / suggest / ask-every / deny + remember rule
- 三层上下文压缩：micro-compact → context-collapse → auto-compact（含熔断器）
- 记忆系统：CRUD + FTS5 搜索 + TTL 衰减 + 冲突解决 + 主动提取 + L0/L1/L2 注入
- 技能系统：声明式 SKILL.md + triggers 动态匹配注入
- 多模型路由：多 Provider + fallback 链 + MoA（Mixture of Agents）
- 子代理：单层不嵌套，并发可配（默认3）
- 审计日志：结构化记录 + Go→Python 跨层查询 API
- SSE 流式输出：text / tool_call / tool_result / permission_request / error / done

## 快速开始

```bash
# 克隆
git clone https://github.com/hrrrb408/Khaos-Agent.git
cd Khaos-Agent

# 配置模型 API Key
export NVIDIA_API_KEY="your-key-here"

# 启动（Python + Go + Web）
make dev
```

三端默认端口：
- Python：localhost:50051
- Go 网关：localhost:8080
- Web 界面：localhost:3000

## 配置

编辑 `config.yaml`，支持任意 OpenAI-compatible API：

```yaml
models:
  providers:
    nvidia:
      type: openai_compatible
      base_url: "https://integrate.api.nvidia.com/v1"
      api_key: "${NVIDIA_API_KEY}"
      models:
        - name: "qwen/qwen3-8b"
          max_context_tokens: 32768
          supports_tools: true
  default_model: "qwen/qwen3-8b"
```

## 测试

```bash
make test          # Python + Go + Rust 全部测试
make test-python   # 仅 Python（217 tests）
make test-go       # 仅 Go
make test-rust     # 仅 Rust（17 tests）
```

## 技术栈

| 层 | 技术 |
|----|------|
| Python | Python 3.11+, aiosqlite, httpx, PyO3 |
| Go | Go 1.26+, net/http,令牌桶限流 |
| Rust | Rust, PyO3, tokio |
| Web | Next.js 15, React 19 |
| 存储 | SQLite + FTS5 |
| 协议 | MIT |

## 项目结构

```
├── python/khaos/        # Python 上层
│   ├── agent/            # 核心循环、压缩、错误处理
│   ├── modes/            # 双模式管理
│   ├── tools/            # 工具注册/调度/实现
│   ├── memory/           # 三层记忆
│   ├── permissions/      # 权限引擎
│   ├── skills/           # 技能系统
│   ├── subagents/        # 子代理
│   ├── routing/          # 模型路由 + MoA
│   ├── audit/            # 审计日志
│   └── db/               # 数据库
├── go/                   # Go API 网关
│   └── cmd/gateway/
├── rust/khaos-core/      # Rust 性能层
│   └── src/token/        # Token 引擎
├── web/                  # Next.js 前端
├── docs/                 # 设计文档
└── start.sh              # 一键启动
```

## License

MIT
