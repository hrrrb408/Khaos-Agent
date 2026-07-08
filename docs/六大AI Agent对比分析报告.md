# 六大 AI Agent 对比分析报告

> 调查日期：2026-07-07
> 目的：为开发"六合一超级 Agent"提供技术选型参考

---

# 第一部分：调研概览

> 基础信息、产品概览、能力对比、技术栈、竞品排名


## 一、总览

| 维度 | Claude Code | Codex CLI | OpenClaw | Hermes | WorkBuddy | Marvis |
|------|------------|-----------|----------|--------|-----------|--------|
| **开发方** | Anthropic | OpenAI | 社区（获OpenAI/NVIDIA赞助） | NousResearch | 腾讯 | 腾讯 |
| **GitHub Stars** | 136,534 | 95,854 | 381,947 | 210,273 | N/A（闭源） | N/A（闭源） |
| **开源协议** | ⚠️自定义（非开源） | Apache-2.0 | MIT | MIT | 闭源 | 闭源 |
| **核心语言** | TypeScript | Rust | TypeScript | Python | N/A（Electron） | N/A（Electron） |

---

| **定位** | 专注Coding | 专注Coding+沙箱 | 通用个人助手 | 通用Agent | 编码+通用Agent | OS级桌面助手 |
| **模型策略** | 单模型（仅Claude） | 单模型（仅OpenAI） | 多Provider多模型 | 多Provider多模型+MoA | 多模型（GLM/Kimi/DeepSeek/混元） | 端云协同（DeepSeek V4+混元+本地） |
| **许可证** | Claude订阅 | OpenAI订阅 | 自带任意Provider | 自带任意Provider+凭证池 | 腾讯订阅（不可中转） | 腾讯订阅（不可中转） |
| **源码可参考** | ❌（泄露源码内容为空） | ✅ 可商用 | ✅ 可商用 | ✅ 可商用（骨架） | ❌ 闭源 | ❌ 闭源（有OpenMarvis开源复现） |

---

---


## 二、各 Agent 详细分析

### 1. Claude Code（Anthropic）

**定位：** 终端里的 agentic coding 工具，理解代码库、执行编程任务、处理 git 工作流。

**技术架构：**
- 语言：TypeScript（sourcemap 恢复确认）
- 协议：⚠️ Claude Code License（自定义，非开源，不可商用参考）
- 模型：仅 Claude（锁定 Anthropic）
- 运行环境：终端 CLI

**核心能力：**
- 代码库全局理解（跨文件依赖分析）
- 多文件编辑（原子化修改，一次操作改多个文件）
- Git 工作流（commit、PR、branch 管理）
- 终端命令执行（直接跑 shell 命令）
- 测试驱动（写代码 → 跑测试 → 自动修 bug 闭环）
- 自然语言交互

**Agent Loop（核心优势）：**
```
理解需求 → 分析代码库 → 制定计划 → 写代码 → 执行测试 → 失败则修 → 循环直到通过
```
全程单模型，但靠工具链形成完整闭环。模型负责思考，工具负责执行。

**可借鉴：**
- Agentic coding 的闭环设计思路
- 多文件原子编辑机制
- 代码库理解能力（context 管理）
- 测试反馈循环

**局限：**
- 锁定 Claude，不能换模型
- 不支持非编程场景
- 无持久记忆、无 cron、无多平台消息
- API 消耗不透明（plan 里看不到 token 用量）

---

### 2. Codex CLI（OpenAI）

**定位：** 轻量级终端 coding agent，安全设计极其精细。

**技术架构：**
- 语言：Rust（codex-rs 核心）
- 协议：Apache-2.0
- 模型：仅 OpenAI（锁定）
- 运行环境：终端 CLI + 桌面 App + IDE 扩展 + Web
- 沙箱：全平台沙箱（macOS Seatbelt、Linux Bubblewrap+Landlock、Windows ACL+WFP）
- 审批系统：三维度交叉权限控制（审批模式 × 沙箱模式 × 协作模式）

**权限系统（核心亮点，极其精细的三维度设计）：**

Codex 的权限不是简单的"高/中/低"，而是三个独立维度交叉组合，每个维度又有多档可选：

#### 维度一：审批模式（Approval Mode）— 控制"agent 什么时候需要问用户"

```typescript
AskForApproval = 
  | "untrusted"          // 除非信任
  | "on-request"         // 模型自决
  | "never"              // 从不确认
  | { "granular": {      // 细粒度逐项配置
      sandbox_approval: boolean,
      rules: boolean,
      skill_approval: boolean,
      request_permissions: boolean,
      mcp_elicitations: boolean,
    }}
```

**四种模式详解：**

**① untrusted（除非信任）— 最保守**
- 只有"受信任"的命令（ls、cat、sed 等只读命令）直接执行
- 其他所有命令都要弹窗让用户确认
- 类似于"每次都要问"，但预定义了一个安全命令白名单
- 适合新手或不信任 agent 的场景

**② on-request（模型自决）— 智能中间态**
- 模型自己判断什么时候该问用户、什么时候可以直接执行
- 通过 `sandbox_permissions: "require_escalated"` 参数请求升级权限
- 必须附带 `justification` 参数告诉用户为什么需要这个权限
- 可以建议 `prefix_rule`（命令前缀规则），用户批准后未来同类命令免确认
- 例：agent 要 `npm install`，请求升级权限，用户批准后以后所有 `npm` 开头的命令都免确认
- 禁止的 prefix_rule：`["python3"]`、`["python", "-"]` 等过于宽泛的；rm 相关的永远不能加持久规则
- 适合有一定经验、希望 agent 灵活但关键时刻还是会问的开发者

**③ never（从不确认）— 完全自主**
- agent 拥有完全自主权，所有命令直接执行
- 执行失败的结果直接返回给模型，模型自己修
- 最危险，但也最高效
- 适合沙箱内运行或高度信任的场景

**④ granular（细粒度）— 逐项精确控制**
- 五个独立开关，每个可以单独开启/关闭：
  - `sandbox_approval`：沙箱相关操作是否需要审批
  - `rules`：基于规则判断的操作是否需要审批
  - `skill_approval`：技能加载/执行是否需要审批
  - `request_permissions`：权限请求是否需要审批
  - `mcp_elicitations`：MCP 插件的交互是否需要审批
- 适合想要精确控制每个维度的专业用户

#### 维度二：沙箱模式（Sandbox Mode）— 控制"agent 能碰哪些文件和网络"

```typescript
SandboxMode = 
  | "read-only"            // 只读
  | "workspace-write"      // 工作区可写
  | "danger-full-access"   // 完全访问（危险）
```

**三种模式详解：**

**① read-only（只读沙箱）**
- agent 只能读取文件，不能写入任何文件
- 网络访问可单独配置（`{{network_access}}` 变量）
- 适合代码审查、分析、调研等只读场景
- 最安全，完全不可能破坏文件系统

**② workspace-write（工作区可写）**
- agent 可以读写当前工作目录（`cwd`）和用户配置的可写根目录（`writable_roots`）
- 修改其他目录的文件需要用户审批
- 网络访问可单独配置
- 这是日常开发的推荐模式——agent 能改项目文件，但不能碰系统文件或项目外的文件

**③ danger-full-access（完全访问）— 危险模式**
- 无文件系统沙箱限制，所有命令直接执行
- 可以读写任何文件、执行任何命令
- 网络访问不受限
- 适合 Docker 容器内运行，或高度信任的环境
- 命名里带 "danger" 不是开玩笑

#### 维度三：协作模式（Collaboration Mode）— 控制"agent 的行为风格和自主程度"

```typescript
// 4种内置模板
collaboration-mode-templates/
  templates/
    default.md          // 默认
    plan.md             // 规划
    execute.md          // 执行
    pair_programming.md // 结对编程
```

**四种模式详解：**

**① default（默认模式）**
- 合理假设直接执行，不轻易停下来问问题
- 如果必须问（答案无法从本地上下文发现且假设有风险），问简洁的纯文本问题
- 永远不写选择题式的问题
- 适合大多数日常开发

**② plan（规划模式）**
- 三个阶段：先聊清楚 → 再定方案 → 最后输出详细计划
- **只能读不能写**（不允许任何修改 repo 状态的操作）
- 允许：读文件、搜索代码、静态分析、dry-run 命令、测试（只写缓存不写源码）
- 禁止：写文件、装依赖、改配置、Git 操作
- 输出的计划必须是"decision complete"——接收方不需要做任何决策
- 适合需求讨论、架构设计、方案评审

**③ execute（执行模式）**
- 端到端独立执行，不协作不讨论
- 缺失信息时自己做合理假设，不问用户，在最终汇报中说明假设内容
- "Think out loud"——分享推理但保持简短，避免设计说教
- "Think ahead"——预判用户还需要什么，提前建议
- "Be mindful of time"——大部分 turn 几秒完成，研究不超过 60 秒
- 如果用户对建议没反应，视为已接受
- 适合"帮我把这个功能做完"这种明确任务

**④ pair_programming（结对编程模式）**
- 把用户当作结对编程的搭档
- 每一步都确认对齐和舒适度，避免一次性做太大的操作
- 解释推理过程，但根据用户信号动态调整深度
- 不需要多轮问问题——边做边确认
- 有多条路时给出清晰选项，用友好的方式邀请用户做选择
- 调试时把用户当作队友，可以问用户去查看 UI 上的错误信息
- 适合一起调试、学习代码、协作开发

#### 三维度交叉组合

三个维度是独立的，可以任意组合。常见组合：

| 场景 | 审批模式 | 沙箱模式 | 协作模式 |
|------|---------|---------|---------|
| 日常开发 | on-request | workspace-write | default |
| 代码审查 | untrusted | read-only | pair_programming |
| 明确的小任务 | never | workspace-write | execute |
| 架构讨论 | untrusted | read-only | plan |
| Docker 内自主开发 | never | danger-full-access | execute |
| 新项目探索 | on-request | workspace-write | pair_programming |
| 不信任的 agent | untrusted | read-only | default |

#### 沙箱实现（跨平台）

Codex 的沙箱不是简单的进程隔离，而是利用各 OS 原生的安全机制：

**macOS：**
- 使用 Seatbelt（macOS 内置的沙箱机制，.sbpl 策略文件）
- 网络策略：seatbelt_network_policy.sbpl
- 读取限制：restricted_read_only_platform_defaults.sbpl

**Linux：**
- 使用 Bubblewrap（bwrap，容器级隔离）+ Landlock（内核级文件访问控制）
- 支持代理路由（proxy_routing）：控制沙箱内的网络请求

**Windows：**
- 使用 Windows ACL（访问控制列表）+ WFP（Windows Filtering Platform，网络过滤）
- 有独立的沙箱设置程序（codex-windows-sandbox-setup.manifest）
- 支持 ConPTY（伪终端）和 elevation（提权）机制

#### 权限持久化与规则系统

- `ExecPolicyAmendment`：命令前缀规则——用户批准某个前缀后，未来同类命令免确认
- `PermissionProfile`：权限配置文件，可以预设和保存
- `prefix_rule` 指导原则：
  - 好的例子：`["npm", "run", "dev"]`、`["gh", "pr", "check"]`、`["cargo", "test"]`
  - 坏的例子：`["python3"]`、`["python", "-"]`（太宽泛，允许任意脚本）
  - 永远禁止：rm 相关命令（破坏性不可逆）
- 权限可以按 turn（单次）或 session（会话级）授予

#### 命令分段安全评估

Codex 不是简单地评估整条命令，而是按 shell 控制运算符拆分成独立段：
- 管道：`|`
- 逻辑运算：`&&`、`||`
- 命令分隔：`;`
- 子 Shell：`(...)`、`$(...)`

每段独立评估沙箱限制和审批需求。例：`git pull | tee output.txt` 被拆成 `["git", "pull"]` 和 `["tee", "output.txt"]` 分别判断。

使用重定向（`>`、`>>`）、替换（`$(...)`）、环境变量（`FOO=bar`）、通配符（`*`、`?`）的命令不会被规则匹配，防止绕过。

**核心能力（除权限外）：**
- 轻量快速（Rust 编写，启动快）
- 终端命令执行
- 代码生成与编辑
- Git 工作流
- 多 Agent 模式（Multi-Agent Mode，可派生子 agent）
- Skill 技能系统
- MCP 协议支持
- 模型切换（GPT-5.5 等多模型可选，但不走 OpenAI 以外的 provider）
- Code Mode Host：独立的 code mode 运行时
- 记忆系统（Thread Memory Mode）

**可借鉴：**
- 三维度交叉权限设计（审批 × 沙箱 × 协作）——这是整个行业最精细的
- 沙箱跨平台实现（Seatbubblewrap+Landlock+ACL+WFP）
- 命令分段安全评估机制
- 权限持久化规则系统（prefix_rule）
- 协作模式的行为风格设计（plan/execute/pair_programming）
- granular 细粒度逐项控制思路

**局限：**
- 锁定 OpenAI（虽然支持多模型，但都是 OpenAI 生态的 GPT 系列）
- 不支持非编程场景
- 无持久记忆（Thread Memory 仅会话内）、无 cron 定时任务
- 无多平台消息渠道
- 权限系统极其复杂，新手上手门槛高

---

### 3. OpenClaw（社区）

**定位：** 个人 AI 助手，本地运行，跨平台，跨渠道。

**技术架构：**
- 语言：TypeScript
- 协议：MIT
- 模型：多 Provider 支持（OpenAI、Anthropic、Google 等）
- 运行环境：Node.js 24+，支持 macOS/Linux/Windows
- 架构：本地 Gateway（控制平面）+ Companion Apps

**核心能力：**
- **26+ 消息渠道**：WhatsApp、Telegram、Slack、Discord、Google Chat、Signal、iMessage、IRC、Teams、Matrix、飞书、LINE、Mattermost、WebChat、微信、QQ 等
- **语音唤醒 + 持续对话**：macOS/iOS 唤醒词，Android 持续语音（ElevenLabs + 系统 TTS）
- **Live Canvas**：agent 驱动的可视化工作区（A2UI 概念）
- **技能系统**：ClawHub 技能注册中心（5400+ 社区技能）
- **多 Agent 路由**：不同渠道/账号路由到隔离的 agent 实例
- **Cron 定时任务 + Webhook**
- **沙箱**：Docker/SSH/OpenShell 后端
- **Companion Apps**：Windows Hub、macOS 菜单栏应用、iOS/Android Node
- **赞助商**：OpenAI、GitHub、NVIDIA、Vercel、Blacksmith、Convex

**可借鉴：**
- 渠道广度（26+ 平台，全球最全）
- Live Canvas（agent 驱动的 UI 交互，创新点）
- 多 Agent 路由架构
- 技能注册中心（ClawHub）的生态建设
- 语音唤醒与 Talk Mode
- Companion App 架构（跨端体验）

**局限：**
- TypeScript 写的，性能不如 Go/Rust
- 功能太多导致复杂度高
- 38万 star 但核心能力分散
- coding 能力不是其强项

---

### 4. Hermes（NousResearch）

**定位：** 随用户一起成长的通用 Agent。

**技术架构：**
- 语言：Python
- 协议：Apache-2.0
- 模型：多 Provider 支持（OpenAI、Anthropic、Google、自定义等）
- 运行环境：终端 + Docker

**核心能力：**
- **技能系统**：可创建/编辑/删除技能（SKILL.md），内置 100+ 技能，覆盖 coding、创意、研究、DevOps、生活等
- **持久记忆**：跨会话记忆（user profile + memory），自动注入 system prompt
- **Delegation**：可生成子 agent 并行处理任务，支持 orchestrator/leaf 角色
- **Cron 定时任务**：定时执行，支持脚本模式（无 agent）和 LLM 驱动模式
- **Computer Use**：通过 MCP 接入 OpenComputerUse，可控制桌面
- **多 Provider**：不锁定任何模型，自由切换
- **多平台消息**：微信、Discord、Telegram 等
- **浏览器自动化**：内置 browser 工具（navigate/click/type/screenshot）
- **Session Search**：FTS5 搜索历史会话
- **TTS**：语音合成

**可借鉴（即本项目的基础架构）：**
- 整体架构是最适合二次开发的基础
- 技能系统设计成熟
- 记忆系统完整
- Delegation 子 agent 调度
- 多 Provider 自由切换
- Computer Use 桌面控制
- Cron + Webhook

**局限：**
- coding 能力不如 Claude Code（非专属设计）
- 渠道覆盖不如 OpenClaw（但够用）
- 无端侧本地模型支持
- 无手机控电脑功能
- Python 性能瓶颈

---

### 5. WorkBuddy（腾讯）

**定位：** AI Agent 办公新范式，腾讯推出的多模型协作编程/办公平台。

**技术架构：**
- 语言：闭源（推测后端 TypeScript + Go，前端 React）
- 模型：多模型（GLM-5.2、Kimi K2.7、DeepSeek V4、混元 Hunyuan3、MiniMax M3 等）
- 后端 API：`copilot.tencent.com/v2/chat/completions`（标准 OpenAI 协议）
- 运行环境：桌面端（Win/Mac/Linux）+ Web

**核心能力：**
- **多模型切换**：GLM-5.2、Kimi K2.7、DeepSeek V4、混元 Hunyuan3 等，按任务选最合适的模型
- **Function Calling**：原生支持 OpenAI 标准工具调用
- **Skill 技能包**：社区已产出大量技能（微信公众号自动发布、CRM、八字紫微排盘等）
- **编程辅助**：代码生成、审查、重构
- **办公场景**：文档处理、数据分析、报告生成
- **中文生态强**：面向中国市场，中文任务优化

**可用模型（从 codebuddy2openai 逆向获取）：**
- `glm-5.2`、`glm-5.1`、`glm-5v-turbo`
- `kimi-k2.7`、`kimi-k2.6`、`kimi-k2.5`
- `deepseek-v4-pro`、`deepseek-v4-flash`
- `minimax-m3-pay`
- `hy3-preview-agent`
- `auto`（自动选择）

**可借鉴：**
- 多模型智能路由（按任务类型选最佳模型）
- 中文场景优化
- Skill 技能生态建设思路
- 端云协同架构

**局限：**
- 闭源，无法二次开发
- 锁定腾讯生态
- coding 能力深度不如 Claude Code/Codex
- 海外模型接入受限

---

### 6. Marvis 马维斯（腾讯）

**定位：** 操作系统级 AI 桌面助手——更懂你的 AI 助手。

**技术架构：**
- 语言：闭源
- 模型：DeepSeek V4 + 混元 Hunyuan3 + 端侧本地模型
- 运行环境：桌面端（Win/Mac）+ Android + iOS
- 架构：端云协同

**核心能力：**
- **双模式运行**：
  - 效率模式：端云协同，又快又准
  - 本地模式：纯端侧大模型，文件零上传，最大程度隐私保护
- **手机远程控制电脑**：手机连接电脑，实时查看任务执行画面，随时接管
- **文件智能搜索**：搜索文件/图片内容、图片内文字（OCR）、按人像/主题/节日/地点等多维度检索，AI 图库 + AI 文档库
- **一句话改电脑设置**：深度理解 PC 操作系统和硬件信息，自然语言修改系统设置
- **文件深度理解与生成**：文档分析、图表生成、文案润色、格式转换
- **应用一句话调用**：APK 和 EXE 应用通过自然语言启动
- **生活场景**：追星签到、游戏任务监控、新闻推送、学习伴读、电影推荐等

**硬件要求：**
- Windows：≥6核 CPU，≥16GB 内存，固态硬盘，Win10+ x64
- macOS：Apple Silicon M1+，macOS 13+

**可借鉴：**
- 端侧本地模型支持（隐私优先）
- 手机控电脑（跨端远程控制）
- 文件智能搜索（多维语义检索）
- OS 级系统控制（一句话改设置）
- 端云协同架构设计

---

**局限：**
- 闭源，无法二次开发
- 硬件要求高（16GB 内存起步）
- 目前仅 Windows/Mac 桌面体验较好
- 锁定腾讯模型生态
- coding 能力不是其方向

---

---

---


## 三、能力矩阵对比

| 能力 | Claude Code | Codex CLI | OpenClaw | Hermes | WorkBuddy | Marvis |
|------|:-----------:|:---------:|:--------:|:------:|:---------:|:------:|
| **通用对话** | △ | △ | ✅ | ✅ | ✅ | ✅ |
| **Coding 深度** | ✅✅ | ✅✅ | △ | ✅ | ✅ | △ |
| **多模型切换** | ❌ | ❌ | ✅ | ✅✅ | ✅ | △ |
| **端侧本地模型** | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| **持久记忆** | ❌ | ❌ | ✅ | ✅✅ | △ | △ |
| **技能/插件系统** | ❌ | ❌ | ✅✅ | ✅✅ | ✅ | △ |
| **定时任务 Cron** | ❌ | ❌ | ✅ | ✅✅ | ❌ | ✅ |
| **子Agent调度** | ✅ | ❌ | ✅ | ✅✅ | ❌ | ✅ |
| **沙箱执行** | ❌ | ✅✅ | ✅ | ❌ | ❌ | ❌ |
| **消息渠道数** | 1 | 1 | 26+ | 10+ | 1 | 1 |
| **桌面控制** | ❌ | ❌ | △ | ✅ | ❌ | ✅✅ |
| **手机控电脑** | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| **文件智能搜索** | △ | △ | △ | ✅✅ | △ | ✅✅ |
| **语音交互** | ❌ | ❌ | ✅ | ✅ | ❌ | ✅ |
| **Canvas/可视化** | ❌ | ❌ | ✅ | ❌ | △ | △ |
| **Git 工作流** | ✅✅ | ✅ | △ | △ | △ | ❌ |

---

| **代码库理解** | ✅✅ | ✅ | △ | ✅ | ✅ | ❌ |
| **凭证池** | ❌ | ❌ | ❌ | ✅✅ | ❌ | ❌ |
| **MoA混合专家** | ❌ | ❌ | ❌ | ✅✅ | ❌ | ❌ |
| **ask_user确认** | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| **审计日志** | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| **错误恢复** | ✅✅ | △ | ✅ | ✅✅ | △ | △ |

> ✅✅ = 核心优势 | ✅ = 支持 | △ = 部分支持 | ❌ = 不支持

---

---


---

---


## 四、技术栈对比


| 维度 | Claude Code | Codex CLI | OpenClaw | Hermes | WorkBuddy | Marvis |
|------|------------|-----------|----------|--------|-----------|--------|
| **后端语言** | TypeScript | Rust | TypeScript | Python | 闭源 | 闭源 |
| **前端** | 终端 CLI | 终端 CLI | Web + Native Apps | Web + TUI + 消息平台 | 桌面App(Electron) | 桌面App(Electron) |
| **运行时** | Node.js | 原生二进制 | Node.js 24+ | Python | N/A | N/A |
| **数据库** | N/A | N/A | SQLite | SQLite (FTS5) | N/A | 本地索引+FTS5 |
| **沙箱** | ❌ | 跨平台(Seatbelt/Bubblewrap/ACL) | Docker/SSH/OpenShell | ❌ | ❌ | ❌ |
| **协议** | Anthropic API | OpenAI API | OpenAI 兼容 | OpenAI 兼容 | OpenAI 兼容 | 专有 |

---

---


## 五、竞品 Stars 排名

```
OpenClaw    ████████████████████████████████████  381,947 ⭐
Hermes      ██████████████████████████████████        210,273 ⭐
Claude Code ████████████████████                  136,534 ⭐
Codex CLI   ███████████████                       95,854 ⭐
WorkBuddy   [闭源 — 腾讯]
Marvis      [闭源 — 腾讯，有 OpenMarvis 开源复现]
```

---

---

# 第二部分：竞品源码深度分析

> Claude Code、Codex CLI、OpenClaw 三款有源码的竞品深度拆解，以及三家核心架构对比

---


> Claude Code、Codex CLI、OpenClaw 三款有源码的竞品深度拆解，以及三家核心架构对比


## 六、Claude Code 源码深度分析（泄露版 v2.1.88）

> **信息来源：** 2026年3月31日 npm 注册表意外发布了 Claude Code v2.1.88 的 sourcemap 文件，社区通过反编译还原了几乎完整的 TypeScript 源码。所有参考仓库截至 2026-07-07 仍然存活（未被 DMCA 下架）。本节分析基于源码，非官方文档推测。

### 6.1 泄露源码概况

| 仓库 | ⭐ | 内容 |
|------|-----|------|
| `Hyper66666/claude-code-sourcemap` | 216 | 泄露源码原始镜像（claude-code-2.1.88.tgz + 还原后的 src/） |
| `Ahmad-progr/claude-leaked-files` | 283 | 泄露源码快照镜像 |
| `fazxes/Claude-code` | 225 | 基于泄露源码重建的 Claude Code |
| `soongenwong/claudecode` | 1,156 | 基于 Claude Code 用 Rust 重写（功能一致） |
| `waiterxiaoyy/Deep-Dive-Claude-Code` | 280 | 13 章源码架构分析 |
| `noya21th/claude-source-leaked` | 124 | 源码分析（87 个隐藏 feature flag、system prompt 等） |
| `Austin1serb/Anthropic-Leaked-Source-Code` | 500 | "完整 Claude 泄露源码" |

**注意：** Claude Code 官方本身不开源，许可证是 "© Anthropic PBC. All rights reserved"。泄露源码可参考架构和设计思想，但不能直接复制粘贴商用。

### 6.2 核心架构概览

```

Claude Code Architecture
========================

CLI 入口 (cli.tsx)
    │
    v
QueryEngine (一个会话一个实例)
├── mutableMessages: Message[]     ← 跨轮次的消息历史
├── totalUsage: Usage             ← 累计 Token 消耗
├── readFileState: FileStateCache ← 文件状态缓存
├── config: QueryEngineConfig     ← 工具/命令/MCP/Agent 定义
├── abortController               ← 中止信号
└── permissionDenials[]           ← 权限拒绝记录

---
### 6.3 Agent 循环（query.ts）—— 为什么编码能力这么强

Claude Code 的核心循环在 `query.ts`，文件大小 67KB，是一个 `while(true)` 循环。对比教学版的 30 行 agent loop，生产版在同样结构上叠加了 7 层能力：

| 层 | 功能 | 教学版 | Claude Code |
|----|------|--------|-------------|
| **API 调用** | 模型请求 | 同步单次调用 | 流式 + fallback 模型 + prompt cache |
| **工具执行** | 运行工具 | 顺序调用 handler | 权限检查 → 并行/串行自动切换 → 流式结果 |
| **消息管理** | 追加结果 | 简单 append | 类型联合（8种消息类型）+ 规范化 + 截断 |
| **上下文压缩** | 控制窗口 | 无 | 三层压缩（micro + auto + session memory） |
| **停止条件** | 循环退出 | `stop_reason` | + maxTurns + maxBudget + abort + stop hooks |
| **错误恢复** | 异常处理 | 无 | 模型 fallback → prompt-too-long 恢复 → max-output 递增重试 |
| **可观测性** | 监控 | 无 | 事件日志 + Token 统计 + headless profiler |

**关键源码片段——循环主体结构：**

```typescript
// query.ts:307-1728 (简化)
while (true) {
  // 1. 技能发现预取（在模型流式响应期间并行执行）
  const pendingSkillPrefetch = skillPrefetch?.startSkillDiscoveryPrefetch(...)

  // 2. 应用工具结果预算限制（防止单次工具返回超大内容）
  messagesForQuery = await applyToolResultBudget(messagesForQuery, ...)

  // 3. 微压缩（截断过大的工具输出，不调用 API）
  const microcompactResult = await deps.microcompact(messagesForQuery, ...)

  // 4. 上下文折叠（将旧消息折叠为摘要条目）
  if (feature('CONTEXT_COLLAPSE')) {
    const collapseResult = await contextCollapse.applyCollapsesIfNeeded(...)
  }

  // 5. 自动压缩（超过阈值时用模型总结前半段对话）
  const { compactionResult } = await deps.autocompact(messagesForQuery, ...)

  // 6. 流式调用 Claude API
  for await (const message of deps.callModel({
    messages: messagesForQuery,
    systemPrompt: fullSystemPrompt,
    tools: toolUseContext.options.tools,
    ...
  })) {
    // 流式产出消息给 UI
    yield message
    // 收集 tool_use 块
    if (message.type === 'tool_use') toolUseBlocks.push(...)
  }

  // 7. 如果没有工具调用 → 退出循环（任务完成）
  if (!needsFollowUp) {
    // ... stop hooks, token budget check ...
    return { reason: 'completed' }
  }

  // 8. 执行工具（只读工具并行，写操作串行）
  const toolUpdates = streamingToolExecutor
    ? streamingToolExecutor.getRemainingResults()
    : runTools(toolUseBlocks, ..., canUseTool, ...)
  for await (const update of toolUpdates) {
    yield update.message
    toolResults.push(update.message)
  }

  // 9. 更新状态，继续循环
  state = {
    messages: [...messagesForQuery, ...assistantMessages, ...toolResults],
    ...
  }
}
```

### 6.4 工具系统—— 38+ 个工具

Claude Code 的工具系统极其精细，每个工具都是一个独立的模块：

```
tools/
├── AgentTool/          (228KB) — 子代理生成器（最大的工具）
├── BashTool/           (17个文件) — Shell 命令执行
│   ├── BashTool.tsx
│   ├── bashPermissions.ts    ← 权限检查
│   ├── bashSecurity.ts       ← 命令安全分析（危险命令警告）
│   ├── commandSemantics.ts   ← 命令语义分析（读/写/网络/删除）
│   ├── sedEditParser.ts      ← sed 编辑解析
│   ├── sedValidation.ts      ← sed 命令验证
│   ├── pathValidation.ts     ← 路径安全验证
│   ├── readOnlyValidation.ts ← 只读验证
│   ├── destructiveCommandWarning.ts ← 破坏性命令警告
│   ├── modeValidation.ts     ← 模式验证（plan模式禁写）
│   ├── shouldUseSandbox.ts    ← 沙箱决策
│   └── prompt.ts              ← Bash 工具的 system prompt
├── FileEditTool/       — 精确文本替换（old_string → new_string）
├── FileReadTool/       — 文件读取（支持范围读取、图片处理）
├── FileWriteTool/      — 文件创建/覆写
├── GrepTool/           — 代码搜索（正则 + glob 过滤）
├── GlobTool/           — 文件名搜索
├── TodoWriteTool/      — 任务列表管理
├── SleepTool/          — 后台任务等待
├── SendMessageTool/     — Agent 间消息通信
├── ComputerUseTool/     — 桌面控制（MCP Computer Use）
└── ...（更多工具）
```

**BashTool 的安全分析链（每次命令执行前经过 6 层检查）：**

1. `modeValidation.ts` — 当前模式是否允许执行（plan 模式只读）
2. `bashPermissions.ts` — 权限规则匹配（allow/deny/ask）
3. `bashSecurity.ts` — 危险命令检测（rm -rf、force push 等）
4. `destructiveCommandWarning.ts` — 破坏性命令二次确认
5. `pathValidation.ts` — 路径安全（禁止绝对路径遍历）
6. `shouldUseSandbox.ts` — 是否需要沙箱隔离

### 6.5 上下文管理—— 三层压缩策略

这是 Claude Code 能处理大型代码库、长对话的关键。模型上下文窗口有限（128K-200K tokens），三层压缩策略自动运作：

```
消息增长过程:

Turn 1:  [user] [assistant] [tool_result]                    ~5K tokens
Turn 5:  [user] [assistant] [tool×3] [assistant] [tool×2]   ~30K tokens
Turn 10: [...大量工具输出...]                                  ~80K tokens
Turn 15: [...接近上限...]                                      ~120K tokens ⚠️

---

                                                                │
         三层压缩策略自动介入:                                   │
         ================================                    │
                                                                v
Layer 1: 微压缩 (microCompact)           ← 单条消息级别
         截断过长的工具输出（零 API 开销）
         e.g. 50K 文件内容 → 保留前1000行 + 后100行 + 中间省略

Layer 2: 自动压缩 (autoCompact)          ← 会话级别
         Token 超过阈值（context_window - 13K）时触发
         用模型总结前半段对话 → 替换为压缩摘要
         压缩后保留最近消息 + 摘要

Layer 3: 会话记忆 (SessionMemory)        ← 跨压缩级别
         压缩前提取关键记忆（用户偏好、决策、进度）
         压缩后重新注入
         "做梦"（autoDream）后台异步整合散落记忆
```

**关键参数（源码中的常量）：**
- `AUTOCOMPACT_BUFFER_TOKENS = 13,000` — 距离上下文窗口上限的缓冲区
- `MAX_OUTPUT_TOKENS_FOR_SUMMARY = 20,000` — 压缩摘要最大输出 token
- `MAX_CONSECUTIVE_AUTOCOMPACT_FAILURES = 3` — 连续压缩失败后停止重试（防死循环）
- `COMPLETION_THRESHOLD = 0.9` — Token 预算使用 90% 时触发预算检查
- `DIMINISHING_THRESHOLD = 500` — 连续 3 轮 delta < 500 tokens 判定为边际收益递减

### 6.6 权限系统—— 6 种模式 + 规则引擎

Claude Code 的权限系统比 Codex 更重规则、更注重安全性：

**6 种权限模式：**
| 模式 | 行为 |
|------|------|
| `default` | 合理假设下直接执行，敏感操作询问 |
| `acceptEdits` | 自动接受代码编辑，其他操作询问 |
| `bypassPermissions` | 跳过所有权限检查（危险） |
| `dontAsk` | 只读 + 代码编辑，拒绝其他操作 |
| `plan` | 只读模式，不执行任何写操作 |
| `auto` | 根据任务自动选择权限级别 |

**权限决策流程（双阶段分类器）：**
```
工具调用请求
    │
    v
Stage 1: Fast Classifier（规则匹配，毫秒级）
├── 检查 CLAUDE.md 中的 allow/deny 规则
├── 检查路径安全性（符号链接、目录遍历）
├── 检查命令语义（只读 vs 写入 vs 网络）
└── 快速放行 / 快速拒绝 / 转到 Stage 2
    │
    v
Stage 2: Thinking Classifier（模型推理，秒级）
├── 发送给模型判断操作安全性
├── 模型分析上下文后决定
└── 最终 allow / deny / ask
```

**权限规则来源：**
- 项目级：`CLAUDE.md` / `.claude/settings.json`（团队共享）
- 用户级：`~/.claude/settings.json`（个人偏好）
- 运行时：用户对话中的即时授权/拒绝

### 6.7 多 Agent 架构—— 三层协作模型

Claude Code 实现了成熟的多 Agent 协作，分三个层级：

**Layer 1: Subagent（一次性子代理）**
```
Parent Agent → spawn → Subagent（fresh context）
                         ↓
                    执行任务
                         ↓
                    返回 summary → Parent 收到
                    Subagent 丢弃
```
- 用途：搜索代码、分析文件、执行不需要跨轮次交互的任务
- 实现：`AgentTool.tsx`（228KB）+ `forkSubagent.ts`
- 关键：子代理有独立的上下文，执行完即销毁，不污染父代理
- 内置类型：`Explore`（代码探索）、`Plan`（规划）、`GeneralPurpose`（通用）、`Verification`（验证）、`ClaudeCodeGuide`（代码指南）

**Layer 2: Teammate（持久化队友）**
```
Lead Agent → spawn → Teammate A（持久化线程）
                 → spawn → Teammate B（持久化线程）
                              ↓
                    JSONL 邮箱双向通信
                    SendMessages ←→ 消息队列
```
- 用途：多文件重构、需要不同专长的任务
- 实现：`teammateMailbox.ts`（33KB）+ `teammate.ts`
- 关键：队友是持久化线程，可以接收多条消息、累积上下文
- 通信：JSONL 文件邮箱（类似 Unix 的 mbox 格式）

**Layer 3: Swarm（自治集群）**
```
.tasks/ 任务看板
├── task_1: pending (unclaimed)      → Alice 自动认领
├── task_2: in_progress (owner:bob) → Bob 执行中
└── task_3: completed                → Carol 完成
```
- 用途：大规模任务分发、自主协作
- 实现：`swarm/` 目录 + 任务看板
- 关键：Agent 自主扫描看板、认领任务、汇报进度
- 任务类型：LocalShellTask、LocalAgentTask、RemoteAgentTask、DreamTask、LocalWorkflowTask、MonitorMcpTask

### 6.8 工具并行执行—— 只读并发 + 写操作串行

Claude Code 的工具执行不是简单的顺序执行，而是智能分区：

```typescript
// toolOrchestration.ts 核心逻辑

function partitionToolCalls(toolUseMessages, toolUseContext) {
  // 将工具调用分为两类：
  // 1. 只读工具（FileRead、Grep、Glob）→ 并行执行
  // 2. 写操作工具（FileEdit、Bash、FileWrite）→ 串行执行
  return batches.map(batch => ({
    isConcurrencySafe: allReadOnly(batch),
    blocks: batch
  }))
}

// 并发执行（最多 10 个同时运行）
function getMaxToolUseConcurrency(): number {
  return parseInt(process.env.CLAUDE_CODE_MAX_TOOL_USE_CONCURRENCY || '10')
}
```

**为什么这样设计：**
- 只读操作互不干扰（读文件 A 不影响读文件 B）→ 并行加速
- 写操作可能互相依赖（编辑文件 A 后再编辑文件 B）→ 串行保证一致性
- 默认最大并发数 10，可通过环境变量调整

### 6.9 流式工具执行（StreamingToolExecutor）

这是 Claude Code 的高级特性——工具不需要等模型完整响应后再执行：

```
传统模式:
模型输出完整响应 → 解析 tool_use → 串行执行工具 → 回传结果 → 模型继续

流式模式:
模型开始流式输出 → 每个流式块一出现就解析 → 只读工具立即开始执行
                  → 模型还在生成的同时，工具结果已经就绪
                  → 模型结束 → 写操作开始执行 → 结果追加 → 循环
```

这意味着：模型在思考下一步该做什么的时候，前置的只读工具（grep、读文件）已经在并行运行了。总等待时间 = max(模型生成时间, 工具执行时间)，而不是两者的和。

### 6.10 Session Memory—— 跨压缩记忆保持

```
SessionMemory/
├── sessionMemory.ts       (16KB) — 记忆管理核心
├── sessionMemoryUtils.ts  (6KB)  — 辅助函数
└── prompts.ts             (12KB) — 记忆提取 prompt
```

**工作原理：**
1. 压缩前：从即将被压缩的消息中提取关键记忆
   - 用户偏好（"我喜欢用 tab 而不是 space"）
   - 重要决策（"选择 PostgreSQL 而不是 MongoDB"）
   - 进度信息（"已完成 3/5 个模块"）
2. 压缩后：将记忆注入到压缩后的消息列表顶部
3. 后台"做梦"（autoDream）：用户空闲时异步整合散落的记忆片段

### 6.11 "做梦"机制（autoDream）

```
autoDream/
├── autoDream.ts           (11KB) — 做梦逻辑
├── config.ts              (1KB)  — 配置
├── consolidationLock.ts   (4KB)  — 防止并发做梦
└── consolidationPrompt.ts (3KB)  — 整合提示词
```

这是 Claude Code 独特的特性——在用户空闲时，后台启动一个 API 调用，将散落在不同消息中的记忆片段整合为连贯的知识条目。类似人类睡眠时的记忆整合。

**关键设计：**
- 异步执行，不阻塞用户交互
- 有锁机制防止并发做梦（consolidationLock）
- 整合后写入 SessionMemory，后续压缩时自动注入

### 6.12 Token 预算管理

```typescript
// query/tokenBudget.ts
const COMPLETION_THRESHOLD = 0.9     // 预算使用 90% 触发检查
const DIMINISHING_THRESHOLD = 500    // 连续 3 轮 delta < 500 判定为递减

function checkTokenBudget(tracker, agentId, budget, globalTurnTokens) {
  const pct = Math.round((turnTokens / budget) * 100)
  const isDiminishing =
    tracker.continuationCount >= 3 &&
    deltaSinceLastCheck < 500 &&
    tracker.lastDeltaTokens < 500

  if (!isDiminishing && turnTokens < budget * 0.9) {
    return { action: 'continue', nudgeMessage: '...' }  // 继续但有提醒
  }
  return { action: 'stop', completionEvent: {...} }       // 停止
}
```

- 预算检查不是简单的"用完就停"
- 有"边际收益递减"检测：如果连续 3 轮每轮新增 token < 500，说明 agent 在空转
- 有"nudge message"机制：快到预算时注入提醒消息，引导 agent 高效收尾

### 6.13 错误恢复—— 五种恢复策略

| 错误类型 | 恢复策略 |
|----------|----------|
| 模型过载（429/503） | 自动切换 fallback 模型重试 |
| prompt-too-long（413） | 先尝试 context collapse drain（折叠加载）→ 再尝试 reactive compact（响应式压缩） |
| max-output-tokens | 先尝试升级到 64K 输出上限 → 再注入恢复消息让 agent 从截断点继续 |
| 流式中途失败 | 清理孤儿消息（tombstone）+ 重建 StreamingToolExecutor |
| 压缩失败 | 熔断机制：连续 3 次失败后停止重试，防止死循环浪费 API 调用 |

### 6.14 Claude Code 编码能力强的根本原因—— 总结

综合以上源码分析，Claude Code 编码能力强的原因不是单一因素，而是**多层设计的协同效应**：

1. **深度代码理解**
   - 启动时自动抓取 git status、分支、最近提交
   - 扫描 CLAUDE.md 项目配置（代码风格、架构约定）
   - 自动发现项目技能（skillPrefetch）

2. **高效的工具链**
   - 38+ 精细工具，每个工具专注一件事
   - 只读工具并行执行（最多 10 个并发）
   - 流式工具执行（模型思考的同时工具已开始运行）
   - Bash 命令经过 6 层安全检查

3. **无限的上下文窗口**
   - 三层压缩策略（micro + auto + session memory）
   - Token 预算管理（边际收益递减检测）
   - prompt-too-long 自动恢复
   - "做梦"后台整合记忆

4. **强大的多 Agent 协作**
   - 三层协作模型（subagent → teammate → swarm）
   - 子代理 fresh context（不污染父代理）
   - 内置验证代理（Verification Agent）
   - 内置探索代理（Explore Agent）

5. **精细的安全设计**
   - 6 种权限模式 + 双阶段分类器
   - 规则引擎（allow/deny/ask + glob 匹配）
   - 环境变量清洗（防 API key 泄露）
   - 沙箱决策（shouldUseSandbox）

6. **生产级的健壮性**
   - 模型 fallback（自动切换备用模型）
   - 5 种错误恢复策略
   - 熔断机制（防死循环）
   - 可观测性（事件日志 + profiler）

### 6.15 对我们产品的集成启示

**应该学习的：**

| 设计 | Claude Code 做法 | 我们应该怎么做 |
|------|------------------|----------------|
| 核心循环 | while(true) + 流式 API + 自动压缩 | 相同架构，Python async 实现 |

---


---

---


## 七、Codex CLI 源码深度分析

### 7.1 权限系统—— 三维度交叉设计

**维度 1：审批模式（Approval Mode）** — 4 种：

| 模式 | 行为 | 适用场景 |
|------|------|----------|
| `untrusted` | 只有"安全"命令直接执行，其他全要用户确认 | 第一次用、不信任的代码库 |
| `on-request` | 模型自己决定什么时候该问用户确认 | 日常使用，平衡速度和安全 |
| `never` | 完全自主，所有命令直接执行 | 高信任度、自动化场景 |
| `granular` | 逐项配置：沙箱审批、规则、技能审批、权限请求、MCP 插件审批各开关 | 精细控制 |

**维度 2：沙箱模式（Sandbox Mode）** — 3 种：

| 模式 | 能力 |
|------|------|
| `read-only` | 只能读文件，不能写、不能执行命令 |
| `workspace-write` | 能读写当前项目目录，其他目录要审批 |
| `danger-full-access` | 无沙箱限制，完全访问 |

**维度 3：协作模式（Collaboration Mode）** — 4 种：

| 模式 | System Prompt 关键指令 | 适用场景 |
|------|------------------------|----------|
| `default` | "合理假设下直接执行；大改动先讨论" | 日常开发 |
| `plan` | "只读不写，讨论方案；列出文件和修改但不要改" | 方案评审 |
| `execute` | "自主循环：写代码→测试→修 bug→循环通过；少问多做" | 批量任务 |
| `pair-programming` | "边做边确认每一步；停下来讨论决策" | 学习/结对 |

**三维度交叉组合表（7 种常见场景）：**

| 场景 | 审批 | 沙箱 | 协作 | 说明 |
|------|------|------|------|------|
| 轻度探索 | untrusted | read-only | plan | 只看不动 |
| 日常开发 | on-request | workspace-write | default | 平衡模式 |
| 自动化任务 | never | danger-full-access | execute | 全自动 |
| 代码评审 | on-request | read-only | plan | 只读评审 |
| CI/CD 集成 | never | workspace-write | execute | 自动构建 |
| 新人学习 | untrusted | workspace-write | pair-programming | 边做边学 |
| 精细控制 | granular | 自定义 | 自定义 | 企业场景 |

### 7.2 沙箱跨平台实现

| 平台 | 沙箱技术 | 实现文件 |
|------|----------|----------|
| macOS | Seatbelt（sandbox-exec） | `sandboxing/macos_seatbelt.rs` |
| Linux | Bubblewrap + Landlock | `sandboxing/linux_bubblewrap.rs` |
| Windows | ACL + WFP（Windows Filtering Platform） | `sandboxing/windows_acl.rs` |

### 7.3 权限持久化与规则系统

- `prefix_rule`：命令前缀规则（如 `npm install` 允许，`rm -rf` 拒绝）
- `PermissionProfile`：权限配置文件，可保存/加载
- 禁止规则（prohibited）：即使其他规则允许，禁止规则也生效

### 7.4 命令分段安全评估

Codex 对 shell 命令的处理比表面看起来更复杂：
- 将 shell 控制运算符（&&、||、;、|、$(、``）拆分为独立命令段
- 每段独立评估安全性
- 防止通过组合绕过安全检查（如 `ls && rm -rf /`）

### 7.5 Codex vs Claude Code 权限设计对比

| 维度 | Claude Code | Codex CLI |
|------|-------------|-----------|
| 维度数 | 1 个（权限模式） | 3 个（审批 × 沙箱 × 协作） |
| 决策方式 | 双阶段分类器（规则 + 模型推理） | 规则 + 模型自决（on-request 模式） |
| 沙箱 | 实现细节不明（从源码看有沙箱） | 跨平台沙箱（Seatbelt/Bubblewrap/ACL） |
| 粒度 | 6 种预设模式 | 三维度交叉 = 理论 48 种组合 |
| 持久化 | CLAUDE.md 规则文件 | prefix_rule + PermissionProfile |
| 安全审计 | 环境变量清洗 + 路径验证 | 命令分段 + 控制运算符拆分 |

**结论：** Codex 的权限设计维度更多、更灵活；Claude Code 的权限决策更智能（有模型参与推理）。我们产品应该融合两者优势。

---

---


## 八、OpenClaw 源码深度分析

> **信息来源：** OpenClaw 是完全开源项目（MIT License），`openclaw/openclaw`，⭐381,947。TypeScript，pnpm workspace monorepo，1.6GB+。源码可直接参考和集成。

### 8.1 项目概况

| 属性 | 值 |
|------|-----|
| 仓库 | `openclaw/openclaw` |
| ⭐ | 381,947（截至 2026-07-07） |
| Forks | 80,111 |
| 语言 | TypeScript |
| 许可证 | MIT（完全开源，可商用） |
| 创建时间 | 2025-11-24 |
| 规模 | 1,683 MB |
| 定位 | "Your own personal AI assistant. Any OS. Any Platform." |
| Slogan | "The AI that actually does things." |
| 赞助商 | OpenAI、GitHub、NVIDIA、Vercel、Blacksmith、Convex |

**关键区别：OpenClaw 不是 coding agent，而是通用 AI 助手。** 它的设计哲学是"一个助手跑在所有设备上、所有渠道里"。编码能力只是其工具集的一部分。

### 8.2 核心架构—— Gateway 控制平面

```
OpenClaw Architecture
======================

Gateway（Node.js 守护进程，launchd/systemd）
├── 多渠道收件箱（26+ 渠道）
│   ├── WhatsApp / Telegram / Discord / Slack / WeChat / QQ
│   ├── Signal / iMessage / IRC / Teams / Matrix / Feishu
│   ├── LINE / Mattermost / Nostr / Twitch / Zalo / ...
│   └── macOS / iOS / Android / Windows / Linux
│
├── 多 Agent 路由（不同渠道/用户路由到不同 agent）
│   ├── 每个 agent 独立工作空间 + 独立会话
│   ├── agent 间通过 sessions_spawn/sessions_send 通信
│   └── 子代理深度限制（DEFAULT_SUBAGENT_MAX_SPAWN_DEPTH）
│
├── 会话管理（Session Store，SQLite）
│   ├── 会话路由（session key → agent binding）
│   ├── 会话持久化（消息、Token 统计、压缩状态）
│   └── 会话恢复（session repair、reconciliation）
│
├── 插件系统（Plugin SDK）
│   ├── 代码插件（运行时扩展）
│   ├── Bundle 插件（打包分发）
│   ├── ClawHub 市场（5,400+ 技能）
│   └── MCP 协议支持
│
├── 工具集（25+ 内置工具）
│   ├── 文件操作：read / write / edit / apply_patch / grep / find / ls
│   ├── 执行：exec（PTY 支持）/ process（后台进程管理）
│   ├── 网络：web_search / web_fetch / browser
│   ├── 代理：sessions_spawn / sessions_yield / subagents
│   ├── 渠道：message / cron / gateway
│   ├── 视觉：canvas / image / image_generate
│   ├── 设备：nodes（配对设备）
│   └── 技能：skill_workshop
│
├── Code Mode（QuickJS WASI 沙箱内执行 JS/TS）
│   ├── 独立于主 agent 的沙箱执行环境
│   ├── 可搜索/调用/让步工具
│   └── 64MB 内存限制、10s 超时、64KB 输出限制
│
└── 安全层
    ├── DM 配对策略（pairing 机制）
    ├── 沙箱后端（Docker / SSH / OpenShell）
    ├── 工具策略管道（7 层策略过滤）
    └── 环境变量清洗
```

### 8.3 Agent 循环—— embedded-agent-runner

OpenClaw 的 agent 循环在 `src/agents/embedded-agent-runner/run.ts`，文件大小 **4,295 行**——比 Claude Code 的 query.ts（67KB）大得多，但这是因为它处理了更多平台/渠道/模型的兼容性逻辑。

**循环核心结构（runEmbeddedAgentInternal，从第 630 行开始）：**

```
runEmbeddedAgentInternal()
    │
    ├─→ 解析 sessionKey / sessionFile
    ├─→ 解析会话路由（哪个 agent 处理这个会话）
    ├─→ 构建 Lane（会话级队列，控制并发）
    │    ├── foreground：用户触发
    │    ├── background：cron/heartbeat/memory/overflow
    │    └── normal：其他
    ├─→ 构建 AbortController（中止信号）
    ├─→ enqueueGlobal/enqueueSession（加入命令队列）
    │
    ├─→ [外层重试循环]（模型 fallback + 压缩恢复）
    │    │
    │    ├─→ resolveAuthProfileOrder（认证轮换）
    │    ├─→ buildAgentRuntimePlan（运行时计划）
    │    ├─→ buildEmbeddedRunPayloads（构建 API 载荷）
    │    │    ├── 构建 system prompt
    │    │    ├── 构建 context files
    │    │    ├── 构建 tool schemas
    │    │    └── 构建 model identity
    │    │
    │    ├─→ runEmbeddedAttemptWithBackend（单次尝试）
    │    │    ├── 调用模型 API（流式）
    │    │    ├── 工具执行
    │    │    ├── 压缩检查（compaction）
    │    │    └── 返回 attempt result
    │    │
    │    ├─→ [错误处理]
    │    │    ├── 429/503 → auth profile rotation（认证轮换）
    │    │    ├── context overflow → compaction（压缩重试）
    │    │    ├── empty response → retry with instruction
    │    │    ├── reasoning only → retry with instruction
    │    │    └── idle timeout → breaker（断路器）
    │    │
    │    └─→ [继续循环或退出]
    │
    └─→ 返回 EmbeddedAgentRunResult
```

### 8.4 System Prompt 组装—— buildAgentSystemPrompt

OpenClaw 的 system prompt 构建极其精细（`system-prompt.ts`，1,426 行），是理解其工作流的关键：

**Context Files 加载顺序（固定优先级）：**

| 优先级 | 文件 | 内容 |
|--------|------|------|
| 10 | `agents.md` | Agent 定义和角色 |
| 20 | `soul.md` | Agent 人格/灵魂 |
| 30 | `identity.md` | 身份信息 |
| 40 | `user.md` | 用户信息 |
| 50 | `tools.md` | 工具使用指南 |
| 60 | `bootstrap.md` | 启动配置 |
| 70 | `memory.md` | 记忆注入 |
| 动态 | `heartbeat.md` | 心跳任务（定期刷新） |

**Prompt Mode（控制注入内容量）：**
- `full`：所有 section（主 agent）
- `minimal`：仅 Tooling + Workspace + Runtime（子代理）
- `none`：仅基本身份行

**工具提示生成：** 动态根据实际可用的工具列表生成 system prompt 中的工具说明，不会告诉模型有它用不了的工具。

### 8.5 子代理系统—— sessions_spawn

OpenClaw 的子代理系统比 Claude Code 更复杂，支持两种模式：

**模式 1：Native Subagent（OpenClaw 内部子代理）**
```
Parent Agent
    │
    ├── sessions_spawn(taskName, goal, context, model, ...)
    │   ├── 验证 spawn 请求（深度限制、工具继承）
    │   ├── 创建子会话（fork from parent）
    │   ├── 注入继承的工具 allow/deny 列表
    │   ├── 注册到 subagent-registry
    │   └── 子代理独立运行
    │
    ├── sessions_yield（等待子代理完成）
    │   └── push-based：子代理完成时自动推送结果
    │
    └── 子代理完成后自动清理（orphan recovery）
```

**模式 2：ACP Harness（外部编码 agent）**
```
Parent Agent
    │
    ├── sessions_spawn(runtime="acp", agentId="codex", ...)
    │   └── 启动外部 ACP 子进程（Claude Code / Codex CLI / OpenCode）
    │       ├── 通过 ACP 协议通信（stdio）
    │       ├── 完整沙箱隔离
    │       └── 结果通过 announce 机制返回
    │
    └── ACP 子进程使用自己的工具集和模型
```

**子代理安全控制：**
- `DEFAULT_SUBAGENT_MAX_SPAWN_DEPTH`：最大嵌套深度
- `DEFAULT_SUBAGENT_MAX_CHILDREN_PER_AGENT`：单 agent 最大子代理数
- `inheritedToolAllowPatch` / `inheritedToolDenyPatch`：工具继承
- `subagent-depth.ts`：深度追踪
- `subagent-orphan-recovery.ts`：孤儿恢复

### 8.6 Code Mode—— QuickJS WASI 沙箱执行

这是 OpenClaw 独有的特性——让模型在沙箱内执行 JS/TS 代码：

```
Code Mode 架构
===============

Agent
    │
    ├── exec(language, code)
    │   └── Worker Threads → QuickJS WASI
    │       ├── 隔离执行环境
    │       ├── 桥接工具调用（search / describe / call / yield）
    │       ├── 等待（snapshot + resume）
    │       └── 输出返回
    │
    └── wait(runId)
        └── 恢复 snapshot 继续执行
```

**Code Mode 限制：**
- 内存：64MB
- 超时：10s
- 输出：64KB
- 快照：10MB
- 最大 pending tool calls：16
- 快照 TTL：900s
- 最大并发：64

### 8.7 工具策略管道—— 7 层过滤

OpenClaw 的工具策略比 Claude Code 和 Codex 都精细，7 层策略管道按顺序应用：

```
工具请求
    │
    v
Layer 1: Profile Policy（用户级配置）
    ↓
Layer 2: Provider Profile Policy（按模型提供商）
    ↓
Layer 3: Global Allow Policy（全局允许列表）
    ↓
Layer 4: Global Provider Allow Policy（按提供商全局允许）
    ↓
Layer 5: Agent Policy（agent 级配置）
    ↓
Layer 6: Agent Provider Policy（按 agent 提供商）
    ↓
Layer 7: Group Policy（组策略）
    ↓
Layer 8: Sender Policy（发送者策略）
    ↓
最终可用工具列表
```

每层都可以 `allow`、`deny` 或传递到下一层。策略支持 glob 模式和插件组（plugin groups）。

### 8.8 上下文压缩—— Compaction 系统

OpenClaw 的压缩系统（`compaction.ts`，455 行）比 Claude Code 更复杂：

**压缩摘要指令（MERGE_SUMMARIES_INSTRUCTIONS）：**
```
必须保留:
- 活跃任务及其当前状态（进行中、阻塞、待处理）
- 批量操作进度（如 "5/17 项已完成"）
- 用户最后请求的内容以及正在做什么
- 已做的决策及其理由
- TODOs、未解决问题和约束
- 任何承诺或后续行动
```

**压缩策略：**
- `identifierPolicy`：`strict`（保留所有标识符）/ `off` / `custom`
- 自适应 chunk ratio（BASE_CHUNK_RATIO / MIN_CHUNK_RATIO）
- oversized fallback plan（超大对话的分阶段处理）
- partial summary（部分摘要合并）
- retry with safety timeout

### 8.9 模型 Fallback 系统—— 1,995 行

OpenClaw 的模型 fallback 系统比 Claude Code 的更成熟（`model-fallback.ts`，1,995 行）：

**Fallback 决策流程：**
```
模型调用失败
    │
    v
分类错误原因（classifyFailoverReason）
    ├── 429 Rate Limit → auth profile rotation（切换认证轮换）
    ├── 503 Overload → cooldown → probe（冷却探测）
    ├── 401/403 Auth → skip this profile
    ├── Context Overflow → compaction（压缩重试）
    └── Unknown → generic retry
    │
    v
resolveFailoverDecision（决策是否继续 fallback）
    ├── 有候选 → 继续尝试下一个
    ├── 候选用尽 → 最终失败
    └── 连续空响应 → 限制重试
    │
    v
尝试下一个模型/提供商
```

**认证轮换（Auth Profile Rotation）：**
- 同一 provider 有多个认证 profile
- 失败时自动切换到下一个 profile
- 冷却期（cooldown）防止频繁切换
- 窗口期追踪（usage window tracking）

### 8.10 渠道系统—— 26+ 渠道支持

OpenClaw 的渠道系统是其最大差异化特性：

| 渠道类型 | 渠道 |
|----------|------|
| 即时通讯 | WhatsApp、Telegram、Signal、iMessage、WeChat、QQ、LINE、Zalo |
| 团队协作 | Discord、Slack、Microsoft Teams、Google Chat、Matrix、Mattermost、Feishu |
| 社交 | Twitch、Nostr、IRC、Nextcloud Talk、Tlon、Synology Chat |
| 桌面/移动 | macOS、iOS、Android、Windows、Linux |
| Web | WebChat |

**DM 安全策略：**
- `dmPolicy="pairing"`：未知发送者需要配对码（默认）
- `dmPolicy="open"`：公开，需显式 `*` 允许
- 配对通过 `openclaw pairing approve <channel> <code>` 管理

### 8.11 沙箱系统—— 多后端

OpenClaw 支持三种沙箱后端：

| 后端 | 适用场景 |
|------|----------|
| Docker | 默认，隔离性最好 |
| SSH | 远程服务器执行 |
| OpenShell | 本地轻量隔离 |

**沙箱工具策略（默认非 main session）：**
- 允许：`bash`、`process`、`read`、`write`、`edit`、`sessions_*`
- 拒绝：`browser`、`canvas`、`nodes`、`cron`、`discord`、`gateway`

### 8.12 技能系统—— Skill Workshop + ClawHub

**Skill Workshop（内置）：**
- 模型可以用 `skill_workshop` 工具创建、修改、审查技能
- 技能提案机制（proposals → accept/reject/quarantine）
- 工作区级技能（`workspace/skills/`）
- 安全审查（skill discovery + quarantine）

**ClawHub 市场：**
- `VoltAgent/awesome-openclaw-skills`（⭐50,976）收录 5,400+ 技能
- 社区贡献技能的集中市场

### 8.13 心跳系统—— Background Automation

OpenClaw 有独特的心跳机制：
```
heartbeat.md（定期刷新的上下文文件）
    │
    v
Agent 读取 HEARTBEAT.md → 执行定时任务
    │
    ├── 如果什么都不需要做 → 回复 HEARTBEAT_OK（不消耗用户注意力）
    └── 如果有任务 → 执行并通知
```

心跳触发来源：cron jobs、webhook、Gmail Pub/Sub、内存溢出提醒等。

### 8.14 OpenClaw 为什么强—— 总结

与 Claude Code/Codex 的"编码专精"不同，OpenClaw 的核心竞争力是**通用性和生态**：

1. **真正的多平台**

---

   - 26+ 渠道（WhatsApp/WeChat/Telegram/Discord/Slack...）
   - 桌面 + 移动 + Web
   - Gateway 守护进程 + 配套 App

2. **成熟的子代理架构**
   - Native subagent（内部）+ ACP harness（外部编码 agent）
   - push-based 完成通知（不用轮询）
   - 深度限制 + 孤儿恢复

3. **精细的工具策略**
   - 7 层策略管道（profile → provider → global → agent → group → sender）
   - 每层可 allow/deny/passthrough
   - 插件组支持

4. **Code Mode（独有）**
   - QuickJS WASI 沙箱内执行 JS/TS
   - 模型可以写代码并直接运行
   - 等待/让步机制

5. **模型 Fallback**
   - 认证轮换（同 provider 多 profile）
   - 冷却探测
   - 压缩后重试
   - 1,995 行的完整 fallback 系统

6. **技能生态**
   - ClawHub 市场（5,400+ 技能）
   - Skill Workshop（模型自创技能）
   - 安全审查 + 隔离

7. **MIT 开源**
   - 完全可商用
   - 代码量巨大（1.6GB+）
   - 活跃社区

### 8.15 对我们产品的集成启示

**应该学习的：**

| 设计 | OpenClaw 做法 | 我们应该怎么做 |
|------|----------------|----------------|
| 渠道系统 | 26+ 渠道 + Gateway | 先做 WeChat + Telegram + Web，架构预留扩展 |
| 子代理 | Native + ACP 双模式 | 学习 ACP 模式（让 Claude Code/Codex 作为编码子代理） |
| 工具策略 | 7 层管道 | 简化为 4 层（profile → agent → group → runtime），但保留可扩展性 |
| Code Mode | QuickJS WASI 沙箱 | 如果需要沙箱代码执行，可借鉴 |
| 模型 Fallback | 认证轮换 + 冷却探测 | 学习认证轮换，适合我们的 NVIDIA NIM 多 key 场景 |
| 技能系统 | 模型自创 + 市场 | 学习 Skill Workshop，让模型能自建技能 |

**应该超越的：**

| 维度 | OpenClaw 限制 | 我们的超越方向 |
|------|---------------|---------------|
| 定位 | 通用助手，编码能力靠 ACP | 通用 + 编码双模式，编码能力自建 |
| 编码 | 依赖外部 ACP（Claude Code/Codex） | 内建编码模式，不依赖外部工具 |
| 记忆 | 基础会话记忆 | 五层记忆系统 + IEH 知识库 |
| 模型路由 | 基础 fallback | 智能路由（任务类型 → 最优模型） |
| UI | 终端 + Web | 原生 App 体验 |
| 复杂度 | 1.6GB 代码量，极重 | 轻量化，先 MVP 再扩展 |

**可以直接用的（MIT 开源）：**
- 工具策略管道设计思路
- 子代理 spawn/yield 模式
- 认证轮换机制
- Compaction 指令模板
- 渠道抽象层设计

---

---


## 九、三大竞品源码核心架构对比（Claude Code / Codex / OpenClaw）

> 注：本章仅覆盖三家有源码分析的产品。完整的六家产品对比（含 Hermes、WorkBuddy、Marvis）见第十二章 12.9 节。

| 维度 | Claude Code（泄露源码） | Codex CLI（Apache-2.0） | OpenClaw（MIT） |
|------|------------------------|------------------------|-----------------|
| **定位** | Coding 专精 | Coding 专精 | 通用 AI 助手 |
| **语言** | TypeScript | Rust | TypeScript |

---

| **规模** | 单一 agent | 单一 CLI | Gateway + 多 agent |
| **许可证** | 自定义（非开源） | Apache-2.0 | MIT |
| **⭐** | N/A（官方） | 95,854 | 381,947 |
| **核心循环** | while(true) 7层 | 标准工具循环 | 嵌入式 runner + Lane 队列 |
| **工具数** | 38+ | 基础 CLI 工具 | 25+ |
| **权限维度** | 6 种模式 + 双阶段分类器 | 3 维度交叉（48 种组合） | 7 层策略管道 |
| **沙箱** | 实现不明 | 跨平台（Seatbelt/Bubblewrap/ACL） | Docker/SSH/OpenShell |
| **上下文压缩** | 3 层（micro+auto+memory） | 基础压缩 | 自适应 chunk + identifier 保留 |
| **多 Agent** | 3 层（subagent→teammate→swarm） | 单 agent | Native + ACP 双模式 |
| **模型支持** | 仅 Claude | OpenAI（gpt 系列） | 任意模型/提供商 |
| **渠道** | 终端 CLI | 终端 CLI | 26+ 渠道 |
| **Code Mode** | 无 | 无 | QuickJS WASI 沙箱 |
| **技能系统** | 内置技能 + 技能发现 | 无 | Skill Workshop + ClawHub 市场（5400+） |
| **错误恢复** | 5 种策略 | 基础重试 | 认证轮换 + 压缩恢复 + 空响应处理 |
| **记忆** | Session Memory + "做梦" | 无持久记忆 | 基础会话记忆 |

**我们的产品定位（融合三者优势）：**

```
通用 Agent（OpenClaw 生态）
    + 编码专精（Claude Code 工作流 + Codex 权限设计）
    + 多模型路由（三者都缺的）
    + 五层记忆系统（超越三者）
    + 开源（MIT 或 Apache-2.0）
```

---

---


# 第三部分：骨架平台 + 闭源产品 + 完整对比

> Hermes Agent 源码分析（产品骨架）、WorkBuddy/Marvis 逆向分析（闭源竞品）、六大 Agent 完整对比


## 十、Hermes Agent 源码深度分析（骨架平台）

> **信息来源：** `NousResearch/hermes-agent`，⭐210,273，MIT License，完全开源可商用。Python 主体，465MB+ 代码量。这是我们产品的骨架——直接 fork 扩展，而非从零搭建。

### 10.1 项目概况

| 属性 | 值 |
|------|-----|
| 仓库 | `NousResearch/hermes-agent` |
| Stars | 210,273（截止 2026-07-07） |
| Forks | 38,496 |
| License | **MIT**（完全开源可商用，可 fork 二开） |
| 主语言 | Python |
| 代码量 | 465MB+（含 Gateway、Platform SDK、Tools 全家桶） |
| 架构 | Gateway + Agent Core + Tool SDK + Platform SDK |
| 默认分支 | main |

### 10.2 整体架构

```
┌─────────────────────────────────────────────────┐
│                   Platforms                      │
│  Weixin │ WhatsApp │ Signal │ QQ │ Discord │ ...  │
│          (gateway/platforms/*.py)               │
├─────────────────────────────────────────────────┤
│                   Gateway                        │
│  session.py (100KB) │ run.py (971KB)             │
│  stream_consumer │ slash_commands (216KB)        │
│  delivery │ mirror │ pairing │ kanban            │
├─────────────────────────────────────────────────┤
│                Agent Core                        │
│  conversation_loop.py │ prompt_builder.py        │
│  system_prompt.py │ context_compressor.py       │
│  tool_executor.py │ delegate_tool.py             │
│  credential_pool.py │ error_classifier.py       │
│  memory_manager.py │ moa_loop.py                │
├─────────────────────────────────────────────────┤
│               Transports (API 抽象)               │
│  chat_completions │ anthropic │ bedrock │ codex   │
│  codex_app_server │ hermes_tools_mcp_server      │
├─────────────────────────────────────────────────┤
│                Tool SDK                          │
│  50+ 内置工具 (100KB-200KB 每个)                   │
│  browser_tool │ delegate_tool │ file_tools        │
│  code_execution │ image_gen │ discord │ cron       │
│  skills_hub (154KB) │ skill_tools                │
└─────────────────────────────────────────────────┘
```

### 10.3 Agent 循环（conversation_loop.py — 1,200+ 行）

Hermes 的 agent 循环比 Claude Code 和 Codex 都复杂得多，因为它是通用 agent + gateway 双重角色。

**核心循环结构（run_conversation 函数，518行开始）：**

```
while (api_call_count < max_iterations AND budget > 0) OR grace_call:
    1. 检查中断请求（用户发新消息）
    2. 消耗 iteration budget
    3. step_callback（Gateway 钩子：agent:step 事件）
    4. /steer 注入（用户在模型思考时发送的实时指令）
    5. 构建消息：
       a. 注入外部记忆 prefetch 内容（memory manager）
       b. 注入插件 pre_llm_call 上下文
       c. 复制 reasoning_content 到 API 消息
       d. 修复 role alternation 违规
       e. 序列化 tool_call JSON（去空白、排序 key → KV cache 友好）
       f. 清除 surrogate 字符（防 Ollama 崩溃）
    6. Pre-API 压缩检查：
       - 计算预估 token 数
       - should_compress() → 调用 _compress_context()
       - 最多 3 次压缩尝试
       - 压缩后 reset retry 状态
    7. 速率限制守卫（Nous Portal RPH 检测）
    8. API 调用（内层 retry 循环，最多 _api_max_retries 次）
       - Nous 速率限制 → 切换 fallback
       - 构建 api_kwargs（含 middleware 处理）
       - pre_api_request 插件钩子
       - Claude prompt caching 注入
       - 降级孤立 tool results / 补齐缺失 results
       - 去除纯 thinking 的 assistant turn
       - 发送 API 请求
    9. 响应处理：
       a. 流式/非流式解析
       b. tool_calls 并行执行（read-only 并发，write 串行）
       c. tool_call 修复（损坏的 JSON 参数）
       d. 结果注入 messages
    10. 空响应/截断响应恢复
    11. 压缩检查（post-response）
    12. 最终响应提取
```

**与 Claude Code / Codex 循环对比：**

| 维度 | Claude Code | Codex | Hermes |
|------|------------|-------|--------|
| 循环入口 | query() 67KB | run() | run_conversation() ~700行有效代码 |
| 最大迭代 | 未公开 | 未公开 | max_iterations（可配）+ iteration_budget |
| 中断机制 | 无 | 无 | `_interrupt_requested` 实时中断 |
| /steer 实时指令 | 无 | 无 | ✅ 模型思考时注入用户指令 |
| Pre-API 压缩 | 无（只在 overflow 时） | 无 | ✅ 发请求前主动压缩 |
| 速率限制守卫 | 无 | 无 | ✅ Nous RPH + 自动 fallback |
| 插件钩子 | 无 | 无 | pre_api_request, post_response, step |
| 流式支持 | ✅ | ✅ | ✅ + stream_consumer（88KB） |
| KV Cache 优化 | 无 | 无 | ✅ JSON 排序 key + 空白标准化 |
| Prompt Caching | ✅ Anthropic | ✅ | ✅ Anthropic + 自动检测 |
| Credential 轮换 | 无 | 无 | ✅ 多 key 池 + 自动刷新 |

### 10.4 三层 System Prompt（system_prompt.py）

Hermes 将 system prompt 拆分为三层，**会话期间只构建一次并缓存**：

| 层 | 内容 | 稳定性 |
|----|------|--------|
| **Stable** | SOUL.md（身份）+ 工具引导 + 技能索引 + 环境检测 + 模型特定引导 | 会话级缓存 |
| **Context** | AGENTS.md / .cursorrules / CLAUDE.md 等项目文件 + system_message | 会话级缓存 |
| **Volatile** | 记忆快照 + 用户画像 + 外部记忆 provider 块 + 时间戳 | 每次注入 |

**关键设计：**
- `build_system_prompt_parts()` 返回 `{stable, context, volatile}` 三个独立字符串
- 最终拼接为单条 system message 发送
- **绝不 mid-session 重新渲染** → 保证上游 prompt cache 前缀稳定
- SOUL.md 是核心身份文件（类似 OpenClaw 的 soul.md）
- Context 文件按优先级加载：`_CLAUDE.md > AGENTS.md > CLAUDE.md > .cursorrules`
- 模型特定引导：
  - Google 模型 → `GOOGLE_MODEL_OPERATIONAL_GUIDANCE`
  - OpenAI/Codex/Grok → `OPENAI_MODEL_EXECUTION_GUIDANCE`
  - 所有模型 → `TOOL_USE_ENFORCEMENT_GUIDANCE` + `PARALLEL_TOOL_CALL_GUIDANCE`

**Context 占用分析（context_breakdown.py — Cursor 风格）：**
```
System Prompt     ████████░░░░░░░░░░░░  基础身份+引导
Tool Definitions  ██████░░░░░░░░░░░░░░  50+ 内置工具 schema
Rules             ████░░░░░░░░░░░░░░░░  项目规则文件
Skills            ███░░░░░░░░░░░░░░░░░  技能索引
MCP               ██░░░░░░░░░░░░░░░░░░  MCP 工具定义
Memory            ██░░░░░░░░░░░░░░░░░░  用户+Agent记忆
Conversation      ████████████████████░░  对话历史（最大）
```

### 10.5 上下文压缩系统（context_compressor.py — 3,046 行）

Hermes 的压缩系统是最复杂的——**三级压缩触发点 + 边界感知 + 头尾保护**。

**三级触发点：**
1. **Turn Prologue（对话开始前）** — `turn_context.py` 中的 `build_turn_context()`
2. **Pre-API（API 调用前）** — 循环内 `should_compress()` 检查
3. **Post-Response（API 响应后）** — 溢出错误 / token 压力检查

**压缩策略（Claude Code 的超集）：**

```python
class ContextCompressor(ContextEngine):
    def should_compress(self, prompt_tokens) -> bool:
        # 基于 threshold_tokens（动态计算的阈值）
        # 含 summary LLM 冷却 + 反抖动保护
    
    def compress(self, messages, current_tokens, focus_topic, force):
        # 1. 保护头部：protect_first_n（最近 N 轮不压缩）
        # 2. 保护尾部：ensure_last_assistant_in_tail + last_user_in_tail
        # 3. 边界对齐：align_boundary_forward + align_boundary_backward
        #    （不切断 tool_call/tool_result 配对）
        # 4. 摘要生成：_generate_summary()（LLM 摘要）
        # 5. 静态回退：_build_static_fallback_summary()（LLM 不可用时）
        # 6. 路径记忆：记住被压缩的文件路径名
```

**与 Claude Code 压缩对比：**

| 特性 | Claude Code | Hermes |
|------|------------|--------|
| 触发点 | 1（overflow 时） | 3（prologue + pre-API + post-response） |
| 摘要 LLM | ✅ | ✅ |
| 静态回退 | ✅ | ✅（保留文件路径 + 工具名） |
| 头部保护 | ✅ | ✅（`protect_first_n` 可配置） |
| 尾部保护 | 仅最后 assistant | 最后 assistant + 最后 user + turn pair 对齐 |
| 边界对齐 | 无 | ✅（不切断 tool_call/result 配对） |
| 反抖动 | 冷却期 | 冷却期 + 失败计数 + 预算回收 |
| Token 阈值 | 固定百分比 | 动态计算（基于 context_length - output 预留） |
| Max 压缩次数 | 无限制 | 3 次/turn（硬上限） |
| 会话轮换 | ✅ | ✅（session rotation + in-place compaction） |

### 10.6 工具系统

**工具数量：50+ 内置工具**

| 工具 | 大小 | 说明 |
|------|------|------|
| browser_tool.py | 201KB | 浏览器自动化（Playwright） |
| delegate_tool.py | 148KB | 子代理委派 |
| file_operations.py | 103KB | 文件操作底层 |
| file_tools.py | 98KB | 文件工具上层 |
| code_execution_tool.py | 76KB | 代码执行（Python） |
| cronjob_tools.py | 53KB | 定时任务 |
| image_generation_tool.py | 64KB | 图像生成 |
| discord_tool.py | 38KB | Discord 集成 |
| browser_supervisor.py | 61KB | 浏览器监督 |
| approval.py | 130KB | 权限审批系统 |
| skills_hub.py | 154KB | 技能市场 |
| skill_tools.py | 60KB | 技能管理 |
| skills_guard.py | 42KB | 技能安全 |
| checkpoint_manager.py | 60KB | 断点续传 |
| kanban_watchers.py | 63KB | 看板系统 |
| stream_consumer.py | 88KB | 流式输出 |
| fuzzy_match.py | 37KB | 模糊匹配（文件编辑用） |

**工具执行（tool_executor.py — 1,647 行）：**
- **并行执行**：`execute_tool_calls_concurrent()` — 只读工具并发，写入工具串行
- **串行执行**：`execute_tool_calls_sequential()` — 兼容模式
- **超时控制**：可配置的 per-tool 和全局超时
- **工具预算**：`BudgetConfig` 限制 tool call 次数和字符数
- **会话持久化**：每个 tool call 后自动 flush session DB

### 10.7 子代理系统（delegate_tool.py — 3,446 行）

Hermes 的子代理比 Claude Code 和 Codex 都更成熟：

```
父 Agent
├── Leaf 子代理（max_concurrent_children 最多 3 个）
│   ├── 独立对话、终端、工具集
│   ├── 无法再委派（max_spawn_depth=1）
│   ├── 完成后结果自动注入父对话
│   └── 后台运行，父不阻塞
└── Orchestrator 子代理（可扩展为多级）
    ├── 可再 spawn 子子代理
    └── max_spawn_depth 可配置
```

**子代理配置维度：**
| 维度 | 说明 |
|------|------|
| `max_concurrent_children` | 并发子代理上限（默认 3） |
| `max_spawn_depth` | 嵌套深度（默认 1 = 叶子级别） |
| `orchestrator_enabled` | 是否允许编排者角色 |
| `toolsets` | 子代理工具集限制 |
| `inherit_mcp_toolsets` | 是否继承父级 MCP 工具 |
| `child_timeout` | 子代理超时 |
| `model` | 可选的 per-child 模型覆盖 |

**子代理创建流程（`_build_child_agent`）：**
1. 构建独立 system prompt（`_build_child_system_prompt`）
2. 继承父级 credential pool 或覆盖
3. 创建独立终端会话
4. 设置进度回调（`_build_child_progress_callback`）
5. 支持后台运行 + 完成通知
6. 摘要预算控制（`_parent_summary_char_budget`）

### 10.8 凭证池系统（credential_pool.py — 2,385 行）

**这是 Hermes 独有的核心竞争力**——Claude Code 和 Codex 都没有多凭证轮换。

```
CredentialPool
├── PooledCredential（单个凭证）
│   ├── api_key
│   ├── base_url
│   ├── priority（优先级）
│   ├── source（环境变量 / OAuth / 设备码 / 文件）
│   ├── exhausted_until（排除截止时间）
│   └── lease（租约锁）
├── select() → 选最高优先级的可用凭证
├── mark_exhausted_and_rotate() → 标记+切换
├── try_refresh_current() → 尝试刷新（OAuth token）
└── 持久化到 ~/.hermes/credentials/
```

**凭证来源：**
1. 环境变量（`HERMES_OPENAI_API_KEY` 等）
2. 单例变量（`openai_api_key`）
3. OAuth 设备码（Anthropic/Codex/xAI）
4. 自定义 provider 池（`custom_providers`）
5. 凭证文件（`~/.hermes/credentials/`）

**刷新机制：**
- Anthropic OAuth → `anthropic_credentials.yaml` 同步
- Codex OAuth → auth store 同步
- xAI OAuth → auth store 同步
- Nous Portal → auth store 同步
- **per-entry 冷却**：同一凭证连续刷新失败 N 次后跳过
- **TTL 排除**：429/403 后设置 exhausted_until

### 10.9 错误分类与恢复（error_classifier.py — 1,599 行）

**20+ 错误类型 + 结构化恢复策略：**

```python
class FailoverReason(Enum):
    # 认证
    auth = "auth"                    # 401/403 → 刷新/轮换凭证
    auth_permanent = "auth_permanent"  # 刷新后仍失败 → 放弃
    
    # 计费
    billing = "billing"               # 402 → 立即轮换
    rate_limit = "rate_limit"         # 429 → 退避+轮换
    upstream_rate_limit = "upstream_rate_limit"  # 上游模型限流 → 切模型
    
    # 服务端
    overloaded = "overloaded"          # 503 → 退避
    server_error = "server_error"      # 500/502 → 重试
    
    # 传输
    timeout = "timeout"               # 超时 → 重建 client + 重试
    ssl_cert_verification = "ssl_cert_verification"  # TLS → 快速失败
    
    # 上下文
    context_overflow = "context_overflow"  # 太长 → 压缩
    payload_too_large = "payload_too_large"  # 413 → 压缩
    image_too_large = "image_too_large"  # 图片太大 → 缩小
    
    # 模型
    model_not_found = "model_not_found"  # 404 → 切模型
    content_policy_blocked = "content_policy_blocked"  # 安全过滤 → 不重试
    
    # 提供商特定
    thinking_signature = "thinking_signature"  # Anthropic thinking 签名
    long_context_tier = "long_context_tier"  # Anthropic 1M 上下文限制
    llama_cpp_grammar_pattern = "llama_cpp_grammar_pattern"  # json-schema 语法
    ...
```

**恢复策略映射：**
- `retryable=True` → 可重试（退避 + 凭证轮换）
- `should_compress=True` → 压缩上下文
- `should_rotate_credential=True` → 切换凭证
- `should_fallback=True` → 切换提供商

### 10.10 MoA（Mixture of Agents）系统（moa_loop.py — 1,074 行）

**Hermes 独有**——参考模型 + 聚合模型架构：

```
用户请求
  ↓
[参考模型 1] ──→ [参考模型 2] ──→ [参考模型 N]
  ↘            ↘             ↙
   ──→ context 聚合 ←──
            ↓
        [聚合模型] ← 最终响应
```

**关键函数：**
- `aggregate_moa_context()` — 收集参考模型输出，注入用户消息
- `_run_references_parallel()` — 并行运行参考模型
- `_preset_temperature()` — 参考模型和聚合模型的温度控制
- `MoAChatCompletions` — OpenAI 兼容的 MoA wrapper

### 10.11 Gateway 多平台架构

**Gateway 核心（run.py — 971KB）：**
- 会话管理（session.py — 100KB）
- 流式输出分发（stream_consumer.py — 88KB）
- 斜杠命令（slash_commands.py — 216KB）
- 配送路由（delivery.py — 22KB）
- 频道目录（channel_directory.py — 17KB）
- 配对系统（pairing.py — 23KB）
- 看板监控（kanban_watchers.py — 63KB）

**支持平台（gateway/platforms/）：**
| 平台 | 文件 | 说明 |
|------|------|------|
| Weixin/WeChat | weixin.py | 微信（当前使用） |
| WhatsApp | whatsapp_cloud.py + whatsapp_common.py | WhatsApp Cloud API |
| Signal | signal.py + signal_format.py | Signal 协议 |
| QQ Bot | qqbot/ | QQ 机器人 |
| Discord | （通过 discord_tool.py） | Discord |
| 元宝 | yuanbao.py + yuanbao_proto.py | 腾讯元宝 |
| 飞书文档 | feishu_doc_tool.py + feishu_drive_tool.py | 飞书文档/网盘 |
| Webhook | webhook.py | 通用 Webhook |
| API Server | api_server.py | REST API |

**Transport 抽象层（agent/transports/）：**
| Transport | 文件 | 说明 |
|-----------|------|------|
| Chat Completions | chat_completions.py (33KB) | OpenAI 兼容 API（最大覆盖） |
| Anthropic Native | anthropic.py (10KB) | Anthropic 直连 |
| AWS Bedrock | bedrock.py (5KB) | AWS 托管 |
| Codex Responses | codex.py (22KB) | OpenAI Codex API |
| Codex App Server | codex_app_server.py + codex_app_server_session.py | Codex 子进程 |
| MCP Server | hermes_tools_mcp_server.py | Hermes 作为 MCP Server |

### 10.12 技能市场（skills_hub.py — 4,110 行）

**七大技能来源：**

| 来源 | 类名 | 说明 |
|------|------|------|
| GitHub 仓库 | `GitHubSource` | 直接从 GitHub 仓库安装技能 |
| Well-Known | `WellKnownSkillSource` | 知名索引站 |
| URL 直装 | `UrlSource` | 直接从 URL 安装 |

---

| Skills.sh | `SkillsShSource` | Skills.sh 市场 |
| ClawHub | `ClawHubSource` | ClawHub 市场（OpenClaw 生态） |
| Claude Marketplace | `ClaudeMarketplaceSource` | Claude 技能市场 |
| LobeHub | `LobeHubSource` | LobeHub agent 目录 |
| Browse.sh | `BrowseShSource` | Browse.sh 目录 |
| Hermes Index | `HermesIndexSource` | Hermes 官方索引 |

**技能安全：**
- `skills_guard.py`（42KB）— 技能审计和安全检查
- `skills_ast_audit.py`（5KB）— AST 级代码审计
- `quarantine/` — 隔离区（先审查再安装）
- `skills_provenance.py` — 来源追踪

### 10.13 记忆系统（memory_manager.py — 1,087 行）

```python
class MemoryManager:
    providers: List[MemoryProvider]  # 可插拔的 provider 列表
    
    def build_system_prompt(self) -> str        # 构建记忆系统提示
    def prefetch_all(self, query) -> str          # 预取记忆（API 调用前）
    def sync_all(...)                            # 写入所有 provider
    def handle_tool_call(self, tool_name, args)   # 处理记忆工具调用
    def on_turn_start(self, turn_number, message) # 每个 turn 开始时
    def on_session_end(self, messages)             # 会话结束时
    def on_memory_write(self, ...)                # 记忆写入回调
    def on_delegation(self, task, result)          # 子代理记忆同步
```

**记忆类型（两个 store）：**
1. **memory store** — Agent 自己的笔记（环境、约定、教训）
2. **user store** — 用户画像（名字、偏好、身份）

**Context Scrubbing：**
- `StreamingContextScrubber` — 流式输出时实时过滤记忆敏感内容
- 防止记忆内容泄漏到终端输出

---

---


> Hermes Agent 源码分析（产品骨架）、WorkBuddy/Marvis 逆向分析（闭源竞品）、六大 Agent 完整对比


### 10.14 与其他三家的核心差异

| 维度 | Claude Code | Codex | OpenClaw | **Hermes** |
|------|------------|-------|----------|-----------|
| 定位 | 编码专精 | 编码沙箱 | 通用助手 | **通用 + 编码** |
| 语言 | TypeScript | Rust | TypeScript | **Python** |
| 许可证 | 自定义（非开源） | Apache-2.0 | MIT | **MIT** |
| 平台 | CLI only | CLI only | 26+ 渠道 | **10+ 平台** |
| 多凭证 | ❌ | ❌ | ❌ | **✅ 凭证池** |
| MoA | ❌ | ❌ | ❌ | **✅ 混合专家** |
| 错误分类 | 双阶段分类器 | 简单重试 | 简单重试 | **20+ 分类** |
| 上下文压缩 | 1 级触发 | 无 | 3 级（micro/auto/session） | **3 级 + 边界保护** |
| 子代理 | 3 层 | 无 | 双模式 | **可配置层级** |
| Prompt Caching | ✅ Anthropic | ❌ | ❌ | **✅ Anthropic + auto** |
| KV Cache | ❌ | ❌ | ❌ | **✅ key 排序** |
| 技能市场 | 内置技能 | ❌ | ClawHub 5.4K | **9 大来源** |
| /steer | ❌ | ❌ | ❌ | **✅ 实时指令** |
| Token 预算 | ✅ | ✅ | ❌ | **✅ 动态计算** |

### 10.15 作为骨架的优势与待改进

**直接可用的核心能力：**
- ✅ Gateway 多平台（已跑在微信上）
- ✅ 凭证池 + 自动轮换 + OAuth 刷新
- ✅ 子代理系统（并行、后台、可配置）
- ✅ 50+ 内置工具
- ✅ 三层 System Prompt + Prompt Cache 稳定
- ✅ 三级上下文压缩（最复杂的压缩系统）
- ✅ 20+ 错误分类 + 结构化恢复
- ✅ MoA 混合专家系统
- ✅ 9 大技能来源 + 安全审计
- ✅ 会话持久化（SQLite）+ session_search
- ✅ 流式输出 + 多种 consumer

**待增强方向（我们产品要做的事）：**
- 🔧 编码专精模式（Claude Code 工作流：写→测→修→循环）
- 🔧 跨平台沙箱（Codex 的 Seatbelt/Bubblewrap）
- 🔧 多维度权限系统（Codex 的 审批×沙箱×协作）
- 🔧 Go 中间层（API 网关 + 高并发）
- 🔧 Rust 底层（token 解析 + 性能瓶颈）
- 🔧 智能模型路由（基于任务类型自动选模型）
- 🔧 订阅计划 + 计费监控
- 🔧 UI/UX 重做（工业粗犷风 + 毛玻璃）

---

---


## 十一、WorkBuddy / CodeBuddy 分析（腾讯闭源产品）

> **信息来源：** WorkBuddy/CodeBuddy 是腾讯云的闭源 AI Agent 产品，无公开源码。本节基于社区逆向工程（codebuddy2openai 转换器、workbuddy-remote 桥接项目）+ 官网公开信息 + 第三方 Skill 生态 + 社区分析文章。**不能作为代码参考**，但可作为产品设计参考。

### 11.1 产品概况

| 属性 | 值 |
|------|-----|
| 产品名 | Tencent Cloud CodeBuddy / WorkBuddy |
| 厂商 | 腾讯（Tencent） |
| 定位 | AI Code Editor + 通用 Agent 平台 |
| 源码 | **闭源**（Electron 桌面应用 + Web IDE） |
| License | **不可商用参考**（腾讯版权） |
| 官网 | https://www.codebuddy.ai/ (国际版) / https://www.codebuddy.cn/ (国内版) |
| 后端 | `copilot.tencent.com`（腾讯云基础设施） |
| 计费 | 腾讯云计费体系（订阅制） |
| 技术栈 | Electron + React（前端）+ 腾讯云后端 |

### 11.2 产品定位

CodeBuddy/WorkBuddy 实际上是**同一个产品的两个名称**：
- **CodeBuddy** — 国际品牌名（面向海外开发者）
- **WorkBuddy** — 国内品牌名（面向中文用户）
- 两者的后端相同（`copilot.tencent.com`），只是域名不同（`codebuddy.ai` vs `codebuddy.cn`）

官方描述：
> "Tencent Cloud CodeBuddy is a next-generation AI Code Editor. Powered by the Tencent Yuanbao Code Large Model, it provides code completion, error diagnosis, technical Q&A, and performance optimization. Supporting mainstream programming languages, it improves coding efficiency by 90% and reduces code error rates by 35%."

**注意**：虽然官方定位是"AI Code Editor"，但实际上 WorkBuddy 已经扩展为**通用 Agent 平台**——支持 Skill 系统、Agent（专家角色）、多模型协作、任务管理等。社区已用它写教程、做 CRM、生成图片视频等非编码任务。

### 11.3 后端架构（从 codebuddy2openai 逆向）

```
桌面客户端（Electron）
    │
    │  CDP (Chrome DevTools Protocol, port 9333)
    ▼
┌─────────────────────────────────────────┐
│  本地 Bridge（bridge-server.mjs）         │
│  HTTP 静态资源服务 + WebSocket 转发       │
└─────────────────────────────────────────┘
    │
    │  HTTPS + Bearer Token
    ▼
┌─────────────────────────────────────────┐
│  copilot.tencent.com（腾讯云后端）       │
│                                          │
│  POST /v2/chat/completions  ← 标准 OpenAI │
│  GET  /v2/plugin/auth/token/refresh      │
│                                          │
│  可用模型：                               │
│  - glm-5.2 / glm-5.1 / glm-5v-turbo     │
│  - kimi-k2.7 / kimi-k2.6 / kimi-k2.5    │
│  - deepseek-v4-pro / deepseek-v4-flash   │
│  - minimax-m3-pay / hy3-preview-agent    │
│  - auto（自动选择）                       │
└─────────────────────────────────────────┘
```

**关键发现：**

1. **后端是标准 OpenAI Chat Completions 协议** — `POST /v2/chat/completions`，原生支持 `tools` / `tool_calls` / SSE 流式。这是最大的逆向发现——意味着腾讯的 Agent 编排可能和 OpenAI 标准高度兼容。

2. **鉴权系统** — 读取本地 auth 文件（`~/Library/Application Support/CodeBuddyExtension/Data/Public/auth/*.info`），包含 `accessToken`、`refreshToken`、`expiresAt`、`enterpriseId` 等。Token 过期时调 `/v2/plugin/auth/token/refresh` 刷新。

3. **多模型支持** — 10+ 模型（GLM 系列、Kimi 系列、DeepSeek 系列、MiniMax、混元），含 `auto` 自动选择模式。

4. **Function Calling 原生支持** — 后端原生处理 tools/tool_calls，无需 prompt 注入或文本解析。

### 11.4 Skill 系统（从第三方 Skill 分析）

**Skill 格式（与 OpenClaw 兼容）：**

```yaml
---
name: "agnes-generator"
description: "使用 Agnes AI 生成图片和视频..."
agent_created: true
---
# SKILL.md 正文（Markdown）
```

**Plugin 格式（WorkBuddy 扩展）：**

```json
{
  "name": "cordys-crm",
  "version": "1.2.0",
  "expertType": "agent",
  "agentName": "cordys-crm",
  "displayName": { "en": "...", "zh": "..." },
  "displayDescription": { "en": "...", "zh": "..." },
  "agents": ["./agents/cordys-crm.md"],
  "skills": ["./skills/cordys-crm"],
  "categoryId": "07-SalesCommerce",
  "defaultInitPrompt": { "zh": "...", "en": "..." },
  "quickPrompts": [...],
  "tags": [...],
  "avatar": "avatars/expert.png"
}
```

**关键特性：**
- SKILL.md 前置 YAML frontmatter + Markdown 正文（与 OpenClaw/Hermes 格式一致）
- Plugin 系统额外支持：Agent 定义、分类目录、初始化 prompt、快捷提示、双语显示、头像
- 插件结构：`.workbuddy-plugin/plugin.json` + `agents/` + `skills/` + `avatars/`
- **兼容 OpenClaw 的 SKILL.md 格式** — 社区标注"OpenClaw/WorkBuddy 兼容"

### 11.5 Agent（专家角色）系统

从 Plugin 格式可以推断：
- **Agent = 专家角色** — 每个 plugin 可以定义一个 agent（`expertType: "agent"`）
- **Agent 定义** = Markdown 文件（`agents/cordys-crm.md`）— 可能包含角色设定、指令、工具绑定
- **初始化 Prompt** — `defaultInitPrompt` 定义用户首次打开时的引导语
- **快捷提示** — `quickPrompts` 提供常用操作的快速入口
- **分类目录** — `categoryId: "07-SalesCommerce"` 暗示有一套标准分类体系

### 11.6 多模型协作

从可用模型列表可以推断：
- **10+ 模型可选**：GLM（智谱）、Kimi（月之暗面）、DeepSeek（深度求索）、MiniMax、混元（腾讯自研）
- **auto 模式**：自动根据任务选择最优模型
- **模型组合**：用户可以手动切换模型，推测也支持 per-task 模型路由

### 11.7 与其他产品的对比

| 维度 | Hermes | OpenClaw | Claude Code | Codex | **WorkBuddy** |
|------|--------|----------|-------------|-------|---------------|
| 定位 | 通用 Agent | 通用助手 | 编码专精 | 编码沙箱 | **编码 + 通用** |
| 源码 | MIT 开源 | MIT 开源 | 泄露（非开源） | Apache-2.0 | **闭源** |
| 语言 | Python | TypeScript | TypeScript | Rust | **TypeScript (Electron)** |
| 平台 | 10+ 渠道 | 26+ 渠道 | CLI only | CLI only | **桌面 + Web** |
| 后端 | 多 provider | 多 provider | Anthropic | OpenAI | **腾讯云** |
| Skill 格式 | SKILL.md | SKILL.md | 无 | 无 | **SKILL.md（兼容 OpenClaw）** |
| Agent 角色 | 子代理 | 子代理 | 内置 | 无 | **专家角色（Plugin）** |
| 多模型 | ✅ 凭证池 | ✅ Fallback | ❌ | ❌ | **✅ 10+ 模型 + auto** |
| 计费 | 用户自付 | 用户自付 | 用户自付 | 用户自付 | **腾讯云订阅** |
| 可集成 | 直接 fork | 直接 fork | 仅参考 | 可参考 | **不可参考（闭源）** |

### 11.8 对我们产品的启示

**可借鉴的设计（不涉及源码）：**

1. **Plugin 系统** — 比 SKILL.md 更完整的 Agent 打包格式：
   - 双语 displayName / displayDescription
   - 分类目录 + 标签
   - 初始化 Prompt + 快捷提示
   - Agent 定义 + Skill 绑定 + 头像
   - 版本号（可做自动更新）

2. **多模型 auto 模式** — 基于任务类型自动选模型，这个 Hermes 还没有

3. **专家角色概念** — 每个 Plugin 是一个"专家"，不是纯工具。用户可以理解为"请了一个 XX 领域的专家来帮忙"

4. **标准 OpenAI 协议后端** — 即便闭源，后端用的是标准协议，说明这个方向是对的

**不可借鉴：**
- ❌ 计费体系绑定腾讯云（无法中转，记忆中已确认）
- ❌ 闭源无法参考代码实现
- ❌ 绑定腾讯生态（企业微信、腾讯文档等）

### 11.9 WorkBuddy 的局限

1. **完全闭源** — 无法分析核心 Agent 循环、权限系统、上下文管理等
2. **绑定腾讯计费** — 用腾讯自己的计费体系，new-api 无法中转（记忆中已确认）
3. **生态封闭** — 虽然支持标准 SKILL.md，但插件分发走腾讯自己的市场
4. **模型受限** — 只能用腾讯后端的模型，无法自选 provider
5. **无 CLI / API 模式** — 只能通过桌面客户端或 Web 使用
6. **无凭证池** — 一个账户一套模型，无法多 key 轮换

---

---


## 十二、Marvis 分析（腾讯闭源 + 开源复现 OpenMarvis）

> **信息来源：** Marvis 是腾讯的闭源 macOS 桌面 AI 助手，无公开源码。本节结合：① OpenMarvis（⭐3，Apache 2.0 开源复现，完全对标 Marvis 行为规范）② Marvis 官网公开信息 ③ 社区逆向分析。Marvis 闭源部分不可参考代码，但 OpenMarvis 是 Apache 2.0 完全开源可参考。

### 12.1 产品概况

| 属性 | 值（Marvis 原版） | 值（OpenMarvis 开源复现） |
|------|------------------|------------------------|
| 产品名 | Marvis | OpenMarvis |
| 厂商 | 腾讯（Tencent） | 社区开源 |
| 定位 | macOS 桌面 AI 助手 | macOS 桌面 AI 助手（对标 Marvis） |
| 源码 | **闭源** | **Apache 2.0（完全开源）** |
| 官网 | https://marvis.app | https://github.com/george351419-sys/OpenMarvis |
| 计费 | 腾讯云计费体系（订阅制） | 用户自带 LLM API Key |
| 技术栈 | 未知（推测 Electron） | FastAPI + Next.js 14 + Electron + SQLite |
| 平台 | macOS + Windows + Android 模拟器 | macOS（Windows 计划中） |

### 12.2 核心架构（从 OpenMarvis 逆向推断 Marvis 设计）

```
┌──────────────────────────────────────────────────────────────────┐
│  前端层（Next.js 14 + Electron 桌面客户端）                        │
│                                                                    │
│  /          首页            ChatStream               Zustand       │
│  /c/[id]    对话页          MessageBubble            useChat       │
│  /schedules 自动任务        TimelinePanel            useTimeline   │
│  /skills    技能广场        NotificationBell         useFilePreview│
├──────────────────────────────┬───────────────────────────────────┤
│  后端层（FastAPI + Python）   │  SSE 事件协议                    │
│                              │  thinking_delta / content_delta    │
│  MainAgent（总调度）          │  tool_call_start / tool_call_result│
│  ├── FileAgent（文件）       │  card / ask_user / sub_agent_*    │
│  ├── SearchAgent（搜索）     │  done / error                     │
│  ├── BrowserAgent（浏览器）  │                                   │
│  ├── ComputerAgent（系统）   │  基础设施                         │
│  └── AppAgent（第三方App）    │  APScheduler / SkillRegistry       │
│                              │  SecurityGate（三层防护）          │
│  工具层（30+ tools）          │                                   │
├──────────────────────────────┴───────────────────────────────────┤
│  数据层                                                          │
│  SQLite + FTS5（对话/记忆/任务/全文索引）+ 文件系统工作区          │
└──────────────────────────────────────────────────────────────────┘
```

### 12.3 四级调度架构

**Marvis/OpenMarvis 的核心创新：Main Agent → Sub Agent → Skill → Tool**

```
用户: "帮我整理这堆 PDF 并生成摘要"
    │
    ▼
MainAgent（总调度，装备所有工具）
    │  分析意图 → 路由到合适的 Sub Agent
    ▼
SubAgentFactory.create("file-agent")
    │  注入特定工具子集（文件+搜索工具）
    │  加载 file-agent 专属 System Prompt
    ▼
FileAgent.run()
    │  独立的 LLM 对话循环
    │  可能调用 Skill:
    ▼
SkillRunner("document_writer")
    │  只注入 manifest.allowed_tools 中的工具
    │  用 skill prompt 替换系统提示词
    ▼
Tool 执行（read_file / write_file / search_chunk...）
    │  每层都经过 SecurityGate 检查
    ▼
结果逐层返回 → MainAgent → 用户
```

**与 Hermes 子代理对比：**

| 维度 | Hermes 子代理 | Marvis/OpenMarvis 子代理 |
|------|--------------|------------------------|
| 架构 | 平级（leaf / orchestrator） | **层级**（Main → Sub → Skill → Tool） |
| 工具集 | 父级可限制 | **每层独立限制**（Sub Agent 有工具子集，Skill 有白名单） |
| System Prompt | 继承父级 | **每层独立**（Main 有主 prompt，Sub 有专属 prompt） |
| 并发 | ✅ 最多 3 个并发 | ❌ 串行调度 |
| 后台运行 | ✅ 后台 + 通知 | ❌ 同步等待 |
| Skill 集成 | 全局 skill_manage | **层级内嵌**（Skill 是 Sub Agent 的子层） |

### 12.4 安全模型（三级风险 + 三层守护）

**Marvis 的安全设计比 Hermes 简洁但有效：**

**三级风险分级：**

| 级别 | 场景 | 处理 |
|------|------|------|
| 🟢 低风险 | 读文件、搜索、创建新文件 | 直接执行，事后汇报 |
| 🟡 中风险 | 覆盖已有文件、修改配置、终止进程 | 告知影响后执行（用户主动要求）/ 强制确认（AI 自主提议） |
| 🔴 高风险 | 批量删除、清空目录、系统级写操作 | 必须弹出 ask_user 卡片，明确授权后执行 |

**三层守护链：**
```
用户输入 → CmdGuard（命令检测）→ PathGuard（路径检测）→ 工具执行
                                                          ↓
                                               CredentialGuard（日志脱敏）
```

| Guard | 职责 | 阻止内容 |
|-------|------|---------|
| **PathGuard** | 路径安全 | `/System` `/Library` `/usr` `/bin` `~/.ssh` `~/.aws` `.env` `../` |
| **CmdGuard** | 命令安全 | `rm -rf` `dd if=` `mkfs` `format` `base64 -d \| sh` 编码绕过 |
| **CredentialGuard** | 凭证脱敏 | `sk-` `AKID` `xoxb-` `ghp_` `AKIA` 等密钥前缀 |

**与 Codex / Hermes 安全系统对比：**

| 维度 | Codex | Hermes | Marvis |
|------|-------|--------|--------|
| 维度数 | 3（审批×沙箱×协作=48种） | 1（全局） | **2（风险级别×执行者意图）** |
| 风险分级 | 自动分类 | 手动配置 | **三级（🟢🟡🔴）** |
| 路径保护 | 沙箱隔离 | 无 | **PathGuard** |
| 命令保护 | 沙箱隔离 | 无 | **CmdGuard**（含编码绕过检测） |
| 凭证保护 | 无 | 无 | **CredentialGuard** |
| ask_user | 无 | 无 | **结构化确认卡片** |
| 沙箱 | ✅ 跨平台 | ❌ | ❌ |

### 12.5 Skill 系统

**Marvis/OpenMarvis 的 Skill = 受限工具白名单的子代理模板：**

```
skills/builtins/file-organizer/
├── manifest.yaml      # 名称、版本、allowed_tools、参数声明
└── prompt.md          # skill 专属系统提示词
```

**Skill manifest 示例：**
```yaml
name: file-organizer
version: "1.0"
description: 整理混乱文件夹
allowed_tools:
  - list_dir
  - read_file
  - write_file
  - delete
  - search_files
params:
  target_dir:
    type: string
    required: true
    description: 要整理的目标目录
```

**Skill 执行流程：**
1. MainAgent 调用 `use_skill("file_organizer", {target_dir: "..."})`
2. SkillRegistry 加载 manifest.yaml + prompt.md
3. SkillRunner 创建专用 AgentBase
4. 只注入 `allowed_tools` 中的工具
5. 用 skill prompt 替换系统提示词
6. 执行完毕返回 MainAgent

**与 Hermes / OpenClaw Skill 对比：**

| 维度 | Hermes | OpenClaw | Marvis/OpenMarvis |
|------|--------|----------|------------------|
| 格式 | SKILL.md（YAML+MD） | SKILL.md（YAML+MD） | **manifest.yaml + prompt.md** |
| 工具限制 | 无（全局工具） | 策略管道限制 | **✅ 白名单强制限制** |
| 嵌套 | 全局加载到 system prompt | discovery + loading | **层级内嵌（Skill 是 Sub Agent 子层）** |
| ask_user | 无 | 无 | **✅ Skill 内可弹确认卡片** |
| 参数化 | 无 | 无 | **✅ manifest 声明参数 + prompt 占位符** |

### 12.6 SSE 事件协议（前后端通信）

**Marvis/OpenMarvis 的前端通信比 Hermes 的 Gateway 更结构化：**

| 事件 | 数据 | 说明 |
|------|------|------|
| `thinking_delta` | `{text}` | 模型思考过程（extended thinking） |
| `content_delta` | `{text}` | 流式文字输出 |
| `tool_call_start` | `{call_id, name, args}` | 工具开始执行 |
| `tool_call_result` | `{call_id, ok, preview, error}` | 工具执行完成 |
| `card` | `{type, payload}` | **结构化卡片**（文件列表/图片画廊/ask_user） |
| `ask_user` | `{ask_id, title, form_type, options}` | **请求用户确认** |
| `sub_agent_start` | `{agent_id, agent_name}` | 子代理启动 |
| `sub_agent_end` | `{agent_id, status}` | 子代理完成 |
| `done` | — | 轮次结束 |
| `error` | `{message}` | 出错 |

**关键创新：**
- **card 事件** — 结构化 UI 卡片，不只是文字输出。文件列表可以渲染为交互式列表，图片可以渲染为画廊
- **ask_user 事件** — 模型主动请求用户确认，前端渲染为确认卡片（勾选框/按钮）
- **sub_agent 事件** — Timeline 面板实时展示调度树

### 12.7 五个 Sub Agent + 六个内置 Skill

**Sub Agent（按领域专项化）：**

| Agent | 领域 | 核心工具 |
|-------|------|---------|
| `file-agent` | 文件全生命周期 | read/write/search/convert |
| `search-agent` | 联网检索+综合 | web_search/web_fetch/ai_search |
| `browser-agent` | 人机交互式网页操作 | Playwright 全套 |
| `computer-agent` | macOS 系统控制 | 音量/亮度/进程/剪贴板 |
| `app-agent` | 第三方 App UI 自动化 | AX Accessibility + Vision |

**内置 Skill：**

| Skill | 触发场景 | 特点 |
|-------|---------|------|
| `file_organizer` | 整理文件夹 | 先 list→提案→ask_user→执行 |
| `document_writer` | 多源合成报告 | PDF/DOCX/MD 混合输入 |
| `excel_processing` | Excel/CSV 分析 | pandas 驱动 |
| `pdf` | PDF 拆合提取 | pdfplumber + pypdf |
| `document_convert` | 格式互转 | pandoc 后端 |
| `planning_with_files` | 长批量任务 | plan.json 断点续传 |

### 12.8 记忆系统

**OpenMarvis 的记忆分两层：**

| 层 | 存储 | 说明 |
|----|------|------|
| 对话记忆 | SQLite Message 表 | 当前对话的完整历史 |
| 长期记忆 | SQLite MemoryEntry 表 | 跨对话的持久记忆（键值对） |
| 全文索引 | FTS5 虚拟表 | 段落级 BM25 检索 |
| 用户偏好 | SQLite UserPreference 表 | 跨对话的用户设置 |
| 审计日志 | AuditLog / WriteAudit | 所有写操作的可追溯日志 |

### 12.9 与六大 Agent 的完整对比

| 维度 | Claude Code | Codex | OpenClaw | Hermes | **Marvis** | WorkBuddy |
|------|------------|-------|----------|--------|-----------|-----------|
| 定位 | 编码专精 | 编码沙箱 | 通用助手 | 通用Agent | **桌面助手** | 编码+通用 |
| 源码 | 泄露(非开源) | Apache-2.0 | MIT | MIT | **闭源** | **闭源** |
| 开源复现 | — | — | — | — | **OpenMarvis(Apache 2.0)** | — |
| 语言 | TypeScript | Rust | TypeScript | Python | **?(Electron)** | TypeScript |
| 平台 | CLI | CLI | 26+渠道 | 10+渠道 | **桌面** | 桌面+Web |
| 多模型 | ❌ | ❌ | ✅Fallback | ✅凭证池 | **✅LiteLLM** | ✅10+模型 |
| 子代理 | 3层 | 无 | 双模式 | 可配置层级 | **4层级** | 专家角色 |
| Skill | 无 | 无 | ClawHub 5.4K | 9大来源 | **白名单限制** | SKILL.md |
| 安全 | 6种权限 | 3维48种 | 工具策略 | 错误分类 | **3级风险+3层守护** | 未知 |
| ask_user | ❌ | ❌ | ❌ | ❌ | **✅结构化卡片** | ❌ |
| 凭证池 | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ |
| MoA | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ |
| 压缩 | 1级 | 无 | 3级 | 3级+边界 | 无(本地) | 未知 |
| 定时任务 | ❌ | ❌ | ✅ | ✅ | **✅自然语言设置** | ❌ |
| FTS5全文检索 | ❌ | ❌ | ❌ | ✅session_search | **✅段落级** | ❌ |
| 审计日志 | ❌ | ❌ | ❌ | ❌ | **✅WriteAudit** | ❌ |
| 计费 | Anthropic | OpenAI | 用户自付 | 用户自付 | **腾讯云** | **腾讯云** |

### 12.10 对我们产品的启示

**从 Marvis/OpenMarvis 可借鉴的核心设计：**

---

1. **四级调度架构** — Main → Sub → Skill → Tool，比 Hermes 的平级子代理更精细化。每一层有独立的工具集和 system prompt。Skill 内可以弹 ask_user 卡片让用户确认

2. **三级风险 + 三层守护** — 比 Hermes 的单一全局安全更实用：
   - PathGuard / CmdGuard / CredentialGuard 三条守护链
   - 风险级别由工具声明（`risk_level: low/medium/high`）
   - ask_user 结构化确认卡片（不只是文字确认）

3. **Skill 白名单机制** — Skill manifest 声明 `allowed_tools`，Skill Agent 只能使用白名单内的工具。这比 Hermes 的全局技能加载更安全

4. **SSE card 事件** — 结构化 UI 卡片渲染（文件列表、图片画廊、确认表单），不只是纯文字流

5. **FTS5 段落级全文检索** — 文件上传后按段落切分索引，BM25 检索返回 top-K 段落

6. **WriteAudit 审计日志** — 所有写操作可追溯

7. **断点续传的批量任务** — plan.json 记录进度，支持 50+ 文件批处理

**Marvis 的局限：**

1. **闭源**（原版） — 无法参考代码。但 OpenMarvis 提供了完整可参考的实现
2. **绑定腾讯计费** — 用腾讯自己的计费体系，new-api 无法中转（同 WorkBuddy）
3. **仅桌面** — 无 CLI / API 模式，无消息平台集成
4. **单用户** — 无协作/多用户支持
5. **仅 macOS 优先** — Windows 支持待实现
6. **无凭证池** — 一个账户一套模型，无法多 key 轮换
7. **无 MoA** — 无多模型混合专家系统
8. **串行调度** — 子代理串行执行，无并发能力
9. **无压缩系统** — 依赖本地 SQLite，无上下文压缩需求（但限制了长对话能力）

---

---


# 第四部分：产品设计

> 双模式切换设计、记忆系统设计、集成建议与路线图


## 十三、核心设计：双模式切换

### 设计理念

不做成两个独立程序，而是同一套 Agent 通过切换**行为上下文**来适配不同场景。本质上是一次切换，改变四件事：

1. **System Prompt** — 角色定义和行为准则
2. **可用工具集** — 不同模式看到不同的工具
3. **模型偏好** — 不同模式优先选不同的模型
4. **交互风格** — 办公多确认，coding 少废话

### 模式定义

#### 办公模式（Work Mode）— 默认

通用 Agent 行为，什么都干。

**工具集：**
- 记忆（memory、session search）
- 技能系统（skill 100+）
- Cron 定时任务
- 多平台消息（微信、Discord、Telegram）
- 浏览器自动化
- Computer Use 桌面控制
- TTS 语音合成
- 文件读写、终端

**模型路由：**
- 日常对话 → 快模型（GLM Turbo、DeepSeek Flash）
- 分析/研究 → 强模型（Claude Sonnet、GPT-5）
- 视觉分析 → 视觉专用模型（Kimi K2.6 等）
- 按 skill 需求自动匹配

**交互风格：**
- 对话式，会反问确认
- 解释详细，分步骤说明
- 中途可以打断、修改方向
- 适合非技术用户

**典型场景：**
- 聊天问答、信息检索
- 写文案、翻译、总结
- 安排日程、设置提醒
- 管理文件、搜索资料
- 控制电脑桌面

---

#### Coding 模式（Code Mode）— 激活后

Agentic Coding 专精，对标 Claude Code + Codex。

**工具集：**
- 文件读写与原子编辑（多文件并发修改）
- 终端执行（shell 命令）
- Git 工作流（commit、branch、PR）
- 代码搜索（全文搜索、语义搜索）
- Lint / 格式化 / 类型检查
- 测试运行（pytest、jest 等）
- 沙箱执行（Docker 隔离，学 Codex）
- 依赖管理（pip、npm、cargo）

**模型路由：**
- 自动选 coding 能力最强的模型
- 优先级：Claude Sonnet > GPT-5 > DeepSeek V4 > 其他
- 不走快模型，宁可慢也要代码质量

**交互风格：**
- 少问多做，不确认就直接干
- 失败自动修，循环到测试通过
- 不解释为什么，只告诉你做了什么
- 输出简洁：diff / 命令输出 / 测试结果
- 适合开发者

**Agent Loop（核心闭环，学 Claude Code）：**
```
理解需求
  → 分析代码库（读文件、搜索依赖）
  → 制定修改计划
  → 执行编辑（多文件原子修改）
  → 运行 lint / 类型检查
  → 运行测试
  → 测试失败？→ 自动分析原因 → 修复 → 重新测试
  → 循环直到全部通过
  → 输出结果摘要
```

**典型场景：**
- 写新功能、修 bug、重构代码
- 代码 review、性能优化
- 项目脚手架搭建
- 自动化测试编写
- Git 工作流（commit、PR、merge）

---

### 模式切换机制

**触发方式：**
- 命令切换：`/code` 进入 Coding 模式，`/work` 回到办公模式
- 上下文自动检测：识别到代码相关任务（打开代码文件、在项目目录下）自动提示切换
- 手动快捷键：桌面 App 侧边栏一键切换

**切换时的状态管理：**
- 会话不中断，历史保留
- 工具集动态加载/卸载（不用的工具不占资源）
- System Prompt 热切换（不重启 agent）
- 模型偏好自动调整

**实现方式（基于 Hermes 架构）：**
```python
# 伪代码示意
class ModeManager:
    def switch(self, mode: str):
        if mode == "code":
            self.load_skills(["coding", "git", "testing", "sandbox"])
            self.set_tools(FILE_EDIT, TERMINAL, GIT, TEST, LINT, SANDBOX)
            self.set_model_preference("claude-sonnet > gpt-5 > deepseek-v4")
            self.set_system_prompt(CODE_SYSTEM_PROMPT)
            self.set_interaction_style("autonomous")  # 少问多做
        elif mode == "work":
            self.load_skills(["default"])  # 通用技能集
            self.set_tools(MEMORY, CRON, BROWSER, COMPUTER_USE, TTS, MESSAGING)
            self.set_model_preference("auto")  # 按任务自动选
            self.set_system_prompt(WORK_SYSTEM_PROMPT)
            self.set_interaction_style("conversational")  # 对话式
```

### 扩展：未来可加的模式

| 模式 | 定位 | 说明 |
|------|------|------|

---

| **办公模式** | 通用 Agent | 当前设计的默认模式 |
| **Coding 模式** | 编程专精 | 当前设计的核心模式 |
| **本地模式** | 离线/隐私 | 学 Marvis，纯端侧本地模型，文件零上传 |
| **专家模式** | 深度分析 | 加载领域专家技能（金融、法律、医疗等），用最强模型，深度推理 |
| **创意模式** | 内容创作 | 写小说、写文案、生图、生视频，加载创意技能集 |

模式数量不限，本质是**技能组 + 工具集 + System Prompt + 模型偏好**的组合。用户甚至可以自定义模式。

---

---


## 十四、记忆系统设计

### 14.1 分层记忆架构

记忆分三层，切换模式时按需加载，不互相污染。

#### 全局记忆（两个模式共享）
- 用户基本信息（名字、身份、语言、时区）
- 核心偏好（不喜欢CoT、诚实第一、不拍马屁、不催睡觉）
- 产品决策记录（需求定义、方向变更、关键决定）
- 跨模式项目进度（"登录功能做完了"，办公模式也能回答）

#### 办公记忆（仅办公模式加载）
- 情感/人际关系（茹、兄弟、家人）
- 日程/生活习惯（作息、兵役、考研）
- 生活场景（护肤、饮食、娱乐）
- 对话风格偏好（文案风格、沟通方式）
- 情绪相关记忆（抑郁、惊恐发作、咖啡提神）

#### Coding 记忆（仅 Coding 模式加载）
- 项目级记忆（结构、依赖、技术栈、框架版本）
- 代码风格偏好（单引号、缩进2空格、命名规范）
- 测试/部署约定（pytest + xdist、Docker Compose）
- 失败经验库（"上次用方案A不行，报了XX错"）
- 模型表现记录（"这个项目Claude比GPT写得好"）
- 代码库指纹（已知bug、测试覆盖率、修改历史）

#### 意图暂存区（跨模式桥梁）
- 办公模式识别到 coding 相关意图时自动暂存
- 切换到 Coding 模式时自动注入
- 例：办公模式瑞邦说"我想给项目加个登录" → 暂存 → 切Coding模式 → 直接开始干活

### 14.2 记忆衰减机制

不是所有记忆都永远有效。旧记忆可能已经过时，需要衰减降级。

**每条记忆的元数据：**
```python
class Memory:
    content: str           # 记忆内容
    layer: str            # global / work / code
    created_at: datetime  # 创建时间
    last_confirmed: datetime  # 最后被用户确认/引用的时间
    access_count: int     # 被读取次数
    confidence: float     # 置信度 0.0~1.0
    source: str           # user_said / agent_observed / inferred
```

**衰减规则：**
| 条件 | 行为 |
|------|------|
| 30天内被用户引用/确认过 | confidence += 0.1（最高1.0） |
| 超过90天未被任何方式访问 | confidence -= 0.05/天 |
| confidence < 0.3 | 不自动注入 context，降级为"按需搜索" |
| confidence < 0.1 | 标记为"过期候选"，下次用户确认时问一句"这个还准确吗？" |
| confidence = 0 | 自动归档删除（或移入冷存储） |

**记忆刷新：**
- 用户纠正旧记忆时（"不是FastAPI了，换Flask了"）→ 旧记忆标记为过期，新记忆替换
- Agent 观察到环境变化时（检测到项目 requirements.txt 变了）→ 主动触发记忆校验
- 批量校验：每7天对 confidence < 0.5 的记忆做一轮自动检测（读文件/看配置验证是否仍然准确）

**示例：**
```
记忆："项目用FastAPI框架"
创建：2026-01-15 | 最后确认：2026-01-15 | confidence: 0.8

2026-03-01 → 超过45天未确认 → confidence 降到 0.55
2026-04-01 → 超过75天 → confidence 降到 0.30 → 降级为按需搜索
2026-05-01 → 超过105天 → confidence 降到 0.05 → 标记过期候选
          → 下次瑞邦提到项目框架时，agent问："你之前用的是FastAPI，现在还用吗？"
          → 瑞邦说"换成Flask了" → 旧记忆删除，新记忆创建，confidence: 1.0
```

### 14.3 记忆冲突处理

同一事实可能存在多条矛盾记忆，需要冲突解决机制。

**冲突检测：**
- 写入新记忆前，搜索是否存在语义冲突的旧记忆
- 冲突判断维度：同一项目、同一对象、时间线矛盾
- 例：记忆A "先不部署" vs 记忆B "先部署试试" → 触发冲突

**冲突解决规则：**
| 规则 | 说明 |
|------|------|
| **最新优先** | 默认听最新的，时间戳晚的覆盖早的 |
| **显式声明优先** | 瑞邦明确说"我改主意了" → 新记忆权重最高 |
| **场景优先** | 办公模式的决定不影响coding模式，反之亦然（除非是全局记忆） |
| **置信度优先** | 如果两条记忆都被多次确认过，置信度高的赢 |
| **挂起等待** | 冲突太严重无法自动判断时 → 生成待确认项，下次交互时问用户 |

**冲突日志：**
```python
class ConflictLog:
    memory_a: Memory
    memory_b: Memory
    conflict_type: str      # temporal / value / scope
    resolved_by: str         # newest / explicit / confidence / user / pending
    resolved_at: datetime
    user_confirmed: bool    # 是否经用户确认
```

**示例：**
```
记忆A："先不部署 new-api"（办公模式，2026-07-07）
记忆B："部署 new-api 试试"（可能来自GPT对话，2026-07-08）

→ 冲突检测触发
→ 最新优先 → 暂时采用 B
→ 但标记为 pending（未确认）
→ 下次瑞邦交互时问："关于 new-api 部署，之前说不部署，后来又说了要部署，现在什么计划？"
→ 瑞邦确认后，淘汰旧记忆，冲突解决
```

### 14.4 Agent 主动记忆

Agent 不只记用户说的，还要记它自己观察到的。

**主动记忆触发条件：**

| 触发场景 | 自动记录内容 | 示例 |
|---------|------------|------|
| 项目扫描 | 项目结构、技术栈、依赖版本 | "检测到项目用 Flask 3.0 + SQLAlchemy" |
| 测试运行 | 测试模式、通过率、已知fail | "pytest 3个skip，2个fail（test_auth相关）" |
| 部署过程 | 部署方式、端口、配置 | "new-api 部署在 localhost:3000，SQLite" |
| 错误修复 | 尝试过的方案和结果 | "方案A不行：报 ConnectionError" |
| 性能观察 | 模型在该项目的表现差异 | "这个项目Claude比GPT少30%token" |
| 环境变化 | 配置文件变更、依赖更新 | "requirements.txt 新增了 redis-py" |
| 用户行为模式 | 使用习惯、高频操作 | "瑞邦每周一上午会问项目进度" |

**主动记忆的 confidence 初始值：**
- 直接观察到的（读文件/跑命令）→ confidence: 0.8
- 推断的（从行为模式归纳）→ confidence: 0.5
- 推断的记忆衰减更快，需要尽快被确认

**降噪机制：**
- 不是所有观察都值得记。只有满足以下条件之一的才主动记忆：
  - 与现有记忆矛盾（触发冲突处理）
  - 是高频操作的规律总结
  - 是项目关键配置变更
  - 是反复出现的错误/失败模式
- 过滤掉：一次性命令、临时文件、调试输出

### 14.5 跨模式智能同步

不是简单隔离，该通的还是要通。

**同步方向与规则：**

| 同传方向 | 规则 | 示例 |
|---------|------|------|
| Coding → 全局 | 项目里程碑/完成状态 | "登录功能做完了" → 全局记住，办公模式能回答 |
| Coding → 全局 | 关键技术决策 | "选了PostgreSQL不选SQLite" → 全局记住 |
| Coding → 全局 | 项目依赖的外部服务 | "new-api跑在3000端口" → 全局记住 |
| 办公 → 全局 | 新的核心偏好 | "我现在开始用Rust" → 全局记住，coding也生效 |
| 办公 → Coding | 项目需求变更 | "登录功能要加验证码" → 同步到coding记忆 |
| 全局 → 两模式 | 无需同步，本身就是共享的 | — |

**不同步的内容：**
- Coding 失败细节（太技术，办公模式不需要）
- 办公情感/关系（coding模式不需要）
- 模式内的临时状态（切换时清除）

**同步机制：**
```python
class SyncManager:
    def on_memory_created(self, memory: Memory):
        # 判断是否需要同步到其他层
        if memory.layer == "code" and self.is_milestone(memory):
            self.promote_to_global(memory)  # 提升到全局
        elif memory.layer == "work" and self.is_requirement_change(memory):
            self.sync_to_code(memory)  # 同步到coding
        elif memory.layer == "code" and self.is_tech_decision(memory):
            self.promote_to_global(memory)
```

### 14.6 Token 预算管理

记忆太多会把 context window 撑爆，需要分级加载。

**三级注入策略：**

| 级别 | 注入方式 | 条件 | 示例 |
|------|---------|------|------|
| **L0 — 永远注入** | 直接写入 system prompt | confidence > 0.8 + 属于核心偏好/用户身份 | "瑞邦不喜欢CoT"、"瑞邦是台湾身份" |
| **L1 — 按需注入** | 检测到相关任务时加载 | confidence > 0.5 + 语义相关 | 检测到coding任务 → 注入项目技术栈记忆 |
| **L2 — 按需搜索** | 不注入，存在向量数据库里 | confidence < 0.5 或冷门记忆 | 需要时通过 semantic search 检索 |

**Token 预算分配：**

假设 context window = 128K tokens：

```
System Prompt:      ~2K tokens（固定）
L0 永远注入记忆:    ~1K tokens（固定，精选≤20条核心记忆）
L1 按需注入记忆:    ~3K tokens（动态，每次注入5~15条相关记忆）
用户输入:           ~2K tokens（预估）
工具输出:           ~50K tokens（动态）
模型输出:           ~8K tokens（预估）
剩余:               ~62K tokens（给对话历史和工具调用链）
```

**压缩策略：**
- L0 记忆定期精简：合并重复的、删除冗余的
- L1 记忆单条上限：不超过 200 字符，超了压缩
- L2 记忆存向量索引，只存摘要和原文指针
- 冷启动：新会话只注入 L0 + L1（按需），L2 等用户提问再检索

**预算超限处理：**
- L0 绝不裁剪（核心偏好不能丢）
- L1 按相关性排序，截断末尾
- 对话历史触发 compaction（像 Hermes 现在做的上下文压缩）

### 14.7 记忆系统总架构图

```
┌─────────────────────────────────────────────────┐
│                  Mode Manager                     │
│         /code ←────────────→ /work               │
└──────────┬──────────────────┬────────────────────┘
           │                  │
    ┌──────▼──────┐   ┌──────▼──────┐
    │ Code Memory │   │ Work Memory │
    │  (项目级)    │   │  (生活级)    │
    └──────┬──────┘   └──────┬──────┘
           │  智能同步        │  智能同步
           │ (里程碑→全局)    │ (偏好→全局)
           ▼                  ▼
    ┌─────────────────────────────┐
    │      Global Memory           │
    │   (核心偏好/身份/决策)       │
    │   L0: 永远注入 (~1K tokens)  │
    └──────────┬──────────────────┘
               │
    ┌──────────▼──────────────────┐
    │      Intent Staging Area     │
    │   (跨模式意图暂存)            │
    └──────────────────────────────┘

    ┌──────────────────────────────┐
    │    Decay Engine (衰减引擎)   │
    │  confidence 随时间/确认衰减    │
    │  定期批量校验 > 自动清理      │
    └──────────────────────────────┘

    ┌──────────────────────────────┐
    │   Conflict Resolver (冲突)    │
    │  最新优先 / 显式优先 / 置信度  │
    │  无法解决 → 挂起问用户         │
    └──────────────────────────────┘

    ┌──────────────────────────────┐
    │  Proactive Observer (主动记忆) │
    │  扫描项目 / 观察行为 / 记录规律  │
    └──────────────────────────────┘

    ┌──────────────────────────────┐
    │   Token Budget Manager        │
    │  L0/L1/L2 分级注入 + 压缩     │
    └──────────────────────────────┘
```

---

---


## 十五、为"六合一超级 Agent"的集成建议

### 技术栈选择

| 维度 | 选择 | 理由 |
|------|------|------|
| **后端语言** | Python（上层）+ Rust（底层性能瓶颈） | Python 生态丰富、AI/ML 库多；Rust 处理 token 解析、并发等性能关键路径 |
| **前端** | Web + TUI + 消息平台（微信/Discord） | 覆盖办公场景的多种交互方式 |
| **运行时** | Python async + Rust FFI | asyncio 处理 I/O 密集型任务，Rust 处理 CPU 密集型 |
| **数据库** | SQLite (FTS5) | 学 Hermes，轻量级、嵌入式、全文搜索 |
| **协议** | OpenAI 兼容 API | 行业标准，覆盖最多模型提供商 |
| **沙箱** | Docker（远端）+ eBPF/landlock（本地） | 学 Codex 的多平台沙箱思路 |

### 架构分层

| 层 | 来源 | 说明 |
|------|------|------|
| **API 网关** | Hermes（Go 中间层） | 多平台接入、认证、限流 |
| **Agent 编排** | Hermes + Claude Code 思路 | Python 上层，system prompt 组装、工具调度、上下文压缩 |
| **工具执行** | Codex（沙箱）+ Claude Code（精细工具） | Coding 模式下 Docker 沙箱；办公模式丰富工具集 |
| **子代理系统** | Hermes（delegate）+ Marvis（四级调度） | 平级子代理 + 层级调度混合 |
| **记忆系统** | 自研（Ch14 设计） | 三层记忆 + 五维优化 + 跨模式同步 |
| **模型路由** | OpenClaw（Fallback）+ 自研 | 按任务类型自动选模型，fallback 链 |

### 集成优先级

| 优先级 | 能力 | 来源 | 复杂度 |
|--------|------|------|--------|
| P0 | Agent 核心循环 | Claude Code query.ts 思路 | 中 |
| P0 | 上下文压缩 | Claude Code 三层压缩 + Hermes 五层记忆 | 高 |
| P0 | 双模式切换 | 自研（Ch13 设计） | 中 |
| P1 | 多模型路由 | OpenClaw Fallback 系统 | 中 |
| P1 | 沙箱执行 | Codex Docker/Seatbelt | 高 |
| P1 | 子代理系统 | Hermes delegate + Marvis 四级 | 高 |
| P2 | 技能市场 | OpenClaw ClawHub + Hermes Skill | 中 |
| P2 | 凭证池 | Hermes Credential Pool | 低 |
| P2 | MoA 混合专家 | Hermes MoA Loop | 中 |
| P3 | 桌面控制 | Marvis 远程桌面 | 高 |
| P3 | ask_user 结构化确认 | Marvis 确认卡片 | 低 |

### 不能直接用的（许可证限制）

- Claude Code：自定义非开源许可证，不能复制粘贴源码，但可学习架构设计
- Codex CLI：Apache-2.0 开源，可以参考和借鉴
- OpenClaw：MIT 开源，可以参考和借鉴
- Hermes：MIT 开源，作为设计参考（从零打造，不 fork）
- WorkBuddy / Marvis：闭源，仅靠逆向分析

### 开发路线图

| 阶段 | 目标 | 核心交付 |
|------|------|----------|
| **Phase 1（MVP）** | 双模式 Agent + 完整工具链 + 记忆系统 + 权限 | 核心循环、双模式切换、文件/终端/Docker沙箱工具、权限引擎、记忆系统（CRUD+FTS5）、三层压缩、CLI界面、错误恢复 |
| **Phase 2** | 多模型路由 + 子代理 + Web界面 | 多Provider+Function层路由、fallback链、子代理调度、Web界面（Next.js）、Git/浏览器/代码搜索工具 |
| **Phase 3** | 生态完善 | 技能市场、MoA、桌面控制、审计日志、高级记忆（衰减/冲突/主动记忆） |

> 范围说明：Phase 1 采用大MVP策略，不压缩范围。开发团队为AI三剑客，开发效率高，无需传统人工开发的渐进式范围控制。
> Phase 1 细节见《需求规格说明书》第6章。

> 开发团队：AI 三剑客（Hermes + GPT + Codex）负责编码，瑞邦担任产品经理。

---


*报告生成：Hermes Agent*
*产品决策：瑞邦*
