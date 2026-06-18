# Agent Attack Surface Reference

> 7 层攻击面 + OWASP Agentic Top 10 (2026) 对应 + 检测入口
> 基于：OWASP Agentic Top 10、Microsoft Defense in Depth (2026-05)、
> Five Eyes Careful Adoption (2026-05)、NIST AI Agent Standards
> Initiative (2026-02)、Microsoft "Tool Call 不是 Function Call" (2026)

---

## 1. Attack Surface Map (7 层)

```
┌─────────────────────────────────────────────────────────────┐
│ L1: 用户输入与外部内容 (User Input & External Content)        │
│     - 直接 Prompt Injection                                  │
│     - 间接 Prompt Injection（网页/文档/邮件/MCP 返回值）        │
├─────────────────────────────────────────────────────────────┤
│ L2: 上下文与记忆 (Context & Memory)                           │
│     - RAG 投毒                                               │
│     - 长期记忆污染（跨会话持久控制）                            │
│     - 上下文窗口溢出                                          │
├─────────────────────────────────────────────────────────────┤
│ L3: 工具调用 (Tool Calls)                                    │
│     - 参数注入（命令/SQL/路径/JSON/模板）                      │
│     - 工具白名单绕过                                          │
│     - 工具组合滥用（链式越权）                                  │
│     - Tool Description 投毒                                  │
├─────────────────────────────────────────────────────────────┤
│ L4: MCP 与插件生态 (MCP & Plugin Ecosystem)                  │
│     - 恶意 MCP Server                                        │
│     - Token Passthrough                                      │
│     - Session Hijack                                         │
│     - 第三方插件供应链                                        │
├─────────────────────────────────────────────────────────────┤
│ L5: 身份与权限 (Identity & Permission)                        │
│     - Token 跨域传播（违反 Token Exchange 原则）               │
│     - "Everything Agent" 越权                                │
│     - 系统账号 vs Agent 独立身份                              │
│     - OBO / CCG 模式错用                                     │
├─────────────────────────────────────────────────────────────┤
│ L6: 多代理协作 (Multi-Agent Collaboration)                    │
│     - 代理间消息伪造                                          │
│     - 共享黑板/任务队列污染                                    │
│     - 级联失败（重试风暴、预算耗尽、状态不一致）                │
│     - HITL 信任利用（社会工程攻击人类审批者）                    │
├─────────────────────────────────────────────────────────────┤
│ L7: 可观测性 (Observability)                                 │
│     - 缺乏 trace 记录                                        │
│     - 日志中含 PII/凭证/系统提示词                             │
│     - 行为基线缺失导致无法识别异常                              │
│     - Evals 缺位                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. Mapping: 7 层 ↔ OWASP Agentic Top 10 (2026)

| 7 层 | OWASP Agentic Top 10 风险 | 风险简称 | 一句话描述 |
|------|--------------------------|---------|----------|
| L1, L2 | ASI01 | Agent Goal Hijack | 通过输入让 Agent 偏离原始目标 |
| L3 | ASI02 | Tool Misuse | 合法工具被用于非预期/越权目的 |
| L5 | ASI03 | Identity & Privilege Abuse | Agent 使用了不当身份或权限 |
| L2 | ASI04 | Memory & Context Poisoning | RAG/记忆被污染，跨会话影响行为 |
| L6 | ASI05 | Insecure Inter-Agent Communication | 代理间通信缺乏认证 |
| L4 | ASI06 | MCP & Plugin Supply Chain | MCP Server / 插件被恶意控制 |
| L3, L6 | ASI07 | Cascading Failures | 一个失败传播为系统性失败 |
| L1 | ASI08 | Prompt Injection (Direct/Indirect) | 直接/间接提示注入 |
| L7 | ASI09 | Insufficient Observability | 缺乏 trace/audit/evals |
| L5, L4 | ASI10 | Excessive Agency | Agent 拥有过多工具与权限 |

---

## 3. 关键工程判断（与 codeaudit 的本质差异）

> **核心判断：Agent 的护栏不能都塞进一个"安全中间件"。**
> 不同攻击面需要不同架构层的护栏：

| 架构层 | 主要应对风险 | 护栏类型 |
|--------|------------|---------|
| AI Gateway | 权限妥协、身份伪造、资源过载、不可追踪 | 输入护栏 + 运维护栏 |
| Reasoning 层 | 目标错位、目标操纵、级联幻觉 | 过程护栏 + 输出护栏 |
| Orchestration | 工具误用、多 Agent 共谋 | 过程护栏 |
| Memory | 记忆投毒 | 过程护栏 |
| Governance | 人类监督缺失、偏见 | 输出护栏 + 运维护栏 |

→ 审计时必须按层定位护栏缺失，而非扫描"有没有 guardrail"。

---

## 4. 致命误解：Tool Call ≠ Function Call

这是 Agent 安全与普通代码审计的**根本分水岭**。

| 维度 | 普通函数调用 | Agent Tool Call |
|------|------------|----------------|
| 调用者 | 确定性业务代码 | 受上下文影响的模型 |
| 参数来源 | 受控流程、类型系统 | prompt、网页、RAG、MCP 返回、历史消息 |
| 失败性质 | 通常是 bug | 可能是安全事故 |
| 权限模型 | 入口处完成 | 每次工具执行都可能跨资源边界 |
| 日志性质 | 调试信息 | 审计证据 |

**审计判断**：
- 当代码中出现 `tool_call` / `bind_tools` / `ToolNode` / `mcp__*` 模式，
  立即切换到"权限请求"语义，而**不是**"函数调用"语义。
- 工具是否在调用前经过 Policy Engine 裁决（六元组：user × agent ×
  action × tool × resource × context）？

详见 `tool-call-risks.md`。

---

## 5. 静态建模流程（Stage 1 详化）

### 5.1 工具定义提取（AST）

**目标语言模式**：

| 框架/语言 | 工具定义模式 |
|----------|------------|
| LangChain (Python) | `@tool` 装饰器、`BaseTool` 子类、`StructuredTool` |
| LangChain (TS) | `tool()`、`DynamicStructuredTool` |
| AutoGen | `register_function`、`@user_proxy.register` |
| CrewAI | `@tool` 装饰器、`BaseTool` 子类 |
| MCP (Python) | `@server.list_tools()`、`@server.call_tool()` |
| MCP (TS) | `server.setRequestHandler(ListToolsRequestSchema, ...)` |
| 自研 | 任何接受 `name` + `description` + `parameters schema` 的注册函数 |

**每个工具需提取的元信息**（9 项，对应 Tool Registry 规范）：

```yaml
- name: read_file
  description: 读取文件内容
  parameters_schema:
    type: object
    properties:
      path: { type: string, description: 文件路径 }
  risk_level: medium  # low/medium/high/critical
  requires_approval: false
  scope: ["data/*"]  # 允许访问的资源范围
  timeout_ms: 5000
  rate_limit: 100/min
  audit_log: full
  data_classification: confidential
```

### 5.2 提示词边界分析（LLM 辅助）

识别 system prompt 中的：
- **指令区**（必须遵守的规则）— 通常包含"你必须"、"禁止"、"始终"等
- **数据注入点**（用户可控的占位符）— `{user_input}`、`{context}`、`{history}`
- **工具描述区**（模型可见的工具列表）

**关键问题**：
- 指令区与数据区是否有结构化分隔？是否有 `<UNTRUSTED_DATA>` 包裹？
- 用户输入是否直接拼接到 system prompt？（危险：f-string、format、+）

### 5.3 权限模型提取

识别：
- `@requires_role('admin')` / `@require_permission` 装饰器
- 角色-工具映射（`ROLE_TOOL_MAP = {"admin": [...], "user": [...]}`）
- Token 来源（用户 token 直传？OBO Exchange？系统账号？）

### 5.4 记忆模块识别

| 模式 | 库/类 |
|------|------|
| LangChain Buffer | `ConversationBufferMemory` / `ConversationBufferWindowMemory` |
| LangChain Vector | `VectorStoreRetrieverMemory` / `Pinecone` / `Chroma` |
| LangGraph | `MemorySaver` / `RedisSaver` / `PostgresSaver` |
| LlamaIndex | `ChatMemoryBuffer` / `VectorMemory` |
| MCP | `resources/list` + `resources/read` |

→ 标记其读写接口，为记忆投毒攻击提供入口。

### 5.5 MCP Server 注册表

提取：
- 每个 MCP Server 的名称、版本、来源（trusted / unknown）
- 暴露的工具列表
- 认证方式（OAuth / API key / 无）
- Token 是否经过 Exchange 还是 passthrough

### 5.6 HITL 触发规则

**致命问题**：HITL 是确定性规则还是模型判断？

- ✅ 确定性：`if tool.risk == 'high': approval_required = True`
- ❌ 危险：`if agent.should_ask_human(): ...` （模型决定）

### 5.7 输出 schema

最终 `agent_model.json`：

```json
{
  "project": "my-agent",
  "type": "LangChain + MCP + VectorStore",
  "tools": [ ... ],
  "system_prompt": {
    "raw": "...",
    "instruction_blocks": [ ... ],
    "data_injection_points": [ ... ]
  },
  "permissions": {
    "role_tool_map": { ... },
    "auth_model": "user_token_passthrough",
    "token_exchange": false
  },
  "memory": {
    "type": "VectorStoreRetrieverMemory",
    "read_interface": "...",
    "write_interface": "...",
    "isolation": "none"
  },
  "mcp_servers": [
    { "name": "...", "trust": "unknown", "tools": [...] }
  ],
  "hitl": {
    "trigger": "model_decision",  // CRITICAL
    "approval_queue": "...",
    "evidence_pack": false
  },
  "observability": {
    "trace": "langfuse",
    "audit_log": "partial",
    "evals": false
  }
}
```

---

## 6. 检测命令清单（按层）

### L1: 用户输入与外部内容

```bash
# 提示词直接拼接（危险）
grep -rn 'f".*{.*user_input}\|format(.*user_input)' --include="*.py"
grep -rn 'system_prompt.*+\|+.*user_input' --include="*.py"

# 系统提示词泄露检测点
grep -rn 'def system_prompt\|SYSTEM_PROMPT\s*=' --include="*.py"

# RAG 摄入是否做来源验证
grep -rn 'def ingest\|add_documents\|vector.*upsert' --include="*.py"
```

### L2: 上下文与记忆

```bash
# 记忆写入接口
grep -rn 'def save\|memory.save\|conversation.save\|persist' --include="*.py"

# 记忆读取无权限过滤
grep -rn 'memory.load\|retriever.invoke\|search(' --include="*.py"

# 长期记忆无 TTL/分区
grep -rn 'ConversationBufferMemory\|VectorStoreRetrieverMemory' --include="*.py"
```

### L3: 工具调用

```bash
# 工具定义
grep -rn '@tool\|def.*\(.*\).*->.*str:' --include="*.py"
grep -rn 'class.*Tool\|StructuredTool\|BaseTool' --include="*.py"

# 危险函数
grep -rn 'eval(\|exec(\|os.system(\|subprocess.*shell=True' --include="*.py"

# 工具调用是否走策略层
grep -rn 'tool_call\|agent.invoke\|agent.run' --include="*.py" | \
  grep -v "policy\|gateway\|approval"
```

### L4: MCP 与插件

```bash
# MCP Server 注册
grep -rn '@server.list_tools\|@server.call_tool' --include="*.py"
grep -rn 'mcp__\|mcpServers' --include="*.json" --include="*.yaml"

# Token passthrough（危险）
grep -rn 'request.headers.*Authorization\|forward.*token' --include="*.py"

# 插件动态加载
grep -rn 'importlib.import_module\|__import__\|exec(' --include="*.py"
```

### L5: 身份与权限

```bash
# 角色定义
grep -rn 'def has_role\|@requires_role\|@permission_required' --include="*.py"

# 工具白名单缺失
grep -rn 'def.*tool.*\(.*\):' --include="*.py" | wc -l  # 与白名单配置对比

# Token Exchange
grep -rn 'obo\|on_behalf_of\|token_exchange' --include="*.py"
```

### L6: 多代理

```bash
# 代理间消息无签名
grep -rn 'def send_message\|agent_a.invoke\|agent_b.invoke' --include="*.py"

# 共享黑板/队列
grep -rn 'shared_memory\|task_queue\|blackboard' --include="*.py"

# HITL 触发
grep -rn 'should_ask_human\|requires_approval\|approval_queue' --include="*.py"
```

### L7: 可观测性

```bash
# 是否有 trace
grep -rn 'trace\|tracer\|opentelemetry' --include="*.py"

# 日志是否含敏感字段
grep -rn 'logger.*\(.*prompt\|logger.*\(.*secret\|logger.*\(.*password' --include="*.py"

# Evals 存在性
find . -name "evals" -type d
grep -rn "ragas\|deepeval\|promptfoo" requirements.txt package.json
```

---

## 7. Agent 特有高危模式

### 7.1 给 Agent 发长期 API Key
- **风险**：等价于永久后门
- **检测**：`OPENAI_API_KEY` / `ANTHROPIC_API_KEY` 写死在配置/环境变量
- **修复**：短期凭证、绑定 session、OBO Exchange

### 7.2 Agent 直接拿用户 token
- **风险**：Tool 层无法区分"用户做的"和"Agent 代用户做的"
- **检测**：`request.headers['Authorization']` 透传至下游
- **修复**：Token Exchange，三跳安全模型（User→Agent→MCP→Data）

### 7.3 工具调用无 schema 校验
- **风险**：参数注入
- **检测**：工具函数直接 `**kwargs` 或 `args` 接 LLM 输出
- **修复**：Pydantic / Zod schema 严格校验

### 7.4 记忆写入无门槛
- **风险**：一次注入变永久控制
- **检测**：`memory.save()` 无 source/origin 校验
- **修复**：写入门禁（来源、内容、TTL、审批）

### 7.5 HITL 由模型判断
- **风险**：Prompt injection 绕过
- **检测**：`if agent.should_ask_human()` 等模式
- **修复**：确定性规则（`if action in {'delete', 'send', 'publish'}`）

### 7.6 Everything Agent
- **风险**：一个 Agent 拿全权限，所有工具默认启用
- **检测**：工具注册表无 `enabled_for_agent` 字段
- **修复**：Agent-as-Microservice，按职责拆分

### 7.7 缺乏 Tool Registry
- **风险**：工具管理散落，特权代码无法收敛
- **检测**：没有统一的 `registry.py` / `tools/__init__.py`
- **修复**：建立 Tool Registry，工具不注册不可用

### 7.8 Shell/Code 执行工具
- **风险**：RCE
- **检测**：`run_shell` / `execute_code` / `eval` 工具
- **修复**：默认禁用；启用时强制沙箱 + 白名单

### 7.9 工具描述投毒（Tool Description Poisoning）
- **风险**：MCP Server 描述中含恶意指令
- **检测**：动态 MCP 注册的工具描述无审计
- **修复**：Tool Description 签名 + 来源校验

### 7.10 跨用户记忆泄露
- **风险**：用户 A 可读用户 B 的记忆
- **检测**：`VectorStoreRetrieverMemory` 无 `user_id` 过滤
- **修复**：按 user_id/tenant_id 强隔离

---

## 8. 优先级与审计顺序

按 OWASP Agentic Top 10 严重度 + 利用难度排序：

| 优先级 | 维度 | 典型检测 |
|--------|------|---------|
| P0 | L3 工具参数注入 | `injection_templates.yaml` 全工具覆盖 |
| P0 | L5 工具白名单 | 工具注册表 vs 实际可用 |
| P0 | L5 Token passthrough | MCP 链路 token 透传 |
| P1 | L2 RAG 投毒 | 摄入接口无来源校验 |
| P1 | L6 HITL 由模型决定 | 审批触发逻辑检查 |
| P1 | L1 间接注入 | 检索内容未隔离 |
| P2 | L3 工具描述投毒 | MCP 工具描述审计 |
| P2 | L4 MCP 供应链 | 注册表来源审查 |
| P2 | L6 多代理消息认证 | agent-to-agent 签名 |
| P3 | L7 观测性 | trace/audit/evals 缺失 |
| P3 | L2 上下文窗口 | 大输入消耗 token |

---

## 9. 参考与延伸阅读

- `references/tool-call-risks.md` — Tool Call ≠ Function Call 深度
- `references/memory-rag-risks.md` — RAG 投毒与记忆污染
- `references/mcp-risks.md` — MCP Server 治理
- `references/identity-permission.md` — Agent 身份与权限
- `references/multi-agent-risks.md` — 多代理与级联失败
- `references/observability-risks.md` — 可观测性盲区
- `templates/injection_templates.yaml` — 攻击 payload 模板
- `templates/attack_chains.yaml` — 多轮攻击链
- `checklists/agentic_audit_checklist.md` — 10 维必查项
