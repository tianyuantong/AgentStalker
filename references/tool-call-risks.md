# Tool Call ≠ Function Call — 工具调用风险深度

> 核心命题：Agent 的每一次 tool call，本质上是一次资源授权请求，不是 function call。
> 混淆这两件事 = 把安全交给最不可靠的层（LLM）。

---

## 1. 五维度崩塌

| 维度 | 普通函数调用 | Agent Tool Call | 崩塌点 |
|------|------------|----------------|--------|
| 调用者 | 确定性业务代码 | 受上下文影响的模型 | 调用意图生成非确定性 |
| 参数来源 | 类型系统 + 校验层 | prompt/网页/RAG/MCP/历史 | 攻击者只需构造合法参数结构 |
| 失败性质 | bug | 安全事故 | 邮件发出去收不回 |
| 权限模型 | 入口处完成 | 跨资源跨等级 | 一刀切覆盖不了工具链 |
| 日志性质 | 调试信息 | 审计证据 | 调试视角 ≠ 审计视角 |

---

## 2. 工具背后的生产能力

| 工具 | 表面功能 | 背后是 |
|------|---------|--------|
| `read_file` | 读文件 | 客户合同、工资单、SSH 密钥、`.env` |
| `execute_sql` | 查数据库 | 订单/库存/账务/隐私 |
| `send_email` | 发邮件 | 内部 → 外部世界 |
| `run_shell` | 执行命令 | 文件系统/网络/凭证/Git/SSH |
| `call_mcp_server` | 调用 MCP | 第三方供应链 |
| `publish_article` | 发文章 | 外部可见的公开内容 |
| `refund_payment` | 退款 | 财务责任 |

→ **给 Agent 一个工具 = 给一把钥匙**

---

## 3. 正确的授权问题（六元组）

```
这个用户 × 哪个 Agent × 什么 Action × 哪个 Tool × 访问什么 Resource ×
在什么 Context 下 — 允许吗？
```

| 维度 | 问的是什么 | 信息 |
|------|----------|------|
| User | 原始用户是谁 | userId |
| Agent | 哪个 Agent 代执行 | agentId |
| Action | read / write / delete / execute / send / publish | 动作类型 |
| Tool | 通过哪个工具 | toolId（含 MCP 标识） |
| Resource | 访问哪个资源 | 文件路径/表名/API endpoint/客户ID/订单号 |
| Context | 什么条件 | sessionId, riskLevel, 时间窗口, 调用频率 |

**错误问题**：`Agent 能不能用这个工具？`（二元判断）
**正确问题**：`这个用户、这个会话、这个 Agent、这个工具、这个资源、当前上下文 — 允许吗？`（六元裁决）

---

## 4. 工具调用链的正确架构

```
LLM/Agent
  → tool_call request
  → Tool Gateway (唯一入口)
    → Schema Validation
    → Policy Engine (六元组)
      → 允许 → Tool Executor
      → 审批 → HITL Service → Tool Executor
      → 拒绝 → 返回拒绝原因
    → Audit Trace (4 字段: user/agent/session/traceId)
  → Tool Result
  → LLM
```

**5 个关键组件**：

1. **Tool Registry**: 9 项元信息（name/desc/schema/risk/approval/scope/timeout/rate/audit）
2. **Tool Gateway**: 唯一入口，不可绕过
3. **Policy Engine**: 六元组裁决，确定性
4. **HITL Service**: 确定性规则触发
5. **Audit Trace**: 4 字段同步写入

---

## 5. 风险分级（4 级）

| 等级 | 典型工具 | 默认策略 |
|------|---------|---------|
| Low | 天气/公开搜索/时间 | Schema + 日志 |
| Medium | 内部知识库/CRM 只读 | 用户权限 + Resource scope |
| High | 邮件/DB 写/工单/内部 API | 六元组 + 审计 |
| Critical | 删除/退款/发布/Shell/支付 | HITL + 二次确认 + trace replay |

---

## 6. LangChain / LangGraph 接入点（不是替代）

### 6.1 LangChain `bind_tools`

```python
# 不安全：直接传给真实函数
llm.bind_tools([read_file, send_email, run_shell])

# 安全：传给 Tool Gateway 包装器
llm.bind_tools([
    gateway.wrap(read_file, risk='medium', scope=['/data/']),
    gateway.wrap(send_email, risk='high', require_approval=True),
])
```

### 6.2 LangGraph Interrupts（HITL 原生支持）

```python
from langgraph.checkpoint import MemorySaver
from langgraph.graph import StateGraph

def high_risk_node(state):
    # 在执行前中断，等待人工确认
    return state

workflow = (
    StateGraph(State)
    .add_node("plan", plan_node)
    .add_node("execute", execute_node)
    .add_node("high_risk_action", high_risk_node)
    .add_edge("plan", "execute")
    .add_edge("execute", "high_risk_action")
    .compile(checkpointer=MemorySaver(), interrupt_before=["high_risk_action"])
)
```

---

## 7. 7 个最小落地步骤

1. **所有工具注册到 Tool Registry**（哪怕只有 3 个）
2. **Agent 只拿工具描述，不拿实现引用**
3. **工具执行统一走 Tool Gateway**
4. **每次调用生成 ToolInvocation 事件**（4 字段）
5. **Policy Engine 检查 5 元**（user × agent × tool × action × resource）
6. **高风险工具 require_approval = true**（配置驱动）
7. **失败默认 fail closed**

---

## 8. 检测清单（针对工具调用层）

- [ ] 工具注册表（Tool Registry）是否存在
- [ ] 工具元信息是否含 9 项
- [ ] Agent 可见工具是否按身份过滤
- [ ] 工具调用前是否过 Schema 校验
- [ ] 工具调用前是否过 Policy Engine（六元组）
- [ ] 工具调用是否记录 Audit Trace（4 字段）
- [ ] 高风险操作是否触发 HITL
- [ ] HITL 触发是确定性规则还是模型判断
- [ ] Tool Gateway 是否唯一入口（无绕过路径）
- [ ] 工具调用失败是否 fail closed

---

## 9. 真实案例参考

详见 `case-references.md`

---

## 10. Rust 特有的工具调用模式

> ⚠️ **Rust agent (Codex / Aider / Rig / 自研 CLI)** 有独立的攻击面：
> - `format!` 不 escape（指令文件直接 format! 进 system prompt）
> - `Command::new(args)` 参数拼接
> - `bincode::deserialize` / `serde_yaml::from_reader` 反序列化
> - workspace 供应链 (keyring / openssl-sys / rmcp)

详细 Rust 专属分析见 `rust-agent-risks.md`（含 8 个 Rust agent 通用漏洞类 + 修复路径）。
