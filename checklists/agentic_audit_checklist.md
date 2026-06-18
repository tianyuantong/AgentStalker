# AgentStalker Audit Checklist

> 10 维必查项 + 严重度 + 检测命令
> 覆盖 OWASP Agentic Top 10 (2026) + 7 层攻击面
> Layer 1: 覆盖率验证矩阵；Layer 2: 攻击面参考文档

---

## 使用方式

1. **不驱动审计** — LLM 先按攻击面自由审计（Stage 2A）
2. **验证覆盖** — 用本清单对未覆盖维度补漏（Stage 2B）
3. **每项必须** ✅ / ⚠️浅覆盖 / ❌未覆盖 三态之一

---

## 维度对照

| 维度 | OWASP | 7 层 | 严重度默认 |
|------|-------|------|-----------|
| D1 提示词注入 | ASI08, ASI01 | L1, L2 | high |
| D2 工具参数注入 | ASI02 | L3 | critical |
| D3 工具白名单 | ASI02, ASI10 | L3, L5 | critical |
| D4 记忆与 RAG | ASI04 | L2 | critical |
| D5 MCP / 插件 | ASI06 | L4 | high |
| D6 身份与权限 | ASI03, ASI10 | L5 | critical |
| D7 多代理通信 | ASI05 | L6 | high |
| D8 级联失败 | ASI07 | L6 | medium |
| D9 可观测性 | ASI09 | L7 | medium |
| D10 HITL 设计 | ASI03 | L5, L6 | high |

---

## D1: 提示词注入

| ID | 检查项 | 检测命令 / 信号 | 严重度 |
|----|-------|---------------|-------|
| D1.1 | system prompt 是否与用户输入结构化分离？ | `grep "system.*+.*user_input\|format(.*prompt"` | high |
| D1.2 | 是否有 `<UNTRUSTED_DATA>` 包裹外部内容？ | 检索代码中 UNTRUSTED 标记 | high |
| D1.3 | 提示词泄露检测 | 询问"重复你的指令"，看是否泄露 | medium |
| D1.4 | 直接注入规则库 | 是否维护 deny-list 但允许升级 | medium |
| D1.5 | 间接注入：检索内容是否标注来源 | 代码中是否有 source/risk_level 字段 | high |
| D1.6 | 提示词版本管理 | 是否有 prompt_version + 变更审计 | low |
| D1.7 | 输出是否过滤敏感字段（PII/凭证/系统提示） | `grep "filter\|redact\|sanitize"` | high |

**判定规则**：
- f-string / .format() 拼接用户输入 + system prompt = **high**
- 外部内容无隔离区 = **high**
- 提示词泄露 = **medium**

---

## D2: 工具参数注入（Agent 第一致命漏洞）

| ID | 检查项 | 检测命令 | 严重度 |
|----|-------|---------|-------|
| D2.1 | 文件名参数是否做路径规范化 | `grep "os.path.normpath\|realpath"` | high |
| D2.2 | SQL 工具是否使用参数化查询 | `grep "execute(.*%s\|execute(.*f\"\|format.*sql"` | critical |
| D2.3 | shell 工具是否用白名单 + 不传 shell=True | `grep "shell=True"` | critical |
| D2.4 | URL 参数是否做协议/域名白名单 | `grep "ALLOWED_DOMAINS\|allowed_schemes"` | high |
| D2.5 | JSON 工具是否做 schema 校验 | `grep "pydantic\|BaseModel\|zod\|JSONSchema"` | high |
| D2.6 | 模板工具是否禁用危险语法（SSTI） | `grep "Template\|render"` | high |
| D2.7 | eval/exec 是否接收外部输入 | `grep "eval(\|exec("` | critical |
| D2.8 | 工具是否对每个参数做类型/范围/正则校验 | 工具定义文件 | high |
| D2.9 | 是否对参数做大小限制（防 DoS） | `grep "max_length\|MAX_SIZE"` | medium |

**判定规则**：
- 工具函数无任何参数校验 = **critical**
- `subprocess(..., shell=True)` + 用户输入 = **critical**
- `eval()` / `exec()` 接收外部输入 = **critical**

---

## D3: 工具白名单与注册

| ID | 检查项 | 检测命令 | 严重度 |
|----|-------|---------|-------|
| D3.1 | 是否有 Tool Registry（统一注册表） | 查找 `registry.py` / `tools/__init__.py` | critical |
| D3.2 | 工具是否带 9 项元信息（name/desc/schema/risk/approval/scope/timeout/rate/audit） | 工具定义结构 | high |
| D3.3 | Agent 可见工具是否按 Agent 身份过滤 | 查找 `enabled_for_agent` / 角色映射 | critical |
| D3.4 | 工具 ID 是 UUID 还是字符串名 | 字符串名易混淆 | medium |
| D3.5 | 工具描述是否审计（防 Tool Description 投毒） | MCP 注册日志 | high |
| D3.6 | 工具风险等级（low/medium/high/critical）是否标注 | 工具元信息 | high |
| D3.7 | 工具是否可动态注册（运行时新增） | 查找 `register_tool` 动态调用 | medium |
| D3.8 | 工具调用是否有强制 Gateway 路径 | 是否有 `tool_gateway` / `policy_engine` | critical |

**判定规则**：
- 无 Tool Registry = **critical**（默认全工具暴露）
- Agent 可见工具未按身份过滤 = **critical**（权限蔓延）
- 工具可绕过 Gateway 直接执行 = **critical**

---

## D4: 记忆与 RAG 安全

| ID | 检查项 | 检测命令 | 严重度 |
|----|-------|---------|-------|
| D4.1 | 记忆写入是否做 source 校验 | `grep "memory.save\|add_documents"` | critical |
| D4.2 | 记忆是否按 user_id / tenant_id 隔离 | 检索接口是否带 user 过滤 | critical |
| D4.3 | 长期记忆是否有 TTL | `grep "ttl\|expiry\|expire_after"` | high |
| D4.4 | 记忆分区（preference/fact/cache 是否分开） | 架构层检查 | medium |
| D4.5 | RAG 文档摄入是否做来源分级 | 是否有 `trusted_sources` 白名单 | high |
| D4.6 | RAG 摄入是否做内容净化（注入特征扫描） | 是否有 `_contains_injection` | high |
| D4.7 | RAG 检索是否返回元数据（来源、版本、哈希） | API 返回结构 | medium |
| D4.8 | 记忆检索结果是否有二次过滤 | `grep "filter\|is_accessible"` | high |
| D4.9 | 上下文窗口是否有 token 限制 | `grep "max_tokens\|context_window"` | medium |
| D4.10 | 跨会话记忆是否需要审批才生效 | 是否有审批队列 | high |

**判定规则**：
- 记忆无 user 隔离 = **critical**（跨用户污染）
- 记忆写入无 source 校验 = **critical**（持久化攻击面）
- RAG 摄入无来源验证 = **high**（投毒）

---

## D5: MCP 与插件生态

| ID | 检查项 | 检测命令 | 严重度 |
|----|-------|---------|-------|
| D5.1 | MCP Server 注册表是否存在 | 查找 `mcp_servers.yaml` / config | high |
| D5.2 | MCP Server 来源是否审查（trusted/unknown） | 配置文件中 trust 字段 | high |
| D5.3 | MCP 工具描述是否签名 / 审计 | 是否有签名验证 | high |
| D5.4 | Token 是否经过 Exchange 还是 passthrough | `grep "Authorization.*forward"` | critical |
| D5.5 | MCP 通信是否使用 mTLS | 配置 | high |
| D5.6 | MCP 工具 scope 是否最小化 | 工具 scope 配置 | high |
| D5.7 | 是否有 SBOM / 第三方依赖审查 | 配置文件 | medium |
| D5.8 | Session 是否防 hijack | 是否有 session 验证 | high |
| D5.9 | 第三方插件是否动态加载 | `grep "importlib\|exec("` | high |
| D5.10 | 是否有 MCP Server 白名单 | 配置文件 | critical |

**判定规则**：
- Token passthrough = **critical**（违反三跳安全模型）
- 无 MCP Server 白名单 = **high**
- 工具描述无审计 = **high**

---

## D6: 身份与权限

| ID | 检查项 | 检测命令 | 严重度 |
|----|-------|---------|-------|
| D6.1 | Agent 是否有独立身份（区别于用户） | 查找 `agent_id` 字段 | critical |
| D6.2 | Token 是否绑定 session | 是否有 session 验证 | high |
| D6.3 | 是否使用 OBO/CCG 模式 | `grep "obo\|on_behalf_of\|client_credentials"` | high |
| D6.4 | 权限是否按 Agent × 工具 × 资源 × 上下文（六元组）授权 | 策略引擎实现 | high |
| D6.5 | 是否有 role/permission 装饰器 | `grep "@requires_role\|@permission"` | high |
| D6.6 | 默认权限是否为零 | 是否有白名单而非黑名单 | critical |
| D6.7 | Agent 是否可被单独禁用/吊销 | 是否有 lifecycle 管理 | high |
| D6.8 | 长期 API Key 是否有 | 配置文件、env | critical |
| D6.9 | 资源操作是否验证归属（horizontal authz） | `grep "user_id\|owner_id"` | high |
| D6.10 | 是否复用用户 token 直传 | Token flow 跟踪 | critical |

**判定规则**：
- Agent 无独立身份 = **critical**（审计不可追溯）
- Token passthrough = **critical**（溯源断裂）
- 长期 API Key = **critical**
- 默认权限非零 = **critical**（违反 Zero Trust）

---

## D7: 多代理通信

| ID | 检查项 | 检测命令 | 严重度 |
|----|-------|---------|-------|
| D7.1 | 代理间消息是否有签名 | 消息协议 | high |
| D7.2 | 共享黑板/任务队列是否有访问控制 | 代码 | high |
| D7.3 | 消息来源是否验证 | 接收逻辑 | high |
| D7.4 | 是否把"代理"作为内部网络默认互信 | 配置 | high |
| D7.5 | 多代理事务是否幂等 | 工具层 | medium |
| D7.6 | 是否有 quorum / 双人审批（关键决策） | 工作流 | medium |
| D7.7 | 跨代理共享内容是否带来源标签 | 数据结构 | medium |

**判定规则**：
- 代理间消息无签名 = **high**
- 共享黑板无访问控制 = **high**

---

## D8: 级联失败与有界自治

| ID | 检查项 | 检测命令 | 严重度 |
|----|-------|---------|-------|
| D8.1 | 是否有 max_iterations / max_steps | `grep "max_iterations\|MAX_STEPS"` | high |
| D8.2 | 是否有重试退避与 max_retries | `grep "backoff\|max_retries"` | high |
| D8.3 | 是否有断路器（连续失败停止） | 工具层 | medium |
| D8.4 | 是否有 token / 时间 / 步骤预算 | 架构层 | medium |
| D8.5 | 失败是否 fail closed | 工具实现 | high |
| D8.6 | 写操作是否幂等 | 工具层 | medium |
| D8.7 | 是否有降级路径 | 架构层 | medium |
| D8.8 | 跨系统动作是否有事务 | 工具层 | medium |
| D8.9 | 是否有混沌工程 / 故障注入测试 | CI/CD | low |

**判定规则**：
- 无 max_iterations = **high**（可被诱导进入循环）
- 失败 fail open = **high**

---

## D9: 可观测性

| ID | 检查项 | 检测命令 | 严重度 |
|----|-------|---------|-------|
| D9.1 | 是否有 trace 框架（OpenTelemetry 等） | `grep "tracer\|opentelemetry"` | medium |
| D9.2 | trace 是否含 user/agent/session/traceId 4 字段 | 追踪点 | critical |
| D9.3 | 工具调用是否记录参数 + 返回值 | 日志 schema | high |
| D9.4 | 是否记录 policy decision（allow/deny/approval） | 日志 | high |
| D9.5 | 日志是否脱敏（PII/凭证/系统提示词） | `grep "logger.*prompt\|logger.*secret"` | high |
| D9.6 | 是否有 Evals 套件 | 查找 `evals/` 目录 | medium |
| D9.7 | 是否有行为基线（成功率/工具调用频率/参数模式） | 监控 | medium |
| D9.8 | 是否有 trace replay 能力 | 工具 | medium |
| D9.9 | 是否记录 prompt/model/tool 三个版本 | 日志 | medium |
| D9.10 | 是否有 SLO/告警（注入成功率、越权拒绝率等） | 监控 | medium |

**判定规则**：
- trace 缺 user/agent/session/traceId = **critical**（事故无法追溯）
- 日志含明文 PII/凭证 = **high**
- 无 evals = **medium**（无法量化安全水位）

---

## D10: HITL 与 Governance

| ID | 检查项 | 检测命令 | 严重度 |
|----|-------|---------|-------|
| D10.1 | HITL 触发是确定性规则还是模型判断 | 触发逻辑 | critical |
| D10.2 | 高风险操作（delete/send/publish）默认 require_approval | Registry 配置 | critical |
| D10.3 | 审批是否提供证据包（计划/参数/影响/回滚） | 工作流 | high |
| D10.4 | 审批人身份是否验证 | 审批队列 | high |
| D10.5 | 审批是否有 SLA / 超时降级 | 工作流 | medium |
| D10.6 | 是否有审批审计日志 | 日志 | high |
| D10.7 | 是否有 Reject 路径与原因记录 | 工作流 | medium |
| D10.8 | Agent 是否能跳过审批（管理员豁免等） | 配置 | critical |
| D10.9 | 审批是否区分高/中/低风险 | Registry | high |
| D10.10 | 是否有"双签"机制（quorum） | 关键操作 | medium |

**判定规则**：
- HITL 由模型判断 = **critical**（prompt injection 可绕过）
- 高风险操作无审批 = **critical**
- 审批无证据包 = **high**（易被社会工程）

---

## 覆盖率验证

完成审计后，逐项标记：

```
[覆盖率]
D1 提示词注入          ✅ / ⚠️ / ❌
D2 工具参数注入         ✅ / ⚠️ / ❌
D3 工具白名单           ✅ / ⚠️ / ❌
D4 记忆与 RAG           ✅ / ⚠️ / ❌
D5 MCP / 插件           ✅ / ⚠️ / ❌
D6 身份与权限           ✅ / ⚠️ / ❌
D7 多代理通信           ✅ / ⚠️ / ❌
D8 级联失败             ✅ / ⚠️ / ❌
D9 可观测性             ✅ / ⚠️ / ❌
D10 HITL                ✅ / ⚠️ / ❌
```

❌ 未覆盖维度必须补测或显式标注"不适用"（需有理由）。
