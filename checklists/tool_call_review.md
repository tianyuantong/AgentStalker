# Tool Call Layer Review Checklist

> 工具调用层硬化检查
> 与 `agentic_audit_checklist.md` 互补，专注 L3 工具调用层
> 评估对象：每个工具 + Tool Gateway + Policy Engine

---

## 1. 工具注册表

| 项 | 必填 | 检测 |
|----|------|------|
| Tool Registry 文件存在 | ✅ | 查找 `registry.py` / `tools/__init__.py` |
| 每个工具含 9 项元信息 | ✅ | name/desc/schema/risk/approval/scope/timeout/rate/audit |
| 工具 ID 是 UUID | ⚠️ | 字符串名易混淆，建议 UUID |
| 工具描述长度 < 500 字符 | ✅ | 长描述可能藏指令 |
| 工具描述通过审计 | ✅ | 见 `mcp-risks.md` §3.3 |
| 工具风险等级已标注 | ✅ | low/medium/high/critical |
| 工具 scope 列表存在 | ✅ | ["data/*"] 而非 "*" |
| 工具 timeout 存在 | ✅ | 防止长任务挂起 |
| 工具 rate_limit 存在 | ✅ | 防止滥用 |
| 工具 audit_log 配置存在 | ✅ | full / minimal / none |

## 2. 参数注入防御

| 参数类型 | 必须 | 禁止模式 |
|---------|------|---------|
| 字符串 | 长度限制 + 字符白名单 | 任何 shell 元字符（;\|&$`<>(){}） |
| 文件路径 | normpath + 沙箱前缀校验 | `..`、绝对路径、UNC、符号链接 |
| URL | 协议白名单（http/https）+ 域名白名单 | file://、gopher://、localhost、169.254.* |
| SQL | 参数化查询（`?` 占位符） | f-string、format、+ 拼接 |
| Shell | 白名单命令 + argv 数组 + shell=False | shell=True、用户输入拼接 |
| JSON | Pydantic / Zod 严格 schema | 未知字段、prototype pollution、$ne 等操作符 |
| 邮件 | 收件人域白名单 + 附件大小限制 | 外部域、>10MB 附件 |
| 数字 | 范围检查 | 负数、超大、NaN、Infinity |
| 数组 | 长度限制 + 元素白名单 | 超长数组、嵌套注入 |

## 3. 工具调用前校验（必须）

```python
# 标准调用前流程
async def call_tool(agent_id, user_id, tool_name, args, context):
    # 1. 工具存在性
    if tool_name not in registry:
        return error("unknown_tool")

    tool = registry[tool_name]

    # 2. Agent 是否有权限
    if tool_name not in agent.allowed_tools:
        return error("tool_not_allowed_for_agent")

    # 3. Schema 校验
    try:
        validated_args = tool.schema(**args)
    except ValidationError as e:
        return error("schema_validation_failed", details=str(e))

    # 4. Policy Engine 裁决
    decision = policy_engine.evaluate(
        user=user_id,
        agent=agent_id,
        tool=tool_name,
        args=validated_args,
        context=context
    )

    if decision == 'deny':
        return error("policy_denied", reason=policy_engine.last_reason)
    elif decision == 'require_approval':
        approval_id = await hitl.request_approval(...)
        if not await hitl.wait_approval(approval_id, timeout=300):
            return error("approval_timeout")
        # 二次确认

    # 5. Audit Trace
    audit_log('tool_call', {
        'agent': agent_id, 'user': user_id, 'tool': tool_name,
        'args_hash': hash(validated_args), 'decision': decision
    })

    # 6. 执行
    return await tool.execute(**validated_args)
```

## 4. 工具执行环境

| 项 | 必填 |
|----|------|
| 工具执行有 timeout | ✅ |
| 工具执行有 max memory | ✅ |
| 工具执行在隔离环境（容器/进程） | ✅ |
| 网络出站受白名单限制 | ✅ |
| 文件系统访问受沙箱限制 | ✅ |
| 凭证不暴露给工具（短期/限定 scope） | ✅ |
| 工具输出大小限制（防 token 耗尽） | ✅ |

## 5. 工具调用后审计

| 项 | 必填 |
|----|------|
| 记录调用参数（hash） | ✅ |
| 记录返回值（截断） | ✅ |
| 记录执行时间 | ✅ |
| 记录 policy decision | ✅ |
| 记录审批人（如有） | ✅ |
| 记录影响面（如 delete X rows） | ✅ |
| 日志脱敏（PII/凭证） | ✅ |

## 6. LangChain / LangGraph 特定

### LangChain `bind_tools` 安全模式

```python
# ❌ 不安全
llm.bind_tools([read_file, send_email, run_shell])

# ✅ 安全：包装器走 Gateway
from agent_gateway import wrap_for_agent

tools = [
    wrap_for_agent(read_file, agent='finance-bot'),
    wrap_for_agent(send_email, agent='finance-bot', require_approval=True),
]
llm.bind_tools(tools)
```

### LangGraph Interrupts

```python
# 在高风险节点前 interrupt
workflow.compile(
    checkpointer=MemorySaver(),
    interrupt_before=["send_email", "delete_record", "publish"]
)
```

## 7. 工具白名单测试用例

```
针对每个工具，验证：

[T1] 已注册的工具可以正常调用
[T2] 未注册的工具调用被拒绝
[T3] Agent 可见工具仅限白名单
[T4] 参数超长被拒绝
[T5] 参数含特殊字符被拒绝（按参数类型）
[T6] 风险等级 critical 工具调用触发 HITL
[T7] HITL 拒绝后工具不执行
[T8] 工具执行超时被 kill
[T9] 工具执行超过 memory limit 被 kill
[T10] 工具调用有审计日志
```

## 8. 高危工具专项

### 8.1 `run_shell` / `execute_code` / `eval`

```python
# 默认禁用
REGISTRY.register(Tool(
    name='run_shell',
    enabled=False,  # 默认不启用
    risk='critical',
    require_approval=True,
    allowed_commands=['ls', 'cat', 'grep', 'wc'],  # 白名单
    shell=False,  # 不传 shell
    timeout=5,
    audit_log='full'
))
```

### 8.2 `read_file` / `write_file`

```python
REGISTRY.register(Tool(
    name='read_file',
    allowed_paths=['/data/'],  # 沙箱前缀
    forbidden_paths=['/etc/', '/root/', '/proc/', '/sys/'],
    max_size_mb=10,
    follow_symlinks=False
))
```

### 8.3 `execute_sql`

```python
REGISTRY.register(Tool(
    name='execute_sql',
    allowed_statements=['SELECT'],  # 默认禁用 INSERT/UPDATE/DELETE
    forbidden_keywords=['information_schema', 'pg_', 'sys.'],
    require_where=True,  # 强制 WHERE
    max_rows=1000
))
```

### 8.4 `send_email`

```python
REGISTRY.register(Tool(
    name='send_email',
    allowed_recipient_domains=['@corp.com'],
    max_recipients=10,
    max_attachment_size_mb=5,
    require_approval_for_external=True,
    redact_pii=True
))
```

### 8.5 `fetch_url` / `http_request`

```python
REGISTRY.register(Tool(
    name='fetch_url',
    allowed_schemes=['http', 'https'],
    blocked_ips=['127.0.0.1', '169.254.169.254', '::1'],
    blocked_domains=['metadata.google.internal', 'metadata.azure.com'],
    allowed_domains=[],  # 空 = 无允许
    timeout=10
))
```
