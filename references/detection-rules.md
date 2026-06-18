# Detection Rules (Agent 安全静态检测规则)

> 静态代码检测规则库
> Stage 1 (MODEL) 与 Stage 2 (ATTACK) 共同使用
> 可直接转换为 Semgrep / Bandit / CodeQL 规则

---

## 1. Semgrep 规则（Python）

### 1.1 工具参数无校验

```yaml
rules:
  - id: agent-tool-no-args-validation
    message: |
      Agent 工具函数缺少参数校验。LLM 生成的参数可能含注入 payload。
      必须使用 Pydantic / Type hints / 显式校验。
    severity: ERROR
    languages: [python]
    patterns:
      - pattern-either:
          - pattern: |
              @tool
              def $FUNC($$$):
                  ...
          - pattern: |
              def $FUNC($$$) -> $RET:
                  """<$DOC>"""
                  ...
    metadata:
      category: agent-security
      owasp: ASI02
      layer: L3
```

### 1.2 Shell 命令用户输入

```yaml
  - id: agent-shell-user-input
    message: |
      Agent 工具调用 subprocess/os.system 接收用户/模型输入，存在命令注入风险。
    severity: ERROR
    languages: [python]
    patterns:
      - pattern-either:
          - pattern: subprocess.run($CMD, shell=True)
          - pattern: subprocess.call($CMD, shell=True)
          - pattern: os.system($CMD)
          - pattern: os.popen($CMD)
      - metavariable-regex:
          metavariable: $CMD
          regex: '.*(?:f"|\+|format).*'
    metadata:
      category: agent-security
      owasp: ASI02
```

### 1.3 SQL 注入

```yaml
  - id: agent-sql-injection
    message: |
      Agent 工具调用 SQL 数据库时使用字符串拼接。
    severity: ERROR
    languages: [python]
    patterns:
      - pattern-either:
          - pattern: cursor.execute(f"...{$X}...")
          - pattern: cursor.execute("...%s..." % $X)
          - pattern: db.execute("...".format($X))
    metadata:
      category: agent-security
      owasp: ASI02
```

### 1.4 Token Passthrough

```yaml
  - id: agent-token-passthrough
    message: |
      Agent 把上游 Authorization 头原样透传给下游。
      应使用 Token Exchange（OBO/CCG）。
    severity: ERROR
    languages: [python]
    patterns:
      - pattern-either:
          - pattern: |
              headers = dict($REQ.headers)
              ...
              requests.$METHOD(..., headers=headers)
          - pattern: |
              $TOKEN = $REQ.headers['Authorization']
              ...
              headers['Authorization'] = $TOKEN
    metadata:
      category: agent-security
      owasp: ASI03
      layer: L5
```

### 1.5 记忆无隔离

```yaml
  - id: agent-memory-no-isolation
    message: |
      记忆/RAG 检索无 user_id / tenant_id 过滤。
      存在跨用户记忆泄露风险。
    severity: ERROR
    languages: [python]
    patterns:
      - pattern-either:
          - pattern: vector_db.search($QUERY)
          - pattern: memory.search($QUERY)
          - pattern: retriever.invoke($QUERY)
      - pattern-not: vector_db.search($QUERY, filter={..., "user_id": ...})
    metadata:
      category: agent-security
      owasp: ASI04
      layer: L2
```

### 1.6 长期 API Key

```yaml
  - id: agent-long-lived-api-key
    message: |
      检测到长期硬编码 API Key。Agent 应使用短期凭证 + Token Exchange。
    severity: WARNING
    languages: [python, yaml, json]
    patterns:
      - pattern-either:
          - pattern: |
              OPENAI_API_KEY = "sk-..."
          - pattern: |
              api_key: "sk-..."
          - pattern: |
              OPENAI_API_KEY: "sk-..."
    metadata:
      category: agent-security
      owasp: ASI03
      layer: L5
```

### 1.7 HITL 模型判断

```yaml
  - id: agent-hitl-model-decision
    message: |
      HITL 触发由模型判断，可被 prompt injection 绕过。
      应改为确定性规则。
    severity: ERROR
    languages: [python]
    patterns:
      - pattern-either:
          - pattern: |
              if $LLM.should_ask_human(...):
                  ...
          - pattern: |
              response = $LLM.complete("Should I ask for approval? ...")
              if "yes" in response:
                  ...
          - pattern: |
              if $AGENT.decide_to_escalate(...):
                  ...
    metadata:
      category: agent-security
      owasp: ASI03
      layer: L5, L6
```

### 1.8 Tool 描述过长

```yaml
  - id: agent-tool-description-suspicious
    message: |
      工具描述异常长（>500 字符），可能藏指令注入。
    severity: WARNING
    languages: [python]
    pattern-regex: '"""[\s\S]{500,}"""'
    paths:
      include:
        - "**/tools/*.py"
        - "**/registry*.py"
    metadata:
      category: agent-security
      owasp: ASI06
      layer: L4
```

### 1.9 缺乏 trace 4 字段

```yaml
  - id: agent-trace-missing-fields
    message: |
      日志/trace 缺少 user_id / agent_id / session_id / trace_id 之一。
      事故无法追溯。
    severity: WARNING
    languages: [python]
    pattern-either:
      - pattern: logger.info(...)
      - pattern: tracer.start_span(...)
    pattern-not-inside: |
      $X = Tracer(trace_id=..., user_id=..., agent_id=..., session_id=...)
    metadata:
      category: agent-security
      owasp: ASI09
      layer: L7
```

### 1.10 MCP Server 无白名单

```yaml
  - id: agent-mcp-no-allowlist
    message: |
      MCP Server 配置无白名单，存在恶意 MCP Server 接入风险。
    severity: ERROR
    languages: [yaml, json]
    pattern-either:
      - pattern: |
          mcp_servers:
            - ...
      - pattern: |
          mcpServers:
            ...
    pattern-not: |
      mcp_servers:
        - $NAME:
            trust: trusted
            ...
    metadata:
      category: agent-security
      owasp: ASI06
      layer: L4
```

---

## 2. Bandit 规则（Python）

```python
# bandit/plugins/agent_security.py

import bandit
from bandit.core import issue
from bandit.core import test_properties as test

@test.checks('Call')
@test.test_id('B901')
def agent_tool_no_validation(context):
    """工具函数缺少参数校验"""
    func = context.call_function_name
    # 检测 @tool 装饰的函数无 Pydantic / schema
    if 'tool' in func.lower():
        args = context.call_args
        if not any('BaseModel' in str(a) or 'pydantic' in str(a).lower() for a in args):
            return issue.Issue(
                severity=bandit.HIGH,
                confidence=bandit.HIGH,
                text="Agent tool without Pydantic validation"
            )
    return None
```

---

## 3. Grep 规则（快速模式匹配）

```bash
# ============ 危险模式（高优先级）============

# 直接拼接 system prompt
grep -rn 'f".*{.*}.*system\|format(.*system' --include="*.py"

# 长期 API Key
grep -rn 'OPENAI_API_KEY\s*=\s*["\x27]' --include="*.py" --include="*.env"
grep -rn 'ANTHROPIC_API_KEY\s*=\s*["\x27]' --include="*.py" --include="*.env"

# eval/exec 接收外部输入
grep -rn 'eval(.*request\|eval(.*input\|exec(.*request\|exec(.*input' --include="*.py"

# shell=True
grep -rn 'shell=True' --include="*.py"

# 字符串拼接 SQL
grep -rn 'execute(f"\|execute(.*% \|execute(.*\.format' --include="*.py"

# Token passthrough
grep -rn "headers.update\|headers\['Authorization'\]" --include="*.py"

# 长期记忆无 TTL
grep -rn "ConversationBufferMemory\b" --include="*.py"

# 检索无 user 过滤
grep -rn "vector.*search\|retriever.invoke" --include="*.py"

# 工具无风险等级标注
grep -rn "@tool\b" --include="*.py" -A 5 | grep -v "risk"

# MCP 无白名单
grep -rn "mcpServers\|mcp_servers" --include="*.json" --include="*.yaml"
```

---

## 4. 自定义 Heuristic（基于代码结构）

| Heuristic | 检测方法 | 风险信号 |
|----------|---------|---------|
| Agent 工具数 > 10 | AST 函数计数 | 可能是 Everything Agent |
| 工具 description > 200 字符 | 字符串长度 | 可能藏指令 |
| 工具无 docstring | AST 检查 | 缺少审计线索 |
| Tool Registry 不存在 | 查找 `registry.py` | 默认全工具暴露 |
| `bind_tools` 无包装器 | AST 节点 | 直接执行函数 |
| LangGraph 节点无 `interrupt_before` | 编译参数 | 高风险动作无审批 |
| Trace 缺 4 字段之一 | span 属性检查 | 事故不可追溯 |
| `agent.invoke` 调用无 `before/after hook` | AST 检查 | 无策略层拦截 |
| Memory 写入接口无审批 | 函数签名 | 持久化攻击面 |
| HITL 触发函数无白名单常量 | 字符串字面量 | 模型可绕过 |

---

## 5. 代码示例：危险 vs 安全

### 5.1 工具定义

```python
# ❌ 危险
@tool
def read_file(path: str) -> str:
    """读取文件"""
    return open(path).read()

# ✅ 安全
from pydantic import BaseModel, Field, constr

class ReadFileParams(BaseModel):
    path: str = Field(..., description="文件路径，必须在 /data/ 下")

@tool(args_schema=ReadFileParams)
def read_file(path: str) -> str:
    """读取文件（沙箱内）"""
    safe_path = os.path.normpath(os.path.join('/data/', path.lstrip('/')))
    if not safe_path.startswith('/data/'):
        raise PermissionError(f"Path not allowed: {path}")
    if not os.path.realpath(safe_path).startswith('/data/'):
        raise PermissionError("Symbolic link escape detected")
    with open(safe_path) as f:
        return f.read(50_000)  # 限制大小
```

### 5.2 Agent 注册

```python
# ❌ 危险
agent = Agent(
    llm=llm,
    tools=[read_file, write_file, execute_sql, send_email, run_shell],
)

# ✅ 安全
agent = Agent(
    llm=llm,
    tools=[
        # 只暴露该 Agent 需要的工具
        gateway.wrap(read_file, scope='/data/'),
        # 高风险工具要求审批
        gateway.wrap(send_email, require_approval=True, allowed_domains=['@corp.com']),
    ],
    identity=AgentIdentity(
        agent_id='support-bot-1',
        allowed_tools={'read_file', 'send_email'},
        max_iterations=10
    ),
)
```

### 5.3 Tool Gateway 入口

```python
# ✅ Tool Gateway 强制入口
async def invoke_tool(agent, tool_name, args, context):
    # 1. 工具存在性
    tool = registry.get(tool_name)
    if not tool:
        raise UnknownToolError(tool_name)

    # 2. Agent 权限
    if tool_name not in agent.allowed_tools:
        raise PermissionError(f"Agent {agent.id} cannot use {tool_name}")

    # 3. Schema 校验
    validated = tool.schema(**args)

    # 4. Policy 裁决
    decision = policy.evaluate(
        user=context.user, agent=agent.id, tool=tool_name,
        args=validated, context=context
    )
    if decision == 'deny':
        raise PolicyDeniedError(policy.last_reason)
    elif decision == 'require_approval':
        await hitl.request(tool, validated, context)
        # 等待审批...

    # 5. Audit
    audit_log('tool_call', agent=agent.id, tool=tool_name, args_hash=hash(validated))

    # 6. 执行（在沙箱中）
    return await tool.execute(**validated)
```
