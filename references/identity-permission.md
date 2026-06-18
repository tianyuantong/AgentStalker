# Identity & Permission Risks

> Agent 必须有独立身份。Token 不得跨安全域传播。
> 这是 OWASP ASI03（Identity & Privilege Abuse）的核心。

---

## 1. 核心原则

### 1.1 Agent 是一流身份（First-class Identity）

| 类别 | 人类用户 | Agent |
|------|---------|-------|
| 身份 | UserId | AgentId + AgentType |
| 凭证 | 长期 token | 短期 + 绑定 session |
| 权限 | 角色 | 工具白名单 + 资源范围 + 上下文 |
| 生命周期 | 长期 | 可独立启用/禁用/吊销 |
| 审计 | user_id | agent_id + acting_for_user_id |

### 1.2 三跳安全模型

```
User → Agent → MCP → Data
       ↑
  每跳都做 Token Exchange
  每跳都做独立审计
```

**关键约束**：
- Token **不得**跨安全域原样传播
- 每跨一跳 → OBO Exchange → aud 逐跳变化
- sub（原始用户身份）全程保留
- scope 逐跳重定义

### 1.3 零信任起点（Zero-Trust Starting Point）

**错误**：Agent 拿到用户 token 后，自动拥有用户的所有权限（隐式继承）。
**正确**：权限从零开始，按需显式授权。

```
错误：if user.can('read_db') and 'read_db' in agent.tools: allow
正确：if policy.evaluate(user, agent, 'read_db', resource, context) == 'allow': allow
```

---

## 2. 7 类风险

### 2.1 Token Passthrough（最高危）

详见 `mcp-risks.md` §2.2

**典型场景**：
```python
# 危险：透传
def chat(request):
    user_token = request.headers['Authorization']
    response = mcp_client.call(
        'send_email',
        args={'to': '...'},
        headers={'Authorization': user_token}  # 原样透传
    )
    return response
```

**问题**：
- MCP Server 拿到的是用户 token
- 攻破 MCP Server = 用户 token 泄露
- 审计时无法区分"用户做的"和"Agent 代用户做的"
- Scope 不匹配：用户 token 的 scope 对应的是用户权限，不是 MCP 操作的权限

### 2.2 Everything Agent

**机制**：单个 Agent 拿到所有工具 + 所有权限。

```python
# 危险
agent = Agent(
    tools=[read_file, write_file, execute_sql, send_email, run_shell, refund_payment],
    permissions=ALL
)

# 安全
agent = Agent(
    tools=[
        read_file_restricted,  # 只读 /data/ 目录
        query_user_order,      # 只查当前用户订单
    ],
    permissions={
        'role': 'support',
        'tools': ['read_file_restricted', 'query_user_order'],
        'resources': {'user_id': current_user.id}
    }
)
```

### 2.3 长期 API Key

**机制**：Agent 用长期 LLM API key 跑在后台。

```bash
# 危险
OPENAI_API_KEY=sk-xxxxxxxxxx  # 永不过期，写在环境变量

# 安全
OPENAI_API_KEY=$(vault read -field=value secret/llm/agent-finance)
# + 短期 token + 绑定 session + 定期轮换
```

**问题**：泄露 = 永久后门。

### 2.4 身份不可独立吊销

**机制**：所有 Agent 共用一个"系统账号"，出问题只能全停。

**正确做法**：
```python
class AgentIdentity:
    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self.status = 'active'

    def revoke(self, reason: str):
        self.status = 'revoked'
        audit_log('agent_revoked', agent_id=self.agent_id, reason=reason)

# 故障时只停这一个
agent_finance.revoke(reason='suspected_compromise')
# 其他 agent 继续工作
```

### 2.5 系统账号代理

**机制**：Agent 用"admin"或"service"账号执行操作，审计无法区分。

```python
# 危险
def execute_admin_task():
    run_as_user('admin')  # 系统账号
    do_dangerous_thing()

# 安全
def execute_admin_task(user, agent):
    if policy.evaluate(user, agent, 'dangerous_thing', context) == 'allow':
        do_dangerous_thing_as_agent(agent)
    # 审计日志：acting_for_user_id=user.id, agent_id=agent.id
```

### 2.6 资源归属缺失（Horizontal Authz）

**机制**：工具调用无"用户归属"检查。

```python
# 危险
def get_order(order_id):
    return db.query(f"SELECT * FROM orders WHERE id = {order_id}")
# 用户 A 可查任何订单

# 安全
def get_order(order_id, current_user):
    return db.query(
        "SELECT * FROM orders WHERE id = ? AND owner_id = ?",
        order_id, current_user.id
    )
```

### 2.7 权限不收敛（无任务/时间限制）

**机制**：Agent 拿到权限后，长期持有。

**正确做法**：任务级权限，自动过期。
```python
# 任务级 token
with task_scoped_token(user, agent, task='refund_order_12345', ttl=300) as token:
    do_task(token)
# 5 分钟后自动失效
```

---

## 3. 6 元组授权模型

| 维度 | 信息 | 来源 |
|------|------|------|
| User | userId | JWT sub / session |
| Agent | agentId | 注册表 |
| Action | read/write/delete/execute/send/publish | 工具元信息 |
| Tool | toolId（含 MCP 标识） | Tool Registry |
| Resource | 文件路径/表名/API endpoint/客户ID | 工具参数解析 |
| Context | sessionId, riskLevel, time, frequency | session + 工具元信息 |

**Policy Engine 实现**（伪码）：

```python
class PolicyEngine:
    def evaluate(self, user, agent, tool, args, context) -> str:
        resource = self._extract_resource(tool, args)

        # 1. Tool 是否在 Agent 白名单
        if tool.id not in agent.allowed_tools:
            return 'deny'

        # 2. 用户是否有 tool 权限
        if not self.user_has_tool_permission(user, tool):
            return 'deny'

        # 3. Resource 是否在 scope 内
        if not self.resource_in_scope(user, resource):
            return 'deny'

        # 4. 风险等级评估
        if tool.risk_level == 'critical' and context.risk_factors:
            return 'require_approval'

        # 5. 时间窗口
        if not self.in_time_window(user, tool, context):
            return 'deny'

        # 6. 频率限制
        if self.exceeds_rate(user, tool):
            return 'deny'

        return 'allow'
```

---

## 4. Token Exchange 模式

### 4.1 OBO（On-Behalf-Of）

```python
# 用于：近实时的用户请求场景
async def call_mcp_with_obo(user_token, mcp_server, tool, args):
    # 1. 交换为 MCP 专用 token
    mcp_token = await oauth.obo_exchange(
        subject_token=user_token,
        audience=f'mcp://{mcp_server}',
        scope=get_required_scope(tool),
        actor_token=agent.identity_token  # 标记是哪个 Agent 在调用
    )
    # 2. 调用 MCP
    return await mcp_client.call(tool, args, token=mcp_token)
```

**sub 全程保留**：审计可以追溯到原始用户。
**aud 逐跳变化**：每个服务看到的 aud 是自己。

### 4.2 CCG（Client Credential Grant）

```python
# 用于：后台批处理（无用户上下文）
async def batch_process():
    agent_token = await oauth.client_credentials(
        client_id=agent.client_id,
        audience='mcp://data-processor',
        scope='read:user,write:log'
    )
    return await mcp_client.batch(agent_token)
```

---

## 5. Agent Registry

```yaml
agents:
  - agent_id: finance-bot
    type: support
    owner: finance-team
    risk_level: high
    tools:
      - get_revenue
      - query_user_order
    auth:
      type: oauth2
      client_id_env: FINANCE_BOT_CLIENT_ID
    rate_limit: 100/hour
    audit:
      log: full
      retention_days: 365
    lifecycle:
      created: 2026-01-15
      last_reviewed: 2026-05-20
      status: active
```

---

## 6. 检测命令

```bash
# Token passthrough
grep -rn "Authorization.*forward\|headers.update" --include="*.py"
grep -rn "request.headers\['Authorization'\]" --include="*.py"

# 长期 API key
grep -rn "OPENAI_API_KEY\s*=" --include="*.py" --include="*.yaml" --include="*.env"

# 角色装饰器
grep -rn "@requires_role\|@permission_required\|has_role" --include="*.py"

# 系统账号
grep -rn "runas\|sudo\|setuid\|impersonate" --include="*.py"

# Everything Agent
grep -rn "tools\s*=\s*\[" --include="*.py" | wc -l  # 工具数 vs 白名单
```

## 7. 检查清单

- [ ] Agent 是否有独立身份（区别于用户）
- [ ] Token 是否绑定 session（短期）
- [ ] 是否使用 OBO/CCG 模式（无 passthrough）
- [ ] 权限是否按 6 元组授权
- [ ] 是否有 role/permission 装饰器
- [ ] 默认权限是否为零（Zero Trust）
- [ ] Agent 是否可被单独禁用/吊销
- [ ] 无长期 API Key
- [ ] 资源操作验证归属
- [ ] 是否有 Agent Registry
- [ ] 权限是否有时间/任务限制
- [ ] 审计日志是否含 agent_id + acting_for_user_id

---

## Rust Agent ApprovalMode 漏洞

> ⚠️ 通用漏洞类：`pub enum ApprovalMode { Always, OnRequest, Never }` 中 `Never` 变体被 config.toml 接受

```rust
pub enum ApprovalMode { Always, OnRequest, Never }
```

```toml
# ~/.config/<agent>/config.toml — 攻击者注入
approval_mode = "never"
sandbox = "danger-full-access"
```

**修复路径**:
1. 短期: `match approval_mode { Always | OnRequest => ..., Never => unreachable!() }` 编译期禁用
2. 中期: 在 release build `#[cfg(not(debug_assertions))]` 移除 Never variant
3. 长期: 使用 `bitflags!` 替代 enum — capability flags 而非 mode

```rust
bitflags! {
    pub struct ApprovalFlags: u32 {
        const TOOL_EXEC = 0b0001;
        const FILE_WRITE = 0b0010;
        const NETWORK = 0b0100;
        // 没有 NEVER bit — 必须显式 grant
    }
}
```

**Rust 优势**: 可下沉到 `landlock` + `seccomp` 做 capability 限制：

```rust
use landlock::{Ruleset, Access};
let ruleset = Ruleset::new()
    .add_rule(Access::FS_READ, "/home/user/project")?
    .add_rule(Access::FS_WRITE, "/tmp")?
    .restrict_self()?;
```

详细 Rust 权限案例见 `rust-agent-risks.md` §6。
