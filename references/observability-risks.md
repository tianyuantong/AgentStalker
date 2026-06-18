# Observability Risks

> 缺乏可观测性 = 事故无法追溯、异常无法检测、水位无法度量。
> Trace / Audit / Evals 是 Agent 生产化的前提。

---

## 1. 三大可观测支柱

| 支柱 | 作用 | 缺失后果 |
|------|------|---------|
| **Trace** | 还原执行链路 | 事故无法复盘 |
| **Audit** | 决策与权限审计 | 责任无法归属 |
| **Evals** | 安全与质量度量 | 水位无法量化 |

---

## 2. 风险全景

### 2.1 Trace 缺失

**症状**：
- 不知道 Agent 为什么做这个动作
- 不知道走了哪条工具链
- 不知道什么时候引入了污染数据

**正确做法**：

```python
# Trace 必须含 4 字段
trace = {
    "trace_id": "trace-xxx",          # 唯一 ID
    "user_id": "user-123",            # 谁
    "agent_id": "agent-finance",      # 哪个 Agent
    "session_id": "session-456",      # 哪个会话
    "spans": [
        {
            "name": "llm_plan",
            "tool": null,
            "args": null,
            "result": "打算调用 execute_sql",
            "duration_ms": 230,
            "parent_span": "root"
        },
        {
            "name": "tool_call",
            "tool": "execute_sql",
            "args": {"query": "SELECT * FROM users"},
            "result": "100 rows",
            "duration_ms": 45,
            "policy_decision": "allow",
            "parent_span": "root"
        },
        {
            "name": "tool_call",
            "tool": "send_email",
            "args": {"to": "..."},
            "result": "sent",
            "duration_ms": 120,
            "policy_decision": "allow",
            "parent_span": "root"
        }
    ]
}
```

### 2.2 日志含敏感字段

**危险**：
```python
# 危险：明文记录 PII/凭证
logger.info(f"User input: {user_input}")
logger.info(f"System prompt: {system_prompt}")
logger.info(f"API key: {api_key}")
```

**正确**：
```python
# 安全：脱敏
logger.info(f"User input hash: {hash(user_input)}")
logger.info(f"System prompt version: {PROMPT_VERSION}")
logger.info(f"API key: {redact(api_key)}")
```

### 2.3 Audit 决策不记录

**症状**：
- 不知道哪个 Policy 规则拒绝了什么
- 不知道审批人是谁、什么时间批准

**正确做法**：
```python
audit_log = {
    "policy_decision": "require_approval",
    "rule": "send_email_to_external",
    "agent_id": "agent-finance",
    "user_id": "user-123",
    "tool": "send_email",
    "args_hash": hash(args),
    "approver": "alice@corp.com",
    "approved_at": "2026-06-17T10:30:00Z",
    "executed": true
}
```

### 2.4 Evals 缺位

**症状**：
- 不知道 Prompt 改一版后安全水位是否变化
- 不知道新工具引入是否引入新漏洞
- 不知道模型升级后是否退化

**正确做法**：维护红队回归集。

```python
# evals/red_team/test_prompt_injection.py
@pytest.mark.parametrize("payload", INJECTION_PAYLOADS)
def test_against_prompt_injection(payload):
    response = agent.run(payload)
    assert response.tool_calls == []  # 不应触发工具
    assert "system prompt" not in response.text.lower()  # 不泄露
    assert response.status != 'compromised'
```

### 2.5 行为基线缺失

**症状**：无法识别异常（攻击 vs 正常用法）。

**正确做法**：建立基线。

```yaml
baselines:
  agent-finance:
    avg_session_duration: 120s
    avg_tool_calls_per_session: 3.5
    top_tools: [query_user_order, get_revenue]
    external_recipient_rate: 0%
    unusual_patterns:
      - "data export to external"
      - "after-hours high-value ops"
```

### 2.6 缺乏版本追踪

**症状**：事故发生时不知道跑的是哪个版本。

**正确做法**：
```python
# 每次调用记录版本
metadata = {
    "prompt_version": "v1.2.3",
    "model_version": "claude-3-5-sonnet-20251001",
    "tool_version": "registry-v2",
    "agent_version": "finance-bot-v3"
}
```

### 2.7 Trace Replay 缺位

**症状**：修复后无法验证"是否真堵住了"。

**正确做法**：
```python
# 用事故 trace 重放
replay_trace(
    trace_id='incident-2026-05-12',
    patches=['fix-VULN-001']
)
# 验证：VULN-001 攻击路径不再成功
```

---

## 3. 最小可观测集（MVI）

| 指标 | 采集位置 | 告警阈值 |
|------|---------|---------|
| 端到端成功率 | 终态节点 | 24h 下降 > 2-5% |
| 注入攻击成功率 (ASR) | 红队回归 | 高于基线 |
| 工具调用错误率 | 工具层 span | 30m 高于基线 + Δ |
| 越权拒绝率 | 策略层 | 突增（结构变化） |
| 写操作回滚率 | 写工具层 | 高于基线 + Δ |
| 循环率/重试率 | 规划/执行 trace | > N 次占比上升 |
| 预算耗尽率 | 执行层 | 24h 上升显著 |
| 外发阻断率 | 出站网关 | 突增（疑似攻击） |
| DLP 命中率 | 输出层 | 突增或高风险命中 |
| 记忆写入异常率 | 记忆写入日志 | 高于基线 + Δ |

---

## 4. Trace Schema (OTel 扩展)

```python
from opentelemetry import trace

# 扩展 Agent 语义
span_attributes = {
    # 身份 4 字段
    "agent.id": "agent-finance",
    "agent.type": "support",
    "user.id": "user-123",
    "session.id": "session-456",
    "trace.id": "trace-xxx",

    # 工具维度
    "tool.name": "send_email",
    "tool.risk_level": "high",
    "tool.requires_approval": True,
    "tool.executed": True,

    # 资源维度
    "resource.type": "external_recipient",
    "resource.value": "attacker@evil.com",

    # 策略维度
    "policy.decision": "require_approval",
    "policy.rule": "external_recipient",
    "policy.approver": "alice@corp.com",

    # 版本维度
    "version.prompt": "v1.2.3",
    "version.model": "claude-3-5-sonnet",
    "version.tool": "registry-v2",
    "version.agent": "v3"
}
```

---

## 5. 事故响应

### 5.1 最小响应清单

```yaml
incident_response:
  detection:
    - 监控告警触发
    - 用户报告
    - 红队发现
  containment:
    - 隔离 Agent（revoke identity）
    - 吊销短期 token
    - 封禁高风险工具
    - 暂停外发能力
  investigation:
    - trace replay
    - audit log 查询
    - 影响面评估
  remediation:
    - 修补代码/策略
    - 更新 Tool Registry
    - 增加红队回归用例
  communication:
    - 内部通报
    - 客户告知（如涉及数据泄露）
    - 监管报告（按合规要求）
```

### 5.2 Trace Replay 工具

```python
class TraceReplayer:
    def replay(self, trace_id, modifications=None):
        """重放事故 trace，验证修复"""
        original_trace = trace_store.get(trace_id)

        # 应用修改（修补后的代码/策略）
        if modifications:
            self._apply_modifications(modifications)

        # 重放
        new_responses = []
        for span in original_trace['spans']:
            if span['type'] == 'llm_plan':
                response = self.llm.complete(span['input'])
                new_responses.append(response)
            elif span['type'] == 'tool_call':
                # 用修补后的工具重放
                response = self.tool_registry[span['tool']](**span['args'])
                new_responses.append(response)

        return self._compare(original_trace, new_responses)
```

---

## 6. 检测命令

```bash
# Trace 框架
grep -rn "tracer\|opentelemetry\|langfuse" --include="*.py"

# 4 字段是否记录
grep -rn "user_id\|agent_id\|session_id\|trace_id" --include="*.py"

# 日志含敏感字段
grep -rn "logger.*prompt\|logger.*secret\|logger.*password" --include="*.py"

# Evals 存在性
find . -name "evals" -type d
grep -rn "ragas\|deepeval\|promptfoo" requirements.txt package.json
```

## 7. 检查清单

- [ ] 是否有 trace 框架
- [ ] trace 是否含 4 字段（user/agent/session/traceId）
- [ ] 工具调用是否记录参数 + 返回值
- [ ] 是否记录 policy decision
- [ ] 日志是否脱敏
- [ ] 是否有 Evals 套件
- [ ] 是否有行为基线
- [ ] 是否有 trace replay 能力
- [ ] 是否记录 prompt/model/tool 版本
- [ ] 是否有 SLO/告警
- [ ] 是否有事故响应 runbook
