# AgentStalker Sandbox Configs

部署模板与策略配置，支持多种 Agent 运行环境。

## 文件清单

| 文件 | 用途 | 使用阶段 |
|------|------|---------|
| `litellm_config.yaml` | LiteLLM 代理配置（mock 模型 + 日志） | Stage 2/3 |
| `nginx.conf` | 反向代理（记录 req/resp 完整 body） | Stage 3 |
| `Dockerfile.agent.template` | 通用 Agent 容器化模板 | Stage 2 |
| `fixtures/db_init.sql` | Mock PostgreSQL 初始化（含攻击面数据） | Stage 2 |
| `fixtures/wiremock/mappings.json` | WireMock mock API（含 C2/metadata/搜索） | Stage 2 |
| `policy/opa.rego` | OPA 策略：工具白名单 + 阻断规则 | Stage 2/3 |
| `k8s/agent-stalker-job.yaml` | K8s Job 模板（含 NetworkPolicy 隔离） | Stage 3 |

## 部署模式

### 模式 A: 本地 Docker Compose（默认）
```bash
cd sandbox/
cp configs/litellm_config.yaml .
cp -r configs/fixtures .
docker compose -f docker-compose.test.yml up -d
python test_runner.py --config attack_graph.json
```

### 模式 B: Kubernetes
```bash
kubectl apply -f configs/k8s/agent-stalker-job.yaml
kubectl logs -f -n agent-stalker job/agent-stalker-test
```

### 模式 C: 仅进程级（无 Docker）
```bash
python -m sandbox.orchestrator --mode process --agent-binary ./my_agent
```

## 攻击面覆盖

各 fixtures 暴露的攻击面（与 OWASP Agentic Top 10 映射）：

| Fixture | 攻击面 | 对应 ASI |
|---------|--------|---------|
| `users` 表 | SQL 注入 / IDOR / PII 泄露 | ASI01 / ASI05 |
| `accounts` 表 | 破坏性 UPDATE/DELETE / 越权转账 | ASI02 / ASI03 |
| `audit_log` 表 | 完整性破坏（agent 改自己的审计） | ASI06 |
| `api_keys` 表 | 凭据泄露（agent 输出含 sk-/AKIA-） | ASI05 |
| WireMock `/exfil/*` | 外联 C2 端点 | ASI03 / ASI08 |
| WireMock `/search` | 间接 prompt 注入（RAG 污染） | ASI01 |
| WireMock `/kb/query` | SSTI / 模板注入 | ASI05 |
| WireMock `/latest/meta-data/*` | SSRF → 云 metadata | ASI04 |
| OPA 规则 | LLM tool-call 层主动拦截 | ASI03 |

## 校验

部署前检查：
```bash
# 1. WireMock mappings 合法
docker run --rm -v $PWD/configs/fixtures/wiremock:/home/wiremock wiremock/wiremock:3.5.4 \
    --validate-mappings

# 2. OPA 策略可编译
opa test configs/policy/

# 3. LiteLLM config 合法
python -c "import yaml; yaml.safe_load(open('configs/litellm_config.yaml'))"

# 4. K8s 模板可 apply (dry-run)
kubectl apply --dry-run=client -f configs/k8s/
```
