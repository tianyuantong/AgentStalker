# AgentStalker v2 路线图

本文档记录已实现的能力、计划中的能力,以及明确不在当前范围内的事项。

---

## 已实现

### Phase A — v1 地基修复(本轮)

| 能力 | 文件 | 说明 |
|------|------|------|
| Rust taint tracker 合并 + C3 修复 | `core/taint_tracker_rust.py` | 合并 full+fast 双 tracker,修重复 dict key 导致动态 SHELL_CMD 漏报 |
| monitoring 包可 import(C1) | `sandbox/monitoring/` | 拆 `_secondary_monitors.py` 为 3 个正式模块 |
| executors 包重构(C2/C4) | `sandbox/executors/` | 拆 `_other_executors.py`,修 NameError + ExecutionResult 冲突 |
| adapters 包重构(H2/H6) | `sandbox/adapters/` | 拆 `_other_frameworks.py`,加 ADAPTER_REGISTRY + get_adapter() |
| heal_diagnose sys(C4) | `sandbox/heal_diagnose.py` | 修 stdin 路径 UnboundLocalError |
| 测试基础设施 | `tests/`, `pyproject.toml` | pytest + 76 个回归测试,守护所有 C1-C5 bug |

### Phase B — MCP 全套审计(本轮新增)

| 能力 | 文件 | 说明 |
|------|------|------|
| MCP 静态抽取 | `core/ast_extractor.py::_extract_mcp` | 工具名/描述/传输(stdio/sse/http),激活死代码 |
| MCP 检测器 | `core/mcp_auditor.py` | R-MCP-SQUAT-001 / R-MCP-DESC-001 / R-MCP-TOKEN-001 |
| MCP 运行时验证 | `sandbox/monitoring/mcp_monitor.py` | MCPMonitor 驱动真实 server,squatting/poisoning/response-injection |
| Verdict R009-R011 | `sandbox/correlation/__init__.py` | MCP 专属规则,兑现 README 声称的 R-MCP-SQUAT-001 |
| MCP payloads | `payloads/mcp.yaml` | 第 14 个 payload 类别 |
| Rust MCP 检测 | `core/mcp_auditor.py::_audit_rust_mcp_servers` | reqwest/ureq token passthrough + doc comment 投毒 |

### Phase C — v2 语义引擎(本轮新增)

| 能力 | 文件 | 说明 |
|------|------|------|
| LLM 调用点抽取 | `core/ast_extractor.py::_extract_llm_invocations` | ChatOpenAI/.invoke()/chat.completions.create |
| 语义污点引擎骨架 | `core/semantic_taint.py` | v2 断点一:LLM hop 概率传播,累积置信度 |
| TaintFlow 置信度字段 | `core/taint_tracker.py` | confidence + feature_type + llm_hops(非破坏) |

---

## 计划中(需额外环境/数据)

### v2 断点一:语义污点引擎校准(当前是骨架)

**当前状态**:`core/semantic_taint.py` 用保守默认值(gpt-4 抵抗 0.70、claude 0.75、open_source 0.50、unknown 0.60)。

**待做**:建立 1000 条对抗测试集校准传播概率。
- 准备 50 个 Agent 项目(GitHub 开源 + 内部)
- 每个 Agent 构造 20 条不同特征输入(direct_instruction / structured_data / indirect_reference / non_text)
- 运行 Agent,统计"输入被成功污染后、LLM 输出确实被改变"的比例
- 输出概率表(按 LLM 型号分表)

**前置条件**:能运行真实 Agent 项目(需 LLM API key + 可运行的 Agent 代码库)。

### v2 断点二:行为基线引擎(eBPF + tool call 语义关联)

**当前状态**:零实现。`EBPFRunner`(sandbox/monitoring/ebpf_runner.py)只有 Tracee docker 编排骨架,无 syscall 与 tool call 的语义关联。

**设计**:
- 在 Agent 工具入口注入 hook(装饰器),记录每次 tool call 的 `{call_id, pid, timestamp, tool_name, args, user_intent}`
- eBPF 探针捕获 syscall,按 PID + 时间窗口关联到 tool call
- 用正常输入跑 N 轮建立行为基线(正常文件/网络/工具序列)
- 运行时偏离基线 = 异常

**前置条件**:Linux + rootless eBPF / Tracee 0.8+ + Docker Engine 24+(沙箱 7 容器)。Windows 环境无法验证。

### v2 断点三:静动关联引擎(自动闭环)

**当前状态**:零实现。

**设计**:
- 静态风险路径 → 自动生成 eBPF 验证策略(hook 点 + 捕获 syscall + 判定规则 + 测试输入)
- 自动执行验证,回填结果到风险路径(确认则置信度 +,未触发则 -)
- 静态置信度 × 动态置信度融合(Stage 4 VerdictEngine R005 是融合点)

**前置条件**:断点二完成 + 真实 Agent 测试环境。

### MCP 扩展检测器

| 向量 | 状态 | references |
|------|------|-----------|
| OAuth scope 过权 | 仅文档 | `references/mcp-risks.md` §2.6 |
| Session Hijack(mTLS/session binding) | 仅文档 | `references/mcp-risks.md` §2.3 |
| SBOM / 供应链签名 / 镜像锁定 | 仅文档 | `references/mcp-risks.md` §2.5 |
| Rust MCP 工具名 squatting | 待做 | 需先增强 `ast_extractor_rust.py` 抽工具名(当前只记 server 位置) |

---

## 明确不做(范围决策)

| 项 | 原因 |
|----|------|
| 引入 `logging` 模块 | 全仓 0 处 logging,`print("[!]")` 是给 Claude Code 编排器读的契约;引入会风格分裂 |
| 全量替换 94 处 `print` | 同上 |
| 统一 argparse(M5) | 每个 CLI 接口差异是合理的,工作量大价值低 |
| env 化所有 localhost 默认值(M6) | 沙箱默认 localhost 是合理的;`AGENT_ENDPOINT` 已支持 env 覆盖 |
| Stage 4 R005 static×dynamic 融合 | 用户本轮未选;断点三完成时一并做 |

---

## 测试与质量

- **76 个回归测试**(本路线图对应轮次),覆盖 C1-C5 bug 回归、MCP 全链路、语义引擎
- **fixture**:`testbeds/` 下 4 个被测对象(rust_mini_agent / mcp_mini_server / rust_mcp_server / python_mini_agent)
- **MCP 运行时测试**需 `pip install mcp fastmcp`(已写入 pyproject.toml `[test]` extras)
- 所有测试本机可跑(无需 Docker/eBPF/LLM API key)
