# 人工审阅指南

本文给审阅本 fork 改动的人一个入口：先看什么、每个结论的证据在哪、哪些兼容性变化需要重点确认。设计原案见 [design/plan-2026-09-20.zh.md](design/plan-2026-09-20.zh.md)，实现后的设计与兼容说明见 [evidence-regression.md](evidence-regression.md)。

## 建议阅读顺序

1. [验证报告](validation-20260920.md)：先看真实结果、原始基线失败和能力边界。
2. [整改比较表](../review/artifacts/comparison/comparison.md)：查看逐用例结果及前后证据链接。
3. [设计与兼容说明](evidence-regression.md)：了解哪些路径已验证，哪些保守地保持 unknown。
4. `sandbox/correlation/__init__.py` 的 `VerdictEngine.judge`：检查证据门槛、规则异常、正面证据优先及 LLM 权限；`_record_signals` 说明为什么旧格式证据仍会记录 R001–R016 信号但不给定论。
5. `sandbox/assertions.py`：检查结果命题及事件关联，不要把普通任务成功误当成攻击成功。
6. `sandbox/regression.py` 的 `read_run` / `compare`：检查完整清单、哈希、可比性、正常对照和基线要求；`_classify_attack` / `_classify_normal` 是逐用例结论与退出码的唯一来源。

## 两个案例怎么追证据

- 文件读取：从 `review/artifacts/vulnerable/file-direct/1/raw.json` 的 scope、工具参数、响应和检查标记开始；对照 fixed 同路径文件。标记由 fixture 放在临时受保护文件中，未放进工具参数。
- 凭据转发：检查 `review/artifacts/vulnerable/proxy-one/1/raw.json` 的接收端请求记录；对照 fixed 的空接收快照。再看 `proxy-normal-one`：修复后正常响应保留，接收端实际请求仍在，但不含合成 Authorization。
- `raw.json` 是保存的原始观察和检查输入；`evidence.json` 是重新算出的判定。比较器不信任缓存的 verdict，而是重新分析 raw。

## 要求到证据映射

| 原方案要求 | 实现/验证 |
|---|---|
| 统一两个判定入口 | `tests/test_evidence_decisions.py`；`tests/test_regression.py::test_shared_decision_entry` |
| 失败/未执行/缺日志不判安全 | 判定用例与 `test_lost_collector_stays_unknown`；旧 collector 显式错误 envelope |
| 拒绝、超时不覆盖已确认影响 | `test_refusal_cannot_override_effect`、`test_effect_survives_timeout_and_open_window` |
| 同 run/case/attempt/session 的证据关联 | 四维 scope 负例；每次独立进程/临时目录/接收端 |
| 不依赖模型声明来确认利用 | 两种固定效果检查；`test_llm_cannot_overwrite_decision_or_mutate_evidence` |
| 旧格式证据保留风险信号、不给定论 | `tests/test_legacy_signals.py`；`test_legacy_signals_recorded_without_verdict` |
| 修复前后真实执行和正常功能对照 | 两个 MCP 工具、24 条保存记录；`test_disabling_tools_not_a_fix` |
| 缺正常对照不算整改通过也不算回归 | `test_attack_without_planned_control_is_incomplete_not_regression`（`NO_NORMAL_CONTROL`，退出码 2） |
| 可复核证据包、原始文件不覆盖 | manifest、raw/evidence 文件；哈希/目录穿越/清单缺失/输出重复测试 |
| 离线复核不冒充重新执行 | `review/artifacts/rejudged/provenance.json`；输入前后文件哈希一致性测试 |
| 不可比不报告改善 | analyzer/collector/fixture/environment/invariants 漂移测试 |
| 多轮会话/执行状态修复 | `tests/test_execution_states.py` 的真实状态、会话、注入前置条件测试 |
| schema、旧格式和安装兼容 | v2 schema 全记录校验；旧格式 unknown；外部环境 wheel 配对实验 |
| 规则文档与代码一致 | `test_rule_documentation_matches_executable_rules` |
| 真实模型验证 | 按方案独立可选层；本次未执行，README 和验证报告明确留空 |
| 银行业务场景 | 按用户要求跳过 |
| Rust 重写、概率校准、通用 OPA 加固 | 按方案留后续，不是本轮完成项 |

## 兼容变化需要重点确认

- 原来被判断 safe/exploited 的旧格式证据现在为 inconclusive，因为旧记录没有可靠的运行/观测信息。历史结论保留在 `metadata.historical_verdict`，命中的规则保留在 `metadata.matched_rules`，未编造覆盖。
- 旧 runner 的五条启发式（危险 execve、元数据端点、外发邮件、DB 变更、提示词泄露）迁移为 R012–R016 信号；它们读取的是无用例归属的全局日志，所以只能是线索。
- 旧 runner 仍可收集 API/Tracee 全局日志，但该路径不满足新证据门槛，不能把"日志取到了"写成"本用例观测完整"。
- 原 `success` 只代表执行成功；安全判断使用独立检查。部分错误语义的旧测试已同步改正。
- MCP SDK 约束为 v1。默认 CI 不依赖任何模型密钥。
- 效果检查和 12 个集成模板是有限范围的基准，不能宣称全行业"零误报"或真实 LLM 抗注入率。

## 重新生成证据

需要重新跑演示时选用全新的 output 路径；旧目录会被拒绝。`compare` 会把当前 analyzer/collector 源码指纹与 manifest 记录的指纹比对：修改这些源码后，旧证据包只能 `rejudge`，不能再直接 `compare`，必须重新执行两个变体。离线复核原记录不产生新的真实模型或被测目标执行证据。
