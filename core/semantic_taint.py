"""
AgentStalker Semantic Taint Engine — v2 断点一骨架
===================================================
修复 v1 taint tracker 在 LLM 节点的"断链"问题:v1 把 LLM 输出全标记为污染,
导致下游所有 tool call 都报警(高误报)。本引擎对 LLM hop 做**概率传播**:
根据输入特征分类计算传播概率,产出累积置信度。

设计:WRAP 不 REPLACE。本引擎后处理 TaintTracker.track() 的输出,不替换它。
保守默认值(留校准接口,不做 1000 条对抗测试集 —— 当前环境不可行)。

概率模型:
  输入特征类型 → 传播概率(经验默认值,需对抗测试校准):
    direct_instruction   0.85  (用户直接注入)
    structured_data      0.60  (prompt 模板拼入用户字段)
    indirect_reference   0.40  (RAG/文件/MCP 间接内容)
    non_text             0.15  (图片/二进制)

  LLM 抵抗因子(占位默认,按 LLM 型号校准):
    gpt-4        0.70
    claude       0.75
    open_source  0.50
    unknown      0.60

  LLM hop 传播概率 = 输入特征概率 × LLM 抵抗因子
  flow 累积置信度 = 路径上所有 hop 的传播概率之乘积

明确不做(超本轮):
  - 1000 条对抗测试集(环境不可行,留校准接口)
  - 断点二/三(eBPF + 静动关联,需 Linux + 真实 Agent)
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class InputFeatureType(Enum):
    """输入特征类型 + 默认传播概率(经验值,需对抗测试校准)。"""
    DIRECT_INSTRUCTION = ("direct_instruction", 0.85)    # 用户直接消息
    STRUCTURED_DATA = ("structured_data", 0.60)          # prompt 模板拼入用户字段
    INDIRECT_REFERENCE = ("indirect_reference", 0.40)    # RAG/文件/MCP 间接内容
    NON_TEXT = ("non_text", 0.15)                        # 图片/二进制/结构化 JSON 参数

    @property
    def probability(self) -> float:
        return self.value[1]

    @property
    def label(self) -> str:
        return self.value[0]


# LLM 抵抗因子占位默认值(需按 LLM 型号用对抗测试校准)。
# 含义:LLM 把被污染输入"传递下去成为污染输出"的概率折扣。
# gpt-4/claude 抵抗较强(指令遵循好),开源模型较弱。
LLM_RESISTANCE_DEFAULTS: dict[str, float] = {
    "gpt-4": 0.70,
    "gpt-4o": 0.70,
    "gpt-3.5": 0.50,
    "claude": 0.75,
    "claude-3": 0.75,
    "claude-sonnet": 0.75,
    "claude-opus": 0.75,
    "claude-haiku": 0.65,
    "deepseek": 0.55,
    "open_source": 0.50,
    "unknown": 0.60,
}


# Source kind → 输入特征类型映射(v1 TaintKind → v2 InputFeatureType)
# 这决定了"这条流的源头属于哪类注入风险"。
SOURCE_TO_FEATURE = {
    "user_input": InputFeatureType.DIRECT_INSTRUCTION,
    "rag_context": InputFeatureType.INDIRECT_REFERENCE,
    "mcp_response": InputFeatureType.INDIRECT_REFERENCE,
    "memory_read": InputFeatureType.INDIRECT_REFERENCE,
    "tool_result": InputFeatureType.STRUCTURED_DATA,
    "web_fetch": InputFeatureType.INDIRECT_REFERENCE,
    "file_content": InputFeatureType.INDIRECT_REFERENCE,
    "config_read": InputFeatureType.INDIRECT_REFERENCE,
}


class SemanticTaintGraph:
    """语义污点传播图(v2 断点一)

    用法:
        tracker = TaintTracker(source_dir, agent_model)
        flows = tracker.track()
        stg = SemanticTaintGraph(agent_model, llm_resistance={"gpt-4": 0.7})
        enriched_flows = stg.enrich(flows)  # 给每个 flow 加 confidence/feature_type/llm_hops
    """

    def __init__(
        self,
        agent_model: dict,
        llm_resistance: dict[str, float] | None = None,
        llm_model_hint: str = "unknown",
    ):
        """
        Args:
            agent_model: agent_model.json(含 Commit 11 的 llm_invocations[])
            llm_resistance: 覆盖默认 LLM 抵抗因子(校准用)
            llm_model_hint: LLM 型号提示(从 agent_model 推断或 caller 指定),
                            用于查 LLM_RESISTANCE_DEFAULTS
        """
        self.agent_model = agent_model
        self.llm_resistance = {**LLM_RESISTANCE_DEFAULTS, **(llm_resistance or {})}
        self.llm_model_hint = llm_model_hint
        # 预处理:从 agent_model 推断 LLM 型号
        self._llm_model = self._infer_llm_model()

    def enrich(self, flows: list) -> list:
        """对每个 flow:分类输入特征 → 检测是否经 LLM hop → 计算累积置信度。

        flows 元素是 core.taint_tracker.TaintFlow(就地修改)。
        返回同一列表(便于链式调用)。
        """
        llm_invocations = self.agent_model.get("llm_invocations", [])
        for flow in flows:
            # 1. 分类输入特征
            source_kind = self._get_source_kind(flow)
            feature_type = SOURCE_TO_FEATURE.get(source_kind, InputFeatureType.STRUCTURED_DATA)
            flow.feature_type = feature_type.label

            # 2. 检测 flow 是否经 LLM hop(启发式:flow 的 source_location 文件里有 LLM 调用,
            #    或 flow 的 path 包含已知 LLM 相关变量名)
            llm_hop = self._detect_llm_hop(flow, llm_invocations)

            # 3. 计算累积置信度
            if llm_hop:
                # 经 LLM:confidence = 输入特征概率 × LLM 抵抗因子
                resistance = self.llm_resistance.get(self._llm_model, self.llm_resistance["unknown"])
                hop_prob = feature_type.probability * resistance
                flow.confidence = round(hop_prob, 3)
                flow.llm_hops = [{
                    "model": self._llm_model,
                    "input_feature": feature_type.label,
                    "input_prob": feature_type.probability,
                    "resistance": resistance,
                    "hop_prob": round(hop_prob, 3),
                }]
            else:
                # 不经 LLM:confidence 保持 1.0(直接污点流,无概率折扣)
                flow.confidence = 1.0
                flow.llm_hops = []

        return flows

    # ============ 内部 ============
    def _get_source_kind(self, flow) -> str:
        """从 TaintFlow 取 source kind 字符串"""
        # TaintNode.kind 是 TaintKind(Enum),.value 是字符串
        try:
            return flow.source.kind.value
        except AttributeError:
            # 兼容 dict 形态
            return flow.source.get("kind", "") if isinstance(flow.source, dict) else ""

    def _detect_llm_hop(self, flow, llm_invocations: list[dict]) -> bool:
        """启发式判断 flow 是否经过 LLM 节点。

        判据(任一成立):
        1. flow 的 source 文件里有 LLM 调用(agent_model.llm_invocations)
        2. flow 的 path 包含 LLM 相关变量名(llm/chain/agent/response/output)
        3. sink 是 PROMPT_CONSTRUCT(值拼接到 prompt,必然经 LLM)
        """
        # 判据 3:sink 是 prompt_construct
        try:
            sink_kind = flow.sink.kind.value
        except AttributeError:
            sink_kind = ""
        if sink_kind == "prompt_construct":
            return True

        # 判据 1:source 文件有 LLM 调用
        try:
            source_loc = flow.source.source_location  # "file.py:42"
        except AttributeError:
            source_loc = ""
        source_file = source_loc.split(":")[0] if source_loc else ""
        if source_file and any(
            inv.get("file") == source_file for inv in llm_invocations
        ):
            return True

        # 判据 2:path 含 LLM 相关变量名
        import re
        path_str = " ".join(flow.path or [])
        if re.search(r'\b(llm|chain|agent|response|output|prompt|completion|message)\b',
                     path_str, re.IGNORECASE):
            return True

        return False

    def _infer_llm_model(self) -> str:
        """从 agent_model 推断 LLM 型号(用于查抵抗因子)。"""
        # 看 system_prompts / llm_invocations 里有没有型号提示
        for inv in self.agent_model.get("llm_invocations", []):
            callee = inv.get("callee", "").lower()
            for model_key in self.llm_resistance:
                if model_key in callee:
                    return model_key
        # 看依赖
        deps = " ".join(self.agent_model.get("dependencies", []) or []).lower()
        if "gpt-4" in deps or "openai" in deps:
            return "gpt-4"
        if "anthropic" in deps or "claude" in deps:
            return "claude"
        if "deepseek" in deps:
            return "deepseek"
        return self.llm_model_hint
