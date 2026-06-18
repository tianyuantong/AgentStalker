"""
LLM Proxy — LLM 调用代理（LiteLLM wrapper）
- 拦截所有 prompt/response
- 提取敏感 token（API key, 系统提示词）
- 检测 prompt 注入尝试
- 标记每条调用与 trace_id
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, asdict, field


@dataclass
class LLMEvent:
    timestamp: float
    layer: str = "llm"
    event_type: str = ""     # request | response | tool_call | refusal
    trace_id: str = ""
    user_id: str = ""
    session_id: str = ""
    agent_id: str = ""
    model: str = ""
    prompt_preview: str = ""
    response_preview: str = ""
    token_usage: dict = field(default_factory=dict)
    tool_calls: list[dict] = field(default_factory=list)
    refusal: bool = False
    injection_detected: bool = False
    sensitive_leak: bool = False
    verdict: str = "neutral"


class LLMProxy:
    """LLM 调用代理（基于 LiteLLM logging callback）"""

    INJECTION_PATTERNS = [
        r"ignore (all )?previous instructions",
        r"忽略.*之前.*指令",
        r"disregard (all )?(prior|above) instructions",
        r"system\s*:\s*you are",
        r"</?\s*system\s*>",
        r"\[INST\]",
        r"<\|im_start\|>system",
        r"###\s*Instruction\s*:",
        r"\bdeveloper mode\b",
        r"\bjailbreak\b",
    ]

    SENSITIVE_PATTERNS = [
        # API keys
        (r"sk-[a-zA-Z0-9]{20,}", "openai_key"),
        (r"sk-ant-[a-zA-Z0-9-]{20,}", "anthropic_key"),
        (r"AIza[0-9A-Za-z_-]{35}", "google_key"),
        (r"AKIA[0-9A-Z]{16}", "aws_access_key"),
        (r"ghp_[a-zA-Z0-9]{36}", "github_token"),
        # 系统提示词泄露
        (r"my (initial|system) prompt", "system_prompt_leak"),
        (r"the (original|true) instructions", "system_prompt_leak"),
        # 凭据
        (r"password[:=]\s*['\"]?\w{6,}", "password"),
        (r"BEGIN RSA PRIVATE KEY", "private_key"),
        (r"BEGIN OPENSSH PRIVATE KEY", "ssh_key"),
    ]

    def __init__(self, output_dir: str = "./output/evidence"):
        self.output_dir = output_dir
        self.events: list[LLMEvent] = []

    def ingest_litellm_log(self, log_path: str) -> list[LLMEvent]:
        """从 LiteLLM 日志解析（JSON Lines）"""
        events = []
        try:
            with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line.startswith("{"):
                        continue
                    try:
                        entry = json.loads(line)
                        events.append(self._parse_litellm_entry(entry))
                    except json.JSONDecodeError:
                        continue
        except FileNotFoundError:
            pass

        self.events.extend([e for e in events if e])
        return [e for e in events if e]

    def _parse_litellm_entry(self, entry: dict) -> LLMEvent | None:
        """解析单条 LiteLLM 日志"""
        # LiteLLM 日志格式：{"call_id": ..., "model": ..., "messages": [...], "response": {...}}
        call_id = entry.get("call_id", "")
        model = entry.get("model", "")
        messages = entry.get("messages", [])

        # 提取 prompt（最后一条 user message）
        prompt_preview = ""
        for msg in reversed(messages):
            if msg.get("role") == "user":
                content = msg.get("content", "")
                if isinstance(content, str):
                    prompt_preview = content[:1000]
                break

        # 提取 response
        response = entry.get("response", {})
        if isinstance(response, dict):
            choices = response.get("choices", [])
            response_text = ""
            if choices:
                msg = choices[0].get("message", {})
                response_text = msg.get("content", "")
        else:
            response_text = str(response)

        # 提取 tool calls
        tool_calls = []
        if isinstance(response, dict):
            choices = response.get("choices", [])
            if choices:
                msg = choices[0].get("message", {})
                for tc in msg.get("tool_calls", []):
                    if isinstance(tc, dict):
                        func = tc.get("function", {})
                        tool_calls.append({
                            "name": func.get("name", ""),
                            "arguments": func.get("arguments", ""),
                        })

        # 检测
        injection_detected = self._detect_injection(prompt_preview)
        sensitive_leak = self._detect_sensitive(prompt_preview + response_text)
        refusal = "refusal" in response_text.lower() or "I cannot" in response_text[:200]

        verdict = "neutral"
        if injection_detected and tool_calls:
            verdict = "malicious"
        elif injection_detected:
            verdict = "suspicious"
        elif sensitive_leak:
            verdict = "malicious"
        elif tool_calls and any(self._is_dangerous_tool(t.get("name", "")) for t in tool_calls):
            verdict = "suspicious"

        return LLMEvent(
            timestamp=entry.get("startTime", time.time()),
            event_type="request" if response is None else "response",
            trace_id=call_id,
            model=model,
            prompt_preview=prompt_preview,
            response_preview=str(response_text)[:1000],
            token_usage=entry.get("usage", {}),
            tool_calls=tool_calls,
            refusal=refusal,
            injection_detected=injection_detected,
            sensitive_leak=sensitive_leak,
            verdict=verdict,
        )

    def _detect_injection(self, text: str) -> bool:
        if not text:
            return False
        text_lower = text.lower()
        for pat in self.INJECTION_PATTERNS:
            if re.search(pat, text_lower, re.IGNORECASE):
                return True
        return False

    def _detect_sensitive(self, text: str) -> bool:
        if not text:
            return False
        for pat, kind in self.SENSITIVE_PATTERNS:
            if re.search(pat, text):
                return True
        return False

    def _is_dangerous_tool(self, name: str) -> bool:
        n = name.lower()
        return any(k in n for k in ["shell", "exec", "command", "send_email", "transfer", "delete", "publish"])

    def save_events(self):
        out_path = f"{self.output_dir}/llm_events.json"
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump([asdict(e) for e in self.events], f, indent=2, ensure_ascii=False)

    def summarize(self) -> dict:
        """汇总统计"""
        total = len(self.events)
        injections = sum(1 for e in self.events if e.injection_detected)
        leaks = sum(1 for e in self.events if e.sensitive_leak)
        refusals = sum(1 for e in self.events if e.refusal)
        tool_calls = sum(len(e.tool_calls) for e in self.events)
        return {
            "total_calls": total,
            "injection_attempts": injections,
            "sensitive_leaks": leaks,
            "refusals": refusals,
            "total_tool_calls": tool_calls,
        }