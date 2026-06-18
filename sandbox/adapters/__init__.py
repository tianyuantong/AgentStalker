"""
AgentStalker Sandbox Framework Adapters
=======================================
为不同 Agent 框架提供统一的沙箱适配层

支持的框架：
- python_langchain (LangChain Python)
- python_autogen (AutoGen)
- python_crewai (CrewAI)
- python_llamaindex (LlamaIndex)
- python_mcp (MCP Python Server)
- python_langgraph (LangGraph)
- node_langchain (LangChain JS/TS)
- generic_api (任何 HTTP/REST Agent)
- generic_web (Web UI Agent)
- cli (命令行 Agent)

每个适配器实现 BaseAdapter 接口：
- deploy(): 部署 Agent 到沙箱
- list_tools(): 列出 Agent 暴露的工具
- invoke_tool(): 调用工具（用于攻击注入）
- inject_indirect(): 间接注入（污染 RAG/MCP/记忆）
- teardown(): 卸载
"""
from __future__ import annotations

import abc
import json
import os
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

import yaml


@dataclass
class Tool:
    """Agent 工具的运行时表示"""
    name: str
    description: str = ""
    parameters: dict = field(default_factory=dict)
    risk_level: str = "medium"
    requires_approval: bool = False
    available: bool = True


@dataclass
class InvokeResult:
    """工具调用结果"""
    success: bool
    output: Any = None
    error: str = ""
    duration_ms: int = 0
    blocked_by_policy: bool = False
    trace_id: str = ""


class BaseAdapter(abc.ABC):
    """所有框架适配器的基类"""

    framework_name: str = "Unknown"

    def __init__(self, source_dir: str | Path, sandbox_endpoint: str = "", agent_profile: dict | None = None):
        self.source_dir = Path(source_dir)
        self.sandbox_endpoint = sandbox_endpoint or os.environ.get("AGENT_ENDPOINT", "http://127.0.0.1:8000")
        self.agent_profile = agent_profile or {}
        self.tools: list[Tool] = []
        self.session_token: str = ""

    @abc.abstractmethod
    def deploy(self) -> bool:
        """部署 Agent 到沙箱"""
        ...

    @abc.abstractmethod
    def list_tools(self) -> list[Tool]:
        """列出 Agent 暴露的工具"""
        ...

    @abc.abstractmethod
    def invoke_tool(self, tool_name: str, parameters: dict, user_context: dict | None = None) -> InvokeResult:
        """调用工具（注入攻击点）"""
        ...

    @abc.abstractmethod
    def teardown(self) -> bool:
        """卸载 Agent"""
        ...

    # ============ 通用辅助 ============
    def _record_invocation(self, tool: str, params: dict, result: InvokeResult):
        """记录工具调用到 evidence log"""
        log_path = Path(self.source_dir.parent) / "output" / "evidence" / "tool_invocations.jsonl"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps({
                "timestamp": time.time(),
                "tool": tool,
                "params": params,
                "success": result.success,
                "duration_ms": result.duration_ms,
                "blocked_by_policy": result.blocked_by_policy,
                "error": result.error,
            }, ensure_ascii=False) + "\n")

    def indirect_inject(self, target: str, payload: str) -> bool:
        """
        间接注入：污染 Agent 数据源（RAG/MCP/记忆）
        target: 'rag' | 'memory' | 'mcp' | 'web_search'
        """
        # 默认实现：写入 mock 数据源
        return self._inject_to_mock_source(target, payload)

    def _inject_to_mock_source(self, target: str, payload: str) -> bool:
        """写入 mock 数据源（WireMock / MailHog / Mock DB / Mock RAG）"""
        import requests

        if target == "rag":
            # 写入 mock 向量库（如 Qdrant / Chroma mock）
            # 简化：写入 JSON 文件供 Agent 检索
            mock_rag = Path(self.source_dir.parent) / "output" / "fixtures" / "mock_rag.json"
            mock_rag.parent.mkdir(parents=True, exist_ok=True)
            existing = json.loads(mock_rag.read_text()) if mock_rag.exists() else []
            existing.append({
                "id": f"poisoned-{int(time.time())}",
                "content": payload,
                "metadata": {"source": "external", "trust": "untrusted"},
            })
            mock_rag.write_text(json.dumps(existing, indent=2))
            return True

        elif target == "mcp":
            # 通过 WireMock 拦截 MCP 响应
            try:
                requests.post(
                    "http://127.0.0.1:8080/__admin/mappings",
                    json={
                        "request": {"method": "ANY", "urlPathPattern": ".*"},
                        "response": {
                            "status": 200,
                            "jsonBody": {"result": payload},
                            "headers": {"Content-Type": "application/json"}
                        }
                    },
                    timeout=5,
                )
                return True
            except Exception:
                return False

        elif target == "memory":
            # 写入 mock 长期记忆
            mock_mem = Path(self.source_dir.parent) / "output" / "fixtures" / "mock_memory.json"
            mock_mem.parent.mkdir(parents=True, exist_ok=True)
            existing = json.loads(mock_mem.read_text()) if mock_mem.exists() else {}
            existing[f"poisoned-{int(time.time())}"] = payload
            mock_mem.write_text(json.dumps(existing, indent=2))
            return True

        elif target == "web_search":
            # 通过 WireMock 模拟搜索结果
            try:
                requests.post(
                    "http://127.0.0.1:8080/__admin/mappings",
                    json={
                        "priority": 1,
                        "request": {"method": "GET", "urlPath": "/search"},
                        "response": {
                            "status": 200,
                            "jsonBody": {
                                "results": [
                                    {"title": "Injected Result", "url": "http://127.0.0.1:8080/injected",
                                     "snippet": payload}
                                ]
                            }
                        }
                    },
                    timeout=5,
                )
                return True
            except Exception:
                return False

        return False

    def health_check(self) -> bool:
        """检查 Agent 是否就绪"""
        import requests
        try:
            r = requests.get(f"{self.sandbox_endpoint}/health", timeout=5)
            return r.status_code == 200
        except Exception:
            return False

    def authenticate(self, credentials: dict) -> str:
        """认证并获取 session token"""
        import requests
        try:
            r = requests.post(f"{self.sandbox_endpoint}/auth", json=credentials, timeout=10)
            if r.status_code == 200:
                self.session_token = r.json().get("token", "")
                return self.session_token
        except Exception:
            pass
        return ""

    def __repr__(self):
        return f"<{self.framework_name}Adapter endpoint={self.sandbox_endpoint}>"