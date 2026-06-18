"""
Generic API Adapter — 通用 HTTP/REST Agent 适配器
适用于任何暴露 HTTP 端点的 Agent（不论框架）
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

from . import BaseAdapter, Tool, InvokeResult


class GenericAPIAdapter(BaseAdapter):
    framework_name = "Generic HTTP API"

    def __init__(self, source_dir: str | Path, sandbox_endpoint: str = "", agent_profile: dict | None = None):
        super().__init__(source_dir, sandbox_endpoint, agent_profile)
        self.discovered_endpoints: list[str] = []

    def deploy(self) -> bool:
        """部署通用 HTTP Agent

        策略：
        - 不修改 Agent 本身
        - 通过 nginx 拦截 + 中间人注入 trace_id 头
        - 通过 WireMock 模拟外部依赖
        """
        # 检查连通性
        if not self.health_check():
            print(f"[!] Agent not reachable at {self.sandbox_endpoint}")
            return False

        # 探测端点
        self._discover_endpoints()
        return True

    def list_tools(self) -> list[Tool]:
        """通过 schema 探测推断工具列表"""
        tools = []
        for ep in self.discovered_endpoints:
            tools.append(Tool(
                name=f"endpoint_{ep}",
                description=f"HTTP endpoint {ep}",
                parameters={},
                risk_level="medium",
            ))
        # 也从 agent_profile 加载（如已有）
        for t in self.agent_profile.get("tools", []):
            tools.append(Tool(
                name=t.get("name", "unknown"),
                description=t.get("description", ""),
                risk_level=t.get("risk_level", "medium"),
            ))
        return tools

    def invoke_tool(self, tool_name: str, parameters: dict, user_context: dict | None = None) -> InvokeResult:
        """调用 HTTP 端点"""
        import requests
        start = time.time()

        # 解析 endpoint
        if tool_name.startswith("endpoint_"):
            endpoint = "/" + tool_name[len("endpoint_"):]
        else:
            endpoint = self._resolve_tool_to_endpoint(tool_name)

        url = self.sandbox_endpoint.rstrip("/") + endpoint

        # 决定 HTTP 方法（启发式）
        method = self._infer_method(tool_name, parameters)

        try:
            if method == "GET":
                r = requests.get(url, params=parameters, timeout=30)
            elif method == "POST":
                r = requests.post(url, json=parameters, timeout=30)
            elif method == "PUT":
                r = requests.put(url, json=parameters, timeout=30)
            elif method == "DELETE":
                r = requests.delete(url, timeout=30)
            else:
                r = requests.request(method, url, json=parameters, timeout=30)

            duration = int((time.time() - start) * 1000)
            success = 200 <= r.status_code < 300
            try:
                output = r.json()
            except Exception:
                output = {"raw": r.text}

            result = InvokeResult(
                success=success,
                output=output,
                error="" if success else f"HTTP {r.status_code}",
                duration_ms=duration,
            )
            self._record_invocation(tool_name, parameters, result)
            return result

        except Exception as e:
            return InvokeResult(
                success=False,
                error=str(e),
                duration_ms=int((time.time() - start) * 1000),
            )

    def teardown(self) -> bool:
        """通用 API 不需要 teardown（Agent 由 docker-compose 控制）"""
        return True

    # ============ 探测 ============
    def _discover_endpoints(self):
        """从 agent_profile 提取或主动探测"""
        # 从 profile
        eps = self.agent_profile.get("exposed_endpoints", [])
        self.discovered_endpoints.extend(eps)

        # 主动探测常见 endpoints
        common_paths = ["/health", "/chat", "/api/chat", "/api/v1/chat",
                        "/invoke", "/api/tools", "/api/v1/tools"]
        for path in common_paths:
            try:
                import requests
                r = requests.get(self.sandbox_endpoint.rstrip("/") + path, timeout=3)
                if r.status_code != 404:
                    self.discovered_endpoints.append(path)
            except Exception:
                continue

    def _resolve_tool_to_endpoint(self, tool_name: str) -> str:
        """从工具名推断 endpoint"""
        # 启发式：tool_name 转 snake_case → kebab-case
        endpoint = "/" + tool_name.replace("_", "-")
        return endpoint

    def _infer_method(self, tool_name: str, params: dict) -> str:
        """根据工具名推断 HTTP 方法"""
        n = tool_name.lower()
        if any(k in n for k in ["create", "add", "post", "send", "submit", "claim", "transfer", "register"]):
            return "POST"
        if any(k in n for k in ["update", "modify", "change", "set", "save"]):
            return "PUT"
        if any(k in n for k in ["delete", "remove", "drop"]):
            return "DELETE"
        if any(k in n for k in ["list", "get", "fetch", "query", "search", "find", "read"]):
            return "GET"
        # 默认 POST
        return "POST"

    def upload_file(self, endpoint: str, file_path: Path, field_name: str = "file") -> InvokeResult:
        """文件上传专用"""
        import requests
        start = time.time()
        try:
            with open(file_path, "rb") as f:
                r = requests.post(
                    self.sandbox_endpoint.rstrip("/") + endpoint,
                    files={field_name: f},
                    timeout=30,
                )
            return InvokeResult(
                success=r.status_code < 300,
                output={"status": r.status_code, "body": r.text[:500]},
                duration_ms=int((time.time() - start) * 1000),
            )
        except Exception as e:
            return InvokeResult(success=False, error=str(e), duration_ms=int((time.time() - start) * 1000))