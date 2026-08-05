"""AutoGen Adapter — 适配 AutoGen Agent 框架

历史:原在 _other_frameworks.py。Commit 5 拆出独立模块,并在 __init__.py
ADAPTER_REGISTRY 注册,使 discovery.py 推荐的 "python_autogen" 字符串可解析。
"""
from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

from . import BaseAdapter, Tool, InvokeResult


class AutoGenAdapter(BaseAdapter):
    framework_name = "AutoGen"

    def deploy(self) -> bool:
        """启动 AutoGen Agent（通常是 long-running 进程）"""
        entry = self._find_entry()
        if not entry:
            return False
        env_overrides = {"AUTOGEN_USE_DOCKER": "False"}  # 强制关闭 AutoGen 自己的 Docker 沙箱
        # AutoGen 用自定义 _find_entry(多候选 + AST-free 内容检查),不走共享 spawn
        env = os.environ.copy()
        env.update(env_overrides)
        try:
            log_path = Path(self.source_dir.parent) / "output" / "evidence" / "autogen.log"
            log_path.parent.mkdir(parents=True, exist_ok=True)
            self.process = subprocess.Popen(
                ["python", str(entry)],
                cwd=entry.parent, env=env,
                stdout=open(log_path, "w"), stderr=subprocess.STDOUT,
            )
            time.sleep(3)
            return True
        except Exception:
            return False

    def list_tools(self) -> list[Tool]:
        """通过 AST 解析 register_function 调用"""
        import ast
        for py in self.source_dir.rglob("*.py"):
            if "test" in str(py):
                continue
            try:
                tree = ast.parse(py.read_text(encoding="utf-8", errors="ignore"))
                for node in ast.walk(tree):
                    if isinstance(node, ast.Call):
                        func_str = ast.unparse(node.func)
                        if "register_function" in func_str:
                            # 提取 tool name
                            for arg in node.args:
                                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                                    self.tools.append(Tool(name=arg.value, risk_level="high"))
            except Exception:
                continue
        return self.tools

    def invoke_tool(self, tool_name: str, parameters: dict, user_context: dict | None = None) -> InvokeResult:
        # AutoGen 工具通过 initiate_chat 调用 — 注入 user message
        start = time.time()
        try:
            # 通过 HTTP 端点（如果有）或 mock 注入
            import requests
            r = requests.post(
                f"{self.sandbox_endpoint}/chat",
                json={"message": f"Please call {tool_name} with {parameters}"},
                timeout=30,
            )
            return InvokeResult(
                success=r.status_code < 300,
                output=r.json() if r.status_code < 300 else {"raw": r.text},
                duration_ms=int((time.time() - start) * 1000),
            )
        except Exception as e:
            return InvokeResult(success=False, error=str(e), duration_ms=int((time.time() - start) * 1000))

    def teardown(self) -> bool:
        return self._stop_process()

    def _find_entry(self) -> Path | None:
        for name in ["main.py", "app.py", "agent.py"]:
            for p in self.source_dir.rglob(name):
                if "test" in str(p):
                    continue
                content = p.read_text(encoding="utf-8", errors="ignore")
                if "autogen" in content.lower() or "AssistantAgent" in content:
                    return p
        return None
