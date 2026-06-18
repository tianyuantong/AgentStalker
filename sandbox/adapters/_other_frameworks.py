"""
其他框架适配器 — AutoGen / CrewAI / LlamaIndex / LangGraph / Node.js / CLI
"""
from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

from . import BaseAdapter, Tool, InvokeResult


# ============ AutoGen ============
class AutoGenAdapter(BaseAdapter):
    framework_name = "AutoGen"

    def deploy(self) -> bool:
        """启动 AutoGen Agent（通常是 long-running 进程）"""
        entry = self._find_entry()
        if not entry:
            return False
        env = os.environ.copy()
        env["AUTOGEN_USE_DOCKER"] = "False"  # 强制关闭 AutoGen 自己的 Docker 沙箱
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
            request = {
                "tool": tool_name,
                "parameters": parameters,
                "user_context": user_context or {},
            }
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
        if hasattr(self, "process") and self.process:
            try:
                self.process.terminate()
                return True
            except Exception:
                return False
        return True

    def _find_entry(self) -> Path | None:
        for name in ["main.py", "app.py", "agent.py"]:
            for p in self.source_dir.rglob(name):
                if "test" in str(p):
                    continue
                content = p.read_text(encoding="utf-8", errors="ignore")
                if "autogen" in content.lower() or "AssistantAgent" in content:
                    return p
        return None


# ============ CrewAI ============
class CrewAIAdapter(BaseAdapter):
    framework_name = "CrewAI"

    def deploy(self) -> bool:
        return self._start_agent()

    def list_tools(self) -> list[Tool]:
        return self.tools

    def invoke_tool(self, tool_name: str, parameters: dict, user_context: dict | None = None) -> InvokeResult:
        # CrewAI 通过 kickoff() 触发 — 注入 input
        import requests
        start = time.time()
        try:
            r = requests.post(
                f"{self.sandbox_endpoint}/kickoff",
                json={"inputs": parameters},
                timeout=60,
            )
            return InvokeResult(
                success=r.status_code < 300,
                output=r.json(),
                duration_ms=int((time.time() - start) * 1000),
            )
        except Exception as e:
            return InvokeResult(success=False, error=str(e))

    def teardown(self) -> bool:
        return self._stop_agent()

    def _start_agent(self) -> bool:
        entry = None
        for p in self.source_dir.rglob("main.py"):
            if "crewai" in p.read_text(encoding="utf-8", errors="ignore").lower():
                entry = p
                break
        if not entry:
            return False
        try:
            self.process = subprocess.Popen(
                ["python", str(entry)],
                cwd=entry.parent,
                stdout=open(Path(self.source_dir.parent) / "output" / "evidence" / "crewai.log", "w"),
                stderr=subprocess.STDOUT,
            )
            time.sleep(3)
            return True
        except Exception:
            return False

    def _stop_agent(self) -> bool:
        if hasattr(self, "process") and self.process:
            try:
                self.process.terminate()
                return True
            except Exception:
                pass
        return True


# ============ LlamaIndex ============
class LlamaIndexAdapter(BaseAdapter):
    framework_name = "LlamaIndex"

    def deploy(self) -> bool:
        return self._start_agent()

    def list_tools(self) -> list[Tool]:
        return self.tools

    def invoke_tool(self, tool_name: str, parameters: dict, user_context: dict | None = None) -> InvokeResult:
        import requests
        start = time.time()
        try:
            r = requests.post(
                f"{self.sandbox_endpoint}/query",
                json={"query": parameters.get("query", "")},
                timeout=30,
            )
            return InvokeResult(
                success=r.status_code < 300,
                output=r.json(),
                duration_ms=int((time.time() - start) * 1000),
            )
        except Exception as e:
            return InvokeResult(success=False, error=str(e))

    def teardown(self) -> bool:
        return self._stop_agent()

    def _start_agent(self) -> bool:
        for p in self.source_dir.rglob("main.py"):
            if "llama" in p.read_text(encoding="utf-8", errors="ignore").lower():
                try:
                    self.process = subprocess.Popen(
                        ["python", str(p)],
                        cwd=p.parent,
                        stdout=open(Path(self.source_dir.parent) / "output" / "evidence" / "llamaindex.log", "w"),
                        stderr=subprocess.STDOUT,
                    )
                    time.sleep(3)
                    return True
                except Exception:
                    return False
        return False

    def _stop_agent(self) -> bool:
        if hasattr(self, "process") and self.process:
            try:
                self.process.terminate()
                return True
            except Exception:
                pass
        return True


# ============ LangGraph ============
class LangGraphAdapter(BaseAdapter):
    framework_name = "LangGraph"

    def deploy(self) -> bool:
        return self._start_agent()

    def list_tools(self) -> list[Tool]:
        return self.tools

    def invoke_tool(self, tool_name: str, parameters: dict, user_context: dict | None = None) -> InvokeResult:
        # LangGraph 通过 invoke(input) 调用
        import requests
        start = time.time()
        try:
            r = requests.post(
                f"{self.sandbox_endpoint}/invoke",
                json={"input": parameters},
                timeout=30,
            )
            return InvokeResult(
                success=r.status_code < 300,
                output=r.json(),
                duration_ms=int((time.time() - start) * 1000),
            )
        except Exception as e:
            return InvokeResult(success=False, error=str(e))

    def teardown(self) -> bool:
        return self._stop_agent()

    def _start_agent(self) -> bool:
        for p in self.source_dir.rglob("*.py"):
            if "langgraph" in p.read_text(encoding="utf-8", errors="ignore").lower() and "test" not in str(p):
                try:
                    self.process = subprocess.Popen(
                        ["python", str(p)],
                        cwd=p.parent,
                        stdout=open(Path(self.source_dir.parent) / "output" / "evidence" / "langgraph.log", "w"),
                        stderr=subprocess.STDOUT,
                    )
                    time.sleep(3)
                    return True
                except Exception:
                    return False
        return False

    def _stop_agent(self) -> bool:
        if hasattr(self, "process") and self.process:
            try:
                self.process.terminate()
                return True
            except Exception:
                pass
        return True


# ============ Generic CLI ============
class CLIAdapter(BaseAdapter):
    framework_name = "CLI Agent"

    def deploy(self) -> bool:
        # CLI 不需要 deploy
        return True

    def list_tools(self) -> list[Tool]:
        return self.tools

    def invoke_tool(self, tool_name: str, parameters: dict, user_context: dict | None = None) -> InvokeResult:
        # 直接 spawn subprocess 注入 payload
        start = time.time()
        cmd = self._build_command(tool_name, parameters)
        try:
            result = subprocess.run(
                cmd,
                input=json.dumps(user_context or {}),
                capture_output=True,
                text=True,
                timeout=30,
                cwd=self.source_dir,
            )
            return InvokeResult(
                success=result.returncode == 0,
                output={"stdout": result.stdout, "stderr": result.stderr},
                error=result.stderr if result.returncode != 0 else "",
                duration_ms=int((time.time() - start) * 1000),
            )
        except Exception as e:
            return InvokeResult(success=False, error=str(e))

    def teardown(self) -> bool:
        return True

    def _build_command(self, tool_name: str, parameters: dict) -> list[str]:
        """构建 CLI 命令"""
        if self.source_dir.suffix == ".py" or (self.source_dir / f"{tool_name}.py").exists():
            return ["python", str(self.source_dir / f"{tool_name}.py")]
        # 默认：尝试运行 tool_name
        return [tool_name] + [str(v) for v in parameters.values()]