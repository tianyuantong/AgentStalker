"""
LangChain Python Agent 适配器
"""
from __future__ import annotations

import ast
import re
import time
from pathlib import Path

from . import BaseAdapter, Tool, InvokeResult


class LangChainAdapter(BaseAdapter):
    framework_name = "LangChain (Python)"

    def deploy(self) -> bool:
        """部署 LangChain Agent 到沙箱

        策略：
        1. 静态扫描 source_dir 识别 @tool / BaseTool / AgentExecutor
        2. 启动时插入 monitoring wrapper（在 ast 注入 trace_id 记录）
        3. 启动 FastAPI wrapper 暴露 HTTP 端点（如果 Agent 原本无 HTTP）
        """
        # 解析源码中的工具
        self._parse_tools_from_source()
        # 生成 runtime wrapper
        wrapper_path = self._generate_wrapper()
        # 启动
        return self._start_agent(wrapper_path)

    def list_tools(self) -> list[Tool]:
        """列出 LangChain Agent 暴露的工具"""
        return self.tools

    def invoke_tool(self, tool_name: str, parameters: dict, user_context: dict | None = None) -> InvokeResult:
        """通过沙箱 HTTP 端点调用工具"""
        import requests
        start = time.time()
        try:
            r = requests.post(
                f"{self.sandbox_endpoint}/invoke",
                json={
                    "tool": tool_name,
                    "parameters": parameters,
                    "user_context": user_context or {},
                },
                headers={"Authorization": f"Bearer {self.session_token}"} if self.session_token else {},
                timeout=30,
            )
            duration = int((time.time() - start) * 1000)
            success = r.status_code == 200
            output = r.json() if success else r.text
            result = InvokeResult(
                success=success,
                output=output,
                error="" if success else f"HTTP {r.status_code}",
                duration_ms=duration,
            )
            self._record_invocation(tool_name, parameters, result)
            return result
        except Exception as e:
            return InvokeResult(success=False, error=str(e), duration_ms=int((time.time() - start) * 1000))

    def teardown(self) -> bool:
        """停止 LangChain Agent"""
        import requests
        try:
            requests.post(f"{self.sandbox_endpoint}/shutdown", timeout=5)
            return True
        except Exception:
            return False

    # ============ 内部 ============
    def _parse_tools_from_source(self):
        """AST 解析工具定义"""
        for py_file in self.source_dir.rglob("*.py"):
            if "__pycache__" in str(py_file) or "test" in str(py_file):
                continue
            try:
                source = py_file.read_text(encoding="utf-8", errors="ignore")
                tree = ast.parse(source)
            except SyntaxError:
                continue

            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    # 检查 @tool 装饰器
                    if any(self._is_tool_decorator(d) for d in node.decorator_list):
                        doc = ast.get_docstring(node) or ""
                        self.tools.append(Tool(
                            name=node.name,
                            description=doc[:500],
                            parameters={a.arg: {"type": "str"} for a in node.args.args},
                            risk_level=self._infer_risk(node.name, doc),
                        ))

                elif isinstance(node, ast.ClassDef):
                    # BaseTool 子类
                    bases = [b.id if isinstance(b, ast.Name) else getattr(b, "attr", "") for b in node.bases]
                    if "BaseTool" in bases or "StructuredTool" in bases:
                        doc = ast.get_docstring(node) or ""
                        self.tools.append(Tool(
                            name=node.name,
                            description=doc[:500],
                            risk_level=self._infer_risk(node.name, doc),
                        ))

    def _is_tool_decorator(self, dec) -> bool:
        if isinstance(dec, ast.Call):
            func = dec.func
            if isinstance(func, ast.Name) and func.id == "tool":
                return True
            if isinstance(func, ast.Attribute) and func.attr == "tool":
                return True
        elif isinstance(dec, ast.Name) and dec.id == "tool":
            return True
        return False

    def _infer_risk(self, name: str, doc: str) -> str:
        text = (name + " " + doc).lower()
        if any(k in text for k in ["shell", "exec", "command", "code", "eval"]):
            return "critical"
        if any(k in text for k in ["delete", "remove", "send_email", "publish", "transfer", "payment"]):
            return "high"
        if any(k in text for k in ["write", "update", "create", "post", "save"]):
            return "medium"
        return "low"

    def _generate_wrapper(self) -> Path:
        """生成运行时 wrapper，注入监控与统一入口"""
        wrapper_dir = self.source_dir.parent / "output" / "wrapper"
        wrapper_dir.mkdir(parents=True, exist_ok=True)
        wrapper_path = wrapper_dir / "langchain_wrapper.py"

        # 序列化工具列表
        tools_json = "[\n"
        for t in self.tools:
            tools_json += f"  {repr(t.name)},\n"
        tools_json += "]"

        content = f'''"""
Auto-generated LangChain Runtime Wrapper for AgentStalker Sandbox
注入监控 + 统一 /invoke 端点
"""
import json
import os
import sys
import time
import traceback
from pathlib import Path

# 把被测 Agent 加入 path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "agent"))

# 导入被测 Agent 的工具
from agent_source import *  # noqa

from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
import uvicorn

app = FastAPI(title="AgentStalker Sandbox Wrapper")

class InvokeRequest(BaseModel):
    tool: str
    parameters: dict
    user_context: dict = {{}}

class InvokeResponse(BaseModel):
    success: bool
    output: dict = None
    error: str = ""
    trace_id: str = ""

# 工具名 → 可调用对象
TOOL_REGISTRY = {{tool.__name__: tool for tool in [
{chr(10).join(f"    {t.name}," for t in self.tools)}
]}}

@app.get("/health")
def health():
    return {{"status": "ok", "tools": list(TOOL_REGISTRY.keys())}}

@app.post("/invoke")
def invoke(req: InvokeRequest, authorization: str = Header(None)):
    trace_id = f"ast-{{int(time.time() * 1000)}}"
    if req.tool not in TOOL_REGISTRY:
        raise HTTPException(status_code=404, detail=f"Tool {{req.tool}} not found")

    tool = TOOL_REGISTRY[req.tool]

    # 记录调用
    log_entry = {{
        "trace_id": trace_id,
        "timestamp": time.time(),
        "tool": req.tool,
        "parameters": req.parameters,
        "user_context": req.user_context,
    }}
    with open("/workspace/output/evidence/invocations.jsonl", "a") as f:
        f.write(json.dumps(log_entry) + "\\n")

    # 执行
    try:
        result = tool(**req.parameters)
        return InvokeResponse(success=True, output={{"value": str(result)}}, trace_id=trace_id)
    except Exception as e:
        return InvokeResponse(success=False, error=str(e), trace_id=trace_id)

@app.post("/shutdown")
def shutdown():
    os._exit(0)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
'''
        wrapper_path.write_text(content, encoding="utf-8")

        # 创建 agent_source 的 __init__
        agent_init = wrapper_dir / "agent_source" / "__init__.py"
        agent_init.parent.mkdir(parents=True, exist_ok=True)

        # 拷贝 Agent 源码并生成聚合 __init__
        import_stmt = ""
        for py_file in self.source_dir.rglob("*.py"):
            if "__pycache__" in str(py_file) or "test" in str(py_file):
                continue
            rel = py_file.relative_to(self.source_dir)
            import_stmt += f"from {rel.stem} import *  # noqa\n"
        agent_init.write_text(import_stmt, encoding="utf-8")

        return wrapper_path

    def _start_agent(self, wrapper_path: Path) -> bool:
        """启动 wrapper"""
        import subprocess
        env = os.environ.copy()
        env["AGENT_MODE"] = "audit"
        env["DATABASE_URL"] = "postgres://testuser:testpass@127.0.0.1:5432/testdb"
        try:
            subprocess.Popen(
                ["python", str(wrapper_path)],
                cwd=wrapper_path.parent,
                env=env,
                stdout=open(wrapper_path.parent / "wrapper.log", "w"),
                stderr=subprocess.STDOUT,
            )
            time.sleep(3)
            return self.health_check()
        except Exception:
            return False