"""Generic CLI Adapter — 适配命令行 Agent

历史:原在 _other_frameworks.py(名为 CLIAdapter)。Commit 5 拆出独立模块。
注意:本 CLIAdapter(BaseAdapter,接口执行器)与 sandbox/executors/cli_executor.py
的 run_cli(底层进程运行)是不同层次 —— 本类实现适配器契约(deploy/list_tools/
invoke_tool),run_cli 是更底层的工具。
"""
from __future__ import annotations

import json
import subprocess
import time

from . import BaseAdapter, Tool, InvokeResult


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
                cwd=str(self.source_dir),
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
