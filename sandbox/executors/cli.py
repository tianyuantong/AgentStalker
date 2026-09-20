"""CLI Executor — 命令行 Agent 执行器

历史:原在 _other_executors.py(trivial 版,只支持 stdin/argv 注入)。
Commit 4 拆出独立模块,并保留与 cli_executor.py(run_cli + CliRunResult)
的关系:本模块的 CLIExecutor 实现接口执行器契约(返回 ExecutionResult),
而 cli_executor.py 的 run_cli 是更底层的进程运行工具(返回 CliRunResult,
含 files_written 等 CLI 专属字段)。两者不冲突。
"""
from __future__ import annotations

import json
import subprocess
import time
import traceback
from pathlib import Path

from .api_executor import ExecutionResult


class CLIExecutor:
    """命令行 Agent 执行器

    通过 stdin / argv 注入 payload
    """

    def __init__(self, command: str, cwd: str | Path = "."):
        self.command = command
        self.cwd = Path(cwd)

    def execute(self, test_case: dict) -> ExecutionResult:
        start = time.time()
        payload = test_case.get("payload", {})

        # 把 payload 转为 stdin 输入
        stdin_data = json.dumps(payload)

        try:
            result = subprocess.run(
                self.command.split(),
                input=stdin_data,
                capture_output=True,
                text=True,
                timeout=test_case.get("timeout", 30),
                cwd=self.cwd,
            )
            duration = int((time.time() - start) * 1000)
            return ExecutionResult(
                success=result.returncode == 0,
                output={"stdout": result.stdout, "stderr": result.stderr, "returncode": result.returncode},
                error=result.stderr if result.returncode != 0 else "",
                duration_ms=duration,
                status="completed" if result.returncode == 0 else "error",
            )
        except Exception as e:
            return ExecutionResult(
                success=False,
                error=f"{e}\n{traceback.format_exc()}",
                duration_ms=int((time.time() - start) * 1000),
                status="timeout" if isinstance(e, subprocess.TimeoutExpired) else "error",
            )
