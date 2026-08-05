"""
AgentStalker CLI Executor
=========================
针对 stdio-based CLI Agent (Aider / Cline / 自研 TUI agent 等) 的执行器。

用法:
  python -m sandbox.executors.cli_executor \\
    --binary /path/to/<agent-binary> \\
    --workspace /tmp/test_workspace \\
    --message "user prompt" \\
    --timeout 60 \\
    --record-output

输出:
  {
    "status": "success" | "timeout" | "error",
    "elapsed_s": float,
    "stdout": "...",
    "stderr": "...",
    "exit_code": int,
    "command": "...",
    "files_written": [...],   # workspace 内新增/修改的文件
  }

支持 TUI mode（stdin 驱动）和 non-interactive mode（如 <agent> exec）。
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path


@dataclass
class CliRunResult:
    """CLI 进程运行结果(底层)。

    历史:原名 ExecutionResult,与 api_executor.ExecutionResult 字段完全不同
    (C4 冲突)。Commit 4 重命名为 CliRunResult 以消除歧义。
    接口执行器契约用的是 api_executor.ExecutionResult(success/output/error/...);
    本类是 run_cli 的返回值,含 CLI 专属字段(files_written/files_read)。
    """
    status: str
    elapsed_s: float
    stdout: str
    stderr: str
    exit_code: int
    command: list
    files_written: list = field(default_factory=list)
    files_read: list = field(default_factory=list)


def run_cli(
    binary: str,
    args: list,
    workspace: str,
    stdin_input: str = "",
    env: dict = None,
    timeout: int = 60,
    record_files: bool = True,
    agent_env_vars: list = None,
) -> CliRunResult:
    """运行 CLI agent 并捕获输出

    agent_env_vars: 由 agent 配置段定义的额外环境变量名列表 (e.g. ["DEEPSEEK_API_KEY", "ANTHROPIC_API_KEY"])。
                    若 caller 已在 env 中提供则用 caller 值, 否则保持 unset
                    (避免硬编码特定 provider 的 key/URL 作为 placeholder)。
    """
    workspace = Path(workspace).resolve()
    workspace.mkdir(parents=True, exist_ok=True)

    full_env = os.environ.copy()
    if env:
        full_env.update(env)
    # 强制 home 指向 workspace 内的 agent config dir
    full_env.setdefault("HOME", str(workspace))
    # 注意: 具体的 LLM provider env vars (DEEPSEEK_API_KEY / ANTHROPIC_API_KEY / OPENAI_API_KEY 等)
    # 不在此处硬编码, 由 caller 通过 env 参数或 agent_env_vars 提供。

    # 记录 workspace 初始文件状态
    initial_files = set()
    if record_files and workspace.exists():
        for p in workspace.rglob("*"):
            if p.is_file():
                initial_files.add(str(p))

    cmd = [binary] + args
    t0 = time.time()
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(workspace),
            input=stdin_input if stdin_input else None,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=full_env,
        )
        elapsed = time.time() - t0
        result = CliRunResult(
            status="success" if proc.returncode == 0 else "error",
            elapsed_s=elapsed,
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
            exit_code=proc.returncode,
            command=cmd,
        )
    except subprocess.TimeoutExpired as e:
        elapsed = time.time() - t0
        result = CliRunResult(
            status="timeout",
            elapsed_s=elapsed,
            stdout=(e.stdout or b"").decode(errors="ignore") if isinstance(e.stdout, bytes) else (e.stdout or ""),
            stderr=(e.stderr or b"").decode(errors="ignore") if isinstance(e.stderr, bytes) else (e.stderr or ""),
            exit_code=-1,
            command=cmd,
        )

    # 检测新增/修改文件
    if record_files and workspace.exists():
        current_files = set()
        for p in workspace.rglob("*"):
            if p.is_file():
                current_files.add(str(p))
        new_files = current_files - initial_files
        result.files_written = sorted(list(new_files))

    return result


def main():
    ap = argparse.ArgumentParser(description="AgentStalker CLI Executor")
    ap.add_argument("--binary", required=True, help="CLI binary path")
    ap.add_argument("--workspace", required=True, help="Working directory")
    ap.add_argument("--args", nargs="*", default=[], help="CLI args")
    ap.add_argument("--stdin", default="", help="Stdin input (for TUI)")
    ap.add_argument("--message", default="", help="Message to pass (mapped to --message or stdin)")
    ap.add_argument("--timeout", type=int, default=60)
    ap.add_argument("--env", help="JSON env overrides")
    ap.add_argument("--output", help="Output JSON file")
    args = ap.parse_args()

    env = {}
    if args.env:
        env = json.loads(args.env)

    stdin = args.stdin
    if args.message and not stdin:
        # TUI mode takes stdin; non-interactive takes -p / --prompt
        # 简单策略: 用 stdin
        stdin = args.message + "\n"

    result = run_cli(
        binary=args.binary,
        args=args.args,
        workspace=args.workspace,
        stdin_input=stdin,
        env=env,
        timeout=args.timeout,
    )

    out = asdict(result)
    if args.output:
        Path(args.output).write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(out, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
