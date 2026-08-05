"""Executors package — multi-channel attack executors.

Channels:
- APIExecutor: HTTP/REST (api_executor.py)
- CLIExecutor: command-line stdin/argv (cli.py)
- MCPExecutor: MCP stdio JSON-RPC (mcp.py)
- WebExecutor: Playwright browser automation (web.py)
- ConversationReplayExecutor: multi-turn scripted dialogue (replay.py)

Also re-exports run_cli / CliRunResult from cli_executor.py (low-level
CLI process runner with files_written tracking, used by Rust-agent auditing).
"""
from .api_executor import APIExecutor, ExecutionResult, ExecutionContext
from .cli import CLIExecutor
from .mcp import MCPExecutor
from .web import WebExecutor
from .replay import ConversationReplayExecutor
# Low-level CLI runner (distinct ExecutionResult-shaped type: CliRunResult)
from .cli_executor import run_cli, CliRunResult

__all__ = [
    "APIExecutor",
    "ExecutionResult",
    "ExecutionContext",
    "CLIExecutor",
    "MCPExecutor",
    "WebExecutor",
    "ConversationReplayExecutor",
    # low-level CLI runner
    "run_cli",
    "CliRunResult",
]
