"""MCP v1 newline-delimited stdio RPC, bounded waits and explicit failures."""
from __future__ import annotations

from collections import deque
import json
import os
from pathlib import Path
import queue
import shlex
import subprocess
import threading
import time

from .api_executor import ExecutionResult


class MCPExecutor:
    def __init__(self, mcp_command="python -m my_mcp_server", cwd=".", *, env=None, timeout=15):
        # posix=False keeps backslashes in Windows paths; the upstream stdio transport supports Windows.
        self.mcp_command = (shlex.split(mcp_command, posix=os.name != "nt") if isinstance(mcp_command, str)
                            else list(mcp_command))
        self.cwd = Path(cwd)
        self.env, self.timeout = env, timeout
        self.process = None
        self._next_id = 100
        self._lines = queue.Queue()
        self._stderr = deque(maxlen=20)
        self._threads = []

    def _ensure_process(self):
        if self.process is not None:
            return
        self.process = subprocess.Popen(self.mcp_command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, cwd=self.cwd, env=self.env,
                                        text=True, bufsize=1)
        def stdout_reader():
            for line in self.process.stdout:
                self._lines.put(line)
            self._lines.put(None)
        def stderr_reader():
            for line in self.process.stderr:
                self._stderr.append(line[:2000])
        for reader in (stdout_reader, stderr_reader):
            t = threading.Thread(target=reader, daemon=True)
            self._threads.append(t)
            t.start()
        try:
            reply = self._send({"jsonrpc": "2.0", "id": 0, "method": "initialize",
                                "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                                           "clientInfo": {"name": "AgentStalker", "version": "1.0"}}})
            if "result" not in reply:
                raise RuntimeError("MCP initialization failed")
            self._notify({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
        except Exception:
            self.teardown()
            raise

    def _notify(self, request):
        self.process.stdin.write(json.dumps(request) + "\n")
        self.process.stdin.flush()

    def _next_request_id(self):
        self._next_id += 1
        return self._next_id

    def _send(self, request):
        if not self.process:
            raise RuntimeError("MCP process not running")
        self._notify(request)
        deadline = time.monotonic() + getattr(self, "timeout", 15)
        for _ in range(1000):
            try:
                # The fallback keeps the legacy in-memory transport test usable.
                line = (self._lines.get(timeout=max(0.001, deadline - time.monotonic()))
                        if hasattr(self, "_lines") else self.process.stdout.readline())
            except queue.Empty as exc:
                raise TimeoutError("MCP response deadline exceeded") from exc
            if not line:
                raise RuntimeError("MCP process closed output")
            if len(line) > 1048576:
                raise RuntimeError("MCP response exceeds 1 MiB")
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(message, dict) and message.get("id") == request.get("id") and "id" in message:
                if "result" not in message and "error" not in message:
                    raise RuntimeError("invalid MCP response")
                return message
        raise RuntimeError("too many unrelated MCP messages")

    def call_tool(self, name, arguments=None):
        self._ensure_process()
        return self._send({"jsonrpc": "2.0", "id": self._next_request_id(), "method": "tools/call",
                           "params": {"name": name, "arguments": arguments or {}}})

    def list_tools(self):
        self._ensure_process()
        response = self._send({"jsonrpc": "2.0", "id": self._next_request_id(),
                               "method": "tools/list", "params": {}})
        if "error" in response:
            raise RuntimeError("MCP tools/list failed")
        tools = response.get("result", {}).get("tools")
        if not isinstance(tools, list):
            raise RuntimeError("MCP tool list absent")
        return tools

    def list_tool_names(self):
        return [t.get("name") for t in self.list_tools()]

    def execute(self, test_case):
        started = time.monotonic()
        try:
            response = self.call_tool(test_case.get("tool", "test_tool"), test_case.get("payload", {}))
            tool_error = response.get("result", {}).get("isError", False)
            return ExecutionResult("result" in response and not tool_error, output=response,
                                   status="completed" if "result" in response and not tool_error else "error",
                                   error="tool returned error" if tool_error else str(response.get("error", "")),
                                   duration_ms=int((time.monotonic() - started) * 1000))
        except Exception as exc:
            return ExecutionResult(False, error=str(exc), status="timeout" if isinstance(exc, TimeoutError) else "error",
                                   duration_ms=int((time.monotonic() - started) * 1000))

    def teardown(self):
        process = self.process
        if process is None:
            return
        try:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
            for thread in self._threads:
                thread.join(timeout=1)
            for stream in (process.stdin, process.stdout, process.stderr):
                try:
                    stream.close()
                except (OSError, BrokenPipeError):
                    pass
        finally:
            self.process = None
            self._threads = []
            self._lines = queue.Queue()
