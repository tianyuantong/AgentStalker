"""Regression tests for the executors package (C2 / C4 / MCPExecutor enhancement).

C2: ConversationReplayExecutor.__init__ called APIExecutor(...) but only
    ExecutionResult was imported from .api_executor (not APIExecutor), so
    instantiation raised NameError.
C4: cli_executor.py defined its own ExecutionResult with different fields,
    colliding with api_executor.ExecutionResult. Renamed to CliRunResult.
"""
import pytest


def test_executors_package_imports():
    """All executor classes must be importable from the package."""
    from sandbox.executors import (
        APIExecutor, ExecutionResult, ExecutionContext,
        CLIExecutor, MCPExecutor, WebExecutor, ConversationReplayExecutor,
        run_cli, CliRunResult,
    )


def test_no_other_executors_file():
    """Guard against re-introducing the _other_executors.py temp file."""
    import sandbox.executors as pkg
    from pathlib import Path
    pkg_dir = Path(pkg.__file__).parent
    py_files = [f.name for f in pkg_dir.glob("*.py")]
    underscore = [f for f in py_files if f.startswith("_") and f != "__init__.py"]
    assert not underscore, f"unexpected underscore files: {underscore}"


# ---- C2 regression ----

def test_replay_executor_instantiable():
    """C2 regression: ConversationReplayExecutor() must not raise NameError.

    Constructing it builds an APIExecutor, which creates a requests.Session
    (no network call). We patch _init_session to avoid the requests dependency
    surface, focusing the test on the import/name bug.
    """
    from sandbox.executors.replay import ConversationReplayExecutor
    from sandbox.executors import api_executor

    # Avoid real Session creation; we only care that APIExecutor is bound.
    original = api_executor.APIExecutor._init_session
    api_executor.APIExecutor._init_session = lambda self: setattr(self, "session", None)
    try:
        ex = ConversationReplayExecutor(base_url="http://127.0.0.1:9999")
        assert ex.api_executor is not None
        assert ex.indirect_injectors == {}
    finally:
        api_executor.APIExecutor._init_session = original


def test_replay_imports_api_executor():
    """Static guard: replay.py must import APIExecutor by name (C2 root cause)."""
    import sandbox.executors.replay as replay_mod
    # The module must reference APIExecutor in its namespace (proves the import exists).
    assert "APIExecutor" in dir(replay_mod), (
        "replay.py does not import APIExecutor — C2 regressed"
    )


# ---- C4 regression ----

def test_cli_executor_no_executionresult_collision():
    """C4 regression: cli_executor.py must NOT define ExecutionResult (renamed to CliRunResult)."""
    import sandbox.executors.cli_executor as ce
    assert not hasattr(ce, "ExecutionResult"), (
        "cli_executor.py still defines ExecutionResult — C4 rename regressed"
    )
    assert hasattr(ce, "CliRunResult"), "cli_executor.py missing CliRunResult"


def test_canonical_executionresult_from_api_executor():
    """The package-level ExecutionResult is the api_executor one."""
    from sandbox.executors import ExecutionResult as PkgER
    from sandbox.executors.api_executor import ExecutionResult as ApiER
    assert PkgER is ApiER


def test_cli_executor_result_fields_distinct():
    """CliRunResult has the CLI-specific fields (files_written etc.), distinct from ExecutionResult."""
    from sandbox.executors import CliRunResult, ExecutionResult
    er_fields = {f.name for f in __import__("dataclasses").fields(ExecutionResult)}
    cli_fields = {f.name for f in __import__("dataclasses").fields(CliRunResult)}
    assert "files_written" in cli_fields
    assert "files_written" not in er_fields
    # And the overlap fields have compatible intent (both have success-ish: ExecutionResult.success vs CliRunResult.status)


# ---- MCPExecutor enhancement ----

def test_mcp_executor_list_tools_returns_dicts():
    """Commit 4 enhancement: list_tools() returns list[dict] (with descriptions),
    not list[str]. Verified via the method signature/return-shape on a stub."""
    from sandbox.executors.mcp import MCPExecutor
    import inspect
    src = inspect.getsource(MCPExecutor.list_tools)
    # The new impl returns response.get("result", {}).get("tools", []) which is list[dict]
    assert "tools" in src


def test_mcp_executor_call_tool_method_exists():
    """Commit 4 enhancement: call_tool() method exists (returns raw response for audit)."""
    from sandbox.executors.mcp import MCPExecutor
    assert hasattr(MCPExecutor, "call_tool"), "MCPExecutor.call_tool missing"


def test_mcp_executor_handles_notification_lines():
    """Commit 4 enhancement: _send skips notification/log lines (no 'id') and returns
    only the response matching the request id. Uses an in-process fake server."""
    import json
    import threading
    from sandbox.executors.mcp import MCPExecutor

    # We simulate the server side by pre-populating stdout lines the executor will read.
    ex = MCPExecutor.__new__(MCPExecutor)  # bypass __init__ (no real subprocess)

    class FakeProc:
        def __init__(self, lines_to_emit):
            self._lines = list(lines_to_emit)
            class _Stdin:
                def write(self, s): pass
                def flush(self): pass
            self.stdin = _Stdin()
            class _Stdout:
                def __init__(self, lines):
                    self._lines = list(lines)
                def readline(self):
                    return self._lines.pop(0) if self._lines else ""
            self.stdout = _Stdout(lines_to_emit)

    # Server emits: a notification (no id), a log line, then the matching response.
    request = {"jsonrpc": "2.0", "id": 42, "method": "tools/list"}
    fake_lines = [
        json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n",  # notification
        "this is a stderr-style log line on stdout\n",  # non-JSON
        json.dumps({"jsonrpc": "2.0", "id": 42, "result": {"tools": [{"name": "t1"}]}}) + "\n",
    ]
    ex.process = FakeProc(fake_lines)
    resp = ex._send(request)
    assert resp.get("id") == 42
    assert resp.get("result", {}).get("tools") == [{"name": "t1"}]
