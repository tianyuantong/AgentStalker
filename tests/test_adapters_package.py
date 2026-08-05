"""Regression tests for the adapters package (H2 registry + H6 dedup + python_mcp response capture).

H2: discovery.py recommends adapter strings (python_autogen/python_crewai/...)
    but no mechanism resolved them to classes. Added ADAPTER_REGISTRY + get_adapter().
H6: CrewAI/LlamaIndex/LangGraph _start_agent were ~95% duplicate. Hoisted into
    BaseAdapter._spawn_by_keyword.
python_mcp.py: invoke_tool used to record only the request, dropping the server
    response (audit blind spot). Now captures the full response.
"""
import inspect

import pytest


def test_adapter_registry_resolves_all():
    """H2 regression: every ADAPTER_REGISTRY entry must resolve to a class."""
    from sandbox.adapters import ADAPTER_REGISTRY, get_adapter, BaseAdapter
    assert ADAPTER_REGISTRY, "registry is empty"
    for name in ADAPTER_REGISTRY:
        cls = get_adapter(name)
        assert issubclass(cls, BaseAdapter), (
            f"{name} -> {cls} is not a BaseAdapter subclass"
        )


def test_adapter_registry_covers_discovery_recommendations():
    """H2 regression: the strings discovery.py emits must all be resolvable."""
    from sandbox.adapters import ADAPTER_REGISTRY
    # From discovery.py recommended_adapter assignments
    discovery_strings = [
        "python_langchain", "python_mcp", "python_autogen",
        "python_crewai", "python_langgraph",
    ]
    for s in discovery_strings:
        assert s in ADAPTER_REGISTRY, (
            f"discovery.py recommends '{s}' but it's not in ADAPTER_REGISTRY"
        )


def test_get_adapter_unknown_raises():
    """get_adapter must raise KeyError for unknown names."""
    from sandbox.adapters import get_adapter
    with pytest.raises(KeyError):
        get_adapter("nonexistent_framework")


def test_no_underscore_adapter_files():
    """Guard against re-introducing _other_frameworks.py."""
    import sandbox.adapters as pkg
    from pathlib import Path
    pkg_dir = Path(pkg.__file__).parent
    py_files = [f.name for f in pkg_dir.glob("*.py")]
    underscore = [f for f in py_files if f.startswith("_") and f != "__init__.py"]
    assert not underscore, f"unexpected underscore files: {underscore}"


# ---- H6 dedup regression ----

def test_crewai_llamaindex_langgraph_use_shared_spawn():
    """H6 regression: the three near-duplicate adapters must delegate to the
    shared BaseAdapter._spawn_by_keyword rather than each defining their own
    subprocess.Popen spawn logic."""
    from sandbox.adapters import BaseAdapter
    from sandbox.adapters.crewai import CrewAIAdapter
    from sandbox.adapters.llamaindex import LlamaIndexAdapter
    from sandbox.adapters.langgraph import LangGraphAdapter

    # _spawn_by_keyword must exist on BaseAdapter (the shared method)
    assert hasattr(BaseAdapter, "_spawn_by_keyword"), (
        "BaseAdapter._spawn_by_keyword missing — H6 dedup incomplete"
    )

    for cls in (CrewAIAdapter, LlamaIndexAdapter, LangGraphAdapter):
        # Each _start_agent should call self._spawn_by_keyword (no raw Popen in body)
        src = inspect.getsource(cls._start_agent)
        assert "_spawn_by_keyword" in src, (
            f"{cls.__name__}._start_agent does not use _spawn_by_keyword"
        )
        assert "subprocess.Popen" not in src, (
            f"{cls.__name__}._start_agent still has inline subprocess.Popen — H6 regressed"
        )


def test_spawn_by_keyword_signature():
    """The shared spawn method accepts the parameters the subclasses need."""
    from sandbox.adapters import BaseAdapter
    sig = inspect.signature(BaseAdapter._spawn_by_keyword)
    params = set(sig.parameters)
    assert {"keyword", "log_name", "glob", "exclude_tests"}.issubset(params), (
        f"_spawn_by_keyword missing params; has {params}"
    )


# ---- python_mcp.py response capture regression ----

def test_mcp_invoke_tool_captures_response():
    """The MCP adapter's invoke_tool output must include the server response,
    not just the request (was an audit blind spot)."""
    from sandbox.adapters.python_mcp import MCPPythonAdapter
    src = inspect.getsource(MCPPythonAdapter.invoke_tool)
    # The new impl puts both mcp_request and mcp_response in output
    assert "mcp_response" in src, (
        "invoke_tool does not capture mcp_response — audit blind spot regressed"
    )


def test_mcp_list_tools_reads_stdout_not_log():
    """list_tools must read from stdout RPC, not grep a log file."""
    from sandbox.adapters.python_mcp import MCPPythonAdapter
    src = inspect.getsource(MCPPythonAdapter.list_tools)
    assert "_send_rpc" in src, "list_tools should use _send_rpc to read stdout"
    assert "mcp_io.log" not in src, "list_tools still greps the log file (fragile)"


def test_mcp_adapter_instantiable():
    """Sanity: MCPPythonAdapter constructs."""
    from sandbox.adapters.python_mcp import MCPPythonAdapter
    ad = MCPPythonAdapter(source_dir="/tmp/nonexistent")
    assert ad.framework_name == "MCP Server (Python)"
    assert ad.tools == []
