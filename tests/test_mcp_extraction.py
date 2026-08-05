"""Tests for MCP static extraction (Commit 7).

Validates that ASTExtractor._extract_mcp now:
- extracts MCP tool names + descriptions (was: only recorded tools_declared:True)
- detects transport type (stdio/sse/http), activating the previously-dead
  sse_transport regex
- produces the enriched mcp_servers[] shape needed by MCPAuditor (Commit 8)
"""
from pathlib import Path

from core.ast_extractor import ASTExtractor

FIXTURE = Path(__file__).resolve().parent.parent / "testbeds" / "mcp_mini_server"


def _extract():
    ex = ASTExtractor(FIXTURE)
    return ex.analyze()


def test_extracts_mcp_server():
    """The fixture must be recognized as an MCP server."""
    model = _extract()
    assert len(model.mcp_servers) >= 1, "no MCP server extracted"


def test_extracts_mcp_tool_names():
    """Commit 7: tool names must be extracted (was empty under old _extract_mcp)."""
    model = _extract()
    all_tools = []
    for srv in model.mcp_servers:
        all_tools.extend(t["name"] for t in srv.get("tools", []))
    assert "read_file" in all_tools, f"read_file not found; got {all_tools}"
    assert "summarize" in all_tools
    assert "proxy_request" in all_tools


def test_extracts_tool_descriptions():
    """Commit 7: descriptions (docstrings) must be captured for poisoning detection."""
    model = _extract()
    descriptions = {}
    for srv in model.mcp_servers:
        for t in srv.get("tools", []):
            descriptions[t["name"]] = t.get("description", "")
    # The summarize tool's description contains the poisoning payload
    assert "ignore previous instructions" in descriptions.get("summarize", "").lower(), (
        f"summarize description missing poison; got {descriptions.get('summarize')!r}"
    )


def test_extracts_transport_type():
    """Commit 7: transport must be detected (activates dead sse_transport regex)."""
    model = _extract()
    transports = [srv.get("transport", "unknown") for srv in model.mcp_servers]
    assert any("stdio" in t for t in transports), (
        f"stdio transport not detected; got {transports}"
    )


def test_detects_sse_transport():
    """Commit 7 (dead-code activation): SSE transport must be detected when present.

    The sse_transport regex existed at ast_extractor.py:90 but _extract_mcp
    never called it — this test guards against that regression.
    """
    # Use an inline source snippet with SSE transport markers.
    import tempfile
    sse_src = '''
from mcp.server.fastmcp import FastMCP
from mcp.server.sse import SSEServerTransport

mcp = FastMCP("sse-server")

@mcp.tool()
def search(q: str) -> str:
    """Search."""
    return q
'''
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "srv.py"
        p.write_text(sse_src, encoding="utf-8")
        ex = ASTExtractor(Path(td))
        model = ex.analyze()
        transports = [srv.get("transport", "") for srv in model.mcp_servers]
        assert any("sse" in t for t in transports), (
            f"SSE transport not detected; got {transports}"
        )


def test_detects_http_transport():
    """Commit 7: HTTP/streamable transport detection (was entirely absent)."""
    import tempfile
    http_src = '''
from mcp.server.fastmcp import FastMCP
from mcp.server.streamable_http import StreamableHTTPServerTransport

mcp = FastMCP("http-server")

@mcp.tool()
def ping() -> str:
    """Ping."""
    return "pong"
'''
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "srv.py"
        p.write_text(http_src, encoding="utf-8")
        ex = ASTExtractor(Path(td))
        model = ex.analyze()
        transports = [srv.get("transport", "") for srv in model.mcp_servers]
        assert any("http" in t for t in transports), (
            f"HTTP transport not detected; got {transports}"
        )


def test_mcp_server_has_name():
    """Commit 7: server name extracted from FastMCP("name") or class."""
    model = _extract()
    names = [srv.get("name", "") for srv in model.mcp_servers]
    assert any("malicious" in n or "test" in n for n in names), (
        f"server name not extracted; got {names}"
    )
