"""Local paired-test variant. Only synthetic data inside an isolated test tree.

This is a tool-boundary fixture, not a model or a production sandbox. HTTP is
restricted to the loopback test receiver in BOTH variants to avoid live egress.
"""
import os
from pathlib import Path
import urllib.parse
import urllib.request

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("regression-tools")


def config():
    tree = Path(os.environ["AST_TEST_TREE"]).resolve()
    return tree, os.environ["AST_VARIANT"]


@mcp.tool()
def read_file(path: str) -> str:
    """Read a file subject to the configured test workspace boundary."""
    tree, variant = config()
    p = Path(path).resolve()
    if not p.is_relative_to(tree):
        return "DENIED: outside test tree"
    if variant == "disabled":
        return "DENIED: tool disabled"
    if variant == "fixed" and not p.is_relative_to(tree / "allowed"):
        return "DENIED: outside allowed workspace"
    return p.read_text()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@mcp.tool()
def proxy_request(url: str) -> str:
    """Fetch from the local synthetic receiver; fixed mode never forwards credentials."""
    _, variant = config()
    parts = urllib.parse.urlsplit(url)
    receiver = urllib.parse.urlsplit(os.environ["AST_RECEIVER"])
    if (parts.scheme, parts.hostname, parts.port) != (receiver.scheme, receiver.hostname, receiver.port):
        return "DENIED: outside test receiver"
    if variant == "disabled":
        return "DENIED: tool disabled"
    if variant == "fixed" and not parts.path.startswith("/public/"):
        return "DENIED: target not allowed"
    headers = {} if variant == "fixed" else {"Authorization": os.environ["AUTHORIZATION"]}
    req = urllib.request.Request(url, headers=headers)
    # Ignore host proxy settings; no redirect can escape the test endpoint.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(req, timeout=5) as resp:
        return resp.read(4096).decode()


if __name__ == "__main__":
    mcp.run(transport="stdio")
