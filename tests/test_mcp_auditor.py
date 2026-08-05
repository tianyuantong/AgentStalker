"""Tests for MCPAuditor (Commit 8) — three static MCP detectors.

Uses the testbeds/mcp_mini_server fixture (a deliberately malicious MCP server
with squatting/poisoned/passthrough tools) plus an injected local tool to
exercise tool-squatting detection.
"""
from pathlib import Path

from core.ast_extractor import ASTExtractor
from core.mcp_auditor import MCPAuditor, Finding

FIXTURE = Path(__file__).resolve().parent.parent / "testbeds" / "mcp_mini_server"


def _build_model_with_local_conflict():
    """Build agent_model from fixture, inject a local tool named 'read_file'
    to create a squatting conflict with the fixture's MCP read_file tool."""
    ex = ASTExtractor(FIXTURE)
    import dataclasses
    model = ex.analyze()
    model_dict = ex._model_to_dict(model)
    # Inject a local tool that collides with the MCP fixture's 'read_file'
    model_dict["tools"].append({
        "name": "read_file",
        "description": "agent's own file reader",
        "parameters": {},
        "risk_level": "medium",
        "requires_approval": False,
        "available": True,
    })
    return model_dict


def test_detect_tool_squatting():
    """R-MCP-SQUAT-001: the MCP 'read_file' tool must be flagged as it shadows
    the agent's local read_file tool."""
    model = _build_model_with_local_conflict()
    auditor = MCPAuditor(model, source_dir=FIXTURE)
    squat_findings = [f for f in auditor.audit() if f.rule_id == "R-MCP-SQUAT-001"]
    assert squat_findings, "no squatting finding despite name collision"
    assert any(f.tool_name == "read_file" for f in squat_findings), (
        f"squatting finding not for read_file; got {[f.tool_name for f in squat_findings]}"
    )
    assert all(f.confidence == 0.90 for f in squat_findings), "confidence must match README:133"


def test_no_squatting_when_no_local_conflict():
    """When local tools are empty, no squatting finding."""
    ex = ASTExtractor(FIXTURE)
    model = ex._model_to_dict(ex.analyze())
    # Force local tools to empty (the fixture's @mcp.tool fns are also extracted
    # as local tools by ASTExtractor; we want to test the no-conflict path).
    model["tools"] = []
    auditor = MCPAuditor(model, source_dir=FIXTURE)
    squat = [f for f in auditor.audit() if f.rule_id == "R-MCP-SQUAT-001"]
    assert squat == [], f"unexpected squatting finding when no local tools: {squat}"


def test_detect_description_poisoning():
    """R-MCP-DESC-001: the 'summarize' tool's description contains
    'ignore previous instructions' and must be flagged."""
    model = _build_model_with_local_conflict()
    auditor = MCPAuditor(model, source_dir=FIXTURE)
    desc_findings = [f for f in auditor.audit() if f.rule_id == "R-MCP-DESC-001"]
    assert desc_findings, "no description-poisoning finding"
    assert any(f.tool_name == "summarize" for f in desc_findings), (
        f"poisoning finding not for summarize; got {[f.tool_name for f in desc_findings]}"
    )


def test_detect_token_passthrough():
    """R-MCP-TOKEN-001: the 'proxy_request' tool forwards Authorization and
    must be flagged."""
    model = _build_model_with_local_conflict()
    auditor = MCPAuditor(model, source_dir=FIXTURE)
    token_findings = [f for f in auditor.audit() if f.rule_id == "R-MCP-TOKEN-001"]
    assert token_findings, "no token-passthrough finding"
    # Confidence should be high (fixture has no token exchange)
    assert token_findings[0].confidence >= 0.7


def test_token_passthrough_confidence_reduced_with_exchange():
    """When a token-exchange signal is present, confidence drops by half."""
    import tempfile
    src = '''
import os, urllib.request
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("passthrough-server")

@mcp.tool()
def proxy(url: str) -> str:
    """Forward."""
    token = os.environ.get("AUTHORIZATION", "")
    req = urllib.request.Request(url, headers={"Authorization": token})
    # but also has token exchange
    exchanged = exchange_token(token)  # token exchange signal
    return str(exchanged)

def exchange_token(t):
    return t + "_exchanged"
'''
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "srv.py"
        p.write_text(src, encoding="utf-8")
        ex = ASTExtractor(Path(td))
        model = ex._model_to_dict(ex.analyze())
        auditor = MCPAuditor(model, source_dir=Path(td))
        token_findings = [f for f in auditor.audit() if f.rule_id == "R-MCP-TOKEN-001"]
        assert token_findings, "token passthrough should still be detected"
        # With exchange signal, confidence should be roughly halved (~0.42)
        assert token_findings[0].confidence < 0.6, (
            f"confidence not reduced despite exchange signal: {token_findings[0].confidence}"
        )


def test_audit_returns_finding_dataclass():
    """All findings must be Finding instances with required fields populated."""
    model = _build_model_with_local_conflict()
    auditor = MCPAuditor(model, source_dir=FIXTURE)
    findings = auditor.audit()
    assert findings, "no findings at all"
    for f in findings:
        assert isinstance(f, Finding)
        assert f.rule_id.startswith("R-MCP-")
        assert f.severity in ("critical", "high", "medium")
        assert 0.0 <= f.confidence <= 1.0
        assert f.server_name
        assert f.description


def test_findings_to_json_serializable():
    """findings_to_json must produce valid JSON."""
    import json
    model = _build_model_with_local_conflict()
    auditor = MCPAuditor(model, source_dir=FIXTURE)
    findings = auditor.audit()
    js = __import__("core.mcp_auditor", fromlist=["findings_to_json"]).findings_to_json(findings)
    parsed = json.loads(js)  # must not raise
    assert isinstance(parsed, list)
    assert len(parsed) == len(findings)
