"""Tests for payloads/mcp.yaml (Commit 10) and Rust MCP detection."""
import re
from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent


# ---- payloads/mcp.yaml schema + content ----

def test_mcp_payload_file_loads():
    """The new 14th payload category must be valid YAML and load."""
    p = REPO_ROOT / "payloads" / "mcp.yaml"
    assert p.exists(), "payloads/mcp.yaml missing"
    data = yaml.safe_load(p.read_text(encoding="utf-8"))
    assert "metadata" in data
    assert "first_pass" in data
    assert "description_poisoning" in data
    assert "token_passthrough" in data


def test_mcp_payload_has_detection_metadata():
    """Each payload block should reference its detector (the contract that makes
    payloads contextualized, per README's 'first_pass/detection/sandbox_monitoring')."""
    data = yaml.safe_load((REPO_ROOT / "payloads" / "mcp.yaml").read_text(encoding="utf-8"))
    # first_pass should mention the squatting detector
    fp_text = str(data.get("first_pass", {}))
    assert "tool_squatting" in fp_text or "MCPMonitor" in fp_text
    # description_poisoning should reference R-MCP-DESC-001
    dp_text = str(data.get("description_poisoning", {}))
    assert "R-MCP-DESC-001" in dp_text


def test_mcp_payload_is_new_category():
    """Commit 10 adds payloads/mcp.yaml as a new payload category."""
    payload_files = list((REPO_ROOT / "payloads").glob("*.yaml"))
    categories = [f for f in payload_files if not f.name.startswith("_")]
    # Before Commit 10 there were 11 named categories (12 files incl _misc);
    # mcp.yaml is the new one. Just verify it's present and named correctly.
    assert (REPO_ROOT / "payloads" / "mcp.yaml") in categories, "mcp.yaml missing"
    assert len(categories) >= 11, f"expected >=11 named categories, got {len(categories)}"


# ---- Rust MCP detection ----

def test_rust_mcp_detects_token_passthrough():
    """Rust MCP server source with .bearer_auth(token) must be flagged."""
    from core.mcp_auditor import MCPAuditor

    fixture = REPO_ROOT / "testbeds" / "rust_mcp_server"
    agent_model = {
        "mcp_servers": [
            {"name": "mcp_qualified", "file": "src/main.rs", "line": 1, "match": "McpClient"}
        ],
    }
    auditor = MCPAuditor(agent_model, source_dir=fixture)
    findings = auditor._audit_rust_mcp_servers()
    token_findings = [f for f in findings if f.rule_id == "R-MCP-TOKEN-001"]
    assert token_findings, f"Rust token passthrough not detected; got {[f.rule_id for f in findings]}"


def test_rust_mcp_detects_description_poisoning():
    """Rust doc comment with 'ignore previous instructions' must be flagged."""
    from core.mcp_auditor import MCPAuditor

    fixture = REPO_ROOT / "testbeds" / "rust_mcp_server"
    agent_model = {
        "mcp_servers": [
            {"name": "mcp_qualified", "file": "src/main.rs", "line": 1, "match": "McpClient"}
        ],
    }
    auditor = MCPAuditor(agent_model, source_dir=fixture)
    findings = auditor._audit_rust_mcp_servers()
    desc_findings = [f for f in findings if f.rule_id == "R-MCP-DESC-001"]
    assert desc_findings, f"Rust desc poisoning not detected; got {[f.rule_id for f in findings]}"


def test_attack_chains_assertions_documented():
    """CH-005/CH-006 assertions should now reference the implemented events."""
    chains = (REPO_ROOT / "templates" / "attack_chains.yaml").read_text(encoding="utf-8")
    # The mapping comments we added
    assert "MCPMonitor event_type=description_poisoning" in chains
    assert "MCPAuditor R-MCP-TOKEN-001" in chains
