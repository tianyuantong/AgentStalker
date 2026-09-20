"""Tests for MCP runtime verification (Commit 9) — MCPMonitor + VerdictEngine R009-R011.

These drive the real testbeds/mcp_mini_server fixture (a FastMCP server with
squatting/poisoned/passthrough tools) and verify the full chain:
MCPMonitor.inspect_server -> MCPEvent -> EvidenceBuilder -> VerdictEngine.

Requires the MCP v1 SDK; skipped if unavailable.
"""
import sys
from pathlib import Path

import pytest

pytest.importorskip("mcp")

from sandbox.monitoring.mcp_monitor import MCPMonitor, MCPEvent
from sandbox.correlation import EvidenceBuilder, VerdictEngine, Evidence, Verdict

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURE_DIR = REPO_ROOT / "testbeds" / "mcp_mini_server"


def _server_command():
    """Command to launch the fixture MCP server as a subprocess."""
    # Run as a module so relative imports resolve; cwd = repo root.
    return [sys.executable, "-m", "testbeds.mcp_mini_server.server"]


def _inspect(local_tools):
    """Helper: run MCPMonitor against the fixture, return events."""
    import os
    cwd = str(REPO_ROOT)
    old_cwd = os.getcwd()
    os.chdir(cwd)
    try:
        mon = MCPMonitor()
        events = mon.inspect_server(
            server_command=_server_command(),
            local_tool_names=local_tools,
            probe_tools=False,  # skip empty-arg probes (fixture tools need args)
        )
        return events
    finally:
        os.chdir(old_cwd)


def test_mcp_monitor_finds_squatting():
    """R009 setup: with read_file in local tools, MCPMonitor must emit a
    tool_squatting event."""
    events = _inspect(local_tools=["read_file", "search"])
    squat = [e for e in events if e.event_type == "tool_squatting"]
    assert squat, f"no squatting event; got {[e.event_type for e in events]}"
    assert any(e.tool_name == "read_file" for e in squat)
    assert all(e.layer == "mcp" and e.verdict == "suspicious" for e in squat)


def test_mcp_monitor_finds_description_poisoning():
    """R010 setup: the summarize tool's poisoned description must be detected at runtime."""
    events = _inspect(local_tools=[])
    poison = [e for e in events if e.event_type == "description_poisoning"]
    assert poison, f"no poisoning event; got {[e.event_type for e in events]}"
    assert any(e.tool_name == "summarize" for e in poison)


def test_no_squatting_when_no_local_conflict():
    """Without read_file in local tools, no squatting event."""
    events = _inspect(local_tools=["totally_different_name"])
    squat = [e for e in events if e.event_type == "tool_squatting"]
    assert squat == [], f"unexpected squatting: {squat}"


def test_verdict_engine_r009_squatting():
    """Legacy tool-name collision is a recorded signal, not proof of exploitation."""
    mon = MCPMonitor()
    # Manually construct the event (don't need a live server for the verdict test)
    event = MCPEvent(
        timestamp=0,
        event_type="tool_squatting",
        server_name="test",
        tool_name="read_file",
        verdict="malicious",
    )
    builder = EvidenceBuilder()
    ev = builder.build(
        test_case={"id": "TC-MCP-1", "title": "squatting", "severity": "high"},
        mcp_events=[event],
    )
    engine = VerdictEngine()
    engine.judge(ev)
    assert ev.verdict == Verdict.INCONCLUSIVE.value  # legacy event has no execution coverage
    assert ev.metadata["reason_code"] == "legacy_unverified"
    assert ev.metadata["matched_rules"] == ["R009"]
    assert ev.metadata["matched_rule"] == "R009"



def test_verdict_engine_r010_description_poisoning():
    """Legacy description event is a recorded signal without execution coverage."""
    from sandbox.correlation import EvidenceBuilder, VerdictEngine, Verdict
    event = MCPEvent(
        timestamp=0,
        event_type="description_poisoning",
        server_name="test",
        tool_name="summarize",
        verdict="suspicious",
    )
    builder = EvidenceBuilder()
    ev = builder.build(
        test_case={"id": "TC-MCP-2", "title": "desc poison"},
        mcp_events=[event],
    )
    VerdictEngine().judge(ev)
    assert ev.verdict == Verdict.INCONCLUSIVE.value
    assert ev.metadata["reason_code"] == "legacy_unverified"
    assert ev.metadata["matched_rules"] == ["R010"]


def test_verdict_engine_r011_token_passthrough():
    """Legacy token event is a recorded signal without independent effect confirmation."""
    event = MCPEvent(
        timestamp=0,
        event_type="token_passthrough",
        server_name="test",
        tool_name="proxy_request",
        verdict="suspicious",
    )
    builder = EvidenceBuilder()
    ev = builder.build(
        test_case={"id": "TC-MCP-3", "title": "token passthrough"},
        mcp_events=[event],
    )
    VerdictEngine().judge(ev)
    assert ev.verdict == Verdict.INCONCLUSIVE.value
    assert ev.metadata["reason_code"] == "legacy_unverified"
    assert ev.metadata["matched_rules"] == ["R011"]


def test_evidence_builder_accepts_mcp_events():
    """EvidenceBuilder.build must accept the new mcp_events kwarg and tag the mcp layer."""
    event = MCPEvent(timestamp=0, event_type="tool_squatting", tool_name="x", verdict="malicious")
    ev = EvidenceBuilder().build(test_case={"id": "T1"}, mcp_events=[event])
    assert "mcp" in ev.layers
    assert len(ev.events) == 1
