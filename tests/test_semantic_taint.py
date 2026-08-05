"""Tests for the semantic taint engine (Commit 11) — v2 breakpoint-1 skeleton.

Validates:
- llm_invocations extraction (ChatOpenAI / .invoke on llm-named object)
- TaintFlow gains confidence/feature_type fields
- flows through an LLM hop get confidence < 1.0; direct flows stay at 1.0
- LLM resistance override works
"""
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURE = REPO_ROOT / "testbeds" / "python_mini_agent"


# ---- LLM invocation extraction ----

def test_extracts_llm_invocations():
    """The fixture's ChatOpenAI(...) and llm.invoke(...) must be extracted."""
    from core.ast_extractor import ASTExtractor
    model = ASTExtractor(FIXTURE).analyze()
    assert len(model.llm_invocations) >= 1, (
        f"no llm_invocations extracted; got {model.llm_invocations}"
    )
    # ChatOpenAI should be one of them
    callees = [inv["callee"] for inv in model.llm_invocations]
    assert any("ChatOpenAI" in c or "invoke" in c for c in callees), (
        f"expected ChatOpenAI or invoke in {callees}"
    )


def test_llm_invocations_serialized():
    """agent_model.json must include llm_invocations."""
    from core.ast_extractor import ASTExtractor
    import json
    model = ASTExtractor(FIXTURE).analyze()
    d = ASTExtractor(FIXTURE)._model_to_dict(model)
    assert "llm_invocations" in d
    # Round-trips as JSON
    json.dumps(d)


# ---- TaintFlow new fields ----

def test_taintflow_has_confidence_default_1():
    """TaintFlow.confidence defaults to 1.0 (backward compatible)."""
    from core.taint_tracker import TaintFlow, TaintNode, TaintKind, SinkKind
    src = TaintNode(var_name="x", kind=TaintKind.USER_INPUT, source_location="a.py:1")
    sink = TaintNode(var_name="y", kind=SinkKind.TOOL_CALL, source_location="a.py:2")
    f = TaintFlow(flow_id="F1", source=src, sink=sink)
    assert f.confidence == 1.0
    assert f.feature_type == ""
    assert f.llm_hops == []


# ---- SemanticTaintGraph enrichment ----

def _enriched_flows():
    """Build flows from fixture + enrich them."""
    from core.ast_extractor import ASTExtractor
    from core.taint_tracker import TaintTracker
    from core.semantic_taint import SemanticTaintGraph

    agent_model = ASTExtractor(FIXTURE)._model_to_dict(ASTExtractor(FIXTURE).analyze())
    tracker = TaintTracker(FIXTURE, agent_model)
    flows = tracker.track()
    stg = SemanticTaintGraph(agent_model)
    return stg.enrich(flows), agent_model


def test_feature_type_classification():
    """Each flow's feature_type must be set based on source kind."""
    flows, _ = _enriched_flows()
    for f in flows:
        assert f.feature_type in (
            "direct_instruction", "structured_data", "indirect_reference", "non_text"
        ), f"bad feature_type {f.feature_type}"


def test_confidence_through_llm_hop_is_discounted():
    """Flows whose source file has an LLM invocation must get confidence < 1.0
    (probabilistic propagation through the LLM hop)."""
    flows, _ = _enriched_flows()
    discounted = [f for f in flows if f.confidence < 1.0]
    # The fixture has ChatOpenAI in agent.py, and flows from that file should be discounted
    if not flows:
        pytest.skip("taint tracker found no flows in fixture")
    assert discounted, (
        f"expected at least one discounted flow; confidences={[f.confidence for f in flows]}"
    )


def test_prompt_construct_sink_is_llm_hop():
    """A flow with a prompt_construct sink must be treated as going through an
    LLM hop (the value reaches the LLM as context)."""
    from core.taint_tracker import TaintFlow, TaintNode, TaintKind, SinkKind
    from core.semantic_taint import SemanticTaintGraph

    src = TaintNode(var_name="fc", kind=TaintKind.FILE_CONTENT, source_location="a.py:1")
    sink = TaintNode(var_name="p", kind=SinkKind.PROMPT_CONSTRUCT, source_location="a.py:2")
    flow = TaintFlow(flow_id="F1", source=src, sink=sink)

    stg = SemanticTaintGraph({})
    stg.enrich([flow])
    assert flow.llm_hops, "prompt_construct sink must register an LLM hop"
    assert flow.confidence < 1.0


def test_no_llm_hop_confidence_unchanged():
    """A flow with no LLM in its file, no LLM var in path, and not a prompt
    sink must keep confidence 1.0."""
    from core.taint_tracker import TaintFlow, TaintNode, TaintKind, SinkKind
    from core.semantic_taint import SemanticTaintGraph

    src = TaintNode(var_name="x", kind=TaintKind.USER_INPUT, source_location="nosuch.py:1")
    sink = TaintNode(var_name="y", kind=SinkKind.SHELL_CMD, source_location="nosuch.py:2")
    flow = TaintFlow(flow_id="F1", source=src, sink=sink, path=["x", "y"])

    stg = SemanticTaintGraph({})  # empty agent_model = no llm_invocations
    stg.enrich([flow])
    assert flow.confidence == 1.0
    assert flow.llm_hops == []


def test_llm_resistance_override():
    """A custom llm_resistance dict must override defaults."""
    from core.taint_tracker import TaintFlow, TaintNode, TaintKind, SinkKind
    from core.semantic_taint import SemanticTaintGraph

    src = TaintNode(var_name="x", kind=TaintKind.USER_INPUT, source_location="a.py:1")
    sink = TaintNode(var_name="y", kind=SinkKind.PROMPT_CONSTRUCT, source_location="a.py:2")
    flow_default = TaintFlow(flow_id="F1", source=src, sink=sink)
    flow_override = TaintFlow(flow_id="F2", source=src, sink=sink)

    stg_default = SemanticTaintGraph({}, llm_model_hint="gpt-4")
    stg_default.enrich([flow_default])

    stg_override = SemanticTaintGraph({}, llm_resistance={"gpt-4": 0.99}, llm_model_hint="gpt-4")
    stg_override.enrich([flow_override])

    assert flow_override.confidence != flow_default.confidence, (
        f"override had no effect: {flow_override.confidence} == {flow_default.confidence}"
    )
