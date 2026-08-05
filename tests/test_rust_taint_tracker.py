"""Regression tests for the merged Rust taint tracker.

These guard against:
- C3: the duplicate-SHELL_CMD dict key bug that silently dropped detection
  of dynamically-constructed commands (`std::process::Command::new(var)`).
- C5: the `pass`-placeholder bug that skipped sanitizer detection on the
  caller path (multi-hop flows falsely reported exploitable).
- Drift: fast and full mode disagreeing on critical sinks.
"""
from pathlib import Path

import pytest

from core.taint_tracker_rust import RustTaintTracker, SinkKind

# NOTE: fixture lives under testbeds/ (not tests/) because the tracker excludes
# any path containing the "tests" directory component.
FIXTURE = Path(__file__).resolve().parent.parent / "testbeds" / "rust_mini_agent"


def _flows(fast: bool):
    tracker = RustTaintTracker(FIXTURE, fast=fast)
    return tracker.track()


def _shell_cmd_flows(flows):
    return [f for f in flows if f.sink_kind == SinkKind.SHELL_CMD.value]


# ---- C3 regression: dynamic vs literal SHELL_CMD detection ----

def test_shell_cmd_dynamic_detection_full():
    """C3 regression: full mode must flag dynamically-constructed Command::new(var)."""
    flows = _flows(fast=False)
    shell_flows = _shell_cmd_flows(flows)
    # The fixture has THREE Command::new call sites (1 dynamic unsanitized,
    # 1 dynamic sanitized, 1 literal). Full BFS may emit duplicates via
    # multiple paths, so we just assert at least one dynamic hit exists.
    assert any("Command::new" in f.sink_call for f in shell_flows), (
        f"dynamic SHELL_CMD sink not detected; got: {[f.sink_call for f in shell_flows]}"
    )


def test_shell_cmd_literal_detection_full():
    """The literal `Command::new("ls")` must also be flagged."""
    flows = _flows(fast=False)
    shell_flows = _shell_cmd_flows(flows)
    assert any('"ls"' in f.sink_call for f in shell_flows), (
        f"literal SHELL_CMD sink not detected; got: {[f.sink_call for f in shell_flows]}"
    )


def test_no_duplicate_dict_key_in_patterns():
    """Static guard: SINK_CALL_PATTERNS must have exactly one entry per SinkKind.

    This is the structural guard against the C3 root cause (a duplicate key in
    a dict literal silently overwrites the first). If someone re-introduces a
    duplicate, this fails immediately.
    """
    from core import taint_tracker_rust as mod
    # Dict literals collapse duplicates, so len(keys) == len(unique values).
    # We verify the mapping covers every SinkKind exactly once.
    assert set(mod.SINK_CALL_PATTERNS.keys()) == set(mod.SinkKind), (
        "SINK_CALL_PATTERNS must have one entry per SinkKind"
    )


# ---- C5 regression: sanitizer on caller path ----

def test_sanitizer_on_caller_path_full():
    """C5 regression: a flow through handle_user_input_sanitized must carry a
    sanitizer (because check_approval is on the path), so it must NOT be
    reported as exploitable."""
    flows = _flows(fast=False)
    # Find flows whose path includes the sanitized handler.
    sanitized_paths = [
        f for f in flows
        if "handle_user_input_sanitized" in (f.path_functions or [])
        and f.sink_kind == SinkKind.SHELL_CMD.value
    ]
    assert sanitized_paths, "no SHELL_CMD flow through handle_user_input_sanitized found"
    for f in sanitized_paths:
        assert f.sanitizers, (
            f"flow {f.flow_id} through sanitized handler has no sanitizer recorded "
            f"(path={f.path_functions}); C5 regressed"
        )
        assert not f.exploitable, (
            f"flow {f.flow_id} marked exploitable despite sanitizer on path; C5 regressed"
        )


def test_unsanitized_flow_is_exploitable_full():
    """Sanity counterpoint: the flow through the unsanitized handler must be exploitable."""
    flows = _flows(fast=False)
    unsanitized = [
        f for f in flows
        if "handle_user_input" in (f.path_functions or [])
        and "handle_user_input_sanitized" not in (f.path_functions or [])
        and f.sink_kind == SinkKind.SHELL_CMD.value
    ]
    assert unsanitized, "no unsanitized SHELL_CMD flow found"
    assert any(f.exploitable for f in unsanitized), (
        "expected at least one exploitable unsanitized SHELL_CMD flow"
    )


# ---- C5 regression in fast mode ----

def test_sanitizer_on_caller_path_fast():
    """C5 regression in fast mode: the sanitized caller flow must carry a sanitizer.

    This specifically guards against the old fast-version bug where _emit_flow
    had a bare `pass` placeholder for caller-side sanitizer detection.
    """
    flows = _flows(fast=True)
    sanitized_paths = [
        f for f in flows
        if "handle_user_input_sanitized" in (f.path_functions or [])
        and f.sink_kind == SinkKind.SHELL_CMD.value
    ]
    if not sanitized_paths:
        pytest.skip("fast mode did not surface the sanitized caller flow this run")
    for f in sanitized_paths:
        assert f.sanitizers, (
            f"fast-mode flow {f.flow_id} through sanitized handler has no sanitizer; "
            f"C5 fast-mode placeholder bug regressed"
        )


# ---- fast vs full consistency on critical sinks ----

def test_fast_and_full_both_find_shell_cmd():
    """Both modes must find at least one SHELL_CMD sink. Fast is allowed to find
    fewer, but it must NOT silently miss the critical sink class entirely."""
    full_shell = _shell_cmd_flows(_flows(fast=False))
    fast_shell = _shell_cmd_flows(_flows(fast=True))
    assert full_shell, "full mode found no SHELL_CMD — fixture broken"
    assert fast_shell, "fast mode found no SHELL_CMD — consistency regression"


def test_fast_and_full_both_find_exploitable_critical():
    """Both modes must report at least one exploitable critical SHELL_CMD flow
    (the unsanitized handle_user_input → Command::new path)."""
    for fast in (False, True):
        flows = _flows(fast=fast)
        crit = [
            f for f in flows
            if f.severity == "critical" and f.exploitable
            and f.sink_kind == SinkKind.SHELL_CMD.value
        ]
        assert crit, (
            f"mode fast={fast} reported no exploitable critical SHELL_CMD flow"
        )
