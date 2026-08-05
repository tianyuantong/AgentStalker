"""Smoke tests — verify the foundational modules import cleanly.

These guard against the C1/C2 class of bugs where a package __init__ references
modules that don't exist. If any of these fail, the rest of the suite is moot.
"""
import importlib


def test_core_package_imports():
    import core  # noqa: F401
    assert importlib.util.find_spec("core") is not None


def test_sandbox_package_imports():
    import sandbox  # noqa: F401
    assert importlib.util.find_spec("sandbox") is not None


def test_yaml_deps_available():
    # PyYAML is the most load-bearing dependency for data files.
    import yaml  # noqa: F401
    import jinja2  # noqa: F401


def test_taint_tracker_python_imports():
    # Stage 1 core entry point must be importable.
    from core import taint_tracker  # noqa: F401


def test_rust_taint_tracker_imports():
    # After Commit 2 merges the two Rust trackers, this is the single survivor.
    from core import taint_tracker_rust  # noqa: F401
