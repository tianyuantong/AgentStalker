"""Regression tests for the monitoring package (C1 + mcp_io layer).

C1: sandbox/monitoring/__init__.py used to import from three non-existent
modules (memory_inspector, credential_monitor, ebpf_runner) whose classes
actually lived in _secondary_monitors.py. The whole package was unimportable.
"""
import pytest


def test_import_sandbox_monitoring():
    """C1 regression: the package must import without ModuleNotFoundError."""
    import sandbox.monitoring  # noqa: F401


def test_all_seven_original_layers_resolvable():
    """All SKILL.md-advertised monitor classes must be importable."""
    from sandbox.monitoring import (
        NetworkMonitor,
        FilesystemMonitor,
        ProcessMonitor,
        LLMProxy,
        MemoryInspector,
        CredentialMonitor,
        EBPFRunner,
    )
    # Each must be a class
    for cls in (NetworkMonitor, FilesystemMonitor, ProcessMonitor, LLMProxy,
                MemoryInspector, CredentialMonitor, EBPFRunner):
        assert isinstance(cls, type), f"{cls} is not a class"


def test_mcp_monitor_resolvable():
    """The new 8th layer (mcp_io) must be importable.

    This resolves the dangling 'mcp_io' string that sandbox/discovery.py
    appends to recommended_monitoring — there was no monitor class for it.
    """
    from sandbox.monitoring import MCPMonitor
    assert isinstance(MCPMonitor, type)


def test_no_underscore_monitor_files_remain():
    """Guard against re-introducing the _monitors.py / _secondary_monitors.py
    temp files. After the split, every monitor lives in a properly-named module."""
    import sandbox.monitoring as pkg
    from pathlib import Path
    pkg_dir = Path(pkg.__file__).parent
    py_files = [f.name for f in pkg_dir.glob("*.py")]
    underscore_files = [f for f in py_files if f.startswith("_") and f != "__init__.py"]
    assert not underscore_files, (
        f"unexpected underscore-prefixed monitor files: {underscore_files}"
    )


def test_memory_inspector_instantiable():
    """Sanity: a split-out class still constructs."""
    from sandbox.monitoring import MemoryInspector
    mi = MemoryInspector(output_dir="./output/evidence_test")
    assert mi.events == []


def test_mcp_monitor_skeleton_raises_not_implemented():
    """The skeleton's inspect_server is intentionally unimplemented until Commit 9."""
    from sandbox.monitoring import MCPMonitor
    mon = MCPMonitor()
    with pytest.raises(NotImplementedError):
        mon.inspect_server("python -m fake_server")
