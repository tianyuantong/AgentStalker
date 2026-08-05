"""Regression test for heal_diagnose C4 (UnboundLocalError: sys).

heal_diagnose.main() referenced sys.stdin.isatty() / sys.stderr but
'import sys' only lived inside an elif branch and the __main__ block,
so a piped-stdin invocation raised UnboundLocalError before reading input.
"""
import io
import sys


def test_heal_diagnose_imports_sys_at_module_level():
    """C4 regression: 'sys' must be importable as a module-level name."""
    import sandbox.heal_diagnose as hd
    assert hasattr(hd, "sys"), "heal_diagnose does not import sys at module level — C4 regressed"


def test_heal_diagnose_main_reads_stdin(monkeypatch):
    """C4 regression: main() must not raise UnboundLocalError when invoked
    with piped stdin (no --error-text / --error-file)."""
    # Simulate piped stdin (not a tty) with some error text.
    fake_stdin = io.StringIO("ModuleNotFoundError: No module named 'fastapi'\n")
    monkeypatch.setattr(sys, "stdin", fake_stdin)
    # argparse reads from sys.argv
    monkeypatch.setattr(sys, "argv", ["heal_diagnose", "--json"])

    import sandbox.heal_diagnose as hd
    # Should not raise UnboundLocalError; returns an int exit code.
    rc = hd.main()
    assert isinstance(rc, int)


def test_heal_diagnose_returns_exit_codes(monkeypatch):
    """The exit-code contract: 0 auto-fixable, 1 unmatched, 2 requires user."""
    import sandbox.heal_diagnose as hd
    monkeypatch.setattr(sys, "argv", ["heal_diagnose", "--error-text", "totally unknown gibberish error"])
    rc = hd.main()
    assert rc == 1, f"unmatched error should return 1, got {rc}"
