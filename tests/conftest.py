"""Pytest configuration shared across the AgentStalker test suite."""
import sys
from pathlib import Path

# Make repo-root importable so `import core` / `import sandbox` work from tests.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

# Expose common fixture roots to tests.
FIXTURES_DIR = _REPO_ROOT / "tests" / "fixtures"
