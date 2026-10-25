"""conftest.py — shared pytest fixtures for ghost-data-audit tests."""

import sys
from pathlib import Path

# Ensure the src directory is on the path so tests can import ghost_audit
_SRC = Path(__file__).parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))
