import os
import sys
import pytest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault("LOG_LEVEL", "WARNING")

@pytest.fixture
def set_env(monkeypatch):
    """Alias of pytest fixture for readability in tests."""
    return monkeypatch
