import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


@pytest.fixture(autouse=True)
def no_real_keys(monkeypatch):
    """Tests never need real credentials or the parent agent session."""
    for key in list(os.environ):
        if key.endswith("_API_KEY") or key.startswith(("CLAUDECODE", "CLAUDE_CODE_")):
            monkeypatch.delenv(key, raising=False)
