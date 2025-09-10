import os
import sys
from pathlib import Path

# Ensure `src` is importable when running tests outside Docker
ROOT = Path(__file__).resolve().parents[1]
# Put project root on sys.path so `import src.*` works
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Keep test output predictable
os.environ.setdefault("LOG_LEVEL", "WARNING")
