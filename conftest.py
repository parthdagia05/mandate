import sys
from pathlib import Path

# The project is a flat layout (kernel/, agent/, sim/, harness/ at the root),
# so tests need the root on the path whether or not the package is installed.
sys.path.insert(0, str(Path(__file__).resolve().parent))
