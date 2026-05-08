from __future__ import annotations

from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from rst_compliance.rst_dashboard import main


if __name__ == "__main__":
    raise SystemExit(main(project_root=Path(__file__).resolve().parent))
