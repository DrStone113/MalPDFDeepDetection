"""Run the interactive, explicitly pinned static extraction launcher."""

import os
from pathlib import Path

for name in ("OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS"):
    os.environ[name] = "1"


if __name__ == "__main__":
    from malpdf.extraction.launcher import main
    raise SystemExit(main(root=Path(__file__).resolve().parents[1]))
