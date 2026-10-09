"""Resume six-branch stacking using sealed Kaggle outputs and 25 saved folds."""

import argparse
import json
import os
from pathlib import Path

for name in ("OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS"):
    os.environ.setdefault(name, "1")

import yaml

from malpdf.experiments.raw_tri_modal_resume import run_raw_tri_modal_resume
from malpdf.static.safety import read_bounded_bytes


def main():
    code_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="configs/raw_tri_modal_v3.yaml")
    parser.add_argument("--data-root", type=Path, default=code_root)
    parser.add_argument("--handoff-run", required=True)
    parser.add_argument("--vision-directory", default="checkpoints")
    parser.add_argument("--execute", action="store_true", help="Evaluate Test once; default is preflight only")
    args = parser.parse_args()
    root = args.data_root.absolute()
    config = yaml.safe_load(read_bounded_bytes(code_root / args.config, boundary=code_root / "configs", max_bytes=128 * 1024))
    result = run_raw_tri_modal_resume(root, code_root, config, args.handoff_run,
        root / args.vision_directory, execute=args.execute)
    print(json.dumps({"status": result["status"], "run_id": result["run_id"], "report": result["report_path"]}, indent=2))


if __name__ == "__main__":
    main()
