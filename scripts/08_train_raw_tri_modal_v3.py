"""Train the authorized full raw cohort from a clean committed code checkout."""

import argparse
import json
import os
from pathlib import Path

for name in ("OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS"):
    os.environ.setdefault(name, "1")

import yaml

from malpdf.experiments.raw_tri_modal_v3 import run_raw_tri_modal
from malpdf.static.safety import read_bounded_bytes


def main():
    code_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="configs/raw_tri_modal_v3.yaml")
    parser.add_argument("--data-root", type=Path, default=code_root)
    parser.add_argument("--run-id")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    configuration = yaml.safe_load(read_bounded_bytes(code_root / args.config, boundary=code_root / "configs", max_bytes=128 * 1024))
    report = run_raw_tri_modal(args.data_root.absolute(), code_root, configuration, execute=args.execute, run_id=args.run_id)
    print(json.dumps({"status": report["status"], "run_id": report["run_id"], "report": report["report_path"]}, indent=2))


if __name__ == "__main__":
    main()
