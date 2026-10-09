"""Prepare, train, export or resume the separately locked multi-cohort v4 study."""

import argparse
import json
import os
from pathlib import Path

for name in ("OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS"):
    os.environ[name] = "1"

import yaml
from malpdf.data.multi_cohort import prepare_v4
from malpdf.experiments.multi_cohort_v4 import export_v4_gpu, resume_v4, train_v4_trees
from malpdf.static.safety import read_bounded_bytes


def main():
    code_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "train-trees", "export-gpu", "evaluate"))
    parser.add_argument("--data-root", type=Path, default=code_root)
    parser.add_argument("--config", default="configs/multi_cohort_v4.yaml")
    parser.add_argument("--prepared-run")
    parser.add_argument("--tree-run")
    parser.add_argument("--handoff-run")
    parser.add_argument("--gpu-directory", type=Path)
    args = parser.parse_args()
    root = args.data_root.absolute()
    if args.action == "prepare":
        cfg = yaml.safe_load(read_bounded_bytes(code_root / args.config, boundary=code_root / "configs", max_bytes=128 * 1024))
        state = prepare_v4(root, code_root, cfg)
    elif args.action == "train-trees":
        if not args.prepared_run: parser.error("--prepared-run is required")
        state = train_v4_trees(root, code_root, args.prepared_run)
    elif args.action == "export-gpu":
        if not args.prepared_run or not args.tree_run: parser.error("--prepared-run and --tree-run are required")
        state = export_v4_gpu(root, code_root, args.prepared_run, args.tree_run)
    else:
        if not args.handoff_run or not args.gpu_directory: parser.error("--handoff-run and --gpu-directory are required")
        state = resume_v4(root, code_root, args.handoff_run, args.gpu_directory)
    print(json.dumps({k: state[k] for k in ("run_id", "status", "report_path")}, indent=2))


if __name__ == "__main__":
    main()
