"""Prepare metadata online; run fixed CIC Train/dev profiling in offline LAB."""

import argparse
import json
import os
from pathlib import Path

for name in ("OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS"):
    os.environ[name] = "1"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "run", "restore-model"))
    parser.add_argument("--config", type=Path, default=Path("configs/cic_static_benchmark.yaml"))
    parser.add_argument("--prepared-run")
    parser.add_argument("--baseline-run", help="Prepare exactly the same subset/config as a completed CIC profile run")
    parser.add_argument("--model-file", type=Path, help="prepare: trusted local G-drop3constant joblib; run/restore-model: original deployment JSON")
    parser.add_argument("--lab-isolated", action="store_true",
        help="Console attestation: NAT/host-only disconnected, shared folders/clipboard/drag-drop disabled")
    args = parser.parse_args()
    from malpdf.experiments.cic_static_benchmark import prepare_cic_profile, run_cic_profile, restore_profile_model
    root = Path(__file__).resolve().parents[1]
    if args.action == "prepare":
        state = prepare_cic_profile(root, args.config, baseline_run=args.baseline_run, model_file=args.model_file)
    elif args.action == "restore-model":
        if not args.model_file:
            parser.error("restore-model requires --model-file")
        state = restore_profile_model(root, args.model_file)
    else:
        if not args.prepared_run:
            parser.error("run requires --prepared-run")
        state = run_cic_profile(root, args.prepared_run, lab_attested=args.lab_isolated, model_file=args.model_file)
    print(json.dumps({key: state[key] for key in ("run_id", "status", "report_path")}, indent=2))


if __name__ == "__main__":
    main()
