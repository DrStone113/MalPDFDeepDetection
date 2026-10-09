"""Prepare authorized CIC PDFs; preserve disputed labels and exclude known source overlap."""

import argparse
import os
from pathlib import Path

for name in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS"):
    os.environ[name] = "1"

import yaml
from malpdf.experiments.cic_cross_dataset import evaluate_prepared_cic, run_cic_cross_dataset


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="configs/cic_cross_dataset_v3.yaml")
    parser.add_argument("--data-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--archive-file", type=Path, action="append", default=[],
                        help="Manually acquired ignored raw-CIC ZIP; repeat for up to three archives")
    parser.add_argument("--audit-conflicts", action="store_true", help="Reparse locally recoverable disputed files for evidence only")
    parser.add_argument("--evaluate", action="store_true", help="Evaluate a complete verified independent external cohort once")
    parser.add_argument("--prepared-run", help="Reuse measured features/cache from an unscored preparation run")
    parser.add_argument("--allow-input-referrals", action="store_true", help="Separately report valid-PDF metrics and unscored input referrals")
    args = parser.parse_args()
    code_root = Path(__file__).resolve().parents[1]
    from malpdf.static.safety import read_bounded_bytes
    config = yaml.safe_load(read_bounded_bytes(code_root / args.config, boundary=code_root / "configs", max_bytes=64 * 1024))
    if args.prepared_run:
        if not args.evaluate or args.archive_file or args.audit_conflicts:
            parser.error("--prepared-run requires --evaluate without archive extraction or audit reparsing")
        result = evaluate_prepared_cic(args.data_root.absolute(), code_root, config,
            args.prepared_run, allow_input_referrals=args.allow_input_referrals)
    else:
        if args.allow_input_referrals:
            parser.error("--allow-input-referrals requires a separately reported --prepared-run evaluation")
        result = run_cic_cross_dataset(args.data_root.absolute(), code_root, config,
            archive_files=args.archive_file,
            audit_conflicts=args.audit_conflicts, evaluate=args.evaluate)
    print(result["report_path"])
    return 0 if result["status"] == "completed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
