"""Preflight or explicitly run paper-aligned XGBoost 10-fold CV."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from malpdf.experiments.xgb_cv10 import XGBCV10Error, run_xgb_cv10

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Preflight or run the fixed paper-aligned XGBoost 10-fold CV experiment."
    )
    parser.add_argument("--dataset", type=Path, default=REPOSITORY_ROOT / "data" / "raw" / "rit-pdfmal-2026.csv")
    parser.add_argument("--config", type=Path, default=REPOSITORY_ROOT / "configs" / "xgb_cv10.yaml")
    parser.add_argument("--run-id", default="seed42", help="New immutable CV output ID (default: seed42).")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--execute", action="store_true", help="Fit 20 fixed XGBoost fold/variant runs after preflight.")
    mode.add_argument("--dry-run", action="store_true", help="Explicitly select the default no-fit preflight mode.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        preflight, paths, records = run_xgb_cv10(
            REPOSITORY_ROOT, args.dataset, args.config, run_id=args.run_id, execute=args.execute
        )
    except (FileNotFoundError, ValueError, XGBCV10Error) as error:
        print(f"XGBoost CV10 not completed: {error}", file=sys.stderr)
        return 1
    print(f"Preflight passed for {len(preflight.frame)} rows and dataset SHA-256 {preflight.dataset_sha256}.")
    print(f"Benchmark-generating code commit: {preflight.benchmark_code_commit}")
    print("Validated future execution plan: 20 fixed XGBoost fits (10 folds x 2 feature variants).")
    if not args.execute:
        print("Dry run only: no folds were fitted and no CV outputs were created.")
        return 0
    assert paths is not None
    print(f"Completed {len(records)} XGBoost fold records.")
    print(f"Tracked reports: {paths.reports_directory}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
