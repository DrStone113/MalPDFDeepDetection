"""Preflight or explicitly run the frozen STRICT6 cross-dataset experiment."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from malpdf.experiments.cross_dataset_strict6 import Strict6Error, run_cross_dataset_strict6

ROOT = Path(__file__).resolve().parents[1]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Preflight or run STRICT6 RIT-to-CIC transfer; dry-run is default.")
    parser.add_argument("--rit", type=Path, default=ROOT / "data" / "raw" / "rit-pdfmal-2026.csv")
    parser.add_argument("--cic-csv", type=Path, default=ROOT / "data" / "external" / "cic_evasive_pdfmal2022" / "PDFMalware2022.csv")
    parser.add_argument("--cic-parquet", type=Path, default=ROOT / "data" / "external" / "cic_evasive_pdfmal2022" / "PDFMalware2022.parquet")
    parser.add_argument("--config", type=Path, default=ROOT / "configs" / "cross_dataset_strict6.yaml")
    parser.add_argument("--run-id", default="seed42")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", help="Verify sources and training readiness without fitting (default).")
    mode.add_argument("--execute", action="store_true", help="Explicitly fit the future 20-result matrix only after preflight succeeds.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        preflight, paths, records = run_cross_dataset_strict6(ROOT, args.rit, args.cic_csv, args.cic_parquet, args.config, run_id=args.run_id, execute=args.execute)
    except (FileNotFoundError, ValueError, Strict6Error) as error:
        print(f"STRICT6 benchmark not completed: {error}", file=sys.stderr)
        return 1
    print(f"Preflight passed: RIT={len(preflight.rit.labels)} rows; canonical CIC={len(preflight.cic.labels)} rows.")
    print(f"Benchmark-generating code commit: {preflight.benchmark_code_commit}")
    if not args.execute:
        print("Dry run only: no classifiers were fitted and no experiment outputs were created.")
        return 0
    assert paths is not None
    print(f"Completed {len(records)} STRICT6 records at {paths.reports_directory}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
