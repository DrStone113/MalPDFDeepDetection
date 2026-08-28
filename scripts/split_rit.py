"""Create deterministic duplicate-aware RIT-PDFMal split metadata."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT / "src"))

from malpdf.data.rit_pdfmal_split import (
    DEFAULT_SPLIT_SEED,
    split_rit_pdfmal_file,
    write_split_artifacts,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create a deterministic duplicate-aware RIT-PDFMal split manifest."
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        default=REPOSITORY_ROOT / "data" / "raw" / "rit-pdfmal-2026.csv",
        help="Path to the CSV dataset (default: data/raw/rit-pdfmal-2026.csv).",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=DEFAULT_SPLIT_SEED,
        help=f"Deterministic tie-break seed (default: {DEFAULT_SPLIT_SEED}).",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=REPOSITORY_ROOT / "data" / "processed" / "rit-pdfmal-2026_split_manifest.csv",
        help="Output CSV manifest path.",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=REPOSITORY_ROOT / "reports" / "rit-pdfmal-2026_split_report.json",
        help="Output JSON report path.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    manifest, report = split_rit_pdfmal_file(args.dataset, seed=args.seed)
    write_split_artifacts(manifest, report, args.manifest, args.report)
    print(f"Dataset: {report['dataset']['filename']}")
    print(f"Manifest: {args.manifest}")
    print(f"Report: {args.report}")
    for split_name, statistics in report["split_statistics"].items():
        print(
            f"{split_name}: {statistics['row_count']} rows; "
            f"Label=0 {statistics['benign']['count']}; "
            f"Label=1 {statistics['malicious']['count']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
