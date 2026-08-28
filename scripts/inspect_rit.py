"""Create a read-only audit report for a RIT-PDFMal-2026 CSV file."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT / "src"))

from malpdf.data.rit_pdfmal import inspect_rit_pdfmal, write_inspection_reports


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Perform a non-mutating RIT-PDFMal-2026 CSV inspection."
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        default=REPOSITORY_ROOT / "data" / "raw" / "rit-pdfmal-2026.csv",
        help="Path to the CSV dataset (default: data/raw/rit-pdfmal-2026.csv).",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=REPOSITORY_ROOT / "reports",
        help="Directory for Markdown and JSON reports (default: reports).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = inspect_rit_pdfmal(args.dataset)
    report_stem = f"{args.dataset.stem}_inspection"
    markdown_path = args.output_dir / f"{report_stem}.md"
    json_path = args.output_dir / f"{report_stem}.json"
    write_inspection_reports(report, markdown_path, json_path)
    print(f"Inspected: {report['dataset']['filename']}")
    print(f"Markdown report: {markdown_path}")
    print(f"JSON report: {json_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
