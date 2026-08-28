"""Produce a conservative v2 RIT-to-CIC mapping review for one explicit source."""

from __future__ import annotations

import argparse
from pathlib import Path

from malpdf.data.cic_pdfmal import inspect_cic_pdfmal
from malpdf.data.cross_dataset_schema import build_mapping_resolution_report, write_mapping_resolution_outputs

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Read-only RIT-to-CIC mapping-resolution audit; no model is trained.")
    parser.add_argument("--cic-dataset", type=Path, required=True, help="Explicit CIC CSV/Parquet mirror under review; no mirror is selected implicitly.")
    parser.add_argument("--reports-root", type=Path, default=REPOSITORY_ROOT / "reports")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = build_mapping_resolution_report(inspect_cic_pdfmal(args.cic_dataset))
    outputs = write_mapping_resolution_outputs(report, args.reports_root)
    print(f"Resolved mapping review for {report['cic_source']['filename']} ({report['cic_source']['sha256']}).")
    print(f"Status counts: {report['new_status_counts']}")
    print(f"COMMON_STRICT={len(report['common_strict_v2'])}; COMMON_TRANSFORMABLE={len(report['common_transformable_v2'])}")
    print(f"Report: {outputs['markdown']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
