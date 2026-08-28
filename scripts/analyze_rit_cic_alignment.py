"""Build read-only RIT-to-CIC schema-alignment evidence; no model is trained."""

from __future__ import annotations

import argparse
from pathlib import Path

from malpdf.data.cic_pdfmal import discover_cic_dataset, inspect_cic_pdfmal, load_cic_pdfmal
from malpdf.data.cross_dataset_schema import build_schema_alignment_report, write_schema_alignment_outputs
from malpdf.data.rit_pdfmal import load_rit_pdfmal

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Read-only RIT-PDFMal-2026 to CIC feature-schema alignment audit.")
    parser.add_argument("--cic-dataset", type=Path, help="Explicit CIC .csv or .parquet table. Defaults to deterministic discovery.")
    parser.add_argument("--cic-dataset-directory", type=Path, default=REPOSITORY_ROOT / "data" / "external" / "cic_evasive_pdfmal2022")
    parser.add_argument("--rit-dataset", type=Path, default=REPOSITORY_ROOT / "data" / "raw" / "rit-pdfmal-2026.csv")
    parser.add_argument("--reports-root", type=Path, default=REPOSITORY_ROOT / "reports")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    cic_path = args.cic_dataset or discover_cic_dataset(args.cic_dataset_directory).selected_path
    cic_report = inspect_cic_pdfmal(cic_path)
    report = build_schema_alignment_report(cic_report, load_cic_pdfmal(cic_path), load_rit_pdfmal(args.rit_dataset))
    outputs = write_schema_alignment_outputs(report, args.reports_root)
    print(f"Aligned {report['rit_feature_count']} RIT features with {report['cic_candidate_predictive_feature_count']} CIC candidate predictors.")
    print(f"COMMON_STRICT={len(report['common_strict'])}; COMMON_TRANSFORMABLE={len(report['common_transformable'])}")
    print(f"Report: {outputs['markdown']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
