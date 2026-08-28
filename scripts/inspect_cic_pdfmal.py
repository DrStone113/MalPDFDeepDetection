"""Run the read-only CIC-Evasive-PDFMal2022 tabular audit."""

from __future__ import annotations

import argparse
from pathlib import Path

from malpdf.data.cic_pdfmal import discover_cic_dataset, inspect_cic_pdfmal, write_cic_audit_outputs

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Read-only audit of a local CIC-Evasive-PDFMal2022 CSV or Parquet feature table.")
    parser.add_argument("--dataset", type=Path, help="Explicit CIC .csv or .parquet table. Defaults to deterministic discovery.")
    parser.add_argument("--dataset-directory", type=Path, default=REPOSITORY_ROOT / "data" / "external" / "cic_evasive_pdfmal2022")
    parser.add_argument("--reports-root", type=Path, default=REPOSITORY_ROOT / "reports")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    path = args.dataset or discover_cic_dataset(args.dataset_directory).selected_path
    report = inspect_cic_pdfmal(path)
    outputs = write_cic_audit_outputs(report, args.reports_root)
    print(f"Audited {report['dimensions']['rows']} rows and {report['dimensions']['columns']} columns from {path.name}.")
    print(f"SHA-256: {report['dataset']['sha256']}")
    print(f"Candidate target: {report['target']['candidate_column']}")
    print(f"Reports: {outputs['markdown']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
