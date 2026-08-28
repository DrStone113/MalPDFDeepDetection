"""Audit every local CIC CSV/Parquet mirror without selecting one for ML use."""

from __future__ import annotations

import argparse
from pathlib import Path

from malpdf.data.cic_source_fidelity import (
    build_source_fidelity_report,
    inspect_cic_sources,
    write_source_fidelity_outputs,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Read-only CIC mirror source-fidelity audit.")
    parser.add_argument("--dataset-directory", type=Path, default=REPOSITORY_ROOT / "data" / "external" / "cic_evasive_pdfmal2022")
    parser.add_argument("--reports-root", type=Path, default=REPOSITORY_ROOT / "reports")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = build_source_fidelity_report(inspect_cic_sources(args.dataset_directory))
    outputs = write_source_fidelity_outputs(report, args.reports_root)
    print(f"Inspected {len(report['sources'])} CIC tabular mirror(s) without selecting a training source.")
    for source in report["sources"]:
        print(f"{source['filename']}: {source['dimensions']['rows']} rows; {source['fidelity_classification']}; SHA-256 {source['sha256']}")
    print(f"Report: {outputs['markdown']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
