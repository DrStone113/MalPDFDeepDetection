"""Audit paper macro-metric semantics from committed Protocol P/G reports."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT / "src"))

from malpdf.analysis.metric_semantics import MetricSemanticsError, run_metric_semantics_audit  # noqa: E402
from malpdf.analysis.protocol_p_vs_g import ProtocolComparisonError  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Derive macro-metric paper-comparison corrections without refitting models."
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Explicitly replace only prior metric-semantics analysis outputs.",
    )
    args = parser.parse_args(argv)
    try:
        paths, tables, _ = run_metric_semantics_audit(REPOSITORY_ROOT, overwrite=args.overwrite)
    except (FileNotFoundError, MetricSemanticsError, ProtocolComparisonError, ValueError) as error:
        print(f"Metric-semantics audit not completed: {error}", file=sys.stderr)
        return 1
    print("Completed report-only paper metric-semantics correction audit.")
    print(f"Tables: {paths.tables_directory} ({len(tables)} CSV files)")
    print(f"Markdown analysis: {paths.markdown_analysis}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
