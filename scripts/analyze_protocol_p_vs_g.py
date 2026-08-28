"""Create thesis analysis outputs from the committed Protocol P/G baselines."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT / "src"))

from malpdf.analysis.protocol_p_vs_g import (  # noqa: E402
    ProtocolComparisonError,
    run_protocol_p_vs_g_analysis,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Analyse committed seed-42 Protocol P and G reports without fitting models."
    )
    parser.add_argument(
        "--protocol-p-directory",
        type=Path,
        default=REPOSITORY_ROOT / "reports" / "experiments" / "protocol_p" / "seed42",
    )
    parser.add_argument(
        "--protocol-g-directory",
        type=Path,
        default=REPOSITORY_ROOT / "reports" / "experiments" / "protocol_g" / "seed42",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Explicitly replace only existing comparative-analysis outputs.",
    )
    args = parser.parse_args(argv)
    try:
        paths, tables, _ = run_protocol_p_vs_g_analysis(
            REPOSITORY_ROOT,
            protocol_p_directory=args.protocol_p_directory,
            protocol_g_directory=args.protocol_g_directory,
            overwrite=args.overwrite,
        )
    except (FileNotFoundError, ProtocolComparisonError, ValueError) as error:
        print(f"Protocol comparison analysis not completed: {error}", file=sys.stderr)
        return 1
    print("Completed report-only Protocol P versus Protocol G comparative analysis.")
    print(f"Tables: {paths.tables_directory} ({len(tables)} CSV files)")
    print(f"Figures: {paths.figures_directory}")
    print(f"Markdown analysis: {paths.markdown_analysis}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
