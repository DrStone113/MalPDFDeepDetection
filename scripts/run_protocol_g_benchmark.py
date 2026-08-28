"""Run the saved-split 10-combination Protocol G benchmark from a clean checkout."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT / "src"))

from malpdf.data.rit_pdfmal_split import DEFAULT_SPLIT_SEED
from malpdf.experiments.protocol_g_benchmark import (
    PRIMARY_G_BENCHMARK_MATRIX,
    ProtocolGBenchmarkError,
    run_protocol_g_benchmark,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the 10-combination feature-vector-disjoint Protocol G benchmark."
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        default=REPOSITORY_ROOT / "data" / "raw" / "rit-pdfmal-2026.csv",
    )
    parser.add_argument("--seed", type=int, default=DEFAULT_SPLIT_SEED)
    parser.add_argument(
        "--split-manifest",
        type=Path,
        default=REPOSITORY_ROOT / "data" / "processed" / "rit-pdfmal-2026_split_manifest.csv",
    )
    parser.add_argument(
        "--split-report",
        type=Path,
        default=REPOSITORY_ROOT / "reports" / "rit-pdfmal-2026_split_report.json",
    )
    parser.add_argument(
        "--protocol-p-summary",
        type=Path,
        default=REPOSITORY_ROOT / "reports" / "experiments" / "protocol_p" / "seed42" / "summary.csv",
    )
    parser.add_argument(
        "--run-id",
        help="Unique optional run ID; existing Protocol G reports and artifacts are never overwritten.",
    )
    args = parser.parse_args(argv)

    try:
        paths, records = run_protocol_g_benchmark(
            REPOSITORY_ROOT,
            args.dataset,
            seed=args.seed,
            run_id=args.run_id,
            manifest_path=args.split_manifest,
            split_report_path=args.split_report,
            protocol_p_summary_path=args.protocol_p_summary,
        )
    except (FileNotFoundError, ProtocolGBenchmarkError, ValueError) as error:
        print(f"Protocol G benchmark not completed: {error}", file=sys.stderr)
        return 1

    print(f"Completed {len(records)} Protocol G runs from the saved feature-vector-disjoint split.")
    print(f"Tracked reports: {paths.reports_directory}")
    print(f"Ignored model artifacts: {paths.model_artifacts_directory}")
    print(f"Primary matrix size: {len(PRIMARY_G_BENCHMARK_MATRIX)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
