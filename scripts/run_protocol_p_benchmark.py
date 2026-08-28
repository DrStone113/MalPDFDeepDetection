"""Run the frozen 10-run Protocol P benchmark from a saved split manifest."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT / "src"))

from malpdf.data.protocol_p import DEFAULT_PROTOCOL_P_SEED
from malpdf.experiments.protocol_p_benchmark import (
    PRIMARY_BENCHMARK_MATRIX,
    ProtocolPBenchmarkError,
    run_protocol_p_benchmark,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the 10-combination, saved-split Protocol P benchmark."
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        default=REPOSITORY_ROOT / "data" / "raw" / "rit-pdfmal-2026.csv",
    )
    parser.add_argument("--seed", type=int, default=DEFAULT_PROTOCOL_P_SEED)
    parser.add_argument(
        "--split-manifest",
        type=Path,
        help="Existing Protocol P manifest below data/processed/protocol_p/.",
    )
    parser.add_argument(
        "--run-id",
        help="Unique optional run ID; existing report and artifact directories are never overwritten.",
    )
    args = parser.parse_args(argv)

    try:
        paths, records = run_protocol_p_benchmark(
            REPOSITORY_ROOT,
            args.dataset,
            seed=args.seed,
            run_id=args.run_id,
            manifest_path=args.split_manifest,
        )
    except (FileNotFoundError, ProtocolPBenchmarkError, ValueError) as error:
        print(f"Protocol P benchmark not completed: {error}", file=sys.stderr)
        return 1

    print(f"Completed {len(records)} Protocol P runs from the saved split.")
    print(f"Tracked reports: {paths.reports_directory}")
    print(f"Ignored model artifacts: {paths.model_artifacts_directory}")
    print(f"Primary matrix size: {len(PRIMARY_BENCHMARK_MATRIX)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
