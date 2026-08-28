"""Preflight or explicitly run the fixed Protocol P/G multi-seed robustness study."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from malpdf.experiments.multiseed_robustness import (
    CANONICAL_PROTOCOLS,
    MODEL_NAMES,
    OFFICIAL_SPLIT_SEEDS,
    MultiSeedRobustnessError,
    run_multiseed_robustness,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Preflight or run the fixed RIT-PDFMal-2026 Protocol P/G multi-seed robustness study."
    )
    parser.add_argument("--dataset", type=Path, default=REPOSITORY_ROOT / "data" / "raw" / "rit-pdfmal-2026.csv")
    parser.add_argument("--config", type=Path, default=REPOSITORY_ROOT / "configs" / "multiseed_robustness.yaml")
    parser.add_argument("--run-id", help="New immutable multiseed run ID; required only for --execute.")
    parser.add_argument("--protocol", choices=("P", "G", "both"), default="both")
    parser.add_argument("--seeds", nargs="+", type=int, default=list(OFFICIAL_SPLIT_SEEDS))
    parser.add_argument("--models", nargs="+", choices=MODEL_NAMES, default=list(MODEL_NAMES))
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--execute", action="store_true", help="Actually fit models after a clean-worktree preflight.")
    mode.add_argument("--dry-run", action="store_true", help="Explicitly select the default preflight-only mode.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    protocols = CANONICAL_PROTOCOLS if args.protocol == "both" else (args.protocol,)
    try:
        preflight, paths, records = run_multiseed_robustness(
            REPOSITORY_ROOT, args.dataset, args.config, run_id=args.run_id,
            protocols=protocols, split_seeds=args.seeds, models=args.models, execute=args.execute,
        )
    except (FileNotFoundError, MultiSeedRobustnessError, ValueError) as error:
        print(f"Multi-seed robustness study not completed: {error}", file=sys.stderr)
        return 1
    print(f"Preflight passed for dataset SHA-256 {preflight.dataset_sha256}.")
    print(f"Benchmark-generating code commit: {preflight.benchmark_code_commit}")
    if not args.execute:
        print("Dry run only: no manifests, model artifacts, or benchmark results were created.")
        return 0
    assert paths is not None
    print(f"Completed {len(records)} protocol/seed/model records.")
    print(f"Tracked reports: {paths.reports_directory}")
    print(f"Ignored model artifacts: {paths.artifact_directory / 'models'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
