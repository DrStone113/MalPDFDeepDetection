"""Prepare one immutable Protocol P split/provenance run without model training."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT / "src"))

from malpdf.data.protocol_p import DEFAULT_PROTOCOL_P_SEED
from malpdf.experiments.protocol_p import prepare_protocol_p_run


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Prepare a Protocol P run; no models are trained.")
    parser.add_argument("--dataset", type=Path, default=REPOSITORY_ROOT / "data" / "raw" / "rit-pdfmal-2026.csv")
    parser.add_argument("--seed", type=int, default=DEFAULT_PROTOCOL_P_SEED)
    parser.add_argument("--run-id", help="Unique optional run ID; existing IDs are never overwritten.")
    args = parser.parse_args(argv)
    paths, result = prepare_protocol_p_run(REPOSITORY_ROOT, args.dataset, seed=args.seed, run_id=args.run_id)
    print(f"Prepared Protocol P run: {paths.run_id}")
    print(f"Manifest: {paths.split_manifest}")
    print(f"Configuration: {paths.experiment_configuration}")
    for name, statistics in result["split"]["split_statistics"].items():
        print(f"{name}: {statistics['row_count']} rows; Label=0 {statistics['benign_label_0_count']}; Label=1 {statistics['malicious_label_1_count']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
