"""Preflight or execute the fixed Protocol G selective static ensemble study."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from malpdf.experiments.selective_static_ensemble import (
    SelectiveEnsembleError,
    execute_selective_ensemble,
    preflight_selective_ensemble,
)


ROOT = Path(__file__).resolve().parents[1]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validation-locked Protocol G XGBoost/FT ensemble; no dynamic execution.")
    parser.add_argument("--dataset", type=Path, default=ROOT / "data" / "raw" / "rit-pdfmal-2026.csv")
    parser.add_argument("--execute", action="store_true", help="Train frozen bases, lock validation selection, then evaluate test once.")
    args = parser.parse_args(argv)
    try:
        preflight = preflight_selective_ensemble(ROOT, args.dataset, require_clean_git=True)
        if not args.execute:
            print(f"Preflight passed: {len(preflight.partitions['train'])}/{len(preflight.partitions['validation'])}/{len(preflight.partitions['test'])} Protocol G rows; no models fit.")
            print(f"Ensemble code commit: {preflight.code_commit_sha}")
            return 0
        result = execute_selective_ensemble(preflight)
    except (FileNotFoundError, ValueError, SelectiveEnsembleError) as error:
        print(f"Selective ensemble run not completed: {error}", file=sys.stderr)
        return 1
    selected = result["selected"]
    print(f"Completed one locked test evaluation: {result['paths'].reports_directory}")
    print(f"Selected validation candidate: {selected['calibration_method']} / {selected['fusion_family']} / xgb_weight={selected['xgb_weight']:.1f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
