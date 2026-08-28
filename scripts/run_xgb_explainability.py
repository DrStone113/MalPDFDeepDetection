"""Preflight or execute the immutable Protocol G XGBoost TreeSHAP analysis."""
from __future__ import annotations
import argparse
import sys
from pathlib import Path
from malpdf.experiments.xgb_explainability import ExplainabilityError, RUN_ID, run_xgb_explainability
from malpdf.experiments.protocol_g_benchmark import ProtocolGBenchmarkError

ROOT = Path(__file__).resolve().parents[1]
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Protocol G XGBoost native TreeSHAP analysis")
    parser.add_argument("--dataset", type=Path, default=ROOT / "data" / "raw" / "rit-pdfmal-2026.csv")
    parser.add_argument("--run-id", default=RUN_ID)
    parser.add_argument("--execute", action="store_true", help="Retrain the fixed model once, verify, and explain test rows.")
    args = parser.parse_args(argv)
    try:
        preflight, result = run_xgb_explainability(ROOT, args.dataset, run_id=args.run_id, execute=args.execute)
    except (FileNotFoundError, ValueError, ExplainabilityError, ProtocolGBenchmarkError) as error:
        print(f"Explainability run not completed: {error}", file=sys.stderr); return 1
    print(f"Preflight passed: {len(preflight.partitions['test'])} Protocol G test rows; {len(preflight.feature_columns)} features.")
    print(f"Explainability code commit: {preflight.code_commit}")
    if result is None:
        print("Dry run only: no model was fitted and no SHAP outputs were created."); return 0
    print(f"TreeSHAP run completed: {result['paths'].reports_directory}"); return 0
if __name__ == "__main__": raise SystemExit(main())
