"""Preflight or evaluate XGBoost/FT/Markov-ResNet tri-modal Protocol G fusion."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from malpdf.experiments.tri_modal_runner import load_tri_modal_configuration, run_tri_modal_fusion

ROOT = Path(__file__).resolve().parents[1]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=ROOT / "configs/tri_modal_fusion.yaml")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--dry-run", action="store_true", help="Default: integrity/alignment checks only; no inference, fitting, or test prediction reads.")
    modes.add_argument("--execute", action="store_true", help="Fit validation-only fusion and evaluate test once, after a persisted lock, from clean committed code.")
    parser.add_argument("--run-id", help="Optional new immutable run identifier.")
    args = parser.parse_args(argv)
    try:
        config = load_tri_modal_configuration(ROOT, args.config)
        report = run_tri_modal_fusion(ROOT, config, execute=args.execute, run_id=args.run_id)
    except (OSError, ValueError, RuntimeError, TypeError, KeyError) as error:
        print(f"Tri-modal evaluation failed: {type(error).__name__}: {error}. Inspect the new run evidence.", file=sys.stderr)
        return 1
    print(f"Status: {report['status']}; test evaluations: {report['test_evaluation_count']}.")
    if report["status"] == "blocked_missing_vision":
        readiness = report["vision_cache_readiness"]
        print(f"Vision: {readiness['matched_ids']}/{readiness['protocol_g_samples']} Protocol G IDs matched; {readiness['source_cache_rows_verified']} source caches verified.")
        print(f"Reason: {readiness['reason']}. No inference/fitting/test evaluation; metrics N/A.")
    elif report["mode"] == "execute":
        choice = report["selection"]
        print(f"Validation-selected candidate: {choice['family']}; order={choice['candidate_order']}.")
        if choice["family"] == "weighted_average":
            w, v = choice["xgb_weight"], choice["vision_weight"]
            print(f"XGB/FT/Vision weights: {(1-v)*w}/{(1-v)*(1-w)}/{v}; zero weights denote controls.")
        for key, metrics in report["metrics"].items():
            print(key + ": " + ", ".join(f"{name}={metrics[name]:.6f}" for name in ("accuracy", "f1_malicious", "mcc", "brier", "log_loss", "ece")))
        print(f"Entropy 10%: coverage={report['routing']['coverage']:.6f}; FN catch={report['routing']['fn_catch_rate']}.")
    else:
        print(f"Eligible preflight: {report['validation_rows']} validation rows; {report['candidate_count']} candidates. No inference/fitting/test evaluation.")
    print(f"Report: {report['report_path']}")
    return 2 if report["status"] == "blocked_missing_vision" else 0


if __name__ == "__main__":
    raise SystemExit(main())
