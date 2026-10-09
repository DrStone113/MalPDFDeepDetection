"""Preflight or evaluate Safety-First five-model, five-fold Protocol G stacking."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from malpdf.experiments.safe_stacking_v3 import load_v3_configuration, run_safe_stacking_v3

ROOT = Path(__file__).resolve().parents[1]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=ROOT / "configs/safe_stacking_v3.yaml")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--dry-run", action="store_true", help="Default: validate schema/source/partition readiness; no raw PDF reads or fitting.")
    modes.add_argument("--execute", action="store_true", help="Measure real PDFs, train 25 fold models, then validation-lock before one test evaluation; clean committed code required.")
    parser.add_argument("--run-id", help="Optional new immutable run identifier.")
    args = parser.parse_args(argv)
    try:
        config = load_v3_configuration(ROOT, args.config)
        report = run_safe_stacking_v3(ROOT, config, execute=args.execute, run_id=args.run_id)
    except (OSError, ValueError, RuntimeError, TypeError, KeyError, ImportError) as error:
        print(f"Safety-first v3 failed: {type(error).__name__}: {error}. Inspect the new run evidence.", file=sys.stderr)
        return 1
    print(f"Status: {report['status']}; base fits: {report['completed_base_fits']}; test evaluations: {report['test_evaluation_count']}.")
    if report["status"] == "blocked_missing_pdf_source":
        readiness = report["pdf_readiness"]
        print(f"Real PDF source mapping: {readiness['matched_ids']}/{readiness['protocol_g_samples']} IDs; foreign source IDs: {readiness['foreign_source_ids']}.")
        print(f"Reason: {readiness['reason']}. No PDF measurements, fitting or test evaluation; metrics N/A.")
    elif report["mode"] == "execute":
        print(f"Validation-selected C={report['selection']['regularization_c']}; Youden threshold={report['selection']['threshold']:.8f}.")
        for key, metrics in report["metrics"].items():
            print(key + ": " + ", ".join(f"{name}={metrics[name]:.6f}" for name in ("accuracy", "f1_malicious", "mcc", "brier", "ece")))
        print(f"Entropy 10%: coverage={report['routing']['coverage']:.6f}; FN catch={report['routing']['fn_catch_rate']}.")
    else:
        print(f"Eligible preflight; roles: {report['validation_role_rows']}; five train folds. No PDF byte reads, fitting or test evaluation.")
    print(f"Report: {report['report_path']}")
    return 2 if report["status"] == "blocked_missing_pdf_source" else 0


if __name__ == "__main__":
    raise SystemExit(main())
