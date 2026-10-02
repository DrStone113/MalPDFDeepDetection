"""Preflight or evaluate validation-locked Protocol G late fusion v2."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from malpdf.experiments.late_fusion_runner import load_late_fusion_configuration, run_late_fusion

ROOT = Path(__file__).resolve().parents[1]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=ROOT / "configs/late_fusion_stacking.yaml")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--dry-run", action="store_true", help="Default: validate validation inputs without fitting or decoding test predictions.")
    modes.add_argument("--execute", action="store_true", help="Official evaluation from a clean committed worktree; validation lock precedes test access.")
    parser.add_argument("--run-id", help="Optional new immutable run identifier.")
    args = parser.parse_args(argv)
    try:
        config = load_late_fusion_configuration(ROOT, args.config)
        report = run_late_fusion(ROOT, config, execute=args.execute, run_id=args.run_id)
    except (OSError, ValueError, RuntimeError, TypeError, KeyError) as error:
        print(f"Late fusion failed: {type(error).__name__}; inspect the new run evidence.", file=sys.stderr)
        return 1
    print(f"Status: {report['status']}; Vision: {report['vision_status']}.")
    if report["mode"] == "dry_run":
        print(f"Preflight: {report['validation_rows']} validation rows; roles {report['validation_role_rows']}; {report['candidate_count']} candidates.")
        print(f"No fitting/test evaluation; official execution requires clean committed code (ready={report['official_execution_ready']}).")
    else:
        for key, metrics in report["metrics"].items():
            print(key + ": " + ", ".join(f"{name}={metrics[name]:.6f}" for name in ("f1_malicious", "mcc", "brier", "log_loss", "ece")))
        routing = report["routing"]
        print(f"Entropy 10%: coverage={routing['coverage']:.6f}; FN catch={routing['fn_catch_rate']}; referrals are abstentions.")
    print(f"Report: {report['report_path']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
