"""Download reviewed public PDF sources only with explicit human authorization."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

import yaml

from malpdf.data.raw_downloads import acquire_raw_datasets, record_acquisition_refusal
from malpdf.static.safety import read_bounded_bytes

ROOT = Path(__file__).resolve().parents[1]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=ROOT / "configs/raw_datasets.yaml")
    parser.add_argument("--execute-authorized", action="store_true", help="Confirm this invocation follows an explicit human acquisition instruction.")
    parser.add_argument("--run-id", help="Optional unused immutable run ID.")
    parser.add_argument("--reuse-run", help="Read-only reuse of verified payloads from an earlier acquisition run; no network fallback.")
    args = parser.parse_args(argv)
    try:
        configuration = yaml.safe_load(read_bounded_bytes(args.config, boundary=ROOT / "configs", max_bytes=128 * 1024))
        summary = acquire_raw_datasets(ROOT, configuration, authorized=args.execute_authorized, run_id=args.run_id, reuse_run=args.reuse_run,
                progress=lambda event: print(json.dumps(event), flush=True))
    except (OSError, ValueError, RuntimeError) as error:
        if args.execute_authorized and not getattr(error, "acquisition_recorded", False):
            refused = record_acquisition_refusal(ROOT, error, run_id=args.run_id)
            print(f"Refusal evidence: {refused['report_path']}", file=sys.stderr)
        print(f"Acquisition refused/failed: {type(error).__name__}: {error}", file=sys.stderr)
        return 1
    print(json.dumps(summary, indent=2))
    return 0 if summary["status"] == "completed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
