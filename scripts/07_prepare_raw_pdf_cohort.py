"""Prepare all authorized PDFs with bounded static features and a new cohort split."""

import argparse
import json
import os
from pathlib import Path
import sys


os.environ["OPENBLAS_NUM_THREADS"] = "1"
os.environ["OMP_NUM_THREADS"] = "1"
os.environ["MKL_NUM_THREADS"] = "1"

import yaml
from malpdf.data.raw_cohort import prepare_raw_cohort, finalize_raw_supervised
from malpdf.static.safety import read_bounded_bytes

ROOT = Path(__file__).resolve().parents[1]


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--config", type=Path, default=ROOT / "configs/raw_pdf_cohort.yaml")
    p.add_argument("--run-id")
    p.add_argument("--finalize-from", type=Path, help="Completed preparation run_summary.json; create a separate full labeled cohort")
    p.add_argument("--execute-authorized", action="store_true")
    args = p.parse_args(argv)
    if not args.execute_authorized:
        p.error("Static access to raw PDFs requires explicit authorization")
    configuration = yaml.safe_load(read_bounded_bytes(args.config, boundary=ROOT / "configs", max_bytes=128 * 1024))
    try:
        if args.finalize_from is not None:
            previous = json.loads(read_bounded_bytes(args.finalize_from, boundary=ROOT / "reports/experiments/raw_pdf_cohort", max_bytes=256 * 1024))
            result = finalize_raw_supervised(ROOT, previous, run_id=args.run_id)
        else:
            result = prepare_raw_cohort(ROOT, configuration, run_id=args.run_id)
    except (OSError, ValueError, RuntimeError, KeyError) as error:
        print("Preparation failed: " + type(error).__name__ + "; see immutable run evidence", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
