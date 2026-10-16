"""Prepare metadata-only CIC extraction jobs and run them from offline console."""

import argparse
import json
import os
from pathlib import Path

for name in ("OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS"):
    os.environ[name] = "1"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "check", "run"))
    parser.add_argument("--config", type=Path, default=Path("configs/extraction_profiles.yaml"))
    parser.add_argument("--prepared-run")
    parser.add_argument("--lab-isolated", action="store_true",
        help="VMware console: disconnected NICs, no shared folders/clipboard/drag-drop or credentials")
    args = parser.parse_args()
    from malpdf.extraction.jobs import load_job, prepare_job, run_job
    root = Path(__file__).resolve().parents[1]
    if args.action == "prepare":
        result = prepare_job(root, root / args.config)
    elif not args.prepared_run:
        parser.error("--prepared-run is required")
    elif args.action == "check":
        lock, _ = load_job(root, args.prepared_run)
        result = {"status": "metadata_verified", "rows": len(lock["rows"]), "pdf_bytes_read": False,
                  "execution": "not_run; console isolation and clean committed code required"}
    else:
        result = run_job(root, args.prepared_run, lab_attested=args.lab_isolated)
    print(json.dumps(result, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
