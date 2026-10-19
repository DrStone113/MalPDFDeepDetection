"""Run full static VM extraction or inspect historical offline jobs."""

import argparse
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("vm", "prepare", "check", "run"))
    parser.add_argument("--config", type=Path)
    parser.add_argument("--prepared-run")
    parser.add_argument("--resume-from", help="VM: reuse verified completed records from this run")
    parser.add_argument("--workers", type=int, help="VM: worker count; default uses all available CPUs")
    parser.add_argument("--lab-isolated", action="store_true",
        help="VMware console: disconnected NICs, no shared folders/clipboard/drag-drop or credentials")
    args = parser.parse_args()
    if args.action in {'vm', 'run'}:
        from malpdf.extraction.lab import require_extraction_platform
        try:
            require_extraction_platform()
        except PermissionError as error:
            parser.exit(2, str(error) + '\n')
    from malpdf.extraction.jobs import load_job, prepare_job, run_job
    root = Path(__file__).resolve().parents[1]
    if args.action == "vm":
        from malpdf.extraction.vm_jobs import run_vm_job
        result = run_vm_job(root, root / (args.config or Path("configs/extraction_vm.yaml")),
                            resume_from=args.resume_from, workers=args.workers)
    elif args.action == "prepare":
        result = prepare_job(root, root / (args.config or Path("configs/extraction_profiles.yaml")))
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
