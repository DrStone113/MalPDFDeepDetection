"""Build SHA-256-addressed byte Markov caches from an explicitly locked manifest."""

from __future__ import annotations

import argparse
import csv
import os
from pathlib import Path
import sys

for name in ('OMP_NUM_THREADS', 'OPENBLAS_NUM_THREADS', 'MKL_NUM_THREADS'):
    os.environ[name] = '1'

import yaml

from malpdf.data.markov_preparation import build_markov_cache

ROOT = Path(__file__).resolve().parents[1]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=ROOT / "configs/markov_cache.yaml")
    parser.add_argument("--manifest", type=Path, help="Explicit override of the locked CSV manifest.")
    parser.add_argument("--preparation-report", type=Path, help="Completed preparation report containing the matching checksum lock.")
    parser.add_argument("--run-id", help="Optional new immutable run identifier.")
    parser.add_argument('--workers', help='auto or a positive worker count bounded by the container CPU quota')
    args = parser.parse_args(argv)
    try:
        configuration = yaml.safe_load(args.config.read_text(encoding="utf-8"))
        required = {"seed", "manifest", "preparation_report", "limits"}
        if not isinstance(configuration, dict) or not required.issubset(configuration) or set(configuration) - required - {'workers'}:
            raise ValueError("Configuration requires seed, manifest, preparation_report and limits")
        if set(configuration["limits"]) != {"max_pdf_bytes", "max_metadata_bytes", "max_samples"}:
            raise ValueError("Configuration requires all three resource caps")
        manifest = args.manifest or Path(configuration["manifest"])
        preparation = args.preparation_report or Path(configuration["preparation_report"])
        workers = args.workers if args.workers is not None else configuration.get('workers', 'auto')
        if isinstance(workers, str) and workers != 'auto': workers = int(workers)
        report = build_markov_cache(ROOT, manifest, preparation, seed=configuration["seed"], run_id=args.run_id, workers=workers, **configuration["limits"])
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, csv.Error) as error:
        print(f"Markov cache preparation failed: {type(error).__name__}; inspect the new run evidence for details.", file=sys.stderr)
        return 1
    print(f"Completed: {report['sample_count']} PDFs; {report['created']} caches created, {report['reused']} reused.")
    print(f"Cache: {report['cache_directory']}/<pdf_sha256>.npy; float32 (256, 256), one channel.")
    print(f"Report: {report['report_path']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
