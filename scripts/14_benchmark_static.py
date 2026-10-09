"""Measure bounded static ingestion and resident inference using synthetic data."""

import argparse
import json
import os
from pathlib import Path

for name in ("OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS"):
    os.environ[name] = "1"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--samples", type=int, default=256)
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--batch-size", type=int, default=128)
    args = parser.parse_args()
    # Spawn replays this file before applying the parser's absolute CPU/AS caps.
    # Keep the model/experiment stack out of the child interpreter's startup.
    from malpdf.experiments.static_benchmark import benchmark_static

    state = benchmark_static(args.report_root, Path(__file__).resolve().parents[1],
        samples=args.samples, repeats=args.repeats, batch_size=args.batch_size)
    print(json.dumps({name: state[name] for name in ("run_id", "status", "report_path", "performance")}, indent=2))


if __name__ == "__main__":
    main()
