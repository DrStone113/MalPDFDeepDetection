"""Fixed CPU CIC Train-only static adaptation using controlled cached features."""

import argparse
import json
import os
from pathlib import Path

for name in ("OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS"):
    os.environ[name] = "1"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path("configs/cic_static_accuracy.yaml"))
    args = parser.parse_args()
    from malpdf.experiments.cic_static_accuracy import train_cic_static
    state = train_cic_static(Path(__file__).resolve().parents[1], args.config)
    print(json.dumps({key: state[key] for key in ("run_id", "status", "report_path")}, indent=2))


if __name__ == "__main__":
    main()
