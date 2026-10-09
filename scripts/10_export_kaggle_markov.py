"""Create a numeric-only ZIP and thin GPU notebook from the locked cohort."""

import argparse
import json
import os
from pathlib import Path

for name in ("OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS"):
    os.environ.setdefault(name, "1")

import yaml
from malpdf.data.kaggle_export import export_kaggle_bundle
from malpdf.static.safety import read_bounded_bytes


def main():
    code_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-root", type=Path, default=code_root)
    parser.add_argument("--config", default="configs/raw_tri_modal_v3.yaml")
    parser.add_argument("--vision-config", default="configs/kaggle_vision.yaml")
    parser.add_argument("--tabular-run", required=True)
    parser.add_argument("--run-id")
    args = parser.parse_args()
    configuration = yaml.safe_load(read_bounded_bytes(code_root / args.config, boundary=code_root / "configs", max_bytes=128 * 1024))
    vision = yaml.safe_load(read_bounded_bytes(code_root / args.vision_config, boundary=code_root / "configs", max_bytes=128 * 1024))
    state = export_kaggle_bundle(args.data_root.absolute(), code_root, configuration, vision, args.tabular_run, run_id=args.run_id)
    print(json.dumps({name: state[name] for name in ("status", "archive", "archive_bytes", "archive_sha256", "notebook", "private_mapping")}, indent=2))


if __name__ == "__main__":
    main()
