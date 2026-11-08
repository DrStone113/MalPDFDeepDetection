
"""Launch or collect the bounded private Kaggle static-development study."""
import argparse
import json
from pathlib import Path

from malpdf.experiments.static_development_handoff import collect, launch


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("launch", "collect"))
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--configuration", type=Path)
    parser.add_argument("--launch-run")
    args = parser.parse_args()
    code_root = Path(__file__).resolve().parents[1]
    if args.action == "launch":
        result = launch(args.root, code_root, args.configuration or code_root / "configs/static_development.yaml")
    else:
        if not args.launch_run or Path(args.launch_run).name != args.launch_run:
            parser.error("collect needs a safe --launch-run identifier")
        result = collect(args.root, code_root, args.launch_run)
    print(json.dumps({key: result[key] for key in ("run_id", "status", "report_path")}, indent=2))


if __name__ == "__main__":
    main()
