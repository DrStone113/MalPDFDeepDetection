"""Create a pinned performance notebook for an already exported numeric ZIP."""

import argparse
import json
from pathlib import Path

from malpdf.data.kaggle_export import export_performance_notebook


def main():
    code_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data-root', type=Path, default=code_root)
    parser.add_argument('--export-run', required=True)
    parser.add_argument('--run-id')
    args = parser.parse_args()
    state = export_performance_notebook(args.data_root.absolute(), code_root, args.export_run, run_id=args.run_id)
    print(json.dumps({key: state[key] for key in ('status', 'notebook', 'notebook_sha256', 'input_archive_sha256')}, indent=2))


if __name__ == '__main__':
    main()
