"""Build compact thesis tables from committed MalPDF research artifacts."""

from __future__ import annotations

import argparse
from pathlib import Path

from malpdf.thesis.evidence import EvidenceError, build_thesis_evidence


def main() -> int:
    parser = argparse.ArgumentParser(description="Build deterministic thesis evidence tables; no experiment is run.")
    parser.add_argument("--output", type=Path, default=None, help="output thesis directory (default: reports/thesis)")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    try:
        result = build_thesis_evidence(root, args.output)
    except EvidenceError as error:
        parser.error(str(error))
    print(f"Built {len(result.table_paths)} thesis tables in {result.output_directory}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
