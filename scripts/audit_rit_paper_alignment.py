"""Produce the read-only local-versus-paper RIT-PDFMal alignment audit."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT / "src"))

from malpdf.data.rit_pdfmal_paper_alignment import (
    build_paper_alignment_report,
    write_paper_alignment_reports,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit local RIT-PDFMal data against the paper.")
    parser.add_argument("--dataset", type=Path, default=REPOSITORY_ROOT / "data" / "raw" / "rit-pdfmal-2026.csv")
    parser.add_argument("--markdown", type=Path, default=REPOSITORY_ROOT / "reports" / "rit-pdfmal-2026_paper_alignment.md")
    parser.add_argument("--json", type=Path, default=REPOSITORY_ROOT / "reports" / "rit-pdfmal-2026_paper_alignment.json")
    args = parser.parse_args(argv)
    report = build_paper_alignment_report(args.dataset)
    write_paper_alignment_reports(report, args.markdown, args.json)
    print(f"Alignment audit written for {report['local_dataset_identity']['filename']}")
    print(f"Markdown: {args.markdown}")
    print(f"JSON: {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
