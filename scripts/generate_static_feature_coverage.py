"""Generate non-overwriting static-extractor coverage documentation from code."""

from __future__ import annotations

from pathlib import Path

from malpdf.static.coverage import write_feature_coverage_outputs


if __name__ == "__main__":
    root = Path(__file__).resolve().parents[1]
    markdown_path, csv_path = write_feature_coverage_outputs(root)
    print(f"Wrote {markdown_path}")
    print(f"Wrote {csv_path}")
