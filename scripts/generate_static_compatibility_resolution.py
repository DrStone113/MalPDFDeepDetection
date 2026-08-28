"""Generate immutable v2 static-extractor compatibility reports from committed code."""

from __future__ import annotations

from pathlib import Path

from malpdf.static.compatibility_resolution import write_compatibility_resolution_outputs


if __name__ == "__main__":
    root = Path(__file__).resolve().parents[1]
    markdown_path, csv_path = write_compatibility_resolution_outputs(root)
    print(f"Wrote {markdown_path}")
    print(f"Wrote {csv_path}")
