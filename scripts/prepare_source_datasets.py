"""Prepare authorized local sources and verify the locked Protocol G split."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
import zipfile

import yaml

from malpdf.data.source_preparation import PreparationLimits, prepare_source_datasets

ROOT = Path(__file__).resolve().parents[1]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=ROOT / "configs/source_preparation.yaml")
    parser.add_argument("--manifest", type=Path, default=ROOT / "data/processed/rit-pdfmal-2026_split_manifest.csv")
    parser.add_argument("--create-missing-manifest", action="store_true", help="Explicitly recreate only an absent manifest, requiring the historical SHA-256 lock.")
    parser.add_argument("--label-cve-malicious", action="store_true", help="Assign user-requested Malicious (Label=1) to the acquisition-locked CVE PDFs and record label provenance.")
    parser.add_argument("--run-id", help="Optional new immutable run identifier.")
    args = parser.parse_args(argv)
    try:
        configuration = yaml.safe_load(args.config.read_text(encoding="utf-8"))
        if not isinstance(configuration, dict) or set(configuration) != {"seed", "limits"}:
            raise ValueError("Configuration requires exactly seed and limits")
        report = prepare_source_datasets(ROOT, limits=PreparationLimits(**configuration["limits"]), seed=configuration["seed"], create_missing_manifest=args.create_missing_manifest, label_cve_malicious=args.label_cve_malicious, manifest_path=args.manifest, run_id=args.run_id)
    except (OSError, ValueError, RuntimeError, TypeError, KeyError, zipfile.BadZipFile) as error:
        print(f"Preparation failed: {type(error).__name__}; inspect the ignored run report for details.", file=sys.stderr)
        return 1
    for name, dataset in report["datasets"].items():
        print(f"{name}: {dataset['sample_count']} {dataset['unit']}; labels {dataset['labels']}; Protocol G {dataset['protocol_g']['status']}")
    print(f"Status: {report['status']}")
    print(f"Report: {report['report_path']}")
    print(f"CVE manifest: {report['datasets']['cve']['manifest_path']}")
    return 0 if report["status"] == "completed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
