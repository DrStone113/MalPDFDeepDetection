"""Explicit one-time builder for the local, ignored static deployment artifact."""

from __future__ import annotations

import argparse
from pathlib import Path

from malpdf.inference.deployment import DeploymentError, build_deployment_model, preflight_deployment_build


def main() -> int:
    parser = argparse.ArgumentParser(description="Preflight or build the immutable full-RIT XGBoost deployment model.")
    parser.add_argument("--execute", action="store_true", help="fit and save the model after preflight; default is dry-run")
    parser.add_argument("--dataset", default="data/raw/rit-pdfmal-2026.csv", help="approved RIT CSV path")
    arguments = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    try:
        preflight = preflight_deployment_build(root, root / arguments.dataset)
        print("Deployment model preflight PASS")
        print(f"Dataset SHA-256: {preflight.dataset_sha256}")
        print(f"Rows/classes: {len(preflight.frame)} / {preflight.class_counts}")
        print(f"Feature schema: {len(preflight.feature_order)} ordered features")
        print(f"Artifact: {preflight.artifact_path}")
        if not arguments.execute:
            print("Dry-run only. Add --execute to build the local ignored artifact once.")
            return 0
        manifest = build_deployment_model(
            preflight,
            command=".\\.venv\\Scripts\\python.exe scripts\\build_deployment_model.py --execute",
        )
        print(f"Deployment model build PASS: {manifest['model_id']}")
        print(f"Artifact SHA-256: {manifest['artifact_sha256']}")
        return 0
    except (DeploymentError, FileNotFoundError, ValueError) as error:
        print(f"Deployment model build refused: {error}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
