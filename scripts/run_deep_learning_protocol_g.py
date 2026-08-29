"""Explicit runner for the fixed Protocol G seed-42 neural comparison."""

from __future__ import annotations

import argparse
from pathlib import Path

from malpdf.experiments.deep_learning_protocol_g import (
    DeepLearningProtocolGError,
    execute_deep_learning_protocol_g,
    preflight_deep_learning_protocol_g,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Preflight or run the fixed Protocol G MLP/FT-Transformer comparison.")
    parser.add_argument("--execute", action="store_true", help="run each fixed neural model once; default is dry-run")
    parser.add_argument("--run-id", default="seed42", help="immutable output identifier (default: seed42)")
    parser.add_argument("--dataset", default="data/raw/rit-pdfmal-2026.csv", help="approved RIT CSV path")
    arguments = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    try:
        preflight = preflight_deep_learning_protocol_g(root, root / arguments.dataset, run_id=arguments.run_id)
        print("Protocol G deep-learning preflight PASS")
        print(f"Dataset SHA-256: {preflight.environment['dataset_sha256']}")
        print(f"Split manifest SHA-256: {preflight.split_summary['split_manifest_sha256']}")
        print(f"Feature schema: {len(preflight.feature_order)} ordered G-drop3constant features")
        print(f"Device selected: {preflight.device}")
        if not arguments.execute:
            print("Dry-run only. Add --execute to train MLP once and FT-Transformer once.")
            return 0
        result = execute_deep_learning_protocol_g(preflight)
        print(f"Official deep-learning comparison PASS: {result['paths'].reports_directory}")
        return 0
    except (DeepLearningProtocolGError, FileNotFoundError, ValueError) as error:
        print(f"Protocol G deep-learning run refused: {error}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
