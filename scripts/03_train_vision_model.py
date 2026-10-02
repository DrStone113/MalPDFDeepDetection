"""Check cached inputs, smoke-train, or train a fully aligned Protocol G ResNet-18."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path
import sys

from malpdf.experiments.vision_runner import load_vision_configuration, run_vision_model

ROOT = Path(__file__).resolve().parents[1]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=ROOT / "configs/vision_resnet18.yaml")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--dry-run", action="store_true", help="Default: untrained forward pass; no optimizer or checkpoint.")
    modes.add_argument("--smoke-train", action="store_true", help="Technical forward/backward and checkpoint check on at most eight caches; same-sample metrics only.")
    modes.add_argument("--execute", action="store_true", help="Train only from a clean worktree with complete locked Protocol G cache mapping.")
    parser.add_argument("--smoke-epochs", type=int, choices=(1, 2), default=2)
    parser.add_argument("--smoke-batch-size", type=int, choices=(1, 2, 4), default=2)
    parser.add_argument("--run-id", help="Optional new immutable run identifier.")
    args = parser.parse_args(argv)
    try:
        configuration = load_vision_configuration(ROOT, args.config)
        report = run_vision_model(ROOT, configuration, execute=args.execute, smoke_train=args.smoke_train, smoke_epochs=args.smoke_epochs, smoke_batch_size=args.smoke_batch_size, run_id=args.run_id)
    except (OSError, ValueError, RuntimeError, TypeError, KeyError, csv.Error) as error:
        print(f"Vision run failed: {type(error).__name__}; inspect the new run evidence.", file=sys.stderr)
        return 1
    readiness = report["protocol_g_readiness"]
    print(f"Status: {report['status']}; Protocol G ready={readiness['ready']}; matched {readiness['matched_ids']}/{readiness['protocol_g_samples']} sample IDs.")
    if "smoke" in report:
        smoke = report["smoke"]
        print(f"Dry-run: {smoke['sample_count']} caches, input (B,1,256,256), output (B,1); diagnostic BCE loss={smoke['bce_loss']:.8f}.")
        print("No optimizer steps/checkpoint; trained-model Accuracy/F1/MCC are unavailable.")
    else:
        if "smoke_training" in report:
            smoke = report["smoke_training"]
            print(f"Smoke training: {smoke['sample_count']} caches, {smoke['epochs']} epochs, batch size {smoke['batch_size']}, {smoke['optimizer_steps']} optimizer steps; finite gradients and changed parameters.")
            print(f"Checkpoint saved and reload verified: {report['checkpoint']['path']}")
            print("Metrics use the same fitting samples; no held-out Protocol G evaluation.")
        for partition, metrics in report["metrics"].items():
            print(f"{partition}: Accuracy={metrics['accuracy']:.6f}, F1 malicious={metrics['f1_malicious']:.6f}, MCC={metrics['mcc']:.6f}, Loss={metrics['loss']:.6f}")
            if metrics.get("single_class_labels"):
                print("Single-class labels: MCC=0 follows scikit-learn's zero-denominator convention; discrimination is unavailable.")
    print(f"Report: {report['report_path']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
