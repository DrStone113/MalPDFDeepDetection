"""Validation-selected vision training and bounded technical cache smoke runs."""

from __future__ import annotations

import csv
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
import math
import os
from pathlib import Path
import platform
import subprocess
import tempfile
from time import perf_counter

import numpy as np
import torch
from torch import nn
from torch.utils.data import DataLoader
import yaml

from malpdf.data.manifest_validator import validate_sha256
from malpdf.data.rit_pdfmal import load_rit_pdfmal, sha256_file
from malpdf.data.vision_dataset import (
    MarkovCacheDataset, align_protocol_g_samples, load_vision_source_manifest,
    verify_vision_caches,
)
from malpdf.deep_learning.training import probabilities_from_logits, set_deep_learning_seed, train_with_validation
from malpdf.evaluation.selective import calibration_metrics
from malpdf.experiments.protocol_g_benchmark import load_saved_protocol_g_split
from malpdf.experiments.protocol_p import repository_git_state
from malpdf.models.vision_resnet import VisionResNet18
from malpdf.static.safety import read_bounded_bytes


def _write_json(path: Path, value: dict) -> None:
    with path.open("x", encoding="utf-8") as output:
        json.dump(value, output, indent=2, allow_nan=False)
        output.write("\n")


def validate_vision_configuration(configuration: dict) -> None:
    if not isinstance(configuration, dict) or set(configuration) != {"seed", "paths", "training", "runtime"}:
        raise ValueError("Vision configuration needs seed, paths, training and runtime")
    if type(configuration["seed"]) is not int or configuration["seed"] != 42:
        raise ValueError("Vision Protocol G seed is locked to 42")
    paths, training, runtime = (configuration[name] for name in ("paths", "training", "runtime"))
    if not isinstance(paths, dict) or set(paths) != {"source_manifest", "source_manifest_sha256", "dataset", "dataset_sha256", "split_manifest", "split_manifest_sha256"}:
        raise ValueError("Vision input paths/checksum locks are incomplete")
    for key, value in paths.items():
        if key.endswith("_sha256"):
            validate_sha256(value)
        elif not isinstance(value, str) or not value:
            raise ValueError("Vision input paths must be nonempty strings")
    if not isinstance(training, dict) or set(training) != {"batch_size", "max_epochs", "learning_rate", "weight_decay", "patience", "min_delta", "threshold", "ece_bins"}:
        raise ValueError("Vision training configuration is incomplete")
    for name, cap in (("batch_size", 64), ("max_epochs", 1000), ("patience", 1000)):
        if type(training[name]) is not int or not 1 <= training[name] <= cap:
            raise ValueError(f"{name} must be a positive integer within its resource cap")
    for name in ("learning_rate", "weight_decay", "min_delta"):
        value = training[name]
        if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
            raise ValueError("Training rates/deltas must be finite nonnegative numbers")
    if training["learning_rate"] == 0 or training["threshold"] != 0.5 or type(training["ece_bins"]) is not int or training["ece_bins"] != 10:
        raise ValueError("Require positive learning rate, threshold 0.5 and 10 ECE bins")
    if not isinstance(runtime, dict) or set(runtime) != {"device", "cpu_threads", "dry_run_max_samples"}:
        raise ValueError("Vision runtime configuration is incomplete")
    if runtime["device"] not in {"cpu", "cuda", "auto"}:
        raise ValueError("Device must be cpu, cuda or auto")
    for name, cap in (("cpu_threads", 8), ("dry_run_max_samples", 64)):
        if type(runtime[name]) is not int or not 1 <= runtime[name] <= cap:
            raise ValueError("Runtime limits must be positive integers within their caps")


def load_vision_configuration(root: Path, path: Path) -> dict:
    content = read_bounded_bytes(path, boundary=root / "configs", max_bytes=128 * 1024)
    configuration = yaml.safe_load(content)
    validate_vision_configuration(configuration)
    return configuration


def _locked_table(root: Path, name: str, expected: str) -> Path:
    path = Path(name)
    if not path.is_absolute():
        path = root / path
    content = read_bounded_bytes(path, boundary=root / "data", max_bytes=16 * 1024 * 1024)
    if hashlib.sha256(content).hexdigest() != expected:
        raise ValueError("Vision input table differs from its checksum lock")
    return path


def _loader(samples, cache_directory: Path, configuration: dict, *, shuffle: bool) -> DataLoader:
    generator = torch.Generator().manual_seed(configuration["seed"])
    return DataLoader(MarkovCacheDataset(samples, cache_directory), batch_size=configuration["training"]["batch_size"], shuffle=shuffle, generator=generator, num_workers=0)


def evaluate_vision_model(model: nn.Module, loader: DataLoader, *, device: torch.device) -> dict:
    """One inference pass supplies classification metrics and stable BCE loss."""
    model.eval()
    truth, scores = [], []
    total_loss, sample_count = 0.0, 0
    criterion = nn.BCEWithLogitsLoss(reduction="sum")
    with torch.no_grad():
        for features, labels in loader:
            logits = model(features.to(device)).reshape(-1)
            loss = criterion(logits, labels.to(device))
            if not torch.isfinite(loss):
                raise RuntimeError("Vision evaluation loss is non-finite")
            truth.append(labels.numpy().astype(int))
            scores.append(probabilities_from_logits(logits))
            total_loss += float(loss.item())
            sample_count += len(labels)
    if not sample_count:
        raise ValueError("Vision evaluation cannot be empty")
    result = calibration_metrics(np.concatenate(truth), np.concatenate(scores), n_bins=10)
    result.update({"loss": total_loss / sample_count, "loss_function": "BCEWithLogitsLoss", "sample_count": sample_count, "evaluation_count": 1})
    return result


def _save_checkpoint(path: Path, payload: dict) -> None:
    descriptor, name = tempfile.mkstemp(prefix=".vision-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            torch.save(payload, output)
            output.flush()
            os.fsync(output.fileno())
        os.link(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _parameter_digest(model: nn.Module) -> str:
    digest = hashlib.sha256()
    for parameter in model.parameters():
        digest.update(parameter.detach().cpu().contiguous().numpy().tobytes())
    return digest.hexdigest()


def _train_smoke_epochs(model: nn.Module, loader: DataLoader, *, device: torch.device,
                        training: dict, epochs: int) -> dict:
    """Exercise gradients and fixed optimizer steps without validation selection."""
    before = _parameter_digest(model)
    optimizer = torch.optim.AdamW(model.parameters(), lr=training["learning_rate"], weight_decay=training["weight_decay"])
    criterion = nn.BCEWithLogitsLoss()
    history, steps = [], 0
    started = perf_counter()
    for epoch in range(1, epochs + 1):
        model.train()
        total_loss, seen, epoch_steps = 0.0, 0, 0
        for features, labels in loader:
            optimizer.zero_grad(set_to_none=True)
            logits = model(features.to(device)).reshape(-1)
            loss = criterion(logits, labels.to(device))
            if not torch.isfinite(loss):
                raise RuntimeError("Smoke training loss is non-finite")
            loss.backward()
            gradients = [parameter.grad for parameter in model.parameters() if parameter.grad is not None]
            if not gradients or any(not torch.isfinite(gradient).all() for gradient in gradients):
                raise RuntimeError("Smoke training gradients are missing or non-finite")
            if not any(torch.count_nonzero(gradient).item() for gradient in gradients):
                raise RuntimeError("Smoke training gradients are all zero")
            optimizer.step()
            if any(not torch.isfinite(parameter).all() for parameter in model.parameters()):
                raise RuntimeError("Smoke optimizer produced non-finite parameters")
            total_loss += float(loss.item()) * len(labels)
            seen += len(labels)
            steps += 1
            epoch_steps += 1
        if not seen:
            raise ValueError("Smoke training cannot be empty")
        history.append({"epoch": epoch, "train_loss": total_loss / seen, "optimizer_steps": epoch_steps})
    optimizer.zero_grad(set_to_none=True)
    after = _parameter_digest(model)
    if before == after:
        raise RuntimeError("Smoke optimizer did not change model parameters")
    return {"history": history, "optimizer_steps": steps, "gradients_finite": True,
            "parameters_changed": True, "parameter_sha256_before": before,
            "parameter_sha256_after": after, "training_seconds": perf_counter() - started}


def _append_log(root: Path, report: dict) -> None:
    notes = "Scratch ResNet-18, one channel (1,256,256); binary Label=1 malicious. Cache-only reads with header/checksum verification; no PDF access or downloads. AdamW/BCEWithLogitsLoss; ECE: 10 equal-width malicious-probability bins."
    if report["mode"] == "execute":
        notes += " Checkpoint selection by validation loss."
    if report["mode"] == "smoke_train":
        notes += " Technical smoke training only: fixed final epoch checkpoint; metrics on the same samples used for fitting, no validation/test evaluation or model selection; not Protocol G performance."
        if "smoke_training" in report:
            smoke = report["smoke_training"]
            notes += f" {smoke['sample_count']} caches; {smoke['epochs']} epochs; batch size {smoke['batch_size']}; {smoke['optimizer_steps']} optimizer steps; finite gradients, changed parameters, checkpoint reload verified."
        if report.get("metrics", {}).get("smoke_same_samples", {}).get("single_class_labels"):
            notes += " Single-class labels: MCC=0 is the scikit-learn zero-denominator convention, not evidence of discrimination; no benign-class or held-out performance estimate."
    if report["mode"] == "dry_run":
        notes += " Dry-run: untrained forward pass only, zero optimizer steps, no checkpoint; F1/MCC/ECE/Brier N/A, no performance evaluation."
        if "smoke" in report:
            notes += f" Smoke samples {report['smoke']['sample_count']}; finite BCE diagnostic loss {report['smoke']['bce_loss']:.8f}."
    if "protocol_g_readiness" in report:
        readiness = report["protocol_g_readiness"]
        notes += f" Protocol G ready={readiness['ready']}; matched IDs {readiness['matched_ids']}/{readiness['protocol_g_samples']}."
    metrics = report.get("metrics", {})
    if not metrics and report["mode"] != "dry_run":
        notes += " Metrics N/A: no trained-model evaluation completed."
    rows = metrics.items() if metrics else [("cache_smoke" if report["mode"] == "dry_run" else "N/A", {})]
    for partition, values in rows:
        fields = [report["finished_at_utc"], report["run_id"], f"vision {report['mode']} / {report['status']}", "G / 42" if report["mode"] == "execute" else "N/A / 42", "vision_resnet18", partition, *[values.get(name, "N/A") for name in ("f1_malicious", "mcc", "ece", "brier")], f"`{report['code_commit_sha']}`", report["git_worktree"]["status"], f"`{report['report_path']}`; `{report['artifact_directory']}/`", notes]
        with (root / "reports/research_log.md").open("a", encoding="utf-8") as output:
            output.write("| " + " | ".join(str(value).replace("|", "\\|").replace("\n", " ") for value in fields) + " |\n")


def run_vision_model(root: Path, configuration: dict, *, execute: bool = False,
                     smoke_train: bool = False, smoke_epochs: int = 2,
                     smoke_batch_size: int = 2, run_id: str | None = None) -> dict:
    """Run forward diagnostics, bounded smoke training, or official Protocol G."""
    validate_vision_configuration(configuration)
    if type(execute) is not bool or type(smoke_train) is not bool or execute and smoke_train:
        raise ValueError("execute and smoke_train must be mutually exclusive explicit booleans")
    if type(smoke_epochs) is not int or smoke_epochs not in (1, 2):
        raise ValueError("Smoke epochs must be 1 or 2")
    if type(smoke_batch_size) is not int or smoke_batch_size not in (1, 2, 4):
        raise ValueError("Smoke batch size must be 1, 2 or 4")
    root = Path(root).resolve()
    commit = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True, check=False).stdout.strip() or "unavailable"
    git_state = repository_git_state(root)
    identifier = run_id or f"run_{datetime.now(timezone.utc):%Y%m%dT%H%M%S%fZ}_{commit[:12]}"
    if not identifier or identifier in {".", ".."} or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for c in identifier):
        raise ValueError("Unsafe vision run identifier")
    directory = root / "reports/experiments/vision_resnet" / identifier
    artifacts = root / "artifacts/vision_resnet" / identifier
    for path in (directory, artifacts):
        if path.exists() or any(part.is_symlink() for part in (path, *path.parents)):
            raise ValueError("Vision run directory exists or contains a symbolic link")
    directory.mkdir(parents=True, exist_ok=False)
    artifacts.mkdir(parents=True, exist_ok=False)
    report = {"run_id": identifier, "started_at_utc": datetime.now(timezone.utc).isoformat(), "mode": "execute" if execute else "smoke_train" if smoke_train else "dry_run", "status": "started", "code_commit_sha": commit, "git_worktree": git_state, "report_path": str((directory / "run_summary.json").relative_to(root)), "artifact_directory": str(artifacts.relative_to(root)), "metrics": {}}
    old_threads = torch.get_num_threads()
    try:
        methodology = {"configuration": configuration, "architecture": "ResNet-18, 1 channel, one binary logit", "weights": "scratch; no download", "training": "Existing train_with_validation; AdamW/BCEWithLogitsLoss; lowest validation loss" if execute else "Fixed-epoch technical AdamW/BCEWithLogitsLoss smoke" if smoke_train else "None; untrained forward pass", "test_policy": "Test once after persisted checkpoint/validation lock" if execute else "No validation or test evaluation", "normalization": "Use cached row probabilities directly; no fitted scaling or augmentation", "cache_reads": "Bounded NPY header/checksum validation; allow_pickle=False; no raw PDF reads", "dry_run": "Untrained forward pass, no fitting/checkpoint/performance claims", "mode": report["mode"], "code_commit_sha": commit}
        if smoke_train:
            methodology["smoke_training"] = {"epochs": smoke_epochs, "batch_size": smoke_batch_size, "max_samples": min(8, configuration["runtime"]["dry_run_max_samples"]), "selection": "First manifest rows in saved order; final epoch, no early stopping or tuning", "evaluation_scope": "Same samples as fitting; technical diagnostic only, not held-out Protocol G", "official_model": False, "threshold": 0.5, "ece_bins": 10, "ece_convention": "10 equal-width malicious-probability bins; p=1 in final bin", "mcc_convention": "scikit-learn returns 0 for zero denominator; mark mcc_defined=False"}
        _write_json(directory / "locked_methodology.json", methodology)
        torch.set_num_threads(configuration["runtime"]["cpu_threads"])
        determinism = set_deep_learning_seed(configuration["seed"])
        requested = configuration["runtime"]["device"]
        if requested == "cuda" and not torch.cuda.is_available():
            raise ValueError("Requested CUDA is unavailable")
        device = torch.device("cuda" if requested == "cuda" or requested == "auto" and torch.cuda.is_available() else "cpu")
        _write_json(directory / "environment_metadata.json", {"python": platform.python_version(), "packages": {name: importlib.metadata.version(name) for name in ("malpdf", "torch", "torchvision", "numpy", "scikit-learn", "pyyaml")}, "device": str(device), "cpu_threads": torch.get_num_threads(), "determinism": determinism, "code_commit_sha": commit, "git_worktree": git_state, "code_sha256": {name: sha256_file(root / name) for name in ("src/malpdf/models/vision_resnet.py", "src/malpdf/data/vision_dataset.py", "src/malpdf/experiments/vision_runner.py", "src/malpdf/static/cache_manager.py", "scripts/03_train_vision_model.py", "configs/vision_resnet18.yaml") if (root / name).is_file()}})
        paths = configuration["paths"]
        dataset_path = _locked_table(root, paths["dataset"], paths["dataset_sha256"])
        split_path = _locked_table(root, paths["split_manifest"], paths["split_manifest_sha256"])
        frame = load_rit_pdfmal(dataset_path)
        _, split, summary = load_saved_protocol_g_split(frame, paths["dataset_sha256"], root, seed=42, manifest_path=split_path)
        if sha256_file(dataset_path) != paths["dataset_sha256"] or summary["split_manifest_sha256"] != paths["split_manifest_sha256"]:
            raise ValueError("Protocol G inputs changed during preflight")
        source_path = Path(paths["source_manifest"])
        source_path = source_path if source_path.is_absolute() else root / source_path
        samples = load_vision_source_manifest(root, source_path, paths["source_manifest_sha256"])
        _, readiness = align_protocol_g_samples(samples, split)
        report["protocol_g_readiness"] = readiness
        _write_json(directory / "data_provenance.json", {"source_manifest_sha256": paths["source_manifest_sha256"], "dataset_sha256": paths["dataset_sha256"], "split_manifest_sha256": paths["split_manifest_sha256"], "protocol_g_readiness": readiness, "split_validation": summary["hard_validation"]})
        if execute and not readiness["ready"]:
            raise ValueError("Official vision training requires complete Protocol G PDF/cache alignment")
        if execute and git_state["status"] != "clean":
            raise ValueError("Official vision training requires a clean committed worktree")
        cache_directory = root / "data/processed/markov_cache"
        samples = verify_vision_caches(samples, cache_directory)
        partitions, _ = align_protocol_g_samples(samples, split)
        model = VisionResNet18().to(device)
        report["parameter_count"] = sum(parameter.numel() for parameter in model.parameters())
        if smoke_train:
            selected = samples[:min(8, configuration["runtime"]["dry_run_max_samples"])]
            smoke_configuration = {**configuration, "training": {**configuration["training"], "batch_size": smoke_batch_size}}
            outcome = _train_smoke_epochs(model, _loader(selected, cache_directory, smoke_configuration, shuffle=True), device=device, training=configuration["training"], epochs=smoke_epochs)
            evaluation_loader = _loader(selected, cache_directory, smoke_configuration, shuffle=False)
            metrics = evaluate_vision_model(model, evaluation_loader, device=device)
            scope = "Same-sample technical smoke diagnostic; no held-out Protocol G metrics"
            tn, fp = metrics["confusion_matrix"][0]
            fn, tp = metrics["confusion_matrix"][1]
            metrics.update({"scope": scope, "single_class_labels": len({sample.label for sample in selected}) == 1,
                            "mcc_defined": (tp + fp) * (tp + fn) * (tn + fp) * (tn + fn) > 0,
                            "mcc_convention": "scikit-learn zero-denominator result is 0"})
            checkpoint_path = artifacts / "smoke_model.pt"
            _save_checkpoint(checkpoint_path, {"model_state_dict": model.state_dict(), "architecture": "vision_resnet18", "purpose": "technical_smoke_only", "official_model": False, "seed": 42, "epochs": smoke_epochs, "batch_size": smoke_batch_size, "optimizer_steps": outcome["optimizer_steps"], "source_manifest_sha256": paths["source_manifest_sha256"], "threshold": 0.5})
            checkpoint = torch.load(checkpoint_path, map_location=device, weights_only=True)
            reloaded = VisionResNet18().to(device)
            reloaded.load_state_dict(checkpoint["model_state_dict"])
            if any(not torch.equal(value, reloaded.state_dict()[name]) for name, value in model.state_dict().items()):
                raise RuntimeError("Smoke checkpoint state round-trip differs")
            reloaded_metrics = evaluate_vision_model(reloaded, evaluation_loader, device=device)
            if any(not math.isclose(metrics[key], reloaded_metrics[key], rel_tol=1e-6, abs_tol=1e-8) for key in ("accuracy", "f1_malicious", "mcc", "loss", "ece", "brier")):
                raise RuntimeError("Smoke checkpoint metrics round-trip differs")
            report["checkpoint"] = {"path": str(checkpoint_path.relative_to(root)), "sha256": sha256_file(checkpoint_path), "purpose": "technical_smoke_only", "reload_verified": True}
            report["smoke_training"] = {**outcome, "sample_count": len(selected), "epochs": smoke_epochs, "batch_size": smoke_batch_size, "checkpoint_saved": True, "checkpoint_reload_verified": True, "validation_evaluations": 0, "test_evaluations": 0, "same_sample_evaluations": 2, "scope": scope}
            report["metrics"]["smoke_same_samples"] = metrics
            with (directory / "training_history.csv").open("x", newline="", encoding="utf-8") as output:
                writer = csv.DictWriter(output, fieldnames=["epoch", "train_loss", "optimizer_steps"])
                writer.writeheader()
                writer.writerows(outcome["history"])
            _write_json(directory / "metrics.json", report["metrics"])
            with (artifacts / "smoke_samples.csv").open("x", newline="", encoding="utf-8") as output:
                writer = csv.writer(output)
                writer.writerow(["sample_id", "Label", "pdf_sha256"])
                writer.writerows((sample.sample_id, sample.label, sample.pdf_sha256) for sample in selected)
            report["status"] = "smoke_train_completed"
        elif not execute:
            selected = samples[:configuration["runtime"]["dry_run_max_samples"]]
            loader = _loader(selected, cache_directory, configuration, shuffle=False)
            model.eval()
            total_loss, seen = 0.0, 0
            with torch.no_grad():
                for features, labels in loader:
                    logits = model(features.to(device))
                    if tuple(logits.shape) != (len(labels), 1):
                        raise RuntimeError("Unexpected vision output shape")
                    probabilities_from_logits(logits)
                    loss = nn.functional.binary_cross_entropy_with_logits(logits.reshape(-1), labels.to(device), reduction="sum")
                    if not torch.isfinite(loss):
                        raise RuntimeError("Dry-run BCE loss is non-finite")
                    total_loss += float(loss.item())
                    seen += len(labels)
            report["smoke"] = {"sample_count": seen, "input_shape": [seen, 1, 256, 256], "output_shape": [seen, 1], "bce_loss": total_loss / seen, "model_trained": False, "optimizer_steps": 0, "checkpoint_saved": False, "scope": "Untrained cache forward diagnostic; no held-out metrics"}
            with (artifacts / "smoke_samples.csv").open("x", newline="", encoding="utf-8") as output:
                writer = csv.writer(output)
                writer.writerow(["sample_id", "Label", "pdf_sha256"])
                writer.writerows((sample.sample_id, sample.label, sample.pdf_sha256) for sample in selected)
            report["status"] = "dry_run_completed"
        else:
            training = configuration["training"]
            train_loader = _loader(partitions["train"], cache_directory, configuration, shuffle=True)
            validation_loader = _loader(partitions["validation"], cache_directory, configuration, shuffle=False)
            outcome = train_with_validation(model, train_loader, validation_loader, device=device, learning_rate=training["learning_rate"], weight_decay=training["weight_decay"], max_epochs=training["max_epochs"], patience=training["patience"], min_delta=training["min_delta"])
            checkpoint_path = artifacts / "best_model.pt"
            _save_checkpoint(checkpoint_path, {"model_state_dict": outcome.best_state_dict, "architecture": "vision_resnet18", "seed": 42, "best_epoch": outcome.best_epoch, "best_validation_loss": outcome.best_validation_loss, "source_manifest_sha256": paths["source_manifest_sha256"], "split_manifest_sha256": paths["split_manifest_sha256"], "threshold": 0.5})
            checkpoint = torch.load(checkpoint_path, map_location=device, weights_only=True)
            model.load_state_dict(checkpoint["model_state_dict"])
            report["checkpoint"] = {"path": str(checkpoint_path.relative_to(root)), "sha256": sha256_file(checkpoint_path), "best_epoch": outcome.best_epoch, "best_validation_loss": outcome.best_validation_loss}
            with (directory / "training_history.csv").open("x", newline="", encoding="utf-8") as output:
                writer = csv.DictWriter(output, fieldnames=["epoch", "train_loss", "validation_loss"])
                writer.writeheader()
                writer.writerows(outcome.history)
            _write_json(directory / "validation_lock.json", {**report["checkpoint"], "seed": 42, "threshold": 0.5, "selection_metric": "validation_loss", "test_evaluations_before_lock": 0})
            report["metrics"]["validation"] = evaluate_vision_model(model, validation_loader, device=device)
            test_loader = _loader(partitions["test"], cache_directory, configuration, shuffle=False)
            report["metrics"]["test"] = evaluate_vision_model(model, test_loader, device=device)
            _write_json(directory / "metrics.json", report["metrics"])
            report["training_seconds"] = outcome.training_seconds
            report["status"] = "completed"
    except BaseException as error:
        report["status"] = "interrupted" if isinstance(error, KeyboardInterrupt) else "failed"
        report["error"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        torch.set_num_threads(old_threads)
        report["finished_at_utc"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        with (directory / "model_comparison.csv").open("x", newline="", encoding="utf-8") as output:
            writer = csv.writer(output)
            writer.writerow(["model", "partition", "accuracy", "f1_malicious", "mcc", "loss", "ece", "brier", "scope"])
            for partition, values in (report["metrics"].items() or [("N/A", {})]):
                writer.writerow(["vision_resnet18", partition, *[values.get(name, "N/A") for name in ("accuracy", "f1_malicious", "mcc", "loss", "ece", "brier")], values.get("scope", "Protocol G held-out evaluation") if values else "No trained-model metrics"])
        _write_json(directory / "run_summary.json", report)
        _append_log(root, report)
    return report
