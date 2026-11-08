"""Fixed MLP/FT-Transformer comparison on the saved Protocol G split.

This module is intentionally narrow: it reuses the immutable feature-vector-
disjoint manifest, uses train-only standardization, selects checkpoints only by
validation loss, and evaluates the test partition once after selection. It
never trains or reads the deployment detector and never creates a split.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from typing import Any

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import torch
import yaml
from sklearn.preprocessing import StandardScaler
from torch.utils.data import DataLoader, TensorDataset

from malpdf.data.rit_pdfmal import load_rit_pdfmal, sha256_file
from malpdf.data.rit_pdfmal_paper_alignment import TARGET_COLUMN
from malpdf.deep_learning.models import build_tabular_model, count_trainable_parameters
from malpdf.deep_learning.training import (
    binary_predictions_from_probabilities,
    evaluate_loaded_binary_model,
    set_deep_learning_seed,
    train_with_validation,
)
from malpdf.evaluation.binary import classification_metrics_from_confusion_counts, evaluate_binary_predictions
from malpdf.experiments.protocol_g_benchmark import (
    G_DROP3CONSTANT,
    ProtocolGBenchmarkError,
    load_saved_protocol_g_split,
    protocol_g_feature_columns,
    protocol_g_feature_view,
    split_frame_from_protocol_g_manifest,
)
from malpdf.experiments.protocol_p import collect_environment_metadata, repository_git_state
from malpdf.static.schema import PROTOCOL_G_DROPPED_CONSTANT_FEATURES, PROTOCOL_G_REQUIRED_FEATURES

EXPERIMENT_NAME = "protocol_g_deep_learning_seed42"
MODEL_NAMES = ("mlp", "ft_transformer")
EXPECTED_DATASET_SHA256 = "2f270ab31fbfe8821fd7f54608cb1aa694a0a8d0bbf2ca000942a68213ef8623"
EXPECTED_SPLIT_MANIFEST_SHA256 = "802c3962bc537ed78f63c5b1a5308e09df357a096f703846d0e5fe57598b4e21"
EXPECTED_PARTITION_ROWS = {"train": 14_602, "validation": 4_868, "test": 4_867}


class DeepLearningProtocolGError(RuntimeError):
    """Raised when the fixed deep-learning comparison cannot safely proceed."""


@dataclass(frozen=True)
class DeepLearningModelPaths:
    """Immutable reports and local checkpoint path for one model family."""

    name: str
    reports_directory: Path
    config_json: Path
    training_history_csv: Path
    metrics_json: Path
    provenance_json: Path
    checkpoint_path: Path
    figure_path: Path


@dataclass(frozen=True)
class DeepLearningPaths:
    """All dedicated output paths; none overlap historical Protocol G results."""

    run_id: str
    reports_directory: Path
    artifact_directory: Path
    comparison_csv: Path
    run_summary_markdown: Path
    analysis_markdown: Path
    models: dict[str, DeepLearningModelPaths]


@dataclass(frozen=True)
class DeepLearningPreflight:
    """Read-only validated inputs for one official two-model comparison."""

    repository_root: Path
    dataset_path: Path
    frame: pd.DataFrame
    partitions: dict[str, pd.DataFrame]
    split_summary: dict[str, Any]
    feature_order: tuple[str, ...]
    scaler: StandardScaler
    configuration: dict[str, Any]
    historical_xgboost: dict[str, Any]
    environment: dict[str, Any]
    code_commit_sha: str
    device: torch.device
    paths: DeepLearningPaths


def _timestamp_utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _safe_run_id(run_id: str) -> str:
    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
    if not run_id or any(character not in allowed for character in run_id):
        raise ValueError("run_id must be non-empty and contain only letters, numbers, '-', or '_'")
    return run_id


def deep_learning_paths(repository_root: str | Path, run_id: str = "seed42") -> DeepLearningPaths:
    """Return the unique official output locations for one Protocol G DL run."""
    root = Path(repository_root).resolve()
    safe_id = _safe_run_id(run_id)
    reports = root / "reports" / "experiments" / "deep_learning" / f"protocol_g_{safe_id}"
    artifacts = root / "artifacts" / "deep_learning" / f"protocol_g_{safe_id}"
    figures = root / "reports" / "figures" / "deep_learning"
    model_paths = {
        name: DeepLearningModelPaths(
            name=name,
            reports_directory=reports / name,
            config_json=reports / name / "config.json",
            training_history_csv=reports / name / "training_history.csv",
            metrics_json=reports / name / "metrics.json",
            provenance_json=reports / name / "provenance.json",
            checkpoint_path=artifacts / name / "best_validation_checkpoint.pt",
            figure_path=figures / f"{name}_training_curve.png",
        )
        for name in MODEL_NAMES
    }
    return DeepLearningPaths(
        run_id=safe_id,
        reports_directory=reports,
        artifact_directory=artifacts,
        comparison_csv=reports / "comparison.csv",
        run_summary_markdown=reports / "run_summary.md",
        analysis_markdown=root / "reports" / "analysis" / "deep_learning_protocol_g_comparison.md",
        models=model_paths,
    )


def _load_configuration(repository_root: Path) -> dict[str, Any]:
    path = repository_root / "configs" / "deep_learning_protocol_g.yaml"
    if not path.is_file():
        raise FileNotFoundError(f"Deep-learning configuration is missing: {path}")
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise DeepLearningProtocolGError("Deep-learning configuration must be a mapping")
    required = {"dataset_sha256", "split_manifest_sha256", "feature_variant", "models", "training"}
    if required.difference(payload):
        raise DeepLearningProtocolGError("Deep-learning configuration is incomplete")
    if payload["dataset_sha256"] != EXPECTED_DATASET_SHA256 or payload["split_manifest_sha256"] != EXPECTED_SPLIT_MANIFEST_SHA256:
        raise DeepLearningProtocolGError("Configuration does not bind the approved dataset and Protocol G split")
    if payload["feature_variant"] != G_DROP3CONSTANT or payload.get("expected_feature_count") != 38:
        raise DeepLearningProtocolGError("Only Protocol G G-drop3constant with 38 features is permitted")
    if tuple(payload.get("excluded_constant_features", ())) != PROTOCOL_G_DROPPED_CONSTANT_FEATURES:
        raise DeepLearningProtocolGError("The configuration must exclude exactly the established three constants")
    if tuple(payload["models"].keys()) != MODEL_NAMES:
        raise DeepLearningProtocolGError("Configuration must contain exactly the MLP and FT-Transformer models")
    training = payload["training"]
    expected_training = {
        "loss": "BCEWithLogitsLoss",
        "class_weighting": "none",
        "optimizer": "AdamW",
        "early_stopping_metric": "validation_loss",
        "threshold": 0.5,
    }
    if any(training.get(name) != value for name, value in expected_training.items()):
        raise DeepLearningProtocolGError("The fixed DL training objective, optimizer, validation control, or threshold changed")
    return payload


def _torch_environment() -> tuple[torch.device, dict[str, Any]]:
    cuda_available = bool(torch.cuda.is_available())
    device = torch.device("cuda" if cuda_available else "cpu")
    gpu_name = "unavailable"
    if cuda_available:
        try:
            gpu_name = torch.cuda.get_device_name(0)
        except Exception:
            gpu_name = "unavailable"
    return device, {
        "torch_version": torch.__version__,
        "cuda_available": cuda_available,
        "cuda_runtime": torch.version.cuda or "unavailable",
        "cuda_gpu_name": gpu_name,
        "device_used": str(device),
    }


def _json_write(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def _assert_output_available(paths: DeepLearningPaths) -> None:
    protected = {"protocol_p", "protocol_g", "multiseed", "xgb_cv10", "explainability"}
    if set(part.casefold() for part in paths.reports_directory.parts) & protected:
        raise DeepLearningProtocolGError("Deep-learning outputs must not overlap historical benchmark paths")
    protected_outputs = [
        paths.reports_directory,
        paths.artifact_directory,
        paths.analysis_markdown,
        *(model.figure_path for model in paths.models.values()),
    ]
    existing = [str(path) for path in protected_outputs if path.exists()]
    if existing:
        raise FileExistsError(f"Refusing to overwrite deep-learning outputs: {existing}")


def load_historical_xgboost_reference(repository_root: str | Path) -> dict[str, Any]:
    """Read the one committed G-drop3constant XGBoost test record; never retrain it."""
    path = Path(repository_root).resolve() / "reports" / "experiments" / "protocol_g" / "seed42" / "metrics.json"
    if not path.is_file():
        raise FileNotFoundError(f"Historical Protocol G metrics are missing: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    matches = [
        record for record in payload.get("runs", [])
        if record.get("status") == "completed"
        and record.get("model_name") == "xgboost"
        and record.get("feature_variant") == G_DROP3CONSTANT
    ]
    if len(matches) != 1:
        raise DeepLearningProtocolGError("Expected exactly one historical Protocol G XGBoost G-drop3constant result")
    record = matches[0]
    if record.get("dataset_sha256") != EXPECTED_DATASET_SHA256 or record.get("split_manifest_sha256") != EXPECTED_SPLIT_MANIFEST_SHA256:
        raise DeepLearningProtocolGError("Historical XGBoost reference has incompatible dataset or split provenance")
    test = record.get("test")
    if not isinstance(test, dict) or not isinstance(test.get("metrics"), dict) or not isinstance(test.get("confusion_counts"), dict):
        raise DeepLearningProtocolGError("Historical XGBoost reference does not contain complete test metrics")
    counts = test["confusion_counts"]
    explicit = classification_metrics_from_confusion_counts(
        tn=int(counts["tn"]), fp=int(counts["fp"]), fn=int(counts["fn"]), tp=int(counts["tp"])
    )
    metrics = dict(test["metrics"])
    metrics.update(explicit)
    return {
        "source_path": str(path),
        "source_sha256": sha256_file(path),
        "record": record,
        "test_metrics": metrics,
        "confusion_counts": {name: int(value) for name, value in counts.items()},
        "training_seconds": float(record["training"]["training_seconds"]),
    }


def _fit_train_only_scaler(partitions: dict[str, pd.DataFrame], feature_order: tuple[str, ...]) -> StandardScaler:
    """Fit exactly once on Protocol G train features; never on validation/test."""
    train_features = protocol_g_feature_view(partitions["train"], G_DROP3CONSTANT)
    if tuple(train_features.columns) != feature_order:
        raise DeepLearningProtocolGError("Train feature order differs from the established Protocol G order")
    return StandardScaler().fit(train_features)


def transform_partition(
    scaler: StandardScaler, partition: pd.DataFrame, feature_order: tuple[str, ...]
) -> tuple[np.ndarray, np.ndarray]:
    """Apply the train-fitted scaler without altering semantic raw source data."""
    features = protocol_g_feature_view(partition, G_DROP3CONSTANT)
    if tuple(features.columns) != feature_order:
        raise DeepLearningProtocolGError("Partition feature order differs from the established Protocol G order")
    transformed = scaler.transform(features).astype(np.float32, copy=False)
    if not np.isfinite(transformed).all():
        raise DeepLearningProtocolGError("Train-fitted scaling produced non-finite values")
    labels = partition[TARGET_COLUMN].to_numpy(dtype=np.float32, copy=True)
    return transformed, labels


def _loader(
    features: np.ndarray,
    labels: np.ndarray,
    *,
    batch_size: int,
    shuffle: bool,
    seed: int,
    device: torch.device,
) -> DataLoader:
    generator = torch.Generator().manual_seed(seed)
    dataset = TensorDataset(torch.from_numpy(features), torch.from_numpy(labels))
    return DataLoader(
        dataset,
        batch_size=batch_size,
        shuffle=shuffle,
        generator=generator if shuffle else None,
        num_workers=0,
        pin_memory=device.type == "cuda",
    )


def preflight_deep_learning_protocol_g(
    repository_root: str | Path,
    dataset_path: str | Path,
    *,
    run_id: str = "seed42",
    require_clean_git: bool = True,
) -> DeepLearningPreflight:
    """Read/validate the saved split and fixed design without training or output writes."""
    root = Path(repository_root).resolve()
    data_path = Path(dataset_path).resolve()
    state = repository_git_state(root)
    if require_clean_git and state.get("status") != "clean":
        raise DeepLearningProtocolGError("Refusing official deep-learning run because the repository is not clean")
    configuration = _load_configuration(root)
    paths = deep_learning_paths(root, run_id)
    _assert_output_available(paths)
    frame = load_rit_pdfmal(data_path)
    dataset_sha256 = sha256_file(data_path)
    if dataset_sha256 != EXPECTED_DATASET_SHA256 or len(frame) != 24_337:
        raise DeepLearningProtocolGError("RIT dataset identity does not match the approved Protocol G dataset")
    try:
        _manifest_path, manifest, split_summary = load_saved_protocol_g_split(
            frame, dataset_sha256, root, seed=42, enforce_expected_invariants=True
        )
    except (ProtocolGBenchmarkError, FileNotFoundError, ValueError) as error:
        raise DeepLearningProtocolGError(f"Saved Protocol G split validation failed: {error}") from error
    if split_summary.get("split_manifest_sha256") != EXPECTED_SPLIT_MANIFEST_SHA256:
        raise DeepLearningProtocolGError("Saved Protocol G manifest checksum differs from the established baseline")
    partitions = split_frame_from_protocol_g_manifest(frame, manifest)
    if {name: len(partitions[name]) for name in EXPECTED_PARTITION_ROWS} != EXPECTED_PARTITION_ROWS:
        raise DeepLearningProtocolGError("Saved Protocol G partition row counts differ from the established baseline")
    feature_order = tuple(protocol_g_feature_columns(frame, G_DROP3CONSTANT))
    if feature_order != PROTOCOL_G_REQUIRED_FEATURES or len(feature_order) != 38:
        raise DeepLearningProtocolGError("Feature order is not exactly the established 38-feature Protocol G order")
    scaler = _fit_train_only_scaler(partitions, feature_order)
    historical_xgboost = load_historical_xgboost_reference(root)
    environment = collect_environment_metadata(data_path, root)
    device, torch_metadata = _torch_environment()
    environment["git_working_tree"] = state
    environment["deep_learning"] = torch_metadata
    code_commit = str(environment.get("git_commit_sha", "unavailable"))
    if require_clean_git and len(code_commit) != 40:
        raise DeepLearningProtocolGError("Refusing official deep-learning run because the Git commit SHA is unavailable")
    return DeepLearningPreflight(
        repository_root=root,
        dataset_path=data_path,
        frame=frame,
        partitions=partitions,
        split_summary=split_summary,
        feature_order=feature_order,
        scaler=scaler,
        configuration=configuration,
        historical_xgboost=historical_xgboost,
        environment=environment,
        code_commit_sha=code_commit,
        device=device,
        paths=paths,
    )


def _save_training_curve(history: pd.DataFrame, path: Path, model_name: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    figure, axis = plt.subplots(figsize=(7, 4.5))
    axis.plot(history["epoch"], history["train_loss"], label="Train loss")
    axis.plot(history["epoch"], history["validation_loss"], label="Validation loss")
    axis.set_xlabel("Epoch")
    axis.set_ylabel("BCEWithLogitsLoss")
    axis.set_title(f"Protocol G {model_name.replace('_', ' ').title()} training")
    axis.legend()
    axis.grid(alpha=0.25)
    figure.tight_layout()
    figure.savefig(path, dpi=180)
    plt.close(figure)


def _checkpoint_payload(
    *,
    model_state_dict: dict[str, torch.Tensor],
    model_name: str,
    preflight: DeepLearningPreflight,
    best_epoch: int,
    best_validation_loss: float,
) -> dict[str, Any]:
    return {
        "model_state_dict": model_state_dict,
        "model_name": model_name,
        "model_configuration": preflight.configuration["models"][model_name],
        "feature_order": list(preflight.feature_order),
        "scaler_mean": preflight.scaler.mean_.astype(float).tolist(),
        "scaler_scale": preflight.scaler.scale_.astype(float).tolist(),
        "best_epoch": best_epoch,
        "best_validation_loss": best_validation_loss,
        "dataset_sha256": EXPECTED_DATASET_SHA256,
        "split_manifest_sha256": EXPECTED_SPLIT_MANIFEST_SHA256,
        "code_commit_sha": preflight.code_commit_sha,
    }


def _confusion_counts(metrics: dict[str, Any]) -> dict[str, int]:
    matrix = metrics["confusion_matrix"]
    return {"tn": int(matrix[0][0]), "fp": int(matrix[0][1]), "fn": int(matrix[1][0]), "tp": int(matrix[1][1])}


def _scaler_provenance(preflight: DeepLearningPreflight) -> dict[str, Any]:
    return {
        "name": "StandardScaler",
        "fit_scope": "Protocol G train partition only",
        "fit_rows": len(preflight.partitions["train"]),
        "not_fit_on": ["validation", "test"],
        "feature_order": list(preflight.feature_order),
        "mean": preflight.scaler.mean_.astype(float).tolist(),
        "scale": preflight.scaler.scale_.astype(float).tolist(),
        "source_data_policy": "Raw values are not imputed, clipped, encoded, or modified; scaling is applied only to model inputs.",
    }


def _run_model(preflight: DeepLearningPreflight, model_name: str) -> dict[str, Any]:
    """Train one fixed architecture, load its best validation checkpoint, test once."""
    paths = preflight.paths.models[model_name]
    training = preflight.configuration["training"]
    model_configuration = preflight.configuration["models"][model_name]
    determinism = set_deep_learning_seed(int(preflight.configuration["model_seed"]))
    train_features, train_labels = transform_partition(preflight.scaler, preflight.partitions["train"], preflight.feature_order)
    validation_features, validation_labels = transform_partition(preflight.scaler, preflight.partitions["validation"], preflight.feature_order)
    train_loader = _loader(train_features, train_labels, batch_size=int(training["batch_size"]), shuffle=True, seed=int(preflight.configuration["model_seed"]), device=preflight.device)
    validation_loader = _loader(validation_features, validation_labels, batch_size=int(training["batch_size"]), shuffle=False, seed=int(preflight.configuration["model_seed"]), device=preflight.device)
    model = build_tabular_model(model_name, model_configuration)
    parameter_count = count_trainable_parameters(model)
    outcome = train_with_validation(
        model,
        train_loader,
        validation_loader,
        device=preflight.device,
        learning_rate=float(training["learning_rate"]),
        weight_decay=float(training["weight_decay"]),
        max_epochs=int(training["max_epochs"]),
        patience=int(training["early_stopping_patience"]),
        min_delta=float(training["early_stopping_min_delta"]),
    )
    paths.checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
    torch.save(
        _checkpoint_payload(
            model_state_dict=outcome.best_state_dict,
            model_name=model_name,
            preflight=preflight,
            best_epoch=outcome.best_epoch,
            best_validation_loss=outcome.best_validation_loss,
        ),
        paths.checkpoint_path,
    )
    checkpoint_sha256 = sha256_file(paths.checkpoint_path)


    checkpoint = torch.load(paths.checkpoint_path, map_location=preflight.device, weights_only=True)
    model.load_state_dict(checkpoint["model_state_dict"])
    model.to(preflight.device)
    test_features, test_labels = transform_partition(preflight.scaler, preflight.partitions["test"], preflight.feature_order)
    test_loader = _loader(test_features, test_labels, batch_size=int(training["batch_size"]), shuffle=False, seed=int(preflight.configuration["model_seed"]), device=preflight.device)
    inference_started = perf_counter()
    truth, probabilities = evaluate_loaded_binary_model(model, test_loader, device=preflight.device)
    inference_seconds = perf_counter() - inference_started
    predictions = binary_predictions_from_probabilities(probabilities, threshold=float(training["threshold"]))
    test_metrics = evaluate_binary_predictions(truth, predictions, probabilities)
    history = pd.DataFrame(outcome.history)
    paths.reports_directory.mkdir(parents=True, exist_ok=False)
    history.to_csv(paths.training_history_csv, index=False)
    _save_training_curve(history, paths.figure_path, model_name)
    configuration_payload = {
        "experiment": EXPERIMENT_NAME,
        "model_name": model_name,
        "model_configuration": model_configuration,
        "training_configuration": training,
        "feature_variant": G_DROP3CONSTANT,
        "feature_order": list(preflight.feature_order),
        "model_seed": preflight.configuration["model_seed"],
    }
    metrics_payload = {
        "model_name": model_name,
        "parameter_count": parameter_count,
        "best_epoch": outcome.best_epoch,
        "best_validation_loss": outcome.best_validation_loss,
        "training_seconds": outcome.training_seconds,
        "test_evaluation": {
            "partition": "test",
            "evaluation_count": 1,
            "threshold": float(training["threshold"]),
            "metrics": test_metrics,
            "confusion_counts": _confusion_counts(test_metrics),
            "inference_total_seconds": inference_seconds,
            "inference_milliseconds_per_sample": inference_seconds * 1000 / len(truth),
        },
    }
    provenance = {
        "experiment": EXPERIMENT_NAME,
        "run_id": preflight.paths.run_id,
        "timestamp_utc": _timestamp_utc(),
        "code_commit_sha": preflight.code_commit_sha,
        "dataset": {"filename": preflight.dataset_path.name, "sha256": EXPECTED_DATASET_SHA256},
        "protocol": "G feature-vector-disjoint; saved manifest reused without regeneration",
        "split": preflight.split_summary,
        "feature_variant": G_DROP3CONSTANT,
        "feature_order": list(preflight.feature_order),
        "scaler": _scaler_provenance(preflight),
        "device": preflight.environment["deep_learning"],
        "determinism": determinism,
        "checkpoint": {"relative_path": str(paths.checkpoint_path.relative_to(preflight.repository_root)).replace("\\", "/"), "sha256": checkpoint_sha256},
        "selection_policy": "Best epoch selected only by minimum validation BCEWithLogitsLoss; test was evaluated once after checkpoint reload.",
        "scope": "Fixed seed-42 MLP/FT-Transformer comparison; no tuning, class weighting, threshold optimization, test-guided selection, CIC data, raw-PDF model, or deployment-model evidence.",
    }
    _json_write(paths.config_json, configuration_payload)
    _json_write(paths.metrics_json, metrics_payload)
    _json_write(paths.provenance_json, provenance)
    return {
        "model_name": model_name,
        "parameter_count": parameter_count,
        "training_seconds": outcome.training_seconds,
        "best_epoch": outcome.best_epoch,
        "best_validation_loss": outcome.best_validation_loss,
        "test_metrics": test_metrics,
        "confusion_counts": _confusion_counts(test_metrics),
        "checkpoint_sha256": checkpoint_sha256,
        "paths": paths,
    }


def _comparison_rows(preflight: DeepLearningPreflight, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    reference = preflight.historical_xgboost
    reference_metrics = reference["test_metrics"]
    rows = [{
        "model": "XGBoost historical Protocol G",
        "source": "committed historical G-drop3constant test result; not retrained",
        "accuracy": reference_metrics["accuracy"],
        "precision_malicious": reference_metrics["precision_malicious"],
        "recall_malicious": reference_metrics["recall_malicious"],
        "f1_malicious": reference_metrics["f1_malicious"],
        "f1_macro": reference_metrics["f1_macro"],
        "roc_auc": reference_metrics["roc_auc"],
        "pr_auc": reference_metrics["pr_auc"],
        "mcc": reference_metrics["mcc"],
        "trainable_parameters": None,
        "model_complexity": "200 trees; trainable-parameter count is not directly comparable",
        "training_seconds": reference["training_seconds"],
        "best_epoch": None,
        "f1_malicious_delta_vs_xgboost": 0.0,
        "mcc_delta_vs_xgboost": 0.0,
    }]
    for record in records:
        metrics = record["test_metrics"]
        rows.append({
            "model": record["model_name"],
            "source": "official fixed seed-42 Protocol G neural run",
            "accuracy": metrics["accuracy"],
            "precision_malicious": metrics["precision_malicious"],
            "recall_malicious": metrics["recall_malicious"],
            "f1_malicious": metrics["f1_malicious"],
            "f1_macro": metrics["f1_macro"],
            "roc_auc": metrics["roc_auc"],
            "pr_auc": metrics["pr_auc"],
            "mcc": metrics["mcc"],
            "trainable_parameters": record["parameter_count"],
            "model_complexity": "trainable scalar parameters; not directly comparable to tree count",
            "training_seconds": record["training_seconds"],
            "best_epoch": record["best_epoch"],
            "f1_malicious_delta_vs_xgboost": metrics["f1_malicious"] - reference_metrics["f1_malicious"],
            "mcc_delta_vs_xgboost": metrics["mcc"] - reference_metrics["mcc"],
        })
    return rows


def _table_markdown(comparison: pd.DataFrame) -> list[str]:
    columns = ["model", "accuracy", "precision_malicious", "recall_malicious", "f1_malicious", "f1_macro", "roc_auc", "pr_auc", "mcc", "trainable_parameters", "training_seconds"]
    lines = ["| Model | Accuracy | Precision (malicious) | Recall (malicious) | F1 (malicious) | F1 macro | ROC-AUC | PR-AUC | MCC | Parameters | Training s |", "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"]
    for _, row in comparison.loc[:, columns].iterrows():
        parameters = "n/a" if pd.isna(row["trainable_parameters"]) else str(int(row["trainable_parameters"]))
        lines.append(
            f"| {row['model']} | {row['accuracy']:.6f} | {row['precision_malicious']:.6f} | {row['recall_malicious']:.6f} | {row['f1_malicious']:.6f} | {row['f1_macro']:.6f} | {row['roc_auc']:.6f} | {row['pr_auc']:.6f} | {row['mcc']:.6f} | {parameters} | {row['training_seconds']:.3f} |"
        )
    return lines


def _run_summary(preflight: DeepLearningPreflight, comparison: pd.DataFrame, records: list[dict[str, Any]]) -> str:
    return "\n".join([
        "# Protocol G seed-42 deep-learning comparison",
        "",
        "This is a focused, fixed-configuration comparison of MLP and FT-Transformer against the already committed historical XGBoost `G-drop3constant` test result. It is not a deployment evaluation and does not retrain XGBoost.",
        "",
        f"- Dataset SHA-256: `{EXPECTED_DATASET_SHA256}`; split manifest SHA-256: `{EXPECTED_SPLIT_MANIFEST_SHA256}`.",
        f"- Partitions: train {len(preflight.partitions['train'])}; validation {len(preflight.partitions['validation'])}; test {len(preflight.partitions['test'])}.",
        "- StandardScaler is fit only on train. Checkpoint selection is by validation BCEWithLogitsLoss; test is evaluated once at threshold 0.5 after checkpoint reload.",
        f"- Device: `{preflight.environment['deep_learning']['device_used']}`; code commit: `{preflight.code_commit_sha}`.",
        "",
        "## Test comparison",
        "",
        *_table_markdown(comparison),
        "",
        "## Confusion matrices",
        "",
        *[f"- {record['model_name']}: TN/FP/FN/TP = {record['confusion_counts']['tn']}/{record['confusion_counts']['fp']}/{record['confusion_counts']['fn']}/{record['confusion_counts']['tp']}." for record in records],
        "",
        "No test metric was used for epoch selection, architecture choice, class weighting, threshold setting, or reruns.",
        "",
    ])


def _analysis_report(preflight: DeepLearningPreflight, comparison: pd.DataFrame, records: list[dict[str, Any]]) -> str:
    best_f1 = comparison.loc[comparison["f1_malicious"].idxmax(), "model"]
    best_mcc = comparison.loc[comparison["mcc"].idxmax(), "model"]
    deltas = {record["model_name"]: record["test_metrics"]["f1_malicious"] - preflight.historical_xgboost["test_metrics"]["f1_malicious"] for record in records}
    lines = [
        "# Protocol G deep-learning comparison",
        "",
        "## 1. Objective",
        "",
        "Assess whether two fixed tabular neural baselines improve on the committed XGBoost detector under the same feature-vector-disjoint Protocol G split. This is a comparative seed-42 result, not a claim that deep learning must win.",
        "",
        "## 2. Dataset and Protocol G",
        "",
        f"RIT-PDFMal-2026 SHA-256 is `{EXPECTED_DATASET_SHA256}`. The saved split manifest SHA-256 is `{EXPECTED_SPLIT_MANIFEST_SHA256}`: train 14,602, validation 4,868, and test 4,867 rows. Identical 41-dimensional static feature vectors are partition-disjoint; this is not evidence of PDF-file identity.",
        "",
        "## 3. Preprocessing",
        "",
        "The exact 38-feature `G-drop3constant` order is used, excluding only Acroform, Colors, and BaseEncoding. StandardScaler was fit on train rows only, then applied unchanged to validation and once to test after selection. Raw semantic values were not imputed, clipped, encoded, or altered.",
        "",
        "## 4. Fixed architectures and training",
        "",
        "- MLP: Linear 38→128→64→32→1, ReLU, LayerNorm after the first hidden layer, dropout 0.2/0.1/0.0.",
        "- FT-Transformer: feature-specific numeric affine tokens, learned CLS token, d_token=32, two self-attention blocks, four heads, feed-forward width 128, GELU, dropout 0.1, and a one-logit head.",
        "- Both use unweighted BCEWithLogitsLoss, AdamW (learning rate 0.001, weight decay 0.0001), batch size 256, maximum 150 epochs, patience 20, model seed 42, and validation-loss-only early stopping. Threshold is fixed at 0.5.",
        "",
        "## 5. Test results and XGBoost comparison",
        "",
        *_table_markdown(comparison),
        "",
        "## 6. Model complexity",
        "",
        *[f"- {record['model_name']}: {record['parameter_count']} trainable scalar parameters; best validation epoch {record['best_epoch']}; training time {record['training_seconds']:.3f} s." for record in records],
        "Parameter count is reported for neural models but is not strictly comparable to XGBoost's 200-tree complexity.",
        "",
        "## 7. Interpretation",
        "",
        f"The highest observed malicious F1 is `{best_f1}`; the highest observed MCC is `{best_mcc}`. MLP F1 delta versus historical XGBoost is {deltas['mlp']:+.6f}; FT-Transformer delta is {deltas['ft_transformer']:+.6f}. These are observed fixed-protocol differences, not an invitation to search architectures until a neural model wins.",
        "",
        "## 8. Threats to validity and conclusion",
        "",
        "This comparison has one Protocol G split seed and fixed compact architectures rather than exhaustive tuning. CUDA determinism was requested, but GPU kernels/drivers can still prevent bit-identical reproduction. The data are static tabular features, not raw PDFs or dynamic behavior, and no cross-dataset/generalization claim follows. XGBoost is a previously committed historical reference rather than a retrained concurrent model. Results therefore answer this focused seed-42 question only.",
        "",
    ]
    return "\n".join(lines)


def execute_deep_learning_protocol_g(preflight: DeepLearningPreflight) -> dict[str, Any]:
    """Run the two fixed neural models once each after an approved clean preflight."""
    _assert_output_available(preflight.paths)
    preflight.paths.reports_directory.mkdir(parents=True, exist_ok=False)
    records = [_run_model(preflight, model_name) for model_name in MODEL_NAMES]
    comparison = pd.DataFrame(_comparison_rows(preflight, records))
    comparison.to_csv(preflight.paths.comparison_csv, index=False)
    preflight.paths.run_summary_markdown.write_text(_run_summary(preflight, comparison, records), encoding="utf-8")
    preflight.paths.analysis_markdown.parent.mkdir(parents=True, exist_ok=True)
    preflight.paths.analysis_markdown.write_text(_analysis_report(preflight, comparison, records), encoding="utf-8")
    return {"records": records, "comparison": comparison, "paths": preflight.paths}


def run_deep_learning_protocol_g(
    repository_root: str | Path,
    dataset_path: str | Path,
    *,
    run_id: str = "seed42",
    execute: bool = False,
) -> tuple[DeepLearningPreflight, dict[str, Any] | None]:
    """Preflight by default; official training requires an explicit execute flag."""
    preflight = preflight_deep_learning_protocol_g(repository_root, dataset_path, run_id=run_id)
    return preflight, execute_deep_learning_protocol_g(preflight) if execute else None
