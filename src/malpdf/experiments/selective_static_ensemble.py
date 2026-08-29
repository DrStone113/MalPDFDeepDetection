"""Validation-locked XGBoost/FT static fusion and hypothetical routing study.

The experiment uses only the existing numerical RIT table and immutable Protocol
G split.  It has no PDF parser, sandbox client, CAPE integration, dynamic
features, or hybrid classifier.  Fusion/calibration/routing choices are made
from validation predictions before the single test prediction pass.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from typing import Any

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import torch
import yaml
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from torch.utils.data import DataLoader, TensorDataset

from malpdf.data.rit_pdfmal import load_rit_pdfmal, sha256_file
from malpdf.data.rit_pdfmal_paper_alignment import TARGET_COLUMN
from malpdf.data.rit_pdfmal_split import build_deterministic_sample_ids
from malpdf.deep_learning.models import build_tabular_model, count_trainable_parameters
from malpdf.deep_learning.training import (
    binary_predictions_from_probabilities,
    evaluate_loaded_binary_model,
    set_deep_learning_seed,
    train_with_validation,
)
from malpdf.evaluation.selective import (
    CALIBRATION_METHODS,
    apply_probability_calibrator,
    binary_disagreement,
    binary_entropy,
    calibration_metrics,
    continuous_disagreement,
    fit_probability_calibrator,
    fuse_probabilities,
    referral_by_uncertainty,
    selective_metrics,
    validate_candidate_grid,
)
from malpdf.experiments.deep_learning_protocol_g import (
    EXPECTED_DATASET_SHA256,
    EXPECTED_PARTITION_ROWS,
    EXPECTED_SPLIT_MANIFEST_SHA256,
    _load_configuration as load_fixed_ft_configuration,
    _torch_environment,
    load_historical_xgboost_reference,
    transform_partition,
)
from malpdf.experiments.protocol_g_benchmark import (
    G_DROP3CONSTANT,
    ProtocolGBenchmarkError,
    load_saved_protocol_g_split,
    protocol_g_feature_columns,
    protocol_g_feature_view,
    split_frame_from_protocol_g_manifest,
)
from malpdf.experiments.protocol_p import collect_environment_metadata, repository_git_state
from malpdf.models.classical import create_model, model_configurations
from malpdf.static.schema import PROTOCOL_G_REQUIRED_FEATURES


EXPERIMENT_NAME = "selective_static_ensemble_protocol_g_seed42"
RUN_ID = "protocol_g_seed42"
SELECTION_METRIC = "mcc"
PRIMARY_UNCERTAINTY = "entropy_of_selected_ensemble_probability"


class SelectiveEnsembleError(RuntimeError):
    """Raised when immutable Protocol G or validation-lock rules are violated."""


@dataclass(frozen=True)
class EnsemblePaths:
    reports_directory: Path
    artifacts_directory: Path
    figures_directory: Path
    analysis_markdown: Path
    config_json: Path
    lock_json: Path
    selection_csv: Path
    validation_predictions_parquet: Path
    test_predictions_parquet: Path
    model_comparison_csv: Path
    calibration_csv: Path
    disagreement_csv: Path
    complementarity_csv: Path
    routing_csv: Path
    fn_overlap_csv: Path
    run_metadata_json: Path
    run_summary_markdown: Path


@dataclass
class EnsemblePreflight:
    root: Path
    dataset_path: Path
    frame: pd.DataFrame
    partitions: dict[str, pd.DataFrame]
    split_summary: dict[str, Any]
    feature_order: tuple[str, ...]
    ft_configuration: dict[str, Any]
    configuration: dict[str, Any]
    environment: dict[str, Any]
    code_commit_sha: str
    device: torch.device
    paths: EnsemblePaths


@dataclass
class TrainedBaseModels:
    xgb: Any
    ft: Any
    scaler: StandardScaler
    xgb_validation_probability: np.ndarray
    ft_validation_probability: np.ndarray
    xgb_training_seconds: float
    ft_training_seconds: float
    ft_parameter_count: int
    ft_best_epoch: int
    ft_best_validation_loss: float
    ft_determinism: dict[str, Any]


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _write_json(path: Path, payload: Any) -> None:
    def json_default(value: Any) -> Any:
        """Convert numerical-library scalars at the provenance boundary only."""
        if isinstance(value, np.integer):
            return int(value)
        if isinstance(value, np.floating):
            return float(value)
        if isinstance(value, np.ndarray):
            return value.tolist()
        if isinstance(value, Path):
            return str(value)
        raise TypeError(f"Unsupported JSON provenance value: {type(value).__name__}")

    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, allow_nan=False, default=json_default) + "\n", encoding="utf-8")


def _safe_id(source_id: str) -> str:
    return "ensemble-" + hashlib.sha256(("selective-static-v1:" + source_id).encode("utf-8")).hexdigest()[:20]


def ensemble_paths(repository_root: str | Path, run_id: str = RUN_ID) -> EnsemblePaths:
    root = Path(repository_root).resolve()
    if run_id != RUN_ID:
        raise ValueError(f"Only fixed run_id {RUN_ID!r} is permitted")
    reports = root / "reports" / "experiments" / "selective_ensemble" / run_id
    return EnsemblePaths(
        reports_directory=reports,
        artifacts_directory=root / "artifacts" / "selective_ensemble" / run_id,
        figures_directory=root / "reports" / "figures" / "selective_ensemble",
        analysis_markdown=root / "reports" / "analysis" / "selective_static_ensemble.md",
        config_json=reports / "config.json",
        lock_json=reports / "locked_methodology.json",
        selection_csv=reports / "selection_results.csv",
        validation_predictions_parquet=reports / "validation_predictions.parquet",
        test_predictions_parquet=reports / "test_predictions.parquet",
        model_comparison_csv=reports / "model_comparison.csv",
        calibration_csv=reports / "calibration_metrics.csv",
        disagreement_csv=reports / "disagreement_analysis.csv",
        complementarity_csv=reports / "complementarity_analysis.csv",
        routing_csv=reports / "routing_analysis.csv",
        fn_overlap_csv=reports / "fn_overlap.csv",
        run_metadata_json=reports / "run_metadata.json",
        run_summary_markdown=reports / "run_summary.md",
    )


def _load_configuration(root: Path) -> dict[str, Any]:
    path = root / "configs" / "selective_static_ensemble.yaml"
    if not path.is_file():
        raise FileNotFoundError(f"Selective ensemble configuration is missing: {path}")
    configuration = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(configuration, dict):
        raise SelectiveEnsembleError("Selective ensemble configuration must be a mapping")
    required = {"dataset_sha256", "split_manifest_sha256", "feature_variant", "validation_lock", "routing", "test_policy"}
    if required.difference(configuration):
        raise SelectiveEnsembleError("Selective ensemble configuration is incomplete")
    if configuration["dataset_sha256"] != EXPECTED_DATASET_SHA256 or configuration["split_manifest_sha256"] != EXPECTED_SPLIT_MANIFEST_SHA256:
        raise SelectiveEnsembleError("Configuration does not bind the approved dataset and Protocol G manifest")
    if configuration["feature_variant"] != G_DROP3CONSTANT or configuration.get("expected_feature_count") != 38:
        raise SelectiveEnsembleError("Only the established 38-feature G-drop3constant view is allowed")
    lock = configuration["validation_lock"]
    if lock.get("selection_metric") != SELECTION_METRIC or lock.get("threshold") != 0.5:
        raise SelectiveEnsembleError("The predeclared MCC selection objective and threshold 0.5 are required")
    if tuple(lock.get("calibration_methods", ())) != CALIBRATION_METHODS:
        raise SelectiveEnsembleError("Calibration candidates must be exactly none, platt, isotonic")
    validate_candidate_grid(lock.get("xgb_weight_grid", ()))
    if tuple(configuration["routing"].get("referral_budgets", ())) != (0.0, 0.05, 0.10, 0.20, 0.30):
        raise SelectiveEnsembleError("Only the preregistered referral budgets 0%, 5%, 10%, 20%, 30% are allowed")
    if configuration["routing"].get("uncertainty_definition") != PRIMARY_UNCERTAINTY:
        raise SelectiveEnsembleError("The primary uncertainty definition changed")
    if int(configuration.get("calibration_metrics", {}).get("ece_bins", 0)) != 10:
        raise SelectiveEnsembleError("ECE must use the fixed ten-bin definition")
    return configuration


def _assert_outputs_available(paths: EnsemblePaths) -> None:
    targets = [paths.reports_directory, paths.artifacts_directory, paths.analysis_markdown]
    if any(path.exists() for path in targets):
        raise FileExistsError("Refusing to overwrite an existing selective-ensemble output or analysis")


def preflight_selective_ensemble(repository_root: str | Path, dataset_path: str | Path, *, require_clean_git: bool = True) -> EnsemblePreflight:
    """Validate immutable inputs and frozen configuration; neither model is fit."""
    root = Path(repository_root).resolve()
    data_path = Path(dataset_path).resolve()
    state = repository_git_state(root)
    if require_clean_git and state.get("status") != "clean":
        raise SelectiveEnsembleError("Official selective-ensemble execution requires a clean Git worktree")
    paths = ensemble_paths(root)
    _assert_outputs_available(paths)
    configuration = _load_configuration(root)
    frame = load_rit_pdfmal(data_path)
    checksum = sha256_file(data_path)
    if checksum != EXPECTED_DATASET_SHA256 or len(frame) != 24_337:
        raise SelectiveEnsembleError("The RIT dataset does not match the approved identity")
    try:
        _manifest_path, manifest, split_summary = load_saved_protocol_g_split(frame, checksum, root, seed=42, enforce_expected_invariants=True)
    except (ProtocolGBenchmarkError, FileNotFoundError, ValueError) as error:
        raise SelectiveEnsembleError(f"Protocol G manifest reuse failed: {error}") from error
    if split_summary.get("split_manifest_sha256") != EXPECTED_SPLIT_MANIFEST_SHA256:
        raise SelectiveEnsembleError("Protocol G manifest checksum differs from the established split")
    partitions = split_frame_from_protocol_g_manifest(frame, manifest)
    if {name: len(partitions[name]) for name in EXPECTED_PARTITION_ROWS} != EXPECTED_PARTITION_ROWS:
        raise SelectiveEnsembleError("Protocol G partition sizes differ from the established split")
    feature_order = tuple(protocol_g_feature_columns(frame, G_DROP3CONSTANT))
    if feature_order != PROTOCOL_G_REQUIRED_FEATURES or len(feature_order) != 38:
        raise SelectiveEnsembleError("The canonical Protocol G feature order changed")
    ft_configuration = load_fixed_ft_configuration(root)
    if ft_configuration["models"]["ft_transformer"] != yaml.safe_load((root / "configs" / "deep_learning_protocol_g.yaml").read_text(encoding="utf-8"))["models"]["ft_transformer"]:
        raise SelectiveEnsembleError("FT-Transformer configuration is not the established configuration")
    environment = collect_environment_metadata(data_path, root)
    device, torch_metadata = _torch_environment()
    environment["git_working_tree"] = state
    environment["deep_learning"] = torch_metadata
    code_sha = str(environment.get("git_commit_sha", "unavailable"))
    if require_clean_git and len(code_sha) != 40:
        raise SelectiveEnsembleError("Official execution requires a full Git commit SHA")
    return EnsemblePreflight(root, data_path, frame, partitions, split_summary, feature_order, ft_configuration, configuration, environment, code_sha, device, paths)


def _loader(features: np.ndarray, labels: np.ndarray, *, batch_size: int, shuffle: bool, seed: int, device: torch.device) -> DataLoader:
    return DataLoader(
        TensorDataset(torch.from_numpy(features), torch.from_numpy(labels)),
        batch_size=batch_size,
        shuffle=shuffle,
        generator=torch.Generator().manual_seed(seed) if shuffle else None,
        num_workers=0,
        pin_memory=device.type == "cuda",
    )


def _synchronize(device: torch.device) -> None:
    if device.type == "cuda":
        torch.cuda.synchronize(device)


def _probabilities_xgb(model: Any, features: pd.DataFrame) -> np.ndarray:
    scores = np.asarray(model.predict_proba(features))[:, 1].astype(float)
    if not np.isfinite(scores).all() or (scores < 0).any() or (scores > 1).any():
        raise SelectiveEnsembleError("XGBoost produced invalid probabilities")
    return scores


def _fit_base_models(preflight: EnsemblePreflight) -> TrainedBaseModels:
    """Fit frozen models using train only and return validation predictions only."""
    train = preflight.partitions["train"]
    validation = preflight.partitions["validation"]
    xgb = create_model("xgboost", 42)
    xgb_start = perf_counter()
    xgb.fit(protocol_g_feature_view(train, G_DROP3CONSTANT), train[TARGET_COLUMN])
    xgb_training = perf_counter() - xgb_start
    xgb_validation = _probabilities_xgb(xgb, protocol_g_feature_view(validation, G_DROP3CONSTANT))

    scaler = StandardScaler().fit(protocol_g_feature_view(train, G_DROP3CONSTANT))
    train_features, train_labels = transform_partition(scaler, train, preflight.feature_order)
    validation_features, validation_labels = transform_partition(scaler, validation, preflight.feature_order)
    training = preflight.ft_configuration["training"]
    determinism = set_deep_learning_seed(int(preflight.ft_configuration["model_seed"]))
    model = build_tabular_model("ft_transformer", preflight.ft_configuration["models"]["ft_transformer"])
    parameter_count = count_trainable_parameters(model)
    outcome = train_with_validation(
        model,
        _loader(train_features, train_labels, batch_size=int(training["batch_size"]), shuffle=True, seed=42, device=preflight.device),
        _loader(validation_features, validation_labels, batch_size=int(training["batch_size"]), shuffle=False, seed=42, device=preflight.device),
        device=preflight.device,
        learning_rate=float(training["learning_rate"]),
        weight_decay=float(training["weight_decay"]),
        max_epochs=int(training["max_epochs"]),
        patience=int(training["early_stopping_patience"]),
        min_delta=float(training["early_stopping_min_delta"]),
    )
    model.load_state_dict(outcome.best_state_dict)
    model.to(preflight.device)
    _synchronize(preflight.device)
    _, ft_validation = evaluate_loaded_binary_model(model, _loader(validation_features, validation_labels, batch_size=int(training["batch_size"]), shuffle=False, seed=42, device=preflight.device), device=preflight.device)
    _synchronize(preflight.device)
    return TrainedBaseModels(xgb, model, scaler, xgb_validation, ft_validation, xgb_training, outcome.training_seconds, parameter_count, outcome.best_epoch, outcome.best_validation_loss, determinism)


def validation_calibration_split(labels: Any, *, fraction: float, seed: int) -> tuple[np.ndarray, np.ndarray]:
    """Return deterministic calibration-fit and disjoint selection positions."""
    truth = np.asarray(labels, dtype=int)
    positions = np.arange(len(truth))
    calibration, selection = train_test_split(positions, train_size=fraction, random_state=seed, stratify=truth)
    return np.sort(calibration), np.sort(selection)


def select_validation_fusion(
    labels: Any,
    xgb_probabilities: Any,
    ft_probabilities: Any,
    *,
    calibration_positions: np.ndarray,
    selection_positions: np.ndarray,
    calibration_methods: tuple[str, ...],
    weights: tuple[float, ...],
    ece_bins: int,
) -> tuple[pd.DataFrame, dict[str, Any]]:
    """Choose a predeclared candidate from validation only; no test argument exists."""
    truth = np.asarray(labels, dtype=int)
    xgb = np.asarray(xgb_probabilities, dtype=float)
    ft = np.asarray(ft_probabilities, dtype=float)
    if not len(truth) or len(xgb) != len(truth) or len(ft) != len(truth):
        raise ValueError("Validation labels and base probabilities must have matching non-empty lengths")
    rows: list[dict[str, Any]] = []
    declared = [("xgboost_only", 1.0), ("ft_transformer_only", 0.0), ("equal_probability_average", 0.5)] + [("weighted_probability_average", weight) for weight in weights]
    for method in calibration_methods:
        xgb_calibrator = fit_probability_calibrator(method, xgb[calibration_positions], truth[calibration_positions], seed=42)
        ft_calibrator = fit_probability_calibrator(method, ft[calibration_positions], truth[calibration_positions], seed=42)
        xgb_selection = apply_probability_calibrator(method, xgb_calibrator, xgb[selection_positions])
        ft_selection = apply_probability_calibrator(method, ft_calibrator, ft[selection_positions])
        for candidate_order, (family, weight) in enumerate(declared):
            probability = fuse_probabilities(xgb_selection, ft_selection, xgb_weight=weight)
            metrics = calibration_metrics(truth[selection_positions], probability, n_bins=ece_bins)
            rows.append({
                "calibration_method": method,
                "fusion_family": family,
                "xgb_weight": weight,
                "candidate_order": candidate_order,
                "selection_partition": "validation_selection_only",
                "selection_rows": int(len(selection_positions)),
                "calibration_fit_rows": int(len(calibration_positions)),
                "selection_metric": SELECTION_METRIC,
                "selection_mcc": metrics["mcc"],
                "selection_f1_malicious": metrics["f1_malicious"],
                "selection_f1_macro": metrics["f1_macro"],
                "selection_brier": metrics["brier"],
                "selection_log_loss": metrics["log_loss"],
                "selection_ece": metrics["ece"],
            })
    results = pd.DataFrame(rows)
    # Stable sorting preserves the declared method/family/grid order for exact ties.
    selected_index = results.sort_values(["selection_mcc", "selection_f1_malicious"], ascending=False, kind="stable").index[0]
    selected = dict(results.loc[selected_index])
    selected["selection_policy"] = "maximize validation-selection MCC; malicious F1 secondary; exact ties keep declared candidate order"
    selected["test_used_for_selection"] = False
    return results, selected


def _fit_selected_calibrators(method: str, labels: np.ndarray, xgb: np.ndarray, ft: np.ndarray) -> tuple[Any, Any]:
    return (
        fit_probability_calibrator(method, xgb, labels, seed=42),
        fit_probability_calibrator(method, ft, labels, seed=42),
    )


def _prediction_table(source_ids: pd.Series, labels: np.ndarray, xgb: np.ndarray, ft: np.ndarray, *, selected_xgb: np.ndarray, selected_ft: np.ndarray, ensemble: np.ndarray, calibration_role: np.ndarray | None = None) -> pd.DataFrame:
    disagreement = binary_disagreement(xgb, ft)
    table = pd.DataFrame({
        "sample_id": [_safe_id(str(value)) for value in source_ids],
        "true_label": labels.astype(int),
        "xgb_probability": xgb,
        "ft_probability": ft,
        "xgb_prediction": (xgb >= 0.5).astype(int),
        "ft_prediction": (ft >= 0.5).astype(int),
        "agreement": (~disagreement),
        "selected_xgb_probability": selected_xgb,
        "selected_ft_probability": selected_ft,
        "ensemble_probability": ensemble,
        "ensemble_prediction": (ensemble >= 0.5).astype(int),
        "model_disagreement": disagreement,
        "continuous_disagreement": continuous_disagreement(xgb, ft),
        "ensemble_confidence": np.abs(ensemble - 0.5),
        "ensemble_entropy": binary_entropy(ensemble),
    })
    if calibration_role is not None:
        table["validation_role"] = calibration_role
    if table["sample_id"].duplicated().any() or not table["sample_id"].str.startswith("ensemble-").all():
        raise SelectiveEnsembleError("Prediction table must contain unique safe sample identifiers only")
    return table.sort_values("sample_id", kind="stable").reset_index(drop=True)


def _metric_row(name: str, partition: str, labels: np.ndarray, probabilities: np.ndarray, ece_bins: int) -> dict[str, Any]:
    metrics = calibration_metrics(labels, probabilities, n_bins=ece_bins)
    return {"model": name, "partition": partition, **{key: metrics[key] for key in ("accuracy", "precision_malicious", "recall_malicious", "f1_malicious", "f1_macro", "roc_auc", "pr_auc", "mcc", "brier", "log_loss", "ece")}}


def _disagreement_rows(labels: np.ndarray, xgb: np.ndarray, ft: np.ndarray) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    xpred, fpred = (xgb >= 0.5).astype(int), (ft >= 0.5).astype(int)
    disagree = xpred != fpred
    xcorrect, fcorrect = xpred == labels, fpred == labels
    complementarity = [{"category": name, "count": int(mask.sum()), "percentage": float(mask.mean())} for name, mask in (
        ("both_correct", xcorrect & fcorrect), ("xgb_only_correct", xcorrect & ~fcorrect), ("ft_only_correct", ~xcorrect & fcorrect), ("both_incorrect", ~xcorrect & ~fcorrect),
    )]
    if not disagree.any():
        return [{"subset": "model_disagreement", "count": 0, "benign_count": 0, "malicious_count": 0, "xgb_correct": 0, "ft_correct": 0, "both_wrong": 0, "mean_xgb_probability": None, "mean_ft_probability": None, "xgb_false_positive": 0, "xgb_false_negative": 0, "ft_false_positive": 0, "ft_false_negative": 0}], complementarity
    subset = disagree
    return [{
        "subset": "model_disagreement", "count": int(subset.sum()), "benign_count": int((labels[subset] == 0).sum()), "malicious_count": int((labels[subset] == 1).sum()),
        "xgb_correct": int(xcorrect[subset].sum()), "ft_correct": int(fcorrect[subset].sum()), "both_wrong": int((~xcorrect[subset] & ~fcorrect[subset]).sum()),
        "mean_xgb_probability": float(xgb[subset].mean()), "mean_ft_probability": float(ft[subset].mean()),
        "xgb_false_positive": int(((xpred == 1) & (labels == 0) & subset).sum()), "xgb_false_negative": int(((xpred == 0) & (labels == 1) & subset).sum()),
        "ft_false_positive": int(((fpred == 1) & (labels == 0) & subset).sum()), "ft_false_negative": int(((fpred == 0) & (labels == 1) & subset).sum()),
    }], complementarity


def _fn_overlap(labels: np.ndarray, xgb: np.ndarray, ft: np.ndarray, ensemble: np.ndarray) -> list[dict[str, Any]]:
    malicious = labels == 1
    xfn = malicious & (xgb < 0.5)
    ffn = malicious & (ft < 0.5)
    efn = malicious & (ensemble < 0.5)
    return [
        {"set": "xgb_false_negatives", "count": int(xfn.sum())}, {"set": "ft_false_negatives", "count": int(ffn.sum())}, {"set": "ensemble_false_negatives", "count": int(efn.sum())},
        {"set": "xgb_and_ft_false_negatives", "count": int((xfn & ffn).sum())}, {"set": "xgb_only_false_negatives", "count": int((xfn & ~ffn).sum())}, {"set": "ft_only_false_negatives", "count": int((~xfn & ffn).sum())},
        {"set": "all_three_false_negatives", "count": int((xfn & ffn & efn).sum())},
    ]


def routing_analysis(labels: np.ndarray, probabilities: np.ndarray, disagreement: np.ndarray, budgets: tuple[float, ...]) -> pd.DataFrame:
    """Evaluate predeclared hypothetical referral policies; no row is corrected."""
    uncertainty = binary_entropy(probabilities)
    rows: list[dict[str, Any]] = []
    policies = (("uncertainty_only", None), ("disagreement_always_then_uncertainty", disagreement), ("unavailable_always_referral_capable", np.zeros(len(labels), dtype=bool)))
    for policy, forced in policies:
        for budget in budgets:
            result = referral_by_uncertainty(uncertainty, referral_rate=budget, always_refer=forced)
            measured = selective_metrics(labels, probabilities, result.referred)
            retained = measured["retained_metrics"]
            rows.append({
                "policy": policy, "requested_referral_rate": budget, "referral_rate": result.referral_rate, "coverage": result.coverage,
                "retained_accuracy": retained["accuracy"], "retained_precision_malicious": retained["precision_malicious"], "retained_recall_malicious": retained["recall_malicious"], "retained_f1_malicious": retained["f1_malicious"], "retained_f1_macro": retained["f1_macro"], "retained_mcc": retained["mcc"],
                "errors_referred": measured["errors_referred"], "error_capture_rate": measured["error_capture_rate"], "false_negatives_referred": measured["fn_referred"], "fn_capture_rate": measured["fn_capture_rate"], "false_positives_referred": measured["fp_referred"], "fp_capture_rate": measured["fp_capture_rate"],
                "fp_retained": measured["fp_retained"], "fn_retained": measured["fn_retained"], "referred_error_rate": measured["referred_error_rate"], "retained_error_rate": measured["retained_error_rate"], "static_prediction_unavailable_rows": 0,
            })
    return pd.DataFrame(rows)


def _save_figures(paths: EnsemblePaths, comparison: pd.DataFrame, routing: pd.DataFrame, complementarity: pd.DataFrame, *, labels: np.ndarray, probabilities: dict[str, np.ndarray]) -> None:
    paths.figures_directory.mkdir(parents=True, exist_ok=True)
    figure, axis = plt.subplots(figsize=(6.8, 5.2))
    for name, values in probabilities.items():
        bin_ids = np.minimum((values * 10).astype(int), 9)
        confidence, observed = [], []
        for index in range(10):
            mask = bin_ids == index
            if mask.any():
                confidence.append(float(values[mask].mean()))
                observed.append(float(labels[mask].mean()))
        axis.plot(confidence, observed, marker="o", label=name)
    axis.plot([0, 1], [0, 1], linestyle="--", color="black", linewidth=1, label="perfect calibration")
    axis.set_xlabel("Mean predicted malicious probability"); axis.set_ylabel("Observed malicious fraction"); axis.set_title("Protocol G test reliability diagram (10 fixed-width bins)"); axis.legend(); axis.grid(alpha=0.25); figure.tight_layout(); figure.savefig(paths.figures_directory / "calibration_reliability.png", dpi=180); plt.close(figure)
    figure, axis = plt.subplots(figsize=(8, 4.6)); plotted = comparison.set_index("model")[["f1_malicious", "mcc"]]; plotted.plot.bar(ax=axis); axis.set_ylabel("Metric value"); axis.set_title("Protocol G static-model comparison"); axis.set_ylim(0.0, 1.02); axis.grid(axis="y", alpha=0.25); figure.tight_layout(); figure.savefig(paths.figures_directory / "ensemble_comparison.png", dpi=180); plt.close(figure)
    primary = routing.loc[routing["policy"] == "uncertainty_only"].sort_values("coverage")
    figure, axis = plt.subplots(figsize=(6.8, 4.8)); axis.plot(primary["coverage"], primary["retained_error_rate"], marker="o"); axis.set_xlabel("Static coverage"); axis.set_ylabel("Retained static error rate"); axis.set_title("Risk–coverage curve (uncertainty-only routing)"); axis.grid(alpha=0.25); figure.tight_layout(); figure.savefig(paths.figures_directory / "risk_coverage.png", dpi=180); plt.close(figure)
    figure, axis = plt.subplots(figsize=(6.8, 4.8)); axis.plot(primary["referral_rate"], primary["fn_retained"], marker="o"); axis.set_xlabel("Referral rate"); axis.set_ylabel("False negatives retained"); axis.set_title("False negatives versus hypothetical referral"); axis.grid(alpha=0.25); figure.tight_layout(); figure.savefig(paths.figures_directory / "fn_vs_referral.png", dpi=180); plt.close(figure)
    figure, axis = plt.subplots(figsize=(6.8, 4.8)); axis.plot(primary["referral_rate"], primary["error_capture_rate"], marker="o", label="All errors"); axis.plot(primary["referral_rate"], primary["fn_capture_rate"], marker="o", label="False negatives"); axis.set_xlabel("Referral rate"); axis.set_ylabel("Capture rate"); axis.set_title("Static error capture by referral"); axis.legend(); axis.grid(alpha=0.25); figure.tight_layout(); figure.savefig(paths.figures_directory / "error_capture.png", dpi=180); plt.close(figure)
    figure, axis = plt.subplots(figsize=(6.8, 4.8)); axis.bar(complementarity["category"], complementarity["count"]); axis.set_ylabel("Test rows"); axis.set_title("XGBoost / FT-Transformer correctness composition"); axis.tick_params(axis="x", rotation=20); figure.tight_layout(); figure.savefig(paths.figures_directory / "disagreement_composition.png", dpi=180); plt.close(figure)


def _analysis_markdown(preflight: EnsemblePreflight, selected: dict[str, Any], comparison: pd.DataFrame, disagreement: pd.DataFrame, routing: pd.DataFrame) -> str:
    primary = routing.loc[(routing["policy"] == "uncertainty_only") & (routing["requested_referral_rate"] == 0.10)].iloc[0]
    lines = [
        "# Selective Static Ensemble and Dynamic Routing Analysis", "", "## 1. Objective", "", "Assess fixed XGBoost/FT-Transformer probability fusion and whether validation-locked uncertainty concentrates errors for hypothetical dynamic referral. No PDF, CAPE, dynamic feature, dynamic classifier, or hybrid model is used.",
        "", "## 2. Base models", "", "The established Protocol G `G-drop3constant` 38-feature XGBoost configuration and fixed FT-Transformer training procedure are reused. XGBoost is reproduced against the historical test record after the validation lock; FT configuration is checked unchanged and trained once with its existing validation-loss stopping procedure.",
        "", "## 3. Calibration and validation lock", "", f"Validation was deterministically stratified into calibration-fit and selection halves. Candidates were none/Platt/isotonic calibration crossed with the declared base/equal/grid-weight fusion family. The locked candidate is `{selected['calibration_method']}` + `{selected['fusion_family']}` with XGBoost weight `{selected['xgb_weight']:.1f}`, selected by validation MCC (`{selected['selection_mcc']:.6f}`), then malicious F1. TEST was not provided to the selector.",
        "", "## 4. Test performance", "", comparison.to_markdown(index=False, floatfmt=".6f"),
        "", "## 5. Error complementarity and disagreement", "", disagreement.to_markdown(index=False, floatfmt=".6f"),
        "", "## 6. Selective classification", "", f"At the predeclared 10% uncertainty-only referral budget, actual referral is `{primary['referral_rate']:.4f}`, retained coverage `{primary['coverage']:.4f}`, error capture `{primary['error_capture_rate']:.4f}`, and false-negative capture `{primary['fn_capture_rate']:.4f}`. Referred rows are abstained/referred, not counted as corrected.",
        "", "## 7. Dynamic-routing efficiency", "", "Routing is a hypothetical recommendation only. Static prediction unavailability remains independently referral-capable in the production contract; there are no unavailable rows in this numerical table evaluation.",
        "", "## 8. Recommended conceptual modes", "", "- FAST: XGBoost-only static prediction; dynamic recommendation only for extraction failure/extreme reviewed policy.", "- BALANCED: selected ensemble plus uncertainty/disagreement routing.", "- MAX ACCURACY: selected ensemble plus a larger predeclared referral budget. None of these are production guarantees.",
        "", "## 9. Threats to validity", "", "One Protocol G split and one FT training run remain insufficient for a general ensemble claim. Calibration selection inherits the FT validation-loss training procedure; calibration fitting and candidate selection were separated within validation, but no external calibration set exists. Feature-vector-disjointness is not file identity, temporal, external, or real-world generalization. Dynamic benefits are not measured.",
        "", "## 10. Future hybrid preparation", "", "A future hybrid vector may contain static ensemble/XGBoost/FT probabilities, disagreement, uncertainty, and only genuinely observed dynamic-schema-v1 fields. This study fabricates none and trains no hybrid model.", "",
    ]
    return "\n".join(lines)


def execute_selective_ensemble(preflight: EnsemblePreflight) -> dict[str, Any]:
    """Run one validation lock followed by exactly one final test inference pass."""
    paths = preflight.paths
    paths.reports_directory.mkdir(parents=True, exist_ok=False)
    paths.artifacts_directory.mkdir(parents=True, exist_ok=False)
    base = _fit_base_models(preflight)
    labels_validation = preflight.partitions["validation"][TARGET_COLUMN].to_numpy(dtype=int)
    lock_cfg = preflight.configuration["validation_lock"]
    calibration_pos, selection_pos = validation_calibration_split(labels_validation, fraction=float(lock_cfg["calibration_fit_fraction"]), seed=int(lock_cfg["calibration_split_seed"]))
    selections, selected = select_validation_fusion(labels_validation, base.xgb_validation_probability, base.ft_validation_probability, calibration_positions=calibration_pos, selection_positions=selection_pos, calibration_methods=tuple(lock_cfg["calibration_methods"]), weights=validate_candidate_grid(lock_cfg["xgb_weight_grid"]), ece_bins=int(preflight.configuration["calibration_metrics"]["ece_bins"]))
    selected_method, selected_weight = str(selected["calibration_method"]), float(selected["xgb_weight"])
    xgb_calibrator, ft_calibrator = _fit_selected_calibrators(selected_method, labels_validation, base.xgb_validation_probability, base.ft_validation_probability)
    selected_xgb_validation = apply_probability_calibrator(selected_method, xgb_calibrator, base.xgb_validation_probability)
    selected_ft_validation = apply_probability_calibrator(selected_method, ft_calibrator, base.ft_validation_probability)
    ensemble_validation = fuse_probabilities(selected_xgb_validation, selected_ft_validation, xgb_weight=selected_weight)
    source_ids = build_deterministic_sample_ids(preflight.frame).astype(str)
    validation_ids = source_ids.loc[preflight.partitions["validation"].index]
    roles = np.full(len(labels_validation), "selection", dtype=object); roles[calibration_pos] = "calibration_fit"
    validation_table = _prediction_table(validation_ids, labels_validation, base.xgb_validation_probability, base.ft_validation_probability, selected_xgb=selected_xgb_validation, selected_ft=selected_ft_validation, ensemble=ensemble_validation, calibration_role=roles)
    _write_json(paths.lock_json, {"locked_at_utc": _timestamp(), "selection": selected, "calibration_fit_rows": len(calibration_pos), "selection_rows": len(selection_pos), "test_evaluation_completed": False, "test_policy": preflight.configuration["test_policy"]})
    selections.to_csv(paths.selection_csv, index=False)
    validation_table.to_parquet(paths.validation_predictions_parquet, index=False)
    _write_json(paths.config_json, preflight.configuration)
    joblib.dump(base.xgb, paths.artifacts_directory / "xgboost.joblib")
    torch.save({"state_dict": base.ft.state_dict(), "feature_order": list(preflight.feature_order), "scaler_mean": base.scaler.mean_.tolist(), "scaler_scale": base.scaler.scale_.tolist(), "configuration": preflight.ft_configuration["models"]["ft_transformer"]}, paths.artifacts_directory / "ft_transformer.pt")
    # The first test access occurs only after the lock has been persisted.
    test = preflight.partitions["test"]
    labels_test = test[TARGET_COLUMN].to_numpy(dtype=int)
    test_features = protocol_g_feature_view(test, G_DROP3CONSTANT)
    start = perf_counter(); xgb_test = _probabilities_xgb(base.xgb, test_features); xgb_seconds = perf_counter() - start
    ft_features, ft_labels = transform_partition(base.scaler, test, preflight.feature_order)
    training = preflight.ft_configuration["training"]
    _synchronize(preflight.device); start = perf_counter(); truth, ft_test = evaluate_loaded_binary_model(base.ft, _loader(ft_features, ft_labels, batch_size=int(training["batch_size"]), shuffle=False, seed=42, device=preflight.device), device=preflight.device); _synchronize(preflight.device); ft_seconds = perf_counter() - start
    if not np.array_equal(truth, labels_test):
        raise SelectiveEnsembleError("FT inference labels do not match the saved Protocol G test partition")
    start = perf_counter(); selected_xgb_test = apply_probability_calibrator(selected_method, xgb_calibrator, xgb_test); selected_ft_test = apply_probability_calibrator(selected_method, ft_calibrator, ft_test); ensemble_test = fuse_probabilities(selected_xgb_test, selected_ft_test, xgb_weight=selected_weight); ensemble_seconds = perf_counter() - start
    historical = load_historical_xgboost_reference(preflight.root)["test_metrics"]
    xgb_metrics = calibration_metrics(labels_test, xgb_test, n_bins=10)
    tolerance = float(preflight.configuration["test_policy"]["xgboost_reproduction_tolerance"])
    for metric in ("accuracy", "precision_malicious", "recall_malicious", "f1_malicious", "f1_macro", "mcc"):
        if abs(float(xgb_metrics[metric]) - float(historical[metric])) > tolerance:
            raise SelectiveEnsembleError(f"XGBoost reproduction differs from historical {metric} beyond tolerance")
    ft_metrics = calibration_metrics(labels_test, ft_test, n_bins=10)
    ensemble_metrics = calibration_metrics(labels_test, ensemble_test, n_bins=10)
    comparison = pd.DataFrame([
        {"model": "xgboost", "probability_source": "raw established base", **{key: xgb_metrics[key] for key in ("accuracy", "precision_malicious", "recall_malicious", "f1_malicious", "f1_macro", "roc_auc", "pr_auc", "mcc", "brier", "log_loss", "ece")}},
        {"model": "ft_transformer", "probability_source": "raw fixed-training base", **{key: ft_metrics[key] for key in ("accuracy", "precision_malicious", "recall_malicious", "f1_malicious", "f1_macro", "roc_auc", "pr_auc", "mcc", "brier", "log_loss", "ece")}},
        {"model": "validation_selected_ensemble", "probability_source": f"{selected_method} calibration; {selected['fusion_family']}; xgb_weight={selected_weight:.1f}", **{key: ensemble_metrics[key] for key in ("accuracy", "precision_malicious", "recall_malicious", "f1_malicious", "f1_macro", "roc_auc", "pr_auc", "mcc", "brier", "log_loss", "ece")}},
    ])
    test_ids = source_ids.loc[test.index]
    test_table = _prediction_table(test_ids, labels_test, xgb_test, ft_test, selected_xgb=selected_xgb_test, selected_ft=selected_ft_test, ensemble=ensemble_test)
    calibration_rows = [
        _metric_row("xgboost_raw", "validation_selection", labels_validation[selection_pos], base.xgb_validation_probability[selection_pos], 10), _metric_row("ft_transformer_raw", "validation_selection", labels_validation[selection_pos], base.ft_validation_probability[selection_pos], 10),
        _metric_row("xgboost_raw", "test", labels_test, xgb_test, 10), _metric_row("ft_transformer_raw", "test", labels_test, ft_test, 10), _metric_row("validation_selected_ensemble", "test", labels_test, ensemble_test, 10),
    ]
    disagreement_rows, complementarity_rows = _disagreement_rows(labels_test, xgb_test, ft_test)
    routing = routing_analysis(labels_test, ensemble_test, binary_disagreement(xgb_test, ft_test), tuple(preflight.configuration["routing"]["referral_budgets"]))
    fn_rows = _fn_overlap(labels_test, xgb_test, ft_test, ensemble_test)
    test_table.to_parquet(paths.test_predictions_parquet, index=False)
    comparison.to_csv(paths.model_comparison_csv, index=False); pd.DataFrame(calibration_rows).to_csv(paths.calibration_csv, index=False); pd.DataFrame(disagreement_rows).to_csv(paths.disagreement_csv, index=False); pd.DataFrame(complementarity_rows).to_csv(paths.complementarity_csv, index=False); routing.to_csv(paths.routing_csv, index=False); pd.DataFrame(fn_rows).to_csv(paths.fn_overlap_csv, index=False)
    _save_figures(paths, comparison, routing, pd.DataFrame(complementarity_rows), labels=labels_test, probabilities={"XGBoost raw": xgb_test, "FT-Transformer raw": ft_test, "Selected ensemble": ensemble_test})
    metadata = {"experiment": EXPERIMENT_NAME, "run_id": RUN_ID, "code_commit_sha": preflight.code_commit_sha, "dataset_sha256": EXPECTED_DATASET_SHA256, "protocol_g_manifest_sha256": EXPECTED_SPLIT_MANIFEST_SHA256, "split": preflight.split_summary, "base_models": {"xgboost_configuration": model_configurations(42)["xgboost"], "ft_transformer_configuration": preflight.ft_configuration["models"]["ft_transformer"], "ft_training_configuration": preflight.ft_configuration["training"]}, "ft_training": {"parameter_count": base.ft_parameter_count, "best_epoch": base.ft_best_epoch, "best_validation_loss": base.ft_best_validation_loss, "determinism": base.ft_determinism}, "test_evaluation": {"count": 1, "xgb_reproduction_verified": True, "test_not_used_for_selection": True}, "runtime": {"xgb_inference_seconds": xgb_seconds, "ft_inference_seconds": ft_seconds, "ensemble_combination_seconds": ensemble_seconds, "test_rows": len(labels_test), "xgb_samples_per_second": len(labels_test) / xgb_seconds, "ft_samples_per_second": len(labels_test) / ft_seconds, "ensemble_samples_per_second": len(labels_test) / ensemble_seconds if ensemble_seconds else None}, "environment": preflight.environment, "dynamic_scope": "hypothetical routing only; no dynamic values, sandbox execution, CAPE execution, or hybrid model"}
    _write_json(paths.run_metadata_json, metadata)
    paths.run_summary_markdown.write_text("# Selective Static Ensemble Run\n\n- Protocol G saved split; 38 G-drop3constant features.\n- Validation-only lock persisted before one test evaluation.\n- Referred rows are abstained, not corrected.\n- No live dynamic/CAPE execution occurred.\n", encoding="utf-8")
    paths.analysis_markdown.write_text(_analysis_markdown(preflight, selected, comparison, pd.DataFrame(disagreement_rows), routing), encoding="utf-8")
    return {"paths": paths, "selected": selected, "comparison": comparison, "routing": routing, "metadata": metadata}
