"""Paper-aligned XGBoost ten-fold cross-validation infrastructure.

The primary method deliberately follows the paper's random row-level
description with ``KFold(shuffle=True, random_state=42)``. It is separate from
both Protocol P's holdout and Protocol G's feature-vector-disjoint evaluation.
The project seed is recorded as a reproducibility choice, not as a paper seed.
"""

from __future__ import annotations

import json
import statistics
import traceback
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Sequence

import numpy as np
import pandas as pd
import yaml
from sklearn.model_selection import KFold

from malpdf.data.protocol_p import P_ALL41, P_DROP3CONSTANT, TARGET_COLUMN, protocol_p_feature_columns, protocol_p_feature_view
from malpdf.data.rit_pdfmal import load_rit_pdfmal, sha256_file
from malpdf.data.rit_pdfmal_paper_alignment import PAPER_XGB_10_FOLD_CV_TABLE6
from malpdf.data.rit_pdfmal_split import build_deterministic_sample_ids
from malpdf.evaluation.binary import evaluate_binary_predictions, fit_predict_and_measure
from malpdf.experiments.protocol_p import collect_environment_metadata, repository_git_state
from malpdf.models.classical import create_model, model_configurations
from malpdf.reproducibility import set_random_seed

EXPERIMENT_NAME = "xgb_cv10"
VERIFIED_DATASET_SHA256 = "2f270ab31fbfe8821fd7f54608cb1aa694a0a8d0bbf2ca000942a68213ef8623"
EXPECTED_DATASET_ROWS = 24_337
CV_SPLIT_SEED = 42
MODEL_RANDOM_STATE = 42
N_SPLITS = 10
CV_ALL41 = "CV-all41"
CV_DROP3CONSTANT = "CV-drop3constant"
EXPECTED_FIT_COUNT = N_SPLITS * 2
CV_VARIANT_TO_PROTOCOL_P_VARIANT = {
    CV_ALL41: P_ALL41.name,
    CV_DROP3CONSTANT: P_DROP3CONSTANT.name,
}
METRIC_NAMES = (
    "accuracy", "precision_malicious", "recall_malicious", "f1_malicious",
    "precision_macro", "recall_macro", "f1_macro", "roc_auc", "pr_auc", "mcc",
)
RUNTIME_NAMES = (
    "training_seconds", "test_inference_total_seconds", "test_inference_milliseconds_per_sample",
)
PAPER_TABLE6_MAPPING = {
    "accuracy": "accuracy",
    "precision_macro": "precision",
    "recall_macro": "recall",
    "f1_macro": "f1",
}


class XGBCV10Error(RuntimeError):
    """Raised when the frozen CV design or its provenance is unsafe to use."""


@dataclass(frozen=True)
class XGBCV10Paths:
    """Immutable tracked-report and ignored-artifact paths for one CV run."""

    run_id: str
    reports_directory: Path
    artifact_directory: Path
    fold_assignments_csv: Path
    all41_fold_metrics_csv: Path
    drop3_fold_metrics_csv: Path
    aggregate_metrics_csv: Path
    paper_comparison_csv: Path
    oof_all41_csv: Path
    oof_drop3_csv: Path
    metrics_json: Path
    environment_json: Path
    experiment_config_json: Path
    run_summary_markdown: Path


@dataclass(frozen=True)
class XGBCV10Preflight:
    """Validated full-data inputs and deterministic fold assignments."""

    repository_root: Path
    dataset_path: Path
    dataset_sha256: str
    frame: pd.DataFrame
    assignments: pd.DataFrame
    fold_validation: dict[str, Any]
    environment: dict[str, Any]
    benchmark_code_commit: str
    config: dict[str, Any]
    paths: XGBCV10Paths


def _timestamp_utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _safe_run_id(run_id: str) -> str:
    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_."
    if not run_id or any(character not in allowed for character in run_id):
        raise ValueError("run_id must be non-empty and contain only letters, numbers, '-', '_', or '.'")
    return run_id


def xgb_cv10_paths(repository_root: str | Path, run_id: str = "seed42") -> XGBCV10Paths:
    """Return paths isolated from all completed Protocol P/G/multi-seed outputs."""
    root = Path(repository_root).resolve()
    safe_id = _safe_run_id(run_id)
    reports = root / "reports" / "experiments" / EXPERIMENT_NAME / safe_id
    artifacts = root / "artifacts" / EXPERIMENT_NAME / safe_id
    return XGBCV10Paths(
        run_id=safe_id,
        reports_directory=reports,
        artifact_directory=artifacts,
        fold_assignments_csv=reports / "fold_assignments.csv",
        all41_fold_metrics_csv=reports / "cv_all41_fold_metrics.csv",
        drop3_fold_metrics_csv=reports / "cv_drop3constant_fold_metrics.csv",
        aggregate_metrics_csv=reports / "aggregate_metrics.csv",
        paper_comparison_csv=reports / "paper_comparison.csv",
        oof_all41_csv=reports / "oof_all41.csv",
        oof_drop3_csv=reports / "oof_drop3constant.csv",
        metrics_json=reports / "metrics.json",
        environment_json=reports / "environment.json",
        experiment_config_json=reports / "experiment_config.json",
        run_summary_markdown=reports / "run_summary.md",
    )


def validate_historical_output_protection(paths: XGBCV10Paths) -> dict[str, Any]:
    """Prove the dedicated CV path cannot target historical protocol outputs."""
    report_parts = {part.casefold() for part in paths.reports_directory.parts}
    artifact_parts = {part.casefold() for part in paths.artifact_directory.parts}
    protected_names = {"protocol_p", "protocol_g", "multiseed"}
    is_valid = (
        EXPERIMENT_NAME in report_parts
        and EXPERIMENT_NAME in artifact_parts
        and not report_parts.intersection(protected_names)
        and not artifact_parts.intersection(protected_names)
    )
    if not is_valid:
        raise XGBCV10Error("CV output path could overlap a protected historical experiment")
    return {
        "is_valid": True,
        "reports_directory": str(paths.reports_directory),
        "artifact_directory": str(paths.artifact_directory),
        "protected_historical_experiments": sorted(protected_names),
    }


def load_xgb_cv10_configuration(path: str | Path) -> dict[str, Any]:
    """Load the committed fixed CV design without accepting mutable defaults."""
    config_path = Path(path)
    try:
        config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as error:
        raise XGBCV10Error(f"Invalid XGBoost CV configuration: {config_path}") from error
    if not isinstance(config, dict):
        raise XGBCV10Error("XGBoost CV configuration must be a mapping")
    validate_xgb_cv10_configuration(config)
    return config


def validate_xgb_cv10_configuration(config: dict[str, Any]) -> None:
    """Lock the primary paper-aligned method against accidental substitutions."""
    dataset = config.get("dataset")
    cv = config.get("cross_validation")
    model = config.get("model")
    if config.get("experiment") != EXPERIMENT_NAME:
        raise XGBCV10Error(f"Configuration experiment must be {EXPERIMENT_NAME}")
    if not isinstance(dataset, dict) or dataset.get("expected_sha256") != VERIFIED_DATASET_SHA256:
        raise XGBCV10Error("Configuration must contain the verified dataset SHA-256")
    if dataset.get("expected_row_count") != EXPECTED_DATASET_ROWS:
        raise XGBCV10Error(f"Configuration must require {EXPECTED_DATASET_ROWS} dataset rows")
    if config.get("target_column") != TARGET_COLUMN:
        raise XGBCV10Error(f"Configuration target column must be {TARGET_COLUMN!r}")
    expected_cv = {
        "splitter": "sklearn.model_selection.KFold",
        "n_splits": N_SPLITS,
        "shuffle": True,
        "cv_split_seed": CV_SPLIT_SEED,
    }
    if not isinstance(cv, dict) or any(cv.get(key) != value for key, value in expected_cv.items()):
        raise XGBCV10Error("Primary CV must be KFold(n_splits=10, shuffle=True, random_state=42)")
    if not isinstance(model, dict) or model.get("name") != "xgboost" or model.get("model_random_state") != MODEL_RANDOM_STATE:
        raise XGBCV10Error("XGBoost model_random_state must remain fixed at 42")
    if tuple(config.get("feature_variants", ())) != (CV_ALL41, CV_DROP3CONSTANT):
        raise XGBCV10Error("Feature variants must be exactly CV-all41 and CV-drop3constant")
    if config.get("expected_future_fit_count") != EXPECTED_FIT_COUNT:
        raise XGBCV10Error(f"Configuration must require exactly {EXPECTED_FIT_COUNT} future XGBoost fits")
    mapping = config.get("paper_reference", {}).get("comparison_mapping")
    if mapping != PAPER_TABLE6_MAPPING:
        raise XGBCV10Error("Paper Table 6 mapping must compare Precision/Recall/F1 with macro metrics")


def primary_cv_splitter() -> KFold:
    """Return the intentionally non-stratified primary KFold splitter."""
    return KFold(n_splits=N_SPLITS, shuffle=True, random_state=CV_SPLIT_SEED)


def cv_feature_columns(frame: pd.DataFrame, feature_variant: str) -> list[str]:
    """Return an unmodified CV feature selection using the existing P definitions."""
    try:
        protocol_variant = CV_VARIANT_TO_PROTOCOL_P_VARIANT[feature_variant]
    except KeyError as error:
        raise XGBCV10Error(f"Unknown CV feature variant: {feature_variant}") from error
    return protocol_p_feature_columns(frame, protocol_variant)


def cv_feature_view(frame: pd.DataFrame, feature_variant: str) -> pd.DataFrame:
    """Select features only; documented semantic values are never transformed."""
    try:
        protocol_variant = CV_VARIANT_TO_PROTOCOL_P_VARIANT[feature_variant]
    except KeyError as error:
        raise XGBCV10Error(f"Unknown CV feature variant: {feature_variant}") from error
    return protocol_p_feature_view(frame, protocol_variant)


def create_cv_fold_assignments(
    frame: pd.DataFrame,
    dataset_sha256: str,
    *,
    cv_split_seed: int = CV_SPLIT_SEED,
) -> tuple[pd.DataFrame, dict[str, Any]]:
    """Create a full-data random KFold assignment with one test fold per row."""
    if cv_split_seed != CV_SPLIT_SEED:
        raise XGBCV10Error("The official primary CV split seed is fixed at 42")
    if TARGET_COLUMN not in frame.columns:
        raise XGBCV10Error(f"Expected target column {TARGET_COLUMN!r} is absent")
    if frame[TARGET_COLUMN].isna().any():
        raise XGBCV10Error("CV target labels cannot be missing")
    splitter = primary_cv_splitter()
    test_folds = np.full(len(frame), -1, dtype=int)
    for fold_number, (_, test_indices) in enumerate(splitter.split(frame), start=1):
        if np.any(test_folds[test_indices] != -1):
            raise XGBCV10Error("A row was assigned to multiple test folds")
        test_folds[test_indices] = fold_number
    if np.any(test_folds == -1):
        raise XGBCV10Error("At least one source row was not assigned to a test fold")
    assignments = pd.DataFrame(
        {
            "sample_id": build_deterministic_sample_ids(frame).astype(str).to_numpy(copy=False),
            "fold": test_folds,
            TARGET_COLUMN: frame[TARGET_COLUMN].to_numpy(copy=False),
            "cv_split_seed": cv_split_seed,
            "dataset_sha256": dataset_sha256,
        }
    )
    validation = validate_cv_fold_assignments(frame, assignments, dataset_sha256=dataset_sha256)
    return assignments, validation


def validate_cv_fold_assignments(
    frame: pd.DataFrame,
    assignments: pd.DataFrame,
    *,
    dataset_sha256: str | None = None,
) -> dict[str, Any]:
    """Verify every row is held out exactly once and every fold is train/test-disjoint."""
    required = {"sample_id", "fold", TARGET_COLUMN, "cv_split_seed", "dataset_sha256"}
    missing = required.difference(assignments.columns)
    if missing:
        raise XGBCV10Error(f"Fold assignments are missing columns: {sorted(missing)}")
    if len(assignments) != len(frame) or not assignments["sample_id"].is_unique:
        raise XGBCV10Error("Fold assignments must contain one unique sample ID for every source row")
    if set(assignments["fold"]) != set(range(1, N_SPLITS + 1)):
        raise XGBCV10Error("Fold assignments must contain exactly folds 1 through 10")
    if set(assignments["cv_split_seed"].astype(int)) != {CV_SPLIT_SEED}:
        raise XGBCV10Error("Fold assignments must record cv_split_seed=42")
    if dataset_sha256 is not None and set(assignments["dataset_sha256"].astype(str)) != {dataset_sha256}:
        raise XGBCV10Error("Fold-assignment dataset SHA-256 does not match the loaded dataset")

    source = pd.DataFrame(
        {
            "sample_id": build_deterministic_sample_ids(frame).astype(str).to_numpy(copy=False),
            "source_label": frame[TARGET_COLUMN].to_numpy(copy=False),
        }
    )
    assigned = assignments.loc[:, ["sample_id", "fold", TARGET_COLUMN]].copy()
    assigned["sample_id"] = assigned["sample_id"].astype(str)
    merged = source.merge(assigned, on="sample_id", how="outer", validate="one_to_one", indicator=True)
    labels_preserved = bool(
        (merged["_merge"] == "both").all()
        and (merged["source_label"] == merged[TARGET_COLUMN]).all()
    )
    if not labels_preserved:
        raise XGBCV10Error("Fold assignments do not preserve source sample IDs and labels")

    fold_statistics: list[dict[str, Any]] = []
    all_ids = set(assignments["sample_id"].astype(str))
    for fold_number in range(1, N_SPLITS + 1):
        test_rows = assignments.loc[assignments["fold"] == fold_number]
        test_ids = set(test_rows["sample_id"].astype(str))
        train_ids = all_ids.difference(test_ids)
        test_has_both_classes = set(test_rows[TARGET_COLUMN]) == {0, 1}
        if not test_has_both_classes:
            raise XGBCV10Error(f"Fold {fold_number} lacks a required target class")
        fold_statistics.append(
            {
                "fold": fold_number,
                "train_row_count": int(len(train_ids)),
                "test_row_count": int(len(test_ids)),
                "train_test_disjoint": len(train_ids.intersection(test_ids)) == 0,
                "benign_test_count": int((test_rows[TARGET_COLUMN] == 0).sum()),
                "malicious_test_count": int((test_rows[TARGET_COLUMN] == 1).sum()),
                "benign_train_count": int((assignments[TARGET_COLUMN] == 0).sum() - (test_rows[TARGET_COLUMN] == 0).sum()),
                "malicious_train_count": int((assignments[TARGET_COLUMN] == 1).sum() - (test_rows[TARGET_COLUMN] == 1).sum()),
            }
        )
    if not all(item["train_test_disjoint"] for item in fold_statistics):
        raise XGBCV10Error("At least one fold has overlapping train/test IDs")
    return {
        "full_dataset_row_count": int(len(frame)),
        "n_splits": N_SPLITS,
        "splitter": "sklearn.model_selection.KFold",
        "shuffle": True,
        "cv_split_seed": CV_SPLIT_SEED,
        "all_rows_used_as_test_exactly_once": True,
        "union_of_test_folds_equals_full_dataset": True,
        "target_labels_preserved": True,
        "expected_future_fit_count": EXPECTED_FIT_COUNT,
        "fold_statistics": fold_statistics,
    }


def frames_for_fold(frame: pd.DataFrame, assignments: pd.DataFrame, fold_number: int) -> tuple[pd.DataFrame, pd.DataFrame, pd.Series]:
    """Partition by deterministic sample IDs, never by an input DataFrame index."""
    if fold_number not in range(1, N_SPLITS + 1):
        raise XGBCV10Error("Fold number must be in 1..10")
    source_ids = build_deterministic_sample_ids(frame).astype(str)
    test_ids = set(assignments.loc[assignments["fold"] == fold_number, "sample_id"].astype(str))
    test_mask = source_ids.isin(test_ids)
    train_mask = ~test_mask
    if bool((train_mask & test_mask).any()) or int(test_mask.sum() + train_mask.sum()) != len(frame):
        raise XGBCV10Error("CV fold does not partition the source frame exactly")
    return frame.loc[train_mask].copy(), frame.loc[test_mask].copy(), source_ids.loc[test_mask].reset_index(drop=True)


def _create_output_directory(paths: XGBCV10Paths) -> None:
    if paths.reports_directory.exists() or paths.artifact_directory.exists():
        raise FileExistsError(f"CV run already exists; refusing to overwrite: {paths.run_id}")
    paths.reports_directory.mkdir(parents=True, exist_ok=False)


def _metric_counts(metrics: dict[str, Any]) -> dict[str, int]:
    matrix = metrics["confusion_matrix"]
    return {"tn": int(matrix[0][0]), "fp": int(matrix[0][1]), "fn": int(matrix[1][0]), "tp": int(matrix[1][1])}


def _fold_record(
    *,
    preflight: XGBCV10Preflight,
    feature_variant: str,
    fold_number: int,
    fold_statistics: dict[str, Any],
) -> dict[str, Any]:
    configuration = model_configurations(MODEL_RANDOM_STATE)["xgboost"]
    return {
        "experiment": EXPERIMENT_NAME,
        "status": "pending",
        "timestamp_utc": _timestamp_utc(),
        "feature_variant": feature_variant,
        "feature_count": len(cv_feature_columns(preflight.frame, feature_variant)),
        "fold": fold_number,
        "dataset_filename": preflight.dataset_path.name,
        "dataset_sha256": preflight.dataset_sha256,
        "cv_split_seed": CV_SPLIT_SEED,
        "model_random_state": MODEL_RANDOM_STATE,
        "fold_statistics": fold_statistics,
        "model_configuration": configuration,
        "preprocessing_configuration": configuration["preprocessing"],
        "metric_semantics": {
            "positive_label": 1,
            "paper_table6_mapping": PAPER_TABLE6_MAPPING,
            "note": "Paper Table 6 averaging is mapped from established project metric-semantics evidence; Table 6 does not independently state it.",
        },
        "environment": preflight.environment,
        "benchmark_generating_code_commit": preflight.benchmark_code_commit,
        "metrics": None,
        "confusion_counts": None,
        "runtime": None,
        "error": None,
    }


def cv_fold_record_schema_is_valid(record: dict[str, Any]) -> bool:
    """Check one persisted fold record has complete explicit-metric provenance."""
    required = {
        "experiment", "status", "feature_variant", "feature_count", "fold", "dataset_sha256",
        "cv_split_seed", "model_random_state", "fold_statistics", "model_configuration",
        "preprocessing_configuration", "metric_semantics", "environment", "benchmark_generating_code_commit",
        "metrics", "confusion_counts", "runtime", "error",
    }
    if not required.issubset(record) or record.get("experiment") != EXPERIMENT_NAME:
        return False
    if record.get("cv_split_seed") != CV_SPLIT_SEED or record.get("model_random_state") != MODEL_RANDOM_STATE:
        return False
    if record.get("status") == "failed":
        return isinstance(record.get("error"), dict)
    if record.get("status") != "completed" or record.get("error") is not None:
        return False
    return (
        isinstance(record.get("metrics"), dict)
        and set(METRIC_NAMES).issubset(record["metrics"])
        and isinstance(record.get("confusion_counts"), dict)
        and isinstance(record.get("runtime"), dict)
    )


def aggregate_cv_fold_metrics(records: Sequence[dict[str, Any]]) -> pd.DataFrame:
    """Aggregate completed fold metrics with sample standard deviation (ddof=1)."""
    rows: list[dict[str, Any]] = []
    for variant in (CV_ALL41, CV_DROP3CONSTANT):
        selected = [record for record in records if record["feature_variant"] == variant and record["status"] == "completed"]
        for metric in (*METRIC_NAMES, *RUNTIME_NAMES):
            values = [
                float(record["metrics"].get(metric) if metric in METRIC_NAMES else record["runtime"].get(metric))
                for record in selected
                if (record["metrics"].get(metric) if metric in METRIC_NAMES else record["runtime"].get(metric)) is not None
            ]
            rows.append(
                {
                    "feature_variant": variant,
                    "metric": metric,
                    "n": len(values),
                    "mean": None if not values else statistics.fmean(values),
                    "sample_standard_deviation": None if len(values) < 2 else statistics.stdev(values),
                    "median": None if not values else statistics.median(values),
                    "minimum": None if not values else min(values),
                    "maximum": None if not values else max(values),
                }
            )
    return pd.DataFrame(rows)


def build_table6_paper_comparison(aggregate_metrics: pd.DataFrame) -> pd.DataFrame:
    """Compare Table 6 means/stds with local macro-aligned aggregate values."""
    rows: list[dict[str, Any]] = []
    for variant in (CV_ALL41, CV_DROP3CONSTANT):
        for local_metric, paper_metric in PAPER_TABLE6_MAPPING.items():
            matching = aggregate_metrics.loc[
                (aggregate_metrics["feature_variant"] == variant)
                & (aggregate_metrics["metric"] == local_metric)
            ]
            if len(matching) != 1:
                raise XGBCV10Error(f"Missing aggregate metric {local_metric} for {variant}")
            local = matching.iloc[0]
            paper_mean = float(PAPER_XGB_10_FOLD_CV_TABLE6["mean"][paper_metric])
            paper_std = float(PAPER_XGB_10_FOLD_CV_TABLE6["standard_deviation"][paper_metric])
            local_mean = local["mean"]
            local_std = local["sample_standard_deviation"]
            rows.append(
                {
                    "feature_variant": variant,
                    "metric": local_metric,
                    "paper_metric": paper_metric,
                    "paper_mean": paper_mean,
                    "local_mean": local_mean,
                    "mean_delta": None if pd.isna(local_mean) else float(local_mean) - paper_mean,
                    "absolute_mean_delta": None if pd.isna(local_mean) else abs(float(local_mean) - paper_mean),
                    "paper_std": paper_std,
                    "local_sample_std": local_std,
                    "std_delta": None if pd.isna(local_std) else float(local_std) - paper_std,
                    "comparison_note": "Paper Precision/Recall/F1 are mapped to local macro metrics using the project's metric-semantics correction; Table 6 does not independently specify averaging.",
                }
            )
    return pd.DataFrame(rows)


def cv_oof_schema_is_valid(frame: pd.DataFrame) -> bool:
    """Validate a lightweight OOF table has no raw features or PDF content."""
    required = {"sample_id", "fold", TARGET_COLUMN, "predicted_label", "malicious_score", "score_source", "feature_variant"}
    return required.issubset(frame.columns) and frame["sample_id"].is_unique and frame["fold"].isin(range(1, N_SPLITS + 1)).all()


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def _summary_frame(records: Sequence[dict[str, Any]], feature_variant: str) -> pd.DataFrame:
    rows: list[dict[str, Any]] = []
    for record in records:
        if record["feature_variant"] != feature_variant:
            continue
        metrics = record["metrics"] or {}
        runtime = record["runtime"] or {}
        rows.append(
            {
                "fold": record["fold"], "status": record["status"], "feature_variant": feature_variant,
                "feature_count": record["feature_count"], **record["fold_statistics"],
                **{metric: metrics.get(metric) for metric in METRIC_NAMES},
                **(record["confusion_counts"] or {"tn": None, "fp": None, "fn": None, "tp": None}),
                **{metric: runtime.get(metric) for metric in RUNTIME_NAMES},
                "score_source": metrics.get("score_source"),
                "error_type": None if record["error"] is None else record["error"]["type"],
                "error_message": None if record["error"] is None else record["error"]["message"],
            }
        )
    return pd.DataFrame(rows)


def _write_outputs(
    preflight: XGBCV10Preflight,
    records: Sequence[dict[str, Any]],
    oof_records: dict[str, list[dict[str, Any]]],
) -> None:
    paths = preflight.paths
    aggregate = aggregate_cv_fold_metrics(records)
    comparison = build_table6_paper_comparison(aggregate)
    _write_json(paths.environment_json, preflight.environment)
    _write_json(paths.experiment_config_json, {
        "experiment": EXPERIMENT_NAME,
        "dataset": {"filename": preflight.dataset_path.name, "sha256": preflight.dataset_sha256, "row_count": len(preflight.frame)},
        "cross_validation": preflight.config["cross_validation"],
        "expected_future_fit_count": EXPECTED_FIT_COUNT,
        "model": {"name": "xgboost", "model_random_state": MODEL_RANDOM_STATE, "configuration": model_configurations(MODEL_RANDOM_STATE)["xgboost"]},
        "feature_variants": [CV_ALL41, CV_DROP3CONSTANT],
        "paper_table6_reference": PAPER_XGB_10_FOLD_CV_TABLE6,
        "paper_comparison_mapping": PAPER_TABLE6_MAPPING,
        "benchmark_generating_code_commit": preflight.benchmark_code_commit,
        "git_working_tree_at_start": preflight.environment["git_working_tree"],
        "scope": "Paper-aligned reproduction attempt, not exact reproduction; no tuning or model-selection steps are included.",
    })
    preflight.assignments.to_csv(paths.fold_assignments_csv, index=False)
    _summary_frame(records, CV_ALL41).to_csv(paths.all41_fold_metrics_csv, index=False)
    _summary_frame(records, CV_DROP3CONSTANT).to_csv(paths.drop3_fold_metrics_csv, index=False)
    aggregate.to_csv(paths.aggregate_metrics_csv, index=False)
    comparison.to_csv(paths.paper_comparison_csv, index=False)
    for variant, output in ((CV_ALL41, paths.oof_all41_csv), (CV_DROP3CONSTANT, paths.oof_drop3_csv)):
        oof = pd.DataFrame(oof_records[variant])
        if len(oof) and not cv_oof_schema_is_valid(oof):
            raise XGBCV10Error(f"OOF schema is invalid for {variant}")
        oof.to_csv(output, index=False)
    _write_json(paths.metrics_json, {"experiment": EXPERIMENT_NAME, "fold_validation": preflight.fold_validation, "records": list(records)})
    completed = sum(record["status"] == "completed" for record in records)
    paths.run_summary_markdown.write_text(
        "\n".join([
            "# XGBoost 10-fold cross-validation run", "",
            f"- Run ID: `{paths.run_id}`.",
            f"- Benchmark-generating code commit: `{preflight.benchmark_code_commit}`.",
            f"- Dataset SHA-256: `{preflight.dataset_sha256}`.",
            "- Primary splitter: KFold(n_splits=10, shuffle=True, random_state=42); seed 42 is a project choice, not a paper seed.",
            "- XGBoost model_random_state is fixed at 42 for every fold.",
            f"- Completed fold records: {completed}; failed records: {len(records) - completed}.",
            "- Both CV-all41 and CV-drop3constant are included. No tuning or cross-protocol split reuse is performed.",
            "",
        ]), encoding="utf-8"
    )


def execute_xgb_cv10_from_preflight(
    preflight: XGBCV10Preflight,
    *,
    model_factory: Callable[[str, int], Any] = create_model,
) -> tuple[XGBCV10Paths, list[dict[str, Any]]]:
    """Run the fixed twenty-fit matrix after a clean committed preflight.

    This is intentionally called only by explicit future ``--execute`` use (or
    synthetic unit tests). Fitted fold models are not retained.
    """
    _create_output_directory(preflight.paths)
    records: list[dict[str, Any]] = []
    oof_records: dict[str, list[dict[str, Any]]] = {CV_ALL41: [], CV_DROP3CONSTANT: []}
    failures: list[str] = []
    fold_statistics = {item["fold"]: item for item in preflight.fold_validation["fold_statistics"]}
    for variant in (CV_ALL41, CV_DROP3CONSTANT):
        for fold_number in range(1, N_SPLITS + 1):
            record = _fold_record(preflight=preflight, feature_variant=variant, fold_number=fold_number, fold_statistics=fold_statistics[fold_number])
            try:
                train_frame, test_frame, test_ids = frames_for_fold(preflight.frame, preflight.assignments, fold_number)
                set_random_seed(MODEL_RANDOM_STATE)
                estimator = model_factory("xgboost", MODEL_RANDOM_STATE)
                predictions, scores, score_source, runtime = fit_predict_and_measure(
                    estimator,
                    cv_feature_view(train_frame, variant),
                    train_frame[TARGET_COLUMN],
                    cv_feature_view(test_frame, variant),
                )
                metrics = evaluate_binary_predictions(test_frame[TARGET_COLUMN], predictions, scores)
                metrics["score_source"] = score_source
                counts = _metric_counts(metrics)
                record.update({"status": "completed", "metrics": metrics, "confusion_counts": counts, "runtime": runtime})
                score_values = np.full(len(test_frame), np.nan) if scores is None else np.asarray(scores, dtype=float)
                oof_records[variant].extend(
                    {
                        "sample_id": sample_id,
                        "fold": fold_number,
                        TARGET_COLUMN: int(label),
                        "predicted_label": int(prediction),
                        "malicious_score": None if np.isnan(score) else float(score),
                        "score_source": score_source,
                        "feature_variant": variant,
                    }
                    for sample_id, label, prediction, score in zip(test_ids, test_frame[TARGET_COLUMN], predictions, score_values, strict=True)
                )
            except Exception as error:
                record.update({"status": "failed", "error": {"type": type(error).__name__, "message": str(error), "traceback": traceback.format_exc()}})
                failures.append(f"{variant}:fold{fold_number}")
            if not cv_fold_record_schema_is_valid(record):
                raise XGBCV10Error(f"Invalid CV fold record: {variant} fold {fold_number}")
            records.append(record)
    _write_outputs(preflight, records, oof_records)
    if failures:
        raise XGBCV10Error("CV has failed folds; partial reports preserve evidence: " + ", ".join(failures))
    return preflight.paths, records


def preflight_xgb_cv10(
    repository_root: str | Path,
    dataset_path: str | Path,
    config: dict[str, Any],
    *,
    run_id: str = "seed42",
    require_clean_git: bool = True,
) -> XGBCV10Preflight:
    """Verify the full official dataset and output safety without fitting a model."""
    validate_xgb_cv10_configuration(config)
    root = Path(repository_root).resolve()
    data_path = Path(dataset_path).resolve()
    git_state = repository_git_state(root)
    if require_clean_git and git_state.get("status") != "clean":
        raise XGBCV10Error(f"Refusing CV execution because repository is not clean: {git_state.get('status')}")
    paths = xgb_cv10_paths(root, run_id)
    output_protection = validate_historical_output_protection(paths)
    if paths.reports_directory.exists() or paths.artifact_directory.exists():
        raise FileExistsError(f"CV output path is unavailable; refusing to overwrite: {paths.run_id}")
    frame = load_rit_pdfmal(data_path)
    dataset_sha256 = sha256_file(data_path)
    if dataset_sha256 != VERIFIED_DATASET_SHA256:
        raise XGBCV10Error(f"Dataset SHA-256 does not match verified RIT-PDFMal data: {dataset_sha256}")
    if len(frame) != EXPECTED_DATASET_ROWS:
        raise XGBCV10Error(f"CV must use the full {EXPECTED_DATASET_ROWS}-row dataset, found {len(frame)}")
    if TARGET_COLUMN not in frame.columns:
        raise XGBCV10Error(f"Expected target column {TARGET_COLUMN!r} is absent")
    if len(cv_feature_columns(frame, CV_ALL41)) != 41 or len(cv_feature_columns(frame, CV_DROP3CONSTANT)) != 38:
        raise XGBCV10Error("CV feature variants do not have the required 41/38 feature counts")
    configuration = model_configurations(MODEL_RANDOM_STATE).get("xgboost")
    if configuration is None or configuration["parameters"].get("random_state") != MODEL_RANDOM_STATE:
        raise XGBCV10Error("Fixed XGBoost configuration is unavailable")
    assignments, fold_validation = create_cv_fold_assignments(frame, dataset_sha256)
    fold_validation["historical_experiment_outputs_protected"] = output_protection
    environment = collect_environment_metadata(data_path, root)
    if require_clean_git and environment["git_working_tree"].get("status") != "clean":
        raise XGBCV10Error("Repository changed during CV preflight; refusing execution")
    if require_clean_git and (environment["git_commit_sha"] == "unavailable" or len(str(environment["git_commit_sha"])) != 40):
        raise XGBCV10Error("Unable to record a full clean benchmark-generating Git commit")
    return XGBCV10Preflight(
        repository_root=root,
        dataset_path=data_path,
        dataset_sha256=dataset_sha256,
        frame=frame,
        assignments=assignments,
        fold_validation=fold_validation,
        environment=environment,
        benchmark_code_commit=str(environment["git_commit_sha"]),
        config=config,
        paths=paths,
    )


def run_xgb_cv10(
    repository_root: str | Path,
    dataset_path: str | Path,
    config_path: str | Path,
    *,
    run_id: str = "seed42",
    execute: bool = False,
    require_clean_git: bool = True,
    model_factory: Callable[[str, int], Any] = create_model,
) -> tuple[XGBCV10Preflight, XGBCV10Paths | None, list[dict[str, Any]]]:
    """Run preflight by default; fitting requires explicit future authorization."""
    config = load_xgb_cv10_configuration(config_path)
    preflight = preflight_xgb_cv10(repository_root, dataset_path, config, run_id=run_id, require_clean_git=require_clean_git)
    if not execute:
        return preflight, None, []
    paths, records = execute_xgb_cv10_from_preflight(preflight, model_factory=model_factory)
    return preflight, paths, records
