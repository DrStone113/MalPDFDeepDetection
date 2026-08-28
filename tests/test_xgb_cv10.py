"""Synthetic tests for the frozen paper-aligned XGBoost CV infrastructure."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import numpy as np
import pandas as pd
import pytest
from sklearn.model_selection import KFold

from malpdf.data.protocol_p import P_ALL41, P_DROP3CONSTANT
from malpdf.experiments.xgb_cv10 import (
    CV_ALL41,
    CV_DROP3CONSTANT,
    CV_SPLIT_SEED,
    EXPECTED_FIT_COUNT,
    MODEL_RANDOM_STATE,
    N_SPLITS,
    PAPER_TABLE6_MAPPING,
    XGBCV10Error,
    XGBCV10Preflight,
    aggregate_cv_fold_metrics,
    build_table6_paper_comparison,
    create_cv_fold_assignments,
    cv_feature_columns,
    cv_feature_view,
    cv_fold_record_schema_is_valid,
    cv_oof_schema_is_valid,
    execute_xgb_cv10_from_preflight,
    frames_for_fold,
    load_xgb_cv10_configuration,
    preflight_xgb_cv10,
    primary_cv_splitter,
    validate_xgb_cv10_configuration,
    xgb_cv10_paths,
)
from malpdf.models.classical import model_configurations


class RecordingProbabilityEstimator:
    """Benign synthetic estimator that records only its training feature rows."""

    def __init__(self) -> None:
        self.classes_ = np.array([0, 1])
        self.fit_feature_values: set[int] = set()
        self.fit_row_count = 0

    def fit(self, features, labels):
        self.fit_row_count = len(features)
        self.fit_feature_values = {int(value) for value in features["feature_0"]}
        return self

    def predict_proba(self, features):
        positive = (features["feature_0"].to_numpy() >= 1000).astype(float)
        return np.column_stack([1.0 - positive, positive])

    def predict(self, features):
        return (features["feature_0"].to_numpy() >= 1000).astype(int)


def _synthetic_frame() -> pd.DataFrame:
    feature_names = [
        "contains_text", "images", "pdf_ver", "pages", "Acroform", "Colors", "BaseEncoding",
    ]
    feature_names.extend(f"feature_{number}" for number in range(34))
    rows: list[dict[str, int | float]] = []
    for label in (0, 1):
        for value in range(50):
            row: dict[str, int | float] = {column: value for column in feature_names}
            row.update(
                {
                    "contains_text": (-1, 0, 1)[value % 3],
                    "images": -1 if value % 4 == 0 else value,
                    "pdf_ver": 3.0 if value % 7 == 0 else 1.7,
                    "pages": 0 if value % 5 == 0 else value + 1,
                    "Acroform": 0,
                    "Colors": 0,
                    "BaseEncoding": 0,
                    "feature_0": label * 1000 + value,
                    "Label": label,
                }
            )
            rows.append(row)
    frame = pd.DataFrame(rows)
    frame.index = pd.RangeIndex(start=500, stop=600)
    assert len(frame) == 100
    assert len(frame.columns) == 42
    return frame


def _config() -> dict:
    root = Path(__file__).resolve().parents[1]
    return load_xgb_cv10_configuration(root / "configs" / "xgb_cv10.yaml")


def _preflight_for_synthetic_execution(tmp_path) -> XGBCV10Preflight:
    frame = _synthetic_frame()
    assignments, validation = create_cv_fold_assignments(frame, "fixture-sha")
    return XGBCV10Preflight(
        repository_root=tmp_path,
        dataset_path=tmp_path / "data" / "raw" / "fixture.csv",
        dataset_sha256="fixture-sha",
        frame=frame,
        assignments=assignments,
        fold_validation=validation,
        environment={
            "python_version": "3.11-test",
            "git_commit_sha": "a" * 40,
            "git_working_tree": {"status": "clean"},
        },
        benchmark_code_commit="a" * 40,
        config=_config(),
        paths=xgb_cv10_paths(tmp_path, "synthetic"),
    )


def test_configuration_locks_kfold_seeds_variants_and_paper_metric_mapping():
    config = _config()
    assert config["cross_validation"]["splitter"] == "sklearn.model_selection.KFold"
    assert config["cross_validation"]["n_splits"] == 10
    assert config["cross_validation"]["shuffle"] is True
    assert config["cross_validation"]["cv_split_seed"] == CV_SPLIT_SEED
    assert config["model"]["model_random_state"] == MODEL_RANDOM_STATE
    assert tuple(config["feature_variants"]) == (CV_ALL41, CV_DROP3CONSTANT)
    assert config["expected_future_fit_count"] == EXPECTED_FIT_COUNT == 20
    assert config["paper_reference"]["comparison_mapping"] == PAPER_TABLE6_MAPPING

    changed = deepcopy(config)
    changed["cross_validation"]["splitter"] = "sklearn.model_selection.StratifiedKFold"
    with pytest.raises(XGBCV10Error, match="KFold"):
        validate_xgb_cv10_configuration(changed)


def test_primary_splitter_is_shuffled_seeded_kfold_not_stratified():
    splitter = primary_cv_splitter()
    assert isinstance(splitter, KFold)
    assert splitter.n_splits == N_SPLITS
    assert splitter.shuffle is True
    assert splitter.random_state == CV_SPLIT_SEED


def test_fold_assignments_are_deterministic_cover_full_dataset_and_preserve_labels():
    frame = _synthetic_frame()
    first, first_validation = create_cv_fold_assignments(frame, "fixture-sha")
    second, second_validation = create_cv_fold_assignments(frame, "fixture-sha")

    pd.testing.assert_frame_equal(first, second)
    assert first["sample_id"].is_unique
    assert set(first["fold"]) == set(range(1, N_SPLITS + 1))
    assert len(first) == len(frame)
    assert first_validation["all_rows_used_as_test_exactly_once"]
    assert first_validation["union_of_test_folds_equals_full_dataset"]
    assert first_validation["target_labels_preserved"]
    assert first_validation["expected_future_fit_count"] == 20
    assert first_validation == second_validation
    assert all(item["test_row_count"] == 10 for item in first_validation["fold_statistics"])
    assert all(item["train_row_count"] == 90 for item in first_validation["fold_statistics"])
    assert all(item["train_test_disjoint"] for item in first_validation["fold_statistics"])
    assert all(item["benign_test_count"] > 0 and item["malicious_test_count"] > 0 for item in first_validation["fold_statistics"])


def test_fold_partition_uses_sample_ids_not_dataframe_index_and_has_no_overlap():
    frame = _synthetic_frame()
    assignments, _ = create_cv_fold_assignments(frame, "fixture-sha")
    for fold in range(1, N_SPLITS + 1):
        train, test, test_ids = frames_for_fold(frame, assignments, fold)
        assert len(train) + len(test) == len(frame)
        assert len(test_ids) == len(test)
        assert set(train["feature_0"]).isdisjoint(set(test["feature_0"]))
        assert set(test_ids) == set(assignments.loc[assignments["fold"] == fold, "sample_id"])


def test_cv_variants_have_exact_feature_sets_and_preserve_special_semantic_values():
    frame = _synthetic_frame()
    all41 = cv_feature_columns(frame, CV_ALL41)
    drop3 = cv_feature_columns(frame, CV_DROP3CONSTANT)
    assert len(all41) == 41
    assert len(drop3) == 38
    assert all41 == [column for column in frame.columns if column != "Label"]
    assert set(all41).difference(drop3) == {"Acroform", "Colors", "BaseEncoding"}
    assert P_ALL41.name == "P-all41"
    assert P_DROP3CONSTANT.name == "P-drop3constant"
    selected = cv_feature_view(frame, CV_DROP3CONSTANT)
    for column in ("contains_text", "images", "pages", "pdf_ver"):
        assert selected[column].tolist() == frame[column].tolist()


def test_xgboost_configuration_uses_the_existing_fixed_model_seed_and_no_scaling():
    configuration = model_configurations(MODEL_RANDOM_STATE)["xgboost"]
    assert configuration["parameters"]["random_state"] == MODEL_RANDOM_STATE
    assert configuration["preprocessing"]["name"] is None
    assert configuration["parameters"]["missing"] == "NaN"


def test_completed_fold_schema_requires_explicit_malicious_and_macro_metrics(tmp_path):
    preflight = _preflight_for_synthetic_execution(tmp_path)
    _, records = execute_xgb_cv10_from_preflight(
        preflight, model_factory=lambda name, seed: RecordingProbabilityEstimator()
    )
    assert len(records) == 20
    assert all(cv_fold_record_schema_is_valid(record) for record in records)
    assert all(record["model_random_state"] == 42 for record in records)
    assert all(record["metrics"]["positive_label"] == 1 for record in records)
    assert all(record["metrics"]["score_source"] == "predict_proba" for record in records)
    assert all(record["confusion_counts"]["fp"] == 0 and record["confusion_counts"]["fn"] == 0 for record in records)
    assert all(sum(record["confusion_counts"].values()) == 10 for record in records)


def test_execution_fits_only_each_fold_training_partition_and_persists_lightweight_outputs(tmp_path):
    preflight = _preflight_for_synthetic_execution(tmp_path)
    estimators: list[RecordingProbabilityEstimator] = []

    def factory(name, seed):
        assert name == "xgboost"
        assert seed == MODEL_RANDOM_STATE
        estimator = RecordingProbabilityEstimator()
        estimators.append(estimator)
        return estimator

    paths, records = execute_xgb_cv10_from_preflight(preflight, model_factory=factory)
    assert len(records) == len(estimators) == 20
    assert all(estimator.fit_row_count == 90 for estimator in estimators)
    for fold in range(1, N_SPLITS + 1):
        _, test, _ = frames_for_fold(preflight.frame, preflight.assignments, fold)
        fold_estimators = (estimators[fold - 1], estimators[N_SPLITS + fold - 1])
        assert all(estimator.fit_feature_values.isdisjoint(set(test["feature_0"])) for estimator in fold_estimators)

    assert paths.reports_directory.is_dir()
    assert not paths.artifact_directory.exists()
    for output in (
        paths.fold_assignments_csv, paths.all41_fold_metrics_csv, paths.drop3_fold_metrics_csv,
        paths.aggregate_metrics_csv, paths.paper_comparison_csv, paths.oof_all41_csv,
        paths.oof_drop3_csv, paths.metrics_json, paths.environment_json,
        paths.experiment_config_json, paths.run_summary_markdown,
    ):
        assert output.is_file()
    assert len(pd.read_csv(paths.oof_all41_csv)) == 100
    assert len(pd.read_csv(paths.oof_drop3_csv)) == 100
    assert cv_oof_schema_is_valid(pd.read_csv(paths.oof_all41_csv))
    persisted = json.loads(paths.metrics_json.read_text(encoding="utf-8"))
    assert len(persisted["records"]) == 20


def test_aggregate_uses_ten_fold_sample_standard_deviation_and_table6_uses_macro_mapping():
    records = []
    for variant in (CV_ALL41, CV_DROP3CONSTANT):
        for fold in range(1, 11):
            metrics = {
                "accuracy": fold / 100,
                "precision_malicious": 0.1,
                "recall_malicious": 0.2,
                "f1_malicious": 0.3,
                "precision_macro": fold / 100,
                "recall_macro": fold / 100,
                "f1_macro": fold / 100,
                "roc_auc": 0.8,
                "pr_auc": 0.9,
                "mcc": 0.7,
            }
            records.append(
                {
                    "feature_variant": variant,
                    "status": "completed",
                    "metrics": metrics,
                    "runtime": {
                        "training_seconds": float(fold),
                        "test_inference_total_seconds": float(fold),
                        "test_inference_milliseconds_per_sample": float(fold),
                    },
                }
            )
    aggregate = aggregate_cv_fold_metrics(records)
    accuracy = aggregate.loc[(aggregate["feature_variant"] == CV_ALL41) & (aggregate["metric"] == "accuracy")].iloc[0]
    assert accuracy["n"] == 10
    assert accuracy["mean"] == pytest.approx(0.055)
    assert accuracy["sample_standard_deviation"] == pytest.approx(np.std(np.arange(0.01, 0.11, 0.01), ddof=1))
    comparison = build_table6_paper_comparison(aggregate)
    assert set(comparison["metric"]) == set(PAPER_TABLE6_MAPPING)
    assert set(comparison["paper_metric"]) == set(PAPER_TABLE6_MAPPING.values())
    macro_precision = comparison.loc[(comparison["feature_variant"] == CV_ALL41) & (comparison["metric"] == "precision_macro")].iloc[0]
    assert macro_precision["paper_metric"] == "precision"
    assert macro_precision["paper_mean"] == pytest.approx(0.995663)


def test_cv_outputs_are_immutable_and_isolated_from_historical_protocol_paths(tmp_path):
    historical = tmp_path / "reports" / "experiments"
    (historical / "protocol_p" / "seed42").mkdir(parents=True)
    (historical / "protocol_g" / "seed42").mkdir(parents=True)
    (historical / "multiseed" / "official-seeds42-46").mkdir(parents=True)
    marker = historical / "protocol_g" / "seed42" / "marker.txt"
    marker.write_text("historical", encoding="utf-8")

    preflight = _preflight_for_synthetic_execution(tmp_path)
    execute_xgb_cv10_from_preflight(preflight, model_factory=lambda name, seed: RecordingProbabilityEstimator())
    assert marker.read_text(encoding="utf-8") == "historical"
    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        execute_xgb_cv10_from_preflight(preflight, model_factory=lambda name, seed: RecordingProbabilityEstimator())


def test_preflight_requires_a_clean_git_repository_before_reading_or_fitting(tmp_path):
    with pytest.raises(XGBCV10Error, match="not clean"):
        preflight_xgb_cv10(tmp_path, tmp_path / "missing.csv", _config())
