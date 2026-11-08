import json

import numpy as np
import pandas as pd
import pytest

from malpdf.data.protocol_p import P_ALL41, P_DROP3CONSTANT, create_protocol_p_split
from malpdf.data.rit_pdfmal import load_rit_pdfmal, sha256_file
from malpdf.experiments.protocol_p_benchmark import (
    PAPER_COMPARISON_METRICS,
    PRIMARY_BENCHMARK_MATRIX,
    BenchmarkRunSpec,
    ProtocolPBenchmarkError,
    benchmark_result_schema_is_valid,
    build_paper_comparison,
    run_protocol_p_benchmark,
    split_frame_from_manifest,
)


class RecordingProbabilityEstimator:
    """Small serializable estimator for benign synthetic benchmark fixtures."""

    def __init__(self):
        self.fit_row_count = 0
        self.fit_feature_values: set[int] = set()
        self.classes_ = np.array([0, 1])

    def fit(self, features, labels):
        self.fit_row_count = len(features)
        self.fit_feature_values = {int(value) for value in features["feature_0"]}
        return self

    def predict_proba(self, features):
        positive = (features["feature_0"].to_numpy() >= 1000).astype(float)
        return np.column_stack([1.0 - positive, positive])

    def predict(self, features):
        return (features["feature_0"].to_numpy() >= 1000).astype(int)


def _fake_environment(dataset_path, repository_root):
    return {
        "python_version": "3.11-test",
        "os_platform": "test-platform",
        "cpu_model": "test-cpu",
        "gpu": "unavailable",
        "system_ram_bytes": "unavailable",
        "library_versions": {
            "numpy": "test",
            "pandas": "test",
            "scikit_learn": "test",
            "xgboost": "test",
        },
        "dataset_sha256": sha256_file(dataset_path),
        "git_commit_sha": "test-commit",
    }


def _saved_split_fixture(tmp_path):
    root = tmp_path
    feature_names = ["contains_text", "pages", "pdf_ver", "Acroform", "Colors", "BaseEncoding"]
    feature_names.extend(f"feature_{index}" for index in range(35))
    rows = []
    for label in (0, 1):
        for value in range(20):
            row = {feature: value for feature in feature_names}
            row["contains_text"] = (-1, 0, 1)[value % 3]
            row["pages"] = 0 if value % 5 == 0 else value + 1
            row["pdf_ver"] = 5.0 if value % 7 == 0 else 1.7
            row["Acroform"] = 0
            row["Colors"] = 0
            row["BaseEncoding"] = 0
            row["feature_0"] = label * 1000 + value
            row["Label"] = label
            rows.append(row)
    dataset_path = root / "data" / "raw" / "fixture.csv"
    dataset_path.parent.mkdir(parents=True)
    pd.DataFrame(rows).to_csv(dataset_path, index=False)
    frame = load_rit_pdfmal(dataset_path)
    dataset_sha256 = sha256_file(dataset_path)
    manifest, _ = create_protocol_p_split(frame, dataset_sha256, seed=42)
    manifest_path = (
        root
        / "data"
        / "processed"
        / "protocol_p"
        / "saved-seed42"
        / "protocol_p_split_manifest.csv"
    )
    manifest_path.parent.mkdir(parents=True)
    manifest.to_csv(manifest_path, index=False)
    return root, dataset_path, frame, manifest, manifest_path


def test_primary_matrix_has_exactly_ten_unique_model_variant_runs():
    assert len(PRIMARY_BENCHMARK_MATRIX) == 10
    assert len(set(PRIMARY_BENCHMARK_MATRIX)) == 10
    assert {specification.model_name for specification in PRIMARY_BENCHMARK_MATRIX} == {
        "logistic_regression",
        "random_forest",
        "decision_tree",
        "gaussian_naive_bayes",
        "xgboost",
    }
    assert {specification.feature_variant for specification in PRIMARY_BENCHMARK_MATRIX} == {
        P_ALL41.name,
        P_DROP3CONSTANT.name,
    }


def test_runner_reuses_saved_manifest_and_serializes_metrics_provenance_and_variants(tmp_path, monkeypatch):

    monkeypatch.setattr("malpdf.experiments.protocol_p_benchmark.repository_git_state",
                        lambda root: {"status": "unavailable", "reason": "synthetic fixture"})
    root, dataset_path, frame, manifest, manifest_path = _saved_split_fixture(tmp_path)
    created_estimators = []

    def factory(model_name, seed):
        estimator = RecordingProbabilityEstimator()
        created_estimators.append(estimator)
        return estimator

    specifications = (
        BenchmarkRunSpec("logistic_regression", P_ALL41.name),
        BenchmarkRunSpec("logistic_regression", P_DROP3CONSTANT.name),
    )
    paths, records = run_protocol_p_benchmark(
        root,
        dataset_path,
        seed=42,
        run_id="synthetic-run",
        manifest_path=manifest_path,
        require_clean_git=False,
        specifications=specifications,
        model_factory=factory,
        environment_collector=_fake_environment,
    )

    train_frame, test_frame = split_frame_from_manifest(frame, manifest)
    assert len(records) == 2
    assert {record["feature_count"] for record in records} == {41, 38}
    assert all(record["status"] == "completed" for record in records)
    assert all(benchmark_result_schema_is_valid(record) for record in records)
    assert all(record["split_manifest"] == str(manifest_path.resolve()) for record in records)
    assert all(record["metrics"]["score_source"] == "predict_proba" for record in records)
    assert all(record["confusion_counts"] == {"tn": 5, "fp": 0, "fn": 0, "tp": 5} for record in records)
    assert all(estimator.fit_row_count == len(train_frame) for estimator in created_estimators)
    assert all(
        estimator.fit_feature_values == {int(value) for value in train_frame["feature_0"]}
        for estimator in created_estimators
    )
    assert not any(
        estimator.fit_feature_values.intersection({int(value) for value in test_frame["feature_0"]})
        for estimator in created_estimators
    )

    persisted = json.loads(paths.metrics_json.read_text(encoding="utf-8"))
    assert len(persisted["runs"]) == 2
    assert persisted["runs"][0]["environment"]["git_working_tree"]["status"] == "unavailable"
    assert paths.summary_csv.is_file()
    assert paths.paper_comparison_csv.is_file()
    assert paths.environment_json.is_file()
    assert paths.experiment_config_json.is_file()
    assert paths.split_summary_json.is_file()
    assert paths.run_summary_markdown.is_file()
    assert len(build_paper_comparison(records)) == len(records) * len(PAPER_COMPARISON_METRICS)


def test_runner_output_directories_are_immutable(tmp_path):
    root, dataset_path, _, _, manifest_path = _saved_split_fixture(tmp_path)
    specification = (BenchmarkRunSpec("logistic_regression", P_ALL41.name),)

    run_protocol_p_benchmark(
        root,
        dataset_path,
        run_id="immutable-run",
        manifest_path=manifest_path,
        require_clean_git=False,
        specifications=specification,
        model_factory=lambda model_name, seed: RecordingProbabilityEstimator(),
        environment_collector=_fake_environment,
    )
    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        run_protocol_p_benchmark(
            root,
            dataset_path,
            run_id="immutable-run",
            manifest_path=manifest_path,
            require_clean_git=False,
            specifications=specification,
            model_factory=lambda model_name, seed: RecordingProbabilityEstimator(),
            environment_collector=_fake_environment,
        )


def test_runner_preserves_failed_run_evidence_and_fails_the_benchmark(tmp_path):
    root, dataset_path, _, _, manifest_path = _saved_split_fixture(tmp_path)
    specification = (BenchmarkRunSpec("logistic_regression", P_ALL41.name),)

    def failing_factory(model_name, seed):
        raise RuntimeError("synthetic model failure")

    with pytest.raises(ProtocolPBenchmarkError, match="failed primary runs"):
        run_protocol_p_benchmark(
            root,
            dataset_path,
            run_id="failure-run",
            manifest_path=manifest_path,
            require_clean_git=False,
            specifications=specification,
            model_factory=failing_factory,
            environment_collector=_fake_environment,
        )

    metrics = json.loads(
        (root / "reports" / "experiments" / "protocol_p" / "failure-run" / "metrics.json").read_text(
            encoding="utf-8"
        )
    )
    failed = metrics["runs"][0]
    assert failed["status"] == "failed"
    assert failed["metrics"] is None
    assert failed["error"]["type"] == "RuntimeError"
    assert "synthetic model failure" in failed["error"]["message"]


def test_paper_comparison_uses_verified_values_and_absolute_differences():
    record = {
        "model_name": "logistic_regression",
        "feature_variant": P_ALL41.name,
        "metrics": {
            "accuracy": 0.9,
            "precision": 0.8,
            "recall": 0.7,
            "f1": 0.6,
            "precision_macro": 0.81,
            "recall_macro": 0.71,
            "f1_macro": 0.61,
        },
        "runtime": {"test_inference_milliseconds_per_sample": 0.5},
    }

    comparison = build_paper_comparison([record])

    accuracy = next(row for row in comparison if row["metric"] == "accuracy")
    assert accuracy["paper_model"] == "LR"
    assert accuracy["local_value"] == 0.9
    assert accuracy["paper_value"] == pytest.approx(0.907313)
    assert accuracy["absolute_difference"] == pytest.approx(0.007313)

    precision = next(row for row in comparison if row["metric"] == "precision_macro")
    assert precision["local_value"] == pytest.approx(0.81)
    assert precision["paper_value"] == pytest.approx(0.906484)
