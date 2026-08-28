import json

import numpy as np
import pandas as pd
import pytest

import malpdf.experiments.protocol_g_benchmark as protocol_g_benchmark
from malpdf.data.rit_pdfmal import load_rit_pdfmal, sha256_file
from malpdf.data.rit_pdfmal_split import create_rit_pdfmal_split
from malpdf.experiments.protocol_g_benchmark import (
    EXPECTED_G_SPLIT,
    G_ALL41,
    G_DROP3CONSTANT,
    G_FEATURE_VARIANT_TO_PROTOCOL_P,
    G_COMPARISON_METRICS,
    PRIMARY_G_BENCHMARK_MATRIX,
    ProtocolGBenchmarkError,
    ProtocolGBenchmarkRunSpec,
    build_protocol_p_vs_g_comparison,
    load_saved_protocol_g_split,
    protocol_g_feature_columns,
    protocol_g_feature_view,
    protocol_g_result_schema_is_valid,
    run_protocol_g_benchmark,
    split_frame_from_protocol_g_manifest,
    _verify_expected_g_split,
)
from malpdf.models.classical import model_configurations


class RecordingProbabilityEstimator:
    """Serializable estimator used only with benign synthetic CSV fixtures."""

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


def _synthetic_g_fixture(tmp_path, monkeypatch):
    root = tmp_path
    feature_names = ["contains_text", "pages", "pdf_ver", "Acroform", "Colors", "BaseEncoding"]
    feature_names.extend(f"feature_{index}" for index in range(35))
    rows = []
    for label in (0, 1):
        for value in range(30):
            row = {feature: value for feature in feature_names}
            row["contains_text"] = (-1, 0, 1)[value % 3]
            row["pages"] = 0 if value % 5 == 0 else value + 1
            row["pdf_ver"] = 5.0 if value % 7 == 0 else 1.7
            row["Acroform"] = 0
            row["Colors"] = 0
            row["BaseEncoding"] = 0
            row["feature_0"] = label * 1000 + value
            row["Label"] = label
            rows.extend([row.copy(), row.copy()])
    dataset_path = root / "data" / "raw" / "fixture.csv"
    dataset_path.parent.mkdir(parents=True)
    pd.DataFrame(rows).to_csv(dataset_path, index=False)
    frame = load_rit_pdfmal(dataset_path)
    manifest, split_result = create_rit_pdfmal_split(frame, seed=42)
    manifest_path = root / "data" / "processed" / "rit-pdfmal-2026_split_manifest.csv"
    manifest_path.parent.mkdir(parents=True)
    manifest.to_csv(manifest_path, index=False)
    dataset_sha = sha256_file(dataset_path)
    report_path = root / "reports" / "rit-pdfmal-2026_split_report.json"
    report_path.parent.mkdir(parents=True)
    report_path.write_text(
        json.dumps({"seed": 42, "dataset": {"sha256": dataset_sha}, "split": split_result}),
        encoding="utf-8",
    )
    monkeypatch.setattr(protocol_g_benchmark, "VERIFIED_DATASET_SHA256", dataset_sha)
    return root, dataset_path, frame, manifest, manifest_path, report_path


def _write_protocol_p_summary(root, specifications):
    rows = []
    for specification in specifications:
        rows.append(
            {
                "model_name": specification.model_name,
                "feature_variant": G_FEATURE_VARIANT_TO_PROTOCOL_P[specification.feature_variant],
                **{metric: 0.9 for metric in G_COMPARISON_METRICS},
            }
        )
    summary_path = root / "reports" / "experiments" / "protocol_p" / "seed42" / "summary.csv"
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(rows).to_csv(summary_path, index=False)
    return summary_path


def test_expected_protocol_g_split_constants_are_fixed():
    assert EXPECTED_G_SPLIT == {
        "train": {"rows": 14602, "groups": 8600, "label_0": 7941, "label_1": 6661},
        "validation": {"rows": 4868, "groups": 3386, "label_0": 2647, "label_1": 2221},
        "test": {"rows": 4867, "groups": 3385, "label_0": 2647, "label_1": 2220},
        "total_rows": 24337,
        "total_groups": 15371,
    }


def test_expected_split_invariant_validator_accepts_exact_manifest_statistics():
    records = []
    for partition in ("train", "validation", "test"):
        expected = EXPECTED_G_SPLIT[partition]
        label_group_counts = {
            0: min(expected["label_0"], expected["groups"] - 1),
            1: expected["groups"] - min(expected["label_0"], expected["groups"] - 1),
        }
        for label, row_count in ((0, expected["label_0"]), (1, expected["label_1"])):
            group_count = label_group_counts[label]
            for group_number in range(group_count):
                records.append(
                    {
                        "sample_id": f"sample_{partition}_{label}_{group_number}",
                        "duplicate_group_id": f"group_{partition}_{label}_{group_number}",
                        "split": partition,
                        "Label": label,
                    }
                )
            for duplicate_number in range(row_count - group_count):
                records.append(
                    {
                        "sample_id": f"sample_{partition}_{label}_extra_{duplicate_number}",
                        "duplicate_group_id": f"group_{partition}_{label}_0",
                        "split": partition,
                        "Label": label,
                    }
                )

    manifest = pd.DataFrame(records)

    assert _verify_expected_g_split(manifest) == {
        name: EXPECTED_G_SPLIT[name] for name in ("train", "validation", "test")
    }


def test_g_feature_variants_reuse_p_selection_and_preserve_semantic_values(tmp_path, monkeypatch):
    _, _, frame, _, _, _ = _synthetic_g_fixture(tmp_path, monkeypatch)

    all_columns = protocol_g_feature_columns(frame, G_ALL41)
    drop_columns = protocol_g_feature_columns(frame, G_DROP3CONSTANT)
    all_view = protocol_g_feature_view(frame, G_ALL41)

    assert len(all_columns) == 41
    assert len(drop_columns) == 38
    assert set(all_columns).difference(drop_columns) == {"Acroform", "Colors", "BaseEncoding"}
    assert all_view["contains_text"].tolist() == frame["contains_text"].tolist()
    assert all_view["pages"].tolist() == frame["pages"].tolist()
    assert all_view["pdf_ver"].tolist() == frame["pdf_ver"].tolist()


def test_saved_g_split_validates_labels_groups_assignments_and_no_feature_vector_leakage(
    tmp_path, monkeypatch
):
    root, dataset_path, frame, manifest, manifest_path, report_path = _synthetic_g_fixture(
        tmp_path, monkeypatch
    )
    _, loaded_manifest, summary = load_saved_protocol_g_split(
        frame,
        sha256_file(dataset_path),
        root,
        manifest_path=manifest_path,
        split_report_path=report_path,
        enforce_expected_invariants=False,
    )
    partitions = split_frame_from_protocol_g_manifest(frame, loaded_manifest)

    assert len(loaded_manifest) == len(manifest) == len(frame)
    assert all(section["is_valid"] for section in summary["hard_validation"].values())
    assert summary["hard_validation"]["zero_group_overlap"]["train_validation"] == 0
    assert summary["hard_validation"]["zero_group_overlap"]["train_test"] == 0
    assert summary["hard_validation"]["zero_group_overlap"]["validation_test"] == 0
    assert sum(len(partition) for partition in partitions.values()) == len(frame)
    assert set(partitions) == {"train", "validation", "test"}


def test_g_runner_uses_train_only_and_protects_protocol_p_outputs(tmp_path, monkeypatch):
    root, dataset_path, frame, manifest, manifest_path, report_path = _synthetic_g_fixture(
        tmp_path, monkeypatch
    )
    specifications = (
        ProtocolGBenchmarkRunSpec("logistic_regression", G_ALL41),
        ProtocolGBenchmarkRunSpec("logistic_regression", G_DROP3CONSTANT),
    )
    protocol_p_summary = _write_protocol_p_summary(root, specifications)
    protocol_p_before = protocol_p_summary.read_bytes()
    estimators = []

    def factory(model_name, seed):
        estimator = RecordingProbabilityEstimator()
        estimators.append(estimator)
        return estimator

    paths, records = run_protocol_g_benchmark(
        root,
        dataset_path,
        run_id="synthetic-run",
        manifest_path=manifest_path,
        split_report_path=report_path,
        protocol_p_summary_path=protocol_p_summary,
        require_clean_git=False,
        enforce_expected_split_invariants=False,
        specifications=specifications,
        model_factory=factory,
        environment_collector=_fake_environment,
    )
    partitions = split_frame_from_protocol_g_manifest(frame, manifest)

    assert len(records) == 2
    assert {record["feature_count"] for record in records} == {41, 38}
    assert all(record["status"] == "completed" for record in records)
    assert all(protocol_g_result_schema_is_valid(record) for record in records)
    assert all(record["validation"]["metrics"]["score_source"] == "predict_proba" for record in records)
    assert all(record["test"]["metrics"]["score_source"] == "predict_proba" for record in records)
    assert all(estimator.fit_row_count == len(partitions["train"]) for estimator in estimators)
    assert all(
        estimator.fit_feature_values == {int(value) for value in partitions["train"]["feature_0"]}
        for estimator in estimators
    )
    evaluation_values = {
        int(value)
        for partition in ("validation", "test")
        for value in partitions[partition]["feature_0"]
    }
    assert not any(estimator.fit_feature_values.intersection(evaluation_values) for estimator in estimators)
    assert protocol_p_summary.read_bytes() == protocol_p_before
    assert paths.summary_validation_csv.is_file()
    assert paths.summary_test_csv.is_file()
    assert paths.metrics_json.is_file()
    assert paths.protocol_p_vs_g_csv.is_file()
    assert paths.confusion_matrices_json.is_file()
    persisted = json.loads(paths.metrics_json.read_text(encoding="utf-8"))
    assert persisted["runs"][0]["environment"]["git_working_tree"]["status"] == "unavailable"


def test_protocol_p_vs_g_comparison_uses_equivalent_variants_and_correct_math():
    protocol_p_summary = pd.DataFrame(
        [
            {
                "model_name": "logistic_regression",
                "feature_variant": "P-all41",
                **{metric: 0.8 for metric in G_COMPARISON_METRICS},
            }
        ]
    )
    record = {
        "model_name": "logistic_regression",
        "feature_variant": G_ALL41,
        "validation": {"metrics": {metric: 0.7 for metric in G_COMPARISON_METRICS}},
        "test": {"metrics": {metric: 0.75 for metric in G_COMPARISON_METRICS}},
    }

    comparison = build_protocol_p_vs_g_comparison(protocol_p_summary, [record])

    assert len(comparison) == len(G_COMPARISON_METRICS)
    accuracy = next(row for row in comparison if row["metric"] == "accuracy")
    assert accuracy["protocol_p_feature_variant"] == "P-all41"
    assert accuracy["protocol_g_test_minus_protocol_p"] == pytest.approx(-0.05)
    assert accuracy["absolute_difference"] == pytest.approx(0.05)


def test_g_runner_enforces_clean_git_before_touching_data(tmp_path, monkeypatch):
    monkeypatch.setattr(
        protocol_g_benchmark,
        "repository_git_state",
        lambda root: {"status": "dirty", "porcelain_entries": [" M source.py"]},
    )

    with pytest.raises(ProtocolGBenchmarkError, match="not clean"):
        run_protocol_g_benchmark(tmp_path, tmp_path / "missing.csv")


def test_g_output_directories_are_immutable_and_failure_evidence_is_preserved(
    tmp_path, monkeypatch
):
    root, dataset_path, _, _, manifest_path, report_path = _synthetic_g_fixture(tmp_path, monkeypatch)
    specification = (ProtocolGBenchmarkRunSpec("logistic_regression", G_ALL41),)
    protocol_p_summary = _write_protocol_p_summary(root, specification)

    run_protocol_g_benchmark(
        root,
        dataset_path,
        run_id="immutable-run",
        manifest_path=manifest_path,
        split_report_path=report_path,
        protocol_p_summary_path=protocol_p_summary,
        require_clean_git=False,
        enforce_expected_split_invariants=False,
        specifications=specification,
        model_factory=lambda model_name, seed: RecordingProbabilityEstimator(),
        environment_collector=_fake_environment,
    )
    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        run_protocol_g_benchmark(
            root,
            dataset_path,
            run_id="immutable-run",
            manifest_path=manifest_path,
            split_report_path=report_path,
            protocol_p_summary_path=protocol_p_summary,
            require_clean_git=False,
            enforce_expected_split_invariants=False,
            specifications=specification,
            model_factory=lambda model_name, seed: RecordingProbabilityEstimator(),
            environment_collector=_fake_environment,
        )

    def failing_factory(model_name, seed):
        raise RuntimeError("synthetic G model failure")

    with pytest.raises(ProtocolGBenchmarkError, match="failed primary runs"):
        run_protocol_g_benchmark(
            root,
            dataset_path,
            run_id="failure-run",
            manifest_path=manifest_path,
            split_report_path=report_path,
            protocol_p_summary_path=protocol_p_summary,
            require_clean_git=False,
            enforce_expected_split_invariants=False,
            specifications=specification,
            model_factory=failing_factory,
            environment_collector=_fake_environment,
        )
    failed_metrics = json.loads(
        (root / "reports" / "experiments" / "protocol_g" / "failure-run" / "metrics.json").read_text(
            encoding="utf-8"
        )
    )
    assert failed_metrics["runs"][0]["error"]["type"] == "RuntimeError"


def test_g_reuses_the_protocol_p_model_configuration_object():
    configuration = model_configurations(42)

    assert set(specification.model_name for specification in PRIMARY_G_BENCHMARK_MATRIX) == set(
        configuration
    )
    assert len(PRIMARY_G_BENCHMARK_MATRIX) == 10
