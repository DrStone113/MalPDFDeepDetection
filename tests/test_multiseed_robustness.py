from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pandas as pd
import pytest

from malpdf.data.protocol_p import P_DROP3CONSTANT, protocol_p_feature_view
from malpdf.data.rit_pdfmal import sha256_file
from malpdf.data.rit_pdfmal_split import build_duplicate_group_ids
import malpdf.experiments.multiseed_robustness as multiseed_robustness
from malpdf.experiments.multiseed_robustness import (
    CANONICAL_METRICS,
    FIXED_MODEL_RANDOM_STATE,
    MODEL_NAMES,
    OFFICIAL_SPLIT_SEEDS,
    G_DROP3CONSTANT,
    MultiSeedPreflight,
    MultiSeedRobustnessError,
    _create_output_directories,
    aggregate_multiseed_results,
    create_seed_split_manifests,
    load_multiseed_configuration,
    multiseed_paths,
    multiseed_result_schema_is_valid,
    persist_seed_split_manifests,
    preflight_multiseed_run,
    run_multiseed_robustness,
    validate_execution_request,
    validate_multiseed_configuration,
)
from malpdf.experiments.protocol_g_benchmark import protocol_g_feature_view
from malpdf.models.classical import model_configurations


class RecordingProbabilityEstimator:
    """Pickle-safe estimator used only for the synthetic execution-path test."""

    classes_ = (0, 1)

    def fit(self, features, labels):
        self.fit_row_count = len(features)
        return self

    def predict_proba(self, features):
        positive = (features["feature_0"].to_numpy() >= 1000).astype(float)
        return __import__("numpy").column_stack([1.0 - positive, positive])

    def predict(self, features):
        return (features["feature_0"].to_numpy() >= 1000).astype(int)


def _synthetic_frame() -> pd.DataFrame:
    feature_names = ["contains_text", "images", "pdf_ver", "pages", "Acroform", "Colors", "BaseEncoding"]
    feature_names.extend(f"feature_{number}" for number in range(34))
    rows: list[dict[str, int | float]] = []
    for label in (0, 1):
        for value in range(30):
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
            # Identical feature vectors intentionally exist; G must keep each group intact.
            rows.extend([row.copy(), row.copy()])
    frame = pd.DataFrame(rows)
    assert len(frame.columns) == 42
    return frame


def _metric_values(value: float) -> dict[str, float | int]:
    metrics: dict[str, float | int] = {metric: value for metric in CANONICAL_METRICS[:10]}
    metrics.update({"tn": 10, "fp": 1, "fn": 2, "tp": 9})
    return metrics


def _record(protocol: str, seed: int, model: str, value: float, *, failed: bool = False) -> dict:
    if failed:
        return {"protocol": protocol, "split_seed": seed, "model_name": model, "status": "failed", "evaluations": {}}
    evaluation = {"metrics": _metric_values(value)}
    return {
        "protocol": protocol,
        "split_seed": seed,
        "model_name": model,
        "status": "completed",
        "evaluations": {"test": evaluation} if protocol == "P" else {"validation": evaluation, "test": evaluation},
    }


def test_committed_configuration_locks_official_seeds_models_variants_and_random_state():
    root = Path(__file__).resolve().parents[1]
    config = load_multiseed_configuration(root / "configs" / "multiseed_robustness.yaml")

    assert tuple(config["split_seeds"]) == OFFICIAL_SPLIT_SEEDS
    assert config["model_random_state"] == FIXED_MODEL_RANDOM_STATE
    assert tuple(config["models"]) == MODEL_NAMES
    assert config["protocols"]["P"]["feature_variant"] == P_DROP3CONSTANT.name
    assert config["protocols"]["G"]["feature_variant"] == G_DROP3CONSTANT

    changed = deepcopy(config)
    changed["model_random_state"] = 43
    with pytest.raises(MultiSeedRobustnessError, match="model_random_state"):
        validate_multiseed_configuration(changed)


def test_execution_request_keeps_model_random_state_separate_from_split_seed():
    official = validate_execution_request()
    partial = validate_execution_request(protocols=("P",), split_seeds=(42, 43), models=("decision_tree",))

    assert official["matrix_status"] == "official_fixed_matrix"
    assert official["model_random_state"] == 42
    assert partial["matrix_status"] == "partial_nonofficial_matrix"
    assert partial["model_random_state"] == 42
    with pytest.raises(MultiSeedRobustnessError, match="Split seeds"):
        validate_execution_request(split_seeds=(41,))


def test_seed_split_generation_is_deterministic_and_keeps_p_and_g_methods_distinct():
    frame = _synthetic_frame()
    first = create_seed_split_manifests(frame, "fixture-sha", seed=42)
    second = create_seed_split_manifests(frame, "fixture-sha", seed=42)
    different_seed = create_seed_split_manifests(frame, "fixture-sha", seed=43)

    pd.testing.assert_frame_equal(first["P"][0], second["P"][0])
    pd.testing.assert_frame_equal(first["G"][0], second["G"][0])
    assert not first["P"][0][["sample_id", "split"]].equals(different_seed["P"][0][["sample_id", "split"]])
    assert not first["G"][0][["sample_id", "split"]].equals(different_seed["G"][0][["sample_id", "split"]])
    assert first["P"][0]["sample_id"].is_unique
    assert first["P"][0]["split"].value_counts().to_dict() == {"train": 90, "test": 30}
    assert first["P"][0].groupby("split")["Label"].value_counts().to_dict() == {
        ("train", 0): 45, ("train", 1): 45, ("test", 0): 15, ("test", 1): 15,
    }
    assert first["P"][0]["seed"].eq(42).all()
    assert first["G"][0]["seed"].eq(42).all()
    assert first["G"][0]["dataset_sha256"].eq("fixture-sha").all()


def test_group_split_has_zero_duplicate_vector_leakage_for_each_seed():
    frame = _synthetic_frame()
    for seed in (42, 43, 44):
        manifest, result = create_seed_split_manifests(frame, "fixture-sha", seed=seed)["G"]
        assert result["hard_validation"]["zero_group_overlap"]["is_valid"]
        assert manifest["sample_id"].is_unique
        assert len(manifest) == len(frame)
        assert manifest.groupby("duplicate_group_id")["split"].nunique().eq(1).all()
        assert set(manifest["duplicate_group_id"]) == set(build_duplicate_group_ids(frame))


def test_canonical_feature_variants_preserve_documented_semantic_values():
    frame = _synthetic_frame()
    p_view = protocol_p_feature_view(frame, P_DROP3CONSTANT.name)
    g_view = protocol_g_feature_view(frame, G_DROP3CONSTANT)

    assert len(p_view.columns) == len(g_view.columns) == 38
    for column in ("contains_text", "images", "pages", "pdf_ver"):
        assert p_view[column].tolist() == frame[column].tolist()
        assert g_view[column].tolist() == frame[column].tolist()


def test_fixed_model_configuration_keeps_stochastic_model_states_at_42():
    configurations = model_configurations(FIXED_MODEL_RANDOM_STATE)
    assert set(configurations) == set(MODEL_NAMES)
    for configuration in configurations.values():
        if "random_state" in configuration["parameters"]:
            assert configuration["parameters"]["random_state"] == FIXED_MODEL_RANDOM_STATE


def test_result_schema_requires_explicit_malicious_and_macro_metric_names():
    record = {
        "protocol": "P", "split_seed": 43, "model_random_state": 42,
        "model_name": "logistic_regression", "feature_variant": P_DROP3CONSTANT.name,
        "status": "completed", "dataset_sha256": "fixture-sha", "split_manifest": "manifest.csv",
        "split_manifest_sha256": "manifest-sha", "model_configuration": {"x": 1},
        "preprocessing_configuration": {"name": "test"}, "benchmark_code_commit": "a" * 40,
        "environment": {"python_version": "3.11-test"}, "error": None,
        "evaluations": {"test": {"metrics": _metric_values(0.9)}},
    }
    assert multiseed_result_schema_is_valid(record)
    del record["evaluations"]["test"]["metrics"]["f1_macro"]
    assert not multiseed_result_schema_is_valid(record)


def test_aggregation_uses_sample_standard_deviation_paired_deltas_and_failure_coverage():
    records = [
        _record("P", 42, "logistic_regression", 0.9),
        _record("P", 43, "logistic_regression", 0.8),
        _record("P", 44, "logistic_regression", 0.7),
        _record("G", 42, "logistic_regression", 0.7),
        _record("G", 43, "logistic_regression", 0.9),
        _record("G", 44, "logistic_regression", 0.0, failed=True),
    ]
    aggregate, paired = aggregate_multiseed_results(
        records, split_seeds=(42, 43, 44), models=("logistic_regression",), protocols=("P", "G")
    )

    p_accuracy = next(row for row in aggregate if row["protocol"] == "P" and row["metric"] == "accuracy")
    assert p_accuracy["n"] == 3
    assert p_accuracy["mean"] == pytest.approx(0.8)
    assert p_accuracy["sample_standard_deviation"] == pytest.approx(0.1)
    g_accuracy = next(row for row in aggregate if row["protocol"] == "G" and row["partition"] == "test" and row["metric"] == "accuracy")
    assert g_accuracy["n"] == 2
    assert g_accuracy["missing_or_failed_seeds"] == [44]
    delta = next(row for row in paired if row["metric"] == "accuracy")
    assert delta["paired_seed_count"] == 2
    assert delta["mean_delta"] == pytest.approx(-0.05)
    assert delta["g_greater_count"] == 1
    assert delta["p_greater_count"] == 1
    assert delta["missing_or_failed_seeds"] == [44]


def test_multiseed_paths_and_manifest_persistence_cannot_overwrite_protocol_baselines(tmp_path):
    p_baseline = tmp_path / "data" / "processed" / "protocol_p" / "seed42" / "manifest.csv"
    g_baseline = tmp_path / "data" / "processed" / "rit-pdfmal-2026_split_manifest.csv"
    p_baseline.parent.mkdir(parents=True)
    g_baseline.parent.mkdir(parents=True, exist_ok=True)
    p_baseline.write_text("immutable P baseline", encoding="utf-8")
    g_baseline.write_text("immutable G baseline", encoding="utf-8")
    before = {path: path.read_bytes() for path in (p_baseline, g_baseline)}
    paths = multiseed_paths(tmp_path, "new-run")
    assert "multiseed" in paths.reports_directory.parts
    assert "protocol_p" not in paths.processed_directory.parts
    assert "protocol_g" not in paths.processed_directory.parts
    _create_output_directories(paths)
    assert paths.configuration_directory.is_dir()
    assert paths.split_summaries_directory.is_dir()

    frame = _synthetic_frame()
    manifests = create_seed_split_manifests(frame, "fixture-sha", seed=43)
    first = persist_seed_split_manifests(paths, manifests, seed=43)
    assert Path(first["P"]["path"]).is_file()
    assert Path(first["G"]["path"]).is_file()
    with pytest.raises(FileExistsError, match="Refusing to overwrite"):
        persist_seed_split_manifests(paths, manifests, seed=43)
    assert {path: path.read_bytes() for path in before} == before


def test_preflight_rejects_non_clean_repository_before_reading_or_writing_dataset(tmp_path):
    root = Path(__file__).resolve().parents[1]
    config = load_multiseed_configuration(root / "configs" / "multiseed_robustness.yaml")
    with pytest.raises(MultiSeedRobustnessError, match="not clean"):
        preflight_multiseed_run(tmp_path, tmp_path / "missing.csv", config, require_clean_git=True)


def test_explicit_execution_writes_new_immutable_outputs_and_reuses_seed42_without_touching_sources(
    tmp_path, monkeypatch
):
    root = Path(__file__).resolve().parents[1]
    config_path = root / "configs" / "multiseed_robustness.yaml"
    frame = _synthetic_frame()
    p_manifest, p_result = create_seed_split_manifests(frame, "fixture-sha", seed=42)["P"]
    g_manifest, g_result = create_seed_split_manifests(frame, "fixture-sha", seed=42)["G"]
    p_manifest_path = tmp_path / "seed42-p.csv"
    g_manifest_path = tmp_path / "seed42-g.csv"
    p_manifest.to_csv(p_manifest_path, index=False)
    g_manifest.to_csv(g_manifest_path, index=False)
    baseline_p = tmp_path / "baseline-p.json"
    baseline_g = tmp_path / "baseline-g.json"
    baseline_p.write_text('{"source":"P"}', encoding="utf-8")
    baseline_g.write_text('{"source":"G"}', encoding="utf-8")
    source_bytes = {path: path.read_bytes() for path in (baseline_p, baseline_g)}
    preflight = MultiSeedPreflight(
        dataset_path=tmp_path / "fixture.csv", dataset_sha256="fixture-sha", frame=frame,
        environment={"python_version": "3.11-test", "git_working_tree": {"status": "clean"}},
        benchmark_code_commit="a" * 40,
        baseline_references={
            "protocol_p_metrics": {"path": str(baseline_p), "sha256": sha256_file(baseline_p)},
            "protocol_g_metrics": {"path": str(baseline_g), "sha256": sha256_file(baseline_g)},
        },
        protocol_p_seed42_manifest=p_manifest_path,
        protocol_g_seed42_manifest=g_manifest_path,
        protocol_p_seed42_summary=p_result,
        protocol_g_seed42_summary=g_result,
    )

    def seed42_records(_root, _preflight, models, protocols):
        records = []
        for protocol in protocols:
            for model in models:
                evaluations = {"test": {"metrics": _metric_values(0.9), "runtime": {}}}
                if protocol == "G":
                    evaluations["validation"] = {"metrics": _metric_values(0.9), "runtime": {}}
                records.append(
                    {
                        "protocol": protocol, "split_seed": 42, "model_random_state": 42,
                        "model_name": model,
                        "feature_variant": P_DROP3CONSTANT.name if protocol == "P" else G_DROP3CONSTANT,
                        "feature_count": 38, "status": "completed", "dataset_sha256": "fixture-sha",
                        "split_manifest": str(p_manifest_path if protocol == "P" else g_manifest_path),
                        "split_manifest_sha256": sha256_file(p_manifest_path if protocol == "P" else g_manifest_path),
                        "split_result": p_result if protocol == "P" else g_result,
                        "model_configuration": {"preprocessing": {"name": None}},
                        "preprocessing_configuration": {"name": None}, "benchmark_code_commit": "b" * 40,
                        "environment": {"python_version": "seed42"}, "reused_seed42_baseline": True,
                        "evaluations": evaluations, "training": {"training_seconds": 0.0},
                        "model_artifact": None, "error": None,
                    }
                )
        return records

    monkeypatch.setattr(multiseed_robustness, "preflight_multiseed_run", lambda *args, **kwargs: preflight)
    monkeypatch.setattr(multiseed_robustness, "_seed42_records", seed42_records)
    _, paths, records = run_multiseed_robustness(
        tmp_path, tmp_path / "fixture.csv", config_path, run_id="synthetic-execute",
        split_seeds=(42, 43), models=("logistic_regression",), execute=True,
        model_factory=lambda model, seed: RecordingProbabilityEstimator(),
    )

    assert paths is not None
    assert len(records) == 4
    assert sum(record["reused_seed42_baseline"] for record in records) == 2
    assert (paths.per_seed_directory / "seed42" / "metrics.json").is_file()
    assert (paths.per_seed_directory / "seed43" / "metrics.json").is_file()
    assert (paths.split_summaries_directory / "seed43.json").is_file()
    assert paths.fixed_design_yaml.is_file()
    assert paths.aggregate_metrics_csv.is_file()
    assert {path: path.read_bytes() for path in source_bytes} == source_bytes
    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        run_multiseed_robustness(
            tmp_path, tmp_path / "fixture.csv", config_path, run_id="synthetic-execute",
            split_seeds=(42, 43), models=("logistic_regression",), execute=True,
            model_factory=lambda model, seed: RecordingProbabilityEstimator(),
        )
