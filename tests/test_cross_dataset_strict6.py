"""Synthetic safety tests for the future-only STRICT6 transfer runner."""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from malpdf.experiments.cross_dataset_strict6 import (
    CIC_EXPECTED_COUNTS,
    METRIC_NAMES,
    MODEL_NAMES,
    STRICT6_SCHEMA_VERSION,
    STRICT_FEATURES,
    CanonicalDatasetView,
    Strict6Error,
    Strict6Preflight,
    canonicalize_cic_strict6,
    deterministic_within_split,
    execute_cross_dataset_strict6_from_preflight,
    load_strict6_configuration,
    mirror_stability_report,
    strict6_paths,
    validate_strict6_configuration,
)


def _records() -> tuple[dict, ...]:
    return tuple(
        {
            "canonical_name": name,
            "rit_column": f"rit_{name}",
            "cic_column": f"Cic{name.title().replace('_', '')}",
            "status": "EXACT",
        }
        for name in STRICT_FEATURES
    )


def _cic_frame(rows: int = 8) -> pd.DataFrame:
    frame = pd.DataFrame({"FileName": [f"{number:064x}" for number in range(rows)]})
    for offset, name in enumerate(STRICT_FEATURES):
        frame[f"Cic{name.title().replace('_', '')}"] = [float(number + offset) for number in range(rows)]
    frame["Class"] = ["Benign" if number % 2 == 0 else "Malicious" for number in range(rows)]
    return frame


def _write_source(frame: pd.DataFrame, path: Path) -> Path:
    frame.to_csv(path, index=False)
    return path


def _view(tmp_path: Path, name: str, offset: int) -> CanonicalDatasetView:
    features = pd.DataFrame({feature: np.arange(16, dtype=float) + offset for feature in STRICT_FEATURES})
    labels = pd.Series([0, 1] * 8, dtype=int)
    return CanonicalDatasetView(
        name=name, source_path=tmp_path / f"{name}.csv", source_sha256=f"{offset}" * 64,
        features=features, labels=labels, safe_sample_ids=pd.Series([f"{name}-{row}" for row in range(16)]),
        source_columns={feature: feature for feature in STRICT_FEATURES}, target_column="Label",
        raw_label_mapping={"Benign": 0, "Malicious": 1}, canonical_view_sha256=f"view-{name}",
    )


class RecordingEstimator:
    """Benign test double used solely to verify training-source boundaries."""

    def __init__(self) -> None:
        self.classes_ = np.array([0, 1])
        self.fit_minimum: float | None = None
        self.fit_rows = 0

    def fit(self, features, labels):
        self.fit_minimum = float(features[STRICT_FEATURES[0]].min())
        self.fit_rows = len(features)
        return self

    def predict(self, features):
        return np.asarray(features[STRICT_FEATURES[0]] % 2, dtype=int)

    def predict_proba(self, features):
        positive = np.asarray(features[STRICT_FEATURES[0]] % 2, dtype=float)
        return np.column_stack([1.0 - positive, positive])


def test_canonical_cic_view_excludes_only_invalid_target_row_and_never_changes_raw_source(tmp_path):
    frame = _cic_frame()
    pseudo = {column: "nan" for column in frame.columns}
    frame = pd.concat([frame, pd.DataFrame([pseudo])], ignore_index=True)
    path = _write_source(frame, tmp_path / "fixture.csv")
    before = path.read_bytes()
    view = canonicalize_cic_strict6(frame, path, _records(), expected_rows=8, expected_counts={0: 4, 1: 4})
    assert view.excluded_invalid_target_rows == 1
    assert view.counts() == {0: 4, 1: 4}
    assert tuple(view.features.columns) == STRICT_FEATURES
    assert path.read_bytes() == before
    assert "nan" not in view.raw_label_mapping


def test_numeric_validation_refuses_unresolved_strict_token(tmp_path):
    frame = _cic_frame()
    frame["CicTrailer"] = frame["CicTrailer"].astype(object)
    frame.loc[2, "CicTrailer"] = "1(1)"
    with pytest.raises(Strict6Error, match="unresolved non-numeric"):
        canonicalize_cic_strict6(frame, _write_source(frame, tmp_path / "bad.csv"), _records())


def test_mirror_stability_is_redacted_and_blocks_an_unexplained_strict_difference(tmp_path):
    csv = _cic_frame()
    parquet = _cic_frame()
    parquet.loc[3, "CicObjstm"] = -1.0
    csv_view = canonicalize_cic_strict6(csv, _write_source(csv, tmp_path / "csv.csv"), _records())
    parquet_view = canonicalize_cic_strict6(parquet, _write_source(parquet, tmp_path / "parquet.csv"), _records())
    rows = mirror_stability_report(csv_view, parquet_view)
    by_feature = {row["canonical_name"]: row for row in rows}
    assert by_feature["objstm"]["classification"] == "MIRROR_UNSTABLE"
    assert by_feature["objstm"]["mismatch_count"] == 1
    assert by_feature["metadata_size"]["classification"] == "MIRROR_STABLE"
    rendered = json.dumps(rows)
    assert csv.loc[0, "FileName"] not in rendered


def test_within_domain_split_is_deterministic_row_level_stratified_and_complete(tmp_path):
    view = _view(tmp_path, "rit", 0)
    first, second = deterministic_within_split(view), deterministic_within_split(view)
    pd.testing.assert_series_equal(first["assignment"], second["assignment"])
    assert first["statistics"] == {"train": {"rows": 12, "benign": 6, "malicious": 6}, "test": {"rows": 4, "benign": 2, "malicious": 2}}
    assert first["row_level_stratified"]


def test_fixed_configuration_locks_six_features_four_tracks_five_models_and_twenty_results():
    root = Path(__file__).resolve().parents[1]
    config = load_strict6_configuration(root / "configs" / "cross_dataset_strict6.yaml")
    validate_strict6_configuration(config)
    assert tuple(config["strict_feature_order"]) == STRICT_FEATURES
    assert tuple(config["models"]) == MODEL_NAMES
    assert config["expected_result_count"] == 20
    broken = dict(config)
    broken["strict_feature_order"] = list(reversed(STRICT_FEATURES))
    with pytest.raises(Strict6Error, match="feature order"):
        validate_strict6_configuration(broken)


def test_synthetic_execution_uses_only_track_training_source_and_keeps_outputs_immutable(tmp_path):
    historical_marker = tmp_path / "reports" / "experiments" / "protocol_g" / "seed42" / "marker.txt"
    historical_marker.parent.mkdir(parents=True)
    historical_marker.write_text("historical", encoding="utf-8")
    rit, cic = _view(tmp_path, "rit", 0), _view(tmp_path, "cic", 1000)
    splits = {"within_rit": deterministic_within_split(rit), "within_cic": deterministic_within_split(cic)}
    paths = strict6_paths(tmp_path, "synthetic")
    preflight = Strict6Preflight(
        repository_root=tmp_path, rit=rit, cic=cic, cic_parquet=cic, schema_records=_records(),
        mirror_stability=tuple({"canonical_name": feature, "classification": "MIRROR_STABLE"} for feature in STRICT_FEATURES),
        distribution_shift=(), within_splits=splits,
        config=load_strict6_configuration(Path(__file__).resolve().parents[1] / "configs" / "cross_dataset_strict6.yaml"),
        environment={"git_working_tree": {"status": "clean"}, "git_commit_sha": "a" * 40},
        benchmark_code_commit="a" * 40, paths=paths, training_ready=True, readiness_failures=(),
    )
    estimators: list[RecordingEstimator] = []

    def factory(model, seed):
        assert model in MODEL_NAMES and seed == 42
        result = RecordingEstimator()
        estimators.append(result)
        return result

    output, records = execute_cross_dataset_strict6_from_preflight(preflight, model_factory=factory)
    assert len(records) == len(estimators) == 20

    assert all(estimator.fit_minimum is not None and estimator.fit_minimum < 1000 for estimator in estimators[:5])
    assert all(estimator.fit_minimum is not None and estimator.fit_minimum >= 1000 for estimator in estimators[5:10])
    assert all(estimator.fit_minimum == 0.0 for estimator in estimators[10:15])
    assert all(estimator.fit_minimum == 1000.0 for estimator in estimators[15:])
    assert all(set(METRIC_NAMES).issubset(record["metrics"]) and record["metrics"]["positive_label"] == 1 for record in records)
    assert output.metrics_json.is_file() and output.comparison_csv.is_file()
    assert all(output.summary_csv(track).is_file() for track in ("within_rit", "within_cic", "rit_to_cic", "cic_to_rit"))
    assert output.split_manifest_csv("within_rit").is_file() and output.split_manifest_csv("within_cic").is_file()
    assert historical_marker.read_text(encoding="utf-8") == "historical"
    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        execute_cross_dataset_strict6_from_preflight(preflight, model_factory=factory)


def test_execution_refuses_a_failed_strict_feature_readiness_preflight(tmp_path):
    rit, cic = _view(tmp_path, "rit", 0), _view(tmp_path, "cic", 1000)
    preflight = Strict6Preflight(
        repository_root=tmp_path, rit=rit, cic=cic, cic_parquet=cic, schema_records=_records(), mirror_stability=(), distribution_shift=(),
        within_splits={"within_rit": deterministic_within_split(rit), "within_cic": deterministic_within_split(cic)},
        config=load_strict6_configuration(Path(__file__).resolve().parents[1] / "configs" / "cross_dataset_strict6.yaml"),
        environment={"git_working_tree": {"status": "clean"}}, benchmark_code_commit="a" * 40,
        paths=strict6_paths(tmp_path, "blocked"), training_ready=False, readiness_failures=("objstm=MIRROR_UNSTABLE",),
    )
    with pytest.raises(Strict6Error, match="objstm=MIRROR_UNSTABLE"):
        execute_cross_dataset_strict6_from_preflight(preflight)
    assert not preflight.paths.reports_directory.exists()
