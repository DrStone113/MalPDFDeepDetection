import math

import numpy as np
import pandas as pd
import pytest
from pandas.testing import assert_frame_equal

from malpdf.data.protocol_p import (
    P_ALL41,
    P_DROP3CONSTANT,
    ProtocolPSplitError,
    create_protocol_p_split,
    protocol_p_feature_columns,
    protocol_p_feature_view,
    validate_protocol_p_manifest,
    write_protocol_p_manifest,
)
from malpdf.evaluation.binary import continuous_positive_scores, evaluate_binary_predictions
from malpdf.models.classical import MODEL_NAMES, create_model


def _protocol_p_frame() -> pd.DataFrame:
    feature_names = ["contains_text", "pages", "pdf_ver", "Acroform", "Colors", "BaseEncoding"]
    feature_names.extend(f"feature_{index}" for index in range(35))
    rows = []
    for label in (0, 1):
        for value in range(40):
            row = {feature: value + label * 100 for feature in feature_names}
            row["contains_text"] = (-1, 0, 1)[value % 3]
            row["pages"] = 0 if value % 7 == 0 else value + 1
            row["pdf_ver"] = 5.0 if value % 11 == 0 else 1.7
            row["Acroform"] = 0
            row["Colors"] = 0
            row["BaseEncoding"] = 0
            row["Label"] = label
            rows.append(row)
    frame = pd.DataFrame(rows)
    frame.index = range(1000, 1000 + len(frame))
    return frame


def test_protocol_p_split_is_deterministic_stratified_and_assigns_every_row_once():
    frame = _protocol_p_frame()
    original = frame.copy(deep=True)

    manifest_one, result_one = create_protocol_p_split(frame, "test-sha", seed=42)
    manifest_two, result_two = create_protocol_p_split(frame, "test-sha", seed=42)

    assert_frame_equal(manifest_one, manifest_two)
    assert result_one["split_statistics"] == result_two["split_statistics"]
    assert result_one["split_statistics"]["train"]["row_count"] == 60
    assert result_one["split_statistics"]["test"]["row_count"] == 20
    assert result_one["split_statistics"]["train"]["benign_label_0_count"] == 30
    assert result_one["split_statistics"]["test"]["malicious_label_1_count"] == 10
    validation = validate_protocol_p_manifest(frame, manifest_one)
    assert all(item["is_valid"] for item in validation.values())
    assert manifest_one["sample_id"].is_unique
    assert set(manifest_one["split"]) == {"train", "test"}
    assert_frame_equal(frame, original)


def test_feature_variants_are_exact_and_preserve_special_values():
    frame = _protocol_p_frame()

    all_columns = protocol_p_feature_columns(frame, P_ALL41.name)
    drop_columns = protocol_p_feature_columns(frame, P_DROP3CONSTANT.name)
    all_view = protocol_p_feature_view(frame, P_ALL41.name)
    drop_view = protocol_p_feature_view(frame, P_DROP3CONSTANT.name)

    assert len(all_columns) == 41
    assert len(drop_columns) == 38
    assert set(all_columns).difference(drop_columns) == {"Acroform", "Colors", "BaseEncoding"}
    assert list(all_view.columns) == all_columns
    assert list(drop_view.columns) == drop_columns
    assert all_view["contains_text"].tolist() == frame["contains_text"].tolist()
    assert all_view["pages"].tolist() == frame["pages"].tolist()
    assert all_view["pdf_ver"].tolist() == frame["pdf_ver"].tolist()


def test_protocol_p_manifest_writer_refuses_protocol_g_and_existing_outputs(tmp_path):
    frame = _protocol_p_frame()
    manifest, _ = create_protocol_p_split(frame, "test-sha", seed=42)

    with pytest.raises(ProtocolPSplitError, match="protocol_p directory"):
        write_protocol_p_manifest(manifest, tmp_path / "protocol_g" / "manifest.csv")

    output = tmp_path / "protocol_p" / "run-a" / "manifest.csv"
    write_protocol_p_manifest(manifest, output)
    with pytest.raises(FileExistsError, match="Refusing to overwrite"):
        write_protocol_p_manifest(manifest, output)


def test_model_factories_create_all_paper_families_and_scaler_fits_train_only():
    models = {name: create_model(name, seed=42) for name in MODEL_NAMES}

    assert set(models) == set(MODEL_NAMES)
    assert list(models["logistic_regression"].named_steps) == ["scaler", "classifier"]
    assert models["random_forest"].n_estimators == 200
    assert models["decision_tree"].criterion == "gini"
    assert models["gaussian_naive_bayes"].var_smoothing == 1e-9
    assert models["xgboost"].get_params()["objective"] == "binary:logistic"

    train_features = np.array([[0.0, 2.0], [2.0, 4.0], [4.0, 6.0], [6.0, 8.0]])
    train_labels = np.array([0, 0, 1, 1])
    held_out_features = np.array([[1000.0, 1000.0], [2000.0, 2000.0]])
    logistic = models["logistic_regression"]
    logistic.fit(train_features, train_labels)
    assert np.allclose(logistic.named_steps["scaler"].mean_, train_features.mean(axis=0))
    assert not np.allclose(logistic.named_steps["scaler"].mean_, np.vstack([train_features, held_out_features]).mean(axis=0))


class _ProbabilityEstimator:
    classes_ = np.array([0, 1])

    def predict_proba(self, features):
        return np.array([[0.8, 0.2], [0.1, 0.9]])


def test_metrics_use_label_one_as_positive_and_scores_not_hard_predictions():
    truth = np.array([0, 0, 1, 1])
    prediction = np.array([0, 1, 1, 1])
    scores, source = continuous_positive_scores(_ProbabilityEstimator(), np.zeros((2, 1)))
    metrics = evaluate_binary_predictions(truth, prediction, np.array([0.1, 0.6, 0.8, 0.9]))

    assert source == "predict_proba"
    assert np.allclose(scores, [0.2, 0.9])
    assert metrics["positive_label"] == 1
    assert math.isclose(metrics["precision"], 2 / 3)
    assert math.isclose(metrics["recall"], 1.0)
    assert math.isclose(metrics["f1"], 0.8)
    assert metrics["confusion_matrix"] == [[1, 1], [0, 2]]
    assert metrics["roc_auc"] is not None
    assert metrics["pr_auc"] is not None
